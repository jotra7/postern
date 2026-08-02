package client_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
)

func addr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", s, err)
	}
	return ap
}

// opErr wraps an errno the way the net package does, so Classify is tested
// against the shape it actually meets rather than a bare errno.
func opErr(errno syscall.Errno) error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", errno),
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// The three distinctions the brief requires the confirmation to draw, plus
// the two edges around them. Matching on errno rather than error text is the
// property: an error string is not an interface.
//
// Mutation verified: replacing the ECONNREFUSED branch with the NoRoute
// branch's errnos fails the "refused" and "host unreachable" rows.
func TestClient_Classify_DistinguishesNoRouteTimeoutAndRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want client.Outcome
	}{
		{"success", nil, client.Connected},
		{"refused", opErr(syscall.ECONNREFUSED), client.Refused},
		{"host unreachable", opErr(syscall.EHOSTUNREACH), client.NoRoute},
		{"network unreachable", opErr(syscall.ENETUNREACH), client.NoRoute},
		{"host down", opErr(syscall.EHOSTDOWN), client.NoRoute},
		{"context deadline", context.DeadlineExceeded, client.TimedOut},
		{"socket deadline", os.ErrDeadlineExceeded, client.TimedOut},
		{"net.Error timeout", &net.OpError{Op: "dial", Err: timeoutErr{}}, client.TimedOut},
		{"something else", errors.New("tls: handshake failure"), client.Unclassified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := client.Classify(tc.err); got != tc.want {
				t.Fatalf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// A refusal is as conclusive as a connection — both prove the packet reached
// the host — so neither is retried. Seconds matter during an incident.
func TestClient_Confirm_StopsRetryingOnADefinitiveOutcome(t *testing.T) {
	for _, tc := range []struct {
		name         string
		err          error
		wantAttempts int
	}{
		{"connected", nil, 1},
		{"refused", opErr(syscall.ECONNREFUSED), 1},
		{"timeout", context.DeadlineExceeded, 2},
		{"no route", opErr(syscall.EHOSTUNREACH), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			dial := func(context.Context, string, string) (net.Conn, error) {
				calls++
				return nil, tc.err
			}
			res := client.Confirm(context.Background(), dial, addr(t, "203.0.113.9:22"), time.Second, 2)
			if calls != tc.wantAttempts {
				t.Fatalf("dialed %d times, want %d", calls, tc.wantAttempts)
			}
			if res.Attempts != tc.wantAttempts {
				t.Fatalf("Result.Attempts = %d, want %d", res.Attempts, tc.wantAttempts)
			}
		})
	}
}

func TestClient_Confirm_RetriesOnceOnATimeout(t *testing.T) {
	calls := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, context.DeadlineExceeded
		}
		return nil, nil
	}
	res := client.Confirm(context.Background(), dial, addr(t, "203.0.113.9:22"), time.Second, 2)
	if res.Outcome != client.Connected {
		t.Fatalf("outcome = %q, want connected; the retry is what covers a single dropped SYN", res.Outcome)
	}
	if res.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", res.Attempts)
	}
}

func TestClient_Confirm_DialsTheAddressItWasGiven(t *testing.T) {
	var got string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		got = network + " " + address
		return nil, nil
	}
	client.Confirm(context.Background(), dial, addr(t, "198.51.100.4:2222"), time.Second, 1)
	if got != "tcp 198.51.100.4:2222" {
		t.Fatalf("dialed %q, want %q", got, "tcp 198.51.100.4:2222")
	}
}

// The CGNAT split-egress case: this is the runbook's signature and the one
// piece of advice a client can offer that the operator could not have
// guessed. It must fire on exactly one combination and no other.
//
// Mutations verified: emitting the hint unconditionally fails the refused,
// no-route, and asserted-source rows; never emitting it fails the timeout
// row.
func TestClient_Advise_SuggestsSourceCIDROnlyOnASentPacketThatThenTimedOut(t *testing.T) {
	asserted := mustPrefix(t, "203.0.113.0/24")
	base := client.Sent{
		Host:      "web-01",
		Service:   "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true,
		TTL:       2 * time.Minute,
	}
	assertedSent := base
	assertedSent.AssertedSource = &asserted
	undelivered := base
	undelivered.Delivered = false

	for _, tc := range []struct {
		name     string
		outcome  client.Outcome
		sent     client.Sent
		wantHint bool
	}{
		{"sent then timed out", client.TimedOut, base, true},
		{"refused", client.Refused, base, false},
		{"no route", client.NoRoute, base, false},
		{"connected", client.Connected, base, false},
		{"timed out after asserting a source already", client.TimedOut, assertedSent, false},
		{"timed out but the knock never left", client.TimedOut, undelivered, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := client.Advise(client.Result{Outcome: tc.outcome}, tc.sent)
			if a.SourceCIDRHint != tc.wantHint {
				t.Fatalf("SourceCIDRHint = %v, want %v (outcome %q)", a.SourceCIDRHint, tc.wantHint, tc.outcome)
			}
			if tc.wantHint {
				if !strings.Contains(a.Hint, "--source-cidr") {
					t.Fatalf("hint %q does not name --source-cidr", a.Hint)
				}
				if !strings.Contains(a.Hint, "web-01") || !strings.Contains(a.Hint, "ssh") {
					t.Fatalf("hint %q is not a command the operator can run as-is", a.Hint)
				}
			} else if strings.Contains(a.Hint, "--source-cidr") {
				t.Fatalf("outcome %q offered the --source-cidr hint: %q", tc.outcome, a.Hint)
			}
		})
	}
}

// The hint alone is not the deliverable — the brief asks for the hint "and
// say why". An operator who is told to retry with a flag but not told what
// it is for cannot judge whether it applies to them.
func TestClient_Advise_TimeoutNamesAllThreeCausesItCannotDistinguish(t *testing.T) {
	a := client.Advise(client.Result{Outcome: client.TimedOut}, client.Sent{
		Host: "web-01", Service: "ssh", Addr: addr(t, "203.0.113.9:22"), Delivered: true,
	})
	for _, want := range []string{"dropped upstream", "agent is not running", "carrier NAT"} {
		if !strings.Contains(a.Detail, want) {
			t.Fatalf("timeout detail does not mention %q; it reads:\n%s", want, a.Detail)
		}
	}
}

// A refusal proves the firewall worked. Saying so is the difference between
// an operator checking the service and an operator debugging postern.
func TestClient_Advise_RefusedSaysThePacketReachedTheHost(t *testing.T) {
	a := client.Advise(client.Result{Outcome: client.Refused}, client.Sent{
		Host: "web-01", Service: "ssh", Addr: addr(t, "203.0.113.9:22"), Delivered: true,
	})
	if !strings.Contains(a.Detail, "reached the host") {
		t.Fatalf("refused detail does not say the packet reached the host:\n%s", a.Detail)
	}
	if !strings.Contains(a.Detail, "nothing is listening") {
		t.Fatalf("refused detail does not name the actual fault:\n%s", a.Detail)
	}
}

func TestClient_Advise_NoRouteSaysTheKnockCannotHaveArrived(t *testing.T) {
	a := client.Advise(client.Result{Outcome: client.NoRoute}, client.Sent{
		Host: "web-01", Service: "ssh", Addr: addr(t, "203.0.113.9:22"), Delivered: true,
	})
	if !strings.Contains(a.Detail, "cannot have arrived") {
		t.Fatalf("no-route detail does not rule out delivery:\n%s", a.Detail)
	}
}

func TestClient_Advise_UnclassifiedCarriesTheUnderlyingError(t *testing.T) {
	a := client.Advise(
		client.Result{Outcome: client.Unclassified, LastErr: errors.New("permission denied")},
		client.Sent{Host: "web-01", Service: "ssh", Addr: addr(t, "203.0.113.9:22"), Delivered: true},
	)
	if !strings.Contains(a.Detail, "permission denied") {
		t.Fatalf("an unclassified outcome dropped the error text:\n%s", a.Detail)
	}
}

// The public SPA path never replies (design section 5), so a TCP connect
// that succeeds establishes that the port is reachable and nothing else.
// Advice used to say "the gate admitted this source" and, on a refusal,
// "postern's part worked".
//
// Neither is knowable, and the case where it matters is not exotic. On a
// fail_posture: open service, design section 7 says an unarmed gate means
// "the port behaves as it would without postern" — so a host whose agent
// has died has that service exposed to the internet with no gate, and the
// operator's own verification tool was telling them the gate was working.
// That is this project's second named failure mode with the tool supplying
// the reassurance.
//
// Mutation verified: restoring either sentence fails this test, and
// dropping GateUnproven or Verify fails it independently of the wording.
func TestClient_Advise_DoesNotAttributeAnOutcomeToAGateItCannotObserve(t *testing.T) {
	sent := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}

	// Phrases that claim knowledge the client does not have. None may appear
	// under any outcome.
	forbidden := []string{
		"the gate admitted",
		"the gate let it through",
		"postern's part worked",
		"is open on",
	}

	// Crossed with every pre-knock finding, because each one opens a branch
	// with its own prose and a stronger claim is exactly where an overclaim
	// gets written.
	for _, outcome := range []client.Outcome{
		client.Connected, client.Refused, client.NoRoute, client.TimedOut, client.Unclassified,
	} {
		for _, prior := range []client.Prior{
			client.PriorUnmeasured, client.PriorShut, client.PriorAnswering, client.PriorUnclear,
		} {
			t.Run(string(outcome)+"/"+string(prior), func(t *testing.T) {
				s := sent
				s.Prior = prior
				a := client.Advise(client.Result{Outcome: outcome}, s)
				text := a.Summary + "\n" + a.Detail + "\n" + a.Hint
				for _, phrase := range forbidden {
					if strings.Contains(text, phrase) {
						t.Errorf("advice claims %q, which the client cannot observe:\n%s", phrase, text)
					}
				}
			})
		}
	}
}

// A connect made before the knock changes what an answer means and cannot
// change what silence means. The three outcomes where nothing came back have
// to read identically however the pre-knock connect went, or `open` would be
// varying its diagnosis of a timeout on evidence that has no bearing on one.
//
// Mutation verified: consulting Sent.Prior in the timeout branch fails this.
func TestClient_Advise_IgnoresThePreKnockConnectOnOutcomesThatCameBackWithNothing(t *testing.T) {
	base := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}

	for _, outcome := range []client.Outcome{client.NoRoute, client.TimedOut, client.Unclassified} {
		t.Run(string(outcome), func(t *testing.T) {
			unmeasured := base
			want := client.Advise(client.Result{Outcome: outcome}, unmeasured)
			for _, prior := range []client.Prior{client.PriorShut, client.PriorAnswering, client.PriorUnclear} {
				s := base
				s.Prior = prior
				got := client.Advise(client.Result{Outcome: outcome}, s)
				if got != want {
					t.Fatalf("a pre-knock connect that found %q changed the advice for %q:\n%+v\nwant\n%+v",
						prior, outcome, got, want)
				}
			}
		})
	}
}

// GateOpened is licensed by one combination and refused by every other. The
// two inputs have to be checked pairwise: an implementation that set it on a
// shut pre-knock connect whatever came back afterwards, and one that set it
// on any successful connect whatever came before, both pass a test that only
// varies one axis.
//
// Mutation verified: setting GateOpened from Sent.Prior alone fails the
// shut/timeout and shut/no-route rows; setting it from the outcome alone
// fails every row where the port was already answering.
func TestClient_Advise_SetsGateOpenedOnlyWhenSilenceBecameAnAnswer(t *testing.T) {
	base := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}

	for _, outcome := range []client.Outcome{
		client.Connected, client.Refused, client.NoRoute, client.TimedOut, client.Unclassified,
	} {
		for _, prior := range []client.Prior{
			client.PriorUnmeasured, client.PriorShut, client.PriorAnswering, client.PriorUnclear,
		} {
			want := prior == client.PriorShut && (outcome == client.Connected || outcome == client.Refused)
			t.Run(string(outcome)+"/"+string(prior), func(t *testing.T) {
				s := base
				s.Prior = prior
				a := client.Advise(client.Result{Outcome: outcome}, s)
				if a.GateOpened != want {
					t.Fatalf("GateOpened = %v, want %v", a.GateOpened, want)
				}
				if a.GateOpened && a.GateUnproven {
					t.Fatal("the same advice both establishes the gate acted and says it cannot")
				}
			})
		}
	}
}

// The pointer to `status` has to appear on exactly the outcomes that cannot
// establish what it can, and a pre-knock connect moves that boundary: a port
// that was already answering is precisely the case where a signed pong is the
// only way to tell a live agent from a dead one behind a fail-open service.
func TestClient_Advise_PointsAtStatusWhereThePreKnockConnectLeavesTheGateUndecided(t *testing.T) {
	base := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}

	for _, tc := range []struct {
		outcome    client.Outcome
		prior      client.Prior
		wantVerify string
	}{
		{client.Connected, client.PriorAnswering, "postern status web-01"},
		{client.Refused, client.PriorAnswering, "postern status web-01"},
		{client.Connected, client.PriorUnmeasured, "postern status web-01"},
		{client.Connected, client.PriorShut, ""},
		{client.Refused, client.PriorShut, ""},
	} {
		t.Run(string(tc.outcome)+"/"+string(tc.prior), func(t *testing.T) {
			s := base
			s.Prior = tc.prior
			a := client.Advise(client.Result{Outcome: tc.outcome}, s)
			if a.Verify != tc.wantVerify {
				t.Fatalf("Verify = %q, want %q", a.Verify, tc.wantVerify)
			}
		})
	}
}

// The two outcomes that reached the host must say so — an operator who is
// told nothing is worse off than one told the wrong thing — and must point
// at the instrument that does establish agent liveness.
func TestClient_Advise_PointsAtStatusWhenItCannotEstablishTheGateActed(t *testing.T) {
	sent := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}

	for _, tc := range []struct {
		outcome      client.Outcome
		wantUnproven bool
	}{
		{client.Connected, true},
		{client.Refused, true},
		{client.NoRoute, false},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			a := client.Advise(client.Result{Outcome: tc.outcome}, sent)
			if a.GateUnproven != tc.wantUnproven {
				t.Fatalf("GateUnproven = %v, want %v", a.GateUnproven, tc.wantUnproven)
			}
			if !tc.wantUnproven {
				return
			}
			if a.Verify != "postern status web-01" {
				t.Fatalf("Verify = %q, want the status command for this host", a.Verify)
			}
			if !strings.Contains(a.Detail, "not") {
				t.Fatalf("the detail does not qualify what it establishes:\n%s", a.Detail)
			}
		})
	}
}

// The specific claim the wording must not make, asserted on its own so the
// reason survives a future rewrite of the prose: a successful connect is
// consistent with there being no agent and no tables at all.
func TestClient_Advise_ConnectedSaysItDoesNotEstablishPosternDidIt(t *testing.T) {
	a := client.Advise(client.Result{Outcome: client.Connected}, client.Sent{
		Host: "web-01", Service: "ssh", Addr: addr(t, "203.0.113.9:22"), Delivered: true,
	})
	if !strings.Contains(a.Detail, "does not establish") {
		t.Fatalf("a successful connect is reported without qualification:\n%s", a.Detail)
	}
	if !strings.Contains(a.Detail, "fail-open") {
		t.Fatalf("the detail does not name the case where this matters — a fail-open service whose "+
			"agent has died is exposed with no gate:\n%s", a.Detail)
	}
}
