package probe_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/probe"
)

// The contract, verbatim from design section 8: phase 1 times out because
// the packet is DROPped, the knock goes out, phase 2 is refused because the
// gate admitted the packet and nothing is listening.
//
// Mutation verified: inverting either phase's accepted outcome in
// closedFailure/openFailure fails this.
func TestProbe_Sweep_PassesWhenPhase1TimesOutAndPhase2IsRefused(t *testing.T) {
	d := newDialer(t, timedOut, refused)
	s := &countingSender{}
	sw := newProber(t, d, s).Sweep(context.Background())

	if !sw.Passed() {
		t.Fatalf("verdict = %s (%s): %s", sw.Verdict, sw.Reason, sw.Summary)
	}
	if sw.Closed.Outcome != client.TimedOut {
		t.Errorf("phase 1 outcome = %s, want %s", sw.Closed.Outcome, client.TimedOut)
	}
	if sw.Open.Outcome != client.Refused {
		t.Errorf("phase 2 outcome = %s, want %s", sw.Open.Outcome, client.Refused)
	}
	if !sw.Knocked || s.count() != 1 {
		t.Errorf("knocked = %v, datagrams sent = %d, want true and exactly 1", sw.Knocked, s.count())
	}
	if sw.Reason != probe.ReasonNone {
		t.Errorf("a passing sweep carries reason %q", sw.Reason)
	}
}

// A rotation host's canary knock has to land on the same current-window
// port `open` uses: the agent does not bind the fixed port at all once
// rotation is on, so a knock sent to KnockAddrPort's fixed default reports
// a permanently red host (ReasonGateNotOpened) whether or not the agent, and
// the mesh path behind it, are perfectly healthy. This is the probe's half
// of the gap Task 7 left in three other places (open, confirm, disarm).
//
// Mutation verified: reverting Sweep's `if port, ok :=
// o.Host.CurrentKnockPort(...)` block, so sw.KnockAddr stays
// p.Host.KnockAddrPort() unconditionally, fails this on the port.
func TestProbe_Sweep_RotationKnocksTheCurrentWindowPort(t *testing.T) {
	d := newDialer(t, timedOut, refused)
	s := &countingSender{}
	host := rotationTestHost(t)
	var ticks int
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	p := &probe.Prober{
		Builder:       client.Builder{Signer: mustSigner(t)},
		Host:          host,
		Counter:       client.NewCounter(t.TempDir() + "/counter.json"),
		Send:          s.send,
		Dial:          d.dial,
		Now:           func() time.Time { ticks++; return base.Add(time.Duration(ticks) * time.Second) },
		NowMS:         func() uint64 { return 600_000 }, // unix 600 -> window 1 at the 10m default
		Sleep:         func(context.Context, time.Duration) error { return nil },
		ClosedTimeout: 2 * time.Second,
		OpenTimeout:   4 * time.Second,
		OpenAttempts:  2,
		Settle:        time.Millisecond,
	}
	sw := p.Sweep(context.Background())
	if !sw.Passed() {
		t.Fatalf("verdict = %s (%s): %s", sw.Verdict, sw.Reason, sw.Summary)
	}
	// Computed straight from knockport rather than through
	// host.CurrentKnockPort, so this is independent of that method's own
	// correctness: a mutation inside CurrentKnockPort makes the knock's port
	// disagree with this one instead of agreeing with itself.
	wantWindow := knockport.Window(600, 10*time.Minute)
	wantPort := knockport.Port(rotationSecret(), wantWindow, 20000, 30000)
	if s.count() != 1 || s.to[0].Addr() != host.KnockAddr || s.to[0].Port() != wantPort {
		t.Fatalf("knock went to %v, want exactly one datagram to %s:%d (the current-window port)",
			s.to, host.KnockAddr, wantPort)
	}
	if sw.KnockAddr.Port() != wantPort {
		t.Fatalf("sw.KnockAddr = %s, want port %d", sw.KnockAddr, wantPort)
	}
}

// This is the whole reason the probe exists, and the specific state that
// motivated it: a host with no agent and no firewall tables at all, where
// every connect returns RST and `postern open` therefore reports the port
// reachable. A probe that checked only phase 2 would report this host green
// forever.
//
// Mutation verified: adding client.Refused to closedFailure's passing set —
// the smallest version of the mistake — turns this sweep into a pass and
// fails this test, TestProbe_Runner_TurnsRedOnTheThirdConsecutiveFailure,
// TestProbe_Runner_ResetsTheStreakOnAPass,
// TestProbe_Webhook_CarriesBothPhaseOutcomes, and the end-to-end
// TestMain_Probe_FailsWhenTheCanaryPortAnswersBeforeTheKnock.
func TestProbe_Sweep_FailsWhenPhase1IsRefused(t *testing.T) {
	d := newDialer(t, refused)
	s := &countingSender{}
	sw := newProber(t, d, s).Sweep(context.Background())

	if sw.Passed() {
		t.Fatalf("a sweep whose closed-gate phase was REFUSED reported a pass: %s", sw.Summary)
	}
	if sw.Reason != probe.ReasonGateNotClosed {
		t.Errorf("reason = %q, want %q", sw.Reason, probe.ReasonGateNotClosed)
	}
	// Not knocking is part of the contract, not an optimisation: opening a
	// gate to a port that already answers cannot make it say anything new,
	// and a sweep that knocked anyway would spend a real lease on a host
	// whose posture is already known to be wrong.
	if sw.Knocked || s.count() != 0 {
		t.Errorf("the sweep knocked after phase 1 failed: knocked = %v, datagrams = %d", sw.Knocked, s.count())
	}
	if len(d.record()) != 1 {
		t.Errorf("connects = %d, want 1: the sweep continued past a failed phase 1", len(d.record()))
	}
	// The diagnosis has to name the thing an operator would otherwise chase
	// for an hour.
	if !strings.Contains(sw.Detail, "no gate open") {
		t.Errorf("the detail does not say the port answers with no gate open:\n%s", sw.Detail)
	}
}

// A listener behind the canary port is red on its own (design section 4):
// it converts a stolen probe key from "can open a port with nothing behind
// it" into "can open a reachable service", which is the claim the
// probe-theft analysis in section 9 rests on.
func TestProbe_Sweep_FailsWhenPhase1Connects(t *testing.T) {
	d := newDialer(t, connected)
	s := &countingSender{}
	sw := newProber(t, d, s).Sweep(context.Background())

	if sw.Passed() {
		t.Fatalf("a sweep that CONNECTED before knocking reported a pass: %s", sw.Summary)
	}
	if sw.Reason != probe.ReasonListenerPresent {
		t.Errorf("reason = %q, want %q", sw.Reason, probe.ReasonListenerPresent)
	}
	if s.count() != 0 {
		t.Errorf("the sweep knocked after phase 1 connected")
	}
}

// The ordinary red: the gate is genuinely shut and the knock did not open
// it. The detail must name all three causes rather than picking one,
// because from here they are indistinguishable — the same honesty
// client.Advise applies to a timed-out open.
func TestProbe_Sweep_FailsWhenPhase2TimesOut(t *testing.T) {
	d := newDialer(t, timedOut)
	s := &countingSender{}
	sw := newProber(t, d, s).Sweep(context.Background())

	if sw.Passed() {
		t.Fatalf("a sweep whose post-knock connect timed out reported a pass")
	}
	if sw.Reason != probe.ReasonGateNotOpened {
		t.Errorf("reason = %q, want %q", sw.Reason, probe.ReasonGateNotOpened)
	}
	if !sw.Knocked {
		t.Error("the sweep did not knock, so it never tested the open path at all")
	}
	for _, want := range []string{"dropped upstream", "agent is not running", "different addresses"} {
		if !strings.Contains(sw.Detail, want) {
			t.Errorf("the detail does not name %q as a cause it cannot rule out:\n%s", want, sw.Detail)
		}
	}
}

// The canary is declared listener_expectation: absent, so a successful
// post-knock connection is a finding rather than a better pass.
func TestProbe_Sweep_FailsWhenPhase2Connects(t *testing.T) {
	d := newDialer(t, timedOut, connected)
	sw := newProber(t, d, &countingSender{}).Sweep(context.Background())

	if sw.Passed() {
		t.Fatalf("a post-knock connect that SUCCEEDED on a listener-absent service reported a pass")
	}
	if sw.Reason != probe.ReasonListenerPresent {
		t.Errorf("reason = %q, want %q", sw.Reason, probe.ReasonListenerPresent)
	}
}

// A knock that never left the probe host says nothing about the target, and
// must not be reported as though it did.
func TestProbe_Sweep_FailsWhenTheKnockCannotBeSent(t *testing.T) {
	d := newDialer(t, timedOut)
	s := &countingSender{err: errors.New("network is down")}
	sw := newProber(t, d, s).Sweep(context.Background())

	if sw.Passed() {
		t.Fatal("a sweep whose knock was never sent reported a pass")
	}
	if sw.Reason != probe.ReasonKnockNotSent {
		t.Errorf("reason = %q, want %q", sw.Reason, probe.ReasonKnockNotSent)
	}
	if sw.Knocked {
		t.Error("Knocked is true for a datagram that failed to send")
	}
	if len(d.record()) != 1 {
		t.Errorf("connects = %d, want 1: phase 2 ran after a failed send", len(d.record()))
	}
}

// The network rejecting the connect outright is connectivity, not
// authorization, and is worth its own reason: it is the one failure where
// suspecting postern is the wrong first move.
func TestProbe_Sweep_FailsWithNoRouteWhenTheNetworkRejectsTheConnect(t *testing.T) {
	sw := newProber(t, newDialer(t, noRoute), &countingSender{}).Sweep(context.Background())
	if sw.Reason != probe.ReasonNoRoute {
		t.Fatalf("reason = %q, want %q", sw.Reason, probe.ReasonNoRoute)
	}
}

// Phase 1 gets exactly one attempt, and the count is asserted rather than
// described. client.Confirm retries a non-definitive outcome, and phase 1's
// passing outcome is the non-definitive one — so a phase 1 built with the
// client's default attempt count would pay its timeout twice on every
// passing sweep.
func TestProbe_Sweep_TakesExactlyOneClosedPhaseAttempt(t *testing.T) {
	d := newDialer(t, timedOut, refused)
	sw := newProber(t, d, &countingSender{}).Sweep(context.Background())

	if sw.Closed.Attempts != 1 {
		t.Errorf("phase 1 attempts = %d, want 1", sw.Closed.Attempts)
	}
	calls := d.record()
	if len(calls) != 2 {
		t.Fatalf("connects = %d, want 2 (one closed, one open): %+v", len(calls), calls)
	}
	// Each phase's own budget, so a single shared timeout cannot pass this.
	if got := calls[0].budget(); got > 2*time.Second || got < time.Second {
		t.Errorf("phase 1 connect budget = %s, want ~2s (ClosedTimeout)", got)
	}
	if got := calls[1].budget(); got > 4*time.Second || got < 3*time.Second {
		t.Errorf("phase 2 connect budget = %s, want ~4s (OpenTimeout)", got)
	}
}

// Both phases dial knock_addr and the canary port, never the SSH hostname.
// On a CDN-fronted host that name resolves to an edge, so a connect there
// would measure a proxy rather than the gate.
func TestProbe_Sweep_ConnectsToKnockAddrAndTheCanaryPort(t *testing.T) {
	d := newDialer(t, timedOut, refused)
	s := &countingSender{}
	sw := newProber(t, d, s).Sweep(context.Background())

	for i, c := range d.record() {
		if c.address != "203.0.113.9:62202" {
			t.Errorf("connect %d went to %s, want 203.0.113.9:62202", i, c.address)
		}
	}
	if got := sw.KnockAddr.String(); got != "203.0.113.9:62201" {
		t.Errorf("knock addr = %s, want 203.0.113.9:62201", got)
	}
	if len(s.to) != 1 || s.to[0].String() != "203.0.113.9:62201" {
		t.Errorf("the datagram went to %v, want one to 203.0.113.9:62201", s.to)
	}
}

// A probe pointed at a host whose config has no canary must fail loudly at
// startup. The alternative is a red host reported every 137 seconds forever
// for a reason that is entirely local.
func TestProbe_Validate_RefusesAHostWithNoCanaryService(t *testing.T) {
	p := newProber(t, newDialer(t, timedOut), &countingSender{})
	p.Service = "nonexistent"
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted a service the host does not have")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("the refusal does not name the missing service: %v", err)
	}
	sw := p.Sweep(context.Background())
	if sw.Reason != probe.ReasonInternal {
		t.Errorf("a sweep against a missing service has reason %q, want %q", sw.Reason, probe.ReasonInternal)
	}
	if sw.Passed() {
		t.Error("a sweep that could not run reported a pass")
	}
}

// CanaryTTL is what the Runner's interval guard compares against, so it has
// to come from the host entry rather than from a default the probe invents.
func TestProbe_CanaryTTL_ComesFromTheHostEntry(t *testing.T) {
	p := newProber(t, newDialer(t, timedOut), &countingSender{})
	if got := p.CanaryTTL(); got != 30*time.Second {
		t.Errorf("CanaryTTL = %s, want 30s (the host entry's canary ttl)", got)
	}
	p.TTL = 45 * time.Second
	if got := p.CanaryTTL(); got != 45*time.Second {
		t.Errorf("CanaryTTL = %s, want 45s (the explicit override)", got)
	}
}

// Every sweep says what it establishes and what it does not. A passing
// sweep in particular must not read as "postern works" without naming the
// phase-1 half that makes it mean anything.
func TestProbe_Sweep_PassingDetailNamesBothPhases(t *testing.T) {
	sw := newProber(t, newDialer(t, timedOut, refused), &countingSender{}).Sweep(context.Background())
	for _, want := range []string{"phase 1", "phase 2", "no firewall"} {
		if !strings.Contains(sw.Detail, want) {
			t.Errorf("a passing sweep's detail omits %q:\n%s", want, sw.Detail)
		}
	}
}
