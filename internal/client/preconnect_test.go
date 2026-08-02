package client_test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
)

// eventLog is one ordered record shared by the sender and the dialer. The
// property a pre-knock connect rests on is that a connect happened before a
// send, and neither a dial log nor a send log can show that on its own: two
// separate counters agree just as happily with the two events in the wrong
// order.
type eventLog struct {
	mu sync.Mutex
	ev []string
}

func (l *eventLog) add(s string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, s)
}

func (l *eventLog) events() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

// sender returns a client.Sender that records the knock in this log.
func (l *eventLog) sender(err error) client.Sender {
	return func(context.Context, netip.AddrPort, []byte) error {
		l.add("knock")
		return err
	}
}

// dialScript answers each connect from a list, so the connect made before the
// knock and the one made after it can give genuinely different answers. A
// fixture that answered both the same way could not tell an implementation
// that measures the port twice from one that measures it once and reports one
// answer as though it were both, and that difference is the entire feature.
//
// It also records each attempt's budget, read from the deadline on the
// context Confirm hands the dialer, so a test can assert on a timeout without
// waiting one out.
type dialScript struct {
	mu      sync.Mutex
	replies []error
	addrs   []string
	budgets []time.Duration
	log     *eventLog
}

func (d *dialScript) dial(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	i := len(d.addrs)
	d.addrs = append(d.addrs, address)
	var budget time.Duration
	if dl, ok := ctx.Deadline(); ok {
		budget = time.Until(dl)
	}
	d.budgets = append(d.budgets, budget)
	d.log.add("connect " + address)
	if i >= len(d.replies) {
		i = len(d.replies) - 1
	}
	return nil, d.replies[i]
}

func (d *dialScript) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

func (d *dialScript) budget(i int) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if i >= len(d.budgets) {
		return 0
	}
	return d.budgets[i]
}

// openFixture runs client.Open against the standard test host, filling in
// whatever the caller left unset.
func openFixture(t *testing.T, o client.OpenOptions) (client.OpenReport, error) {
	t.Helper()
	if o.Builder.Signer == nil {
		o.Builder = client.Builder{Signer: mustGenerate(t, "laptop-primary")}
	}
	if o.Host == nil {
		host := mustGenerate(t, "web-01")
		o.Host = testHost(t, host.Public().Encryption, host.Public().Signing)
	}
	if o.Service == "" {
		o.Service = "ssh"
	}
	if o.Counter == nil {
		o.Counter = client.NewCounter(filepath.Join(t.TempDir(), "counter.json"))
	}
	if o.Send == nil {
		o.Send = (&eventLog{}).sender(nil)
	}
	if o.NowMS == nil {
		o.NowMS = fixedClock(testNowMS)
	}
	return client.Open(context.Background(), o)
}

// The knock has to come between the two connects. A connect made after the
// send is measuring the state the knock produced, which is what `open`
// already had, so an implementation that gets the order wrong reports the
// post-knock answer twice and calls the second one evidence.
//
// Mutation verified: moving the pre-knock connect below the send makes the
// first event a knock and fails here.
func TestClient_Open_ConnectsBeforeItSendsTheKnock(t *testing.T) {
	log := &eventLog{}
	d := &dialScript{replies: []error{context.DeadlineExceeded, nil}, log: log}

	if _, err := openFixture(t, client.OpenOptions{
		Dial: d.dial, Send: log.sender(nil), ConnectAttempts: 1,
	}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := []string{"connect 203.0.113.9:22", "knock", "connect 203.0.113.9:22"}
	got := log.events()
	if len(got) != len(want) {
		t.Fatalf("open produced %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d was %q, want %q; the whole sequence was %v", i, got[i], want[i], got)
		}
	}
}

// Silence before and an answer after is the one pair of observations that
// establishes the gate acted, and it is the pair `open` could not produce
// before it connected first.
//
// Mutation verified: skipping the pre-knock connect leaves Prior unmeasured
// and GateOpened false; deriving Prior from the confirmation's outcome
// instead of the pre-knock one makes it PriorAnswering. Either fails here.
func TestClient_Open_ReportsTheGateOpenedWhenThePortWasShutBeforeTheKnock(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded, nil}}

	rep, err := openFixture(t, client.OpenOptions{Dial: d.dial, ConnectAttempts: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if rep.Before.Outcome != client.TimedOut {
		t.Fatalf("the pre-knock connect reports %q, want a timeout", rep.Before.Outcome)
	}
	if rep.Sent.Prior != client.PriorShut {
		t.Fatalf("Sent.Prior = %q, want %q", rep.Sent.Prior, client.PriorShut)
	}
	if rep.Result.Outcome != client.Connected {
		t.Fatalf("the confirmation reports %q, want connected", rep.Result.Outcome)
	}
	if !rep.Advice.GateOpened {
		t.Fatalf("a port that was shut before the knock and answered after it did not set GateOpened:\n%s",
			rep.Advice.Detail)
	}
	if rep.Advice.GateUnproven {
		t.Fatal("shut-then-open is still reported as proving nothing about the gate, which is the " +
			"ambiguity the pre-knock connect exists to remove")
	}
	if !strings.Contains(rep.Advice.Detail, "did not answer before the knock") {
		t.Fatalf("the detail does not say what the pre-knock connect found:\n%s", rep.Advice.Detail)
	}
}

// The other half of the same axis, and the reason both halves are needed: a
// port that already answered establishes nothing, and an operator during an
// outage is owed the difference between "postern opened this" and "this was
// open before you asked".
//
// Mutation verified: reporting GateOpened whenever the confirmation connected
// passes the shut-first test above and fails this one.
func TestClient_Open_ClaimsNothingWhenThePortAnsweredBeforeTheKnock(t *testing.T) {
	log := &eventLog{}
	d := &dialScript{replies: []error{nil, nil}, log: log}

	rep, err := openFixture(t, client.OpenOptions{
		Dial: d.dial, Send: log.sender(nil), ConnectAttempts: 1,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// The knock goes out on this reading too. internal/probe stops after a
	// phase 1 like this one and is right to; an operator running `open` twice
	// inside one lease sees exactly this, and not knocking would let the lease
	// they were extending expire under them.
	events := log.events()
	if len(events) != 3 || events[1] != "knock" {
		t.Fatalf("open produced %v; a port that already answered must not stop the knock", events)
	}

	if rep.Sent.Prior != client.PriorAnswering {
		t.Fatalf("Sent.Prior = %q, want %q", rep.Sent.Prior, client.PriorAnswering)
	}
	if rep.Result.Outcome != client.Connected {
		t.Fatalf("the confirmation reports %q, want connected", rep.Result.Outcome)
	}
	if rep.Advice.GateOpened {
		t.Fatal("a port that answered before the knock was reported as a gate this command opened")
	}
	if !rep.Advice.GateUnproven {
		t.Fatal("a port that answered before the knock was not marked as proving nothing")
	}
	if rep.Advice.Verify != "postern status web-01" {
		t.Fatalf("Verify = %q; this is the outcome where a liveness pong is the only thing that "+
			"separates a live agent from a fail-open port with a dead one", rep.Advice.Verify)
	}
	for _, want := range []string{"reachable before the knock", "never armed", "fail-open"} {
		if !strings.Contains(rep.Advice.Detail, want) {
			t.Fatalf("the detail does not mention %q, so the three states it cannot separate are "+
				"not on offer:\n%s", want, rep.Advice.Detail)
		}
	}
}

// Both connects have to go to the service address. A pre-knock connect aimed
// anywhere else measures something other than the thing the knock opens, and
// the two halves would then be evidence about two different ports.
func TestClient_Open_ConnectsToTheServiceAddressBothTimes(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded, nil}}

	rep, err := openFixture(t, client.OpenOptions{Dial: d.dial, ConnectAttempts: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := d.calls()
	if len(got) != 2 {
		t.Fatalf("open made %d connects (%v), want one before the knock and one after", len(got), got)
	}
	for i, address := range got {
		if address != "203.0.113.9:22" {
			t.Fatalf("connect %d went to %q, want the service address 203.0.113.9:22", i, address)
		}
	}
	if rep.Sent.Addr.String() != "203.0.113.9:22" {
		t.Fatalf("the report names %s as the address that was confirmed", rep.Sent.Addr)
	}
}

// The pre-knock connect gets one attempt whatever --attempts says. Confirm
// retries a non-definitive outcome, and here the non-definitive outcome is
// the one a healthy host is supposed to give, so retrying it would multiply
// the cost of every working open by the attempt count and learn nothing.
//
// Mutation verified: passing the confirmation's attempt count to the
// pre-knock connect makes it dial three times instead of once.
func TestClient_Open_GivesTheConnectBeforeTheKnockASingleAttempt(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded}}

	if _, err := openFixture(t, client.OpenOptions{
		Dial: d.dial, ConnectAttempts: 3, ConnectTimeout: time.Millisecond,
	}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if got := len(d.calls()); got != 4 {
		t.Fatalf("open made %d connects, want 4: one before the knock and three after", got)
	}
}

// Two seconds by default, and never the confirmation's four. The pre-knock
// connect is waiting for an answer it hopes not to get, which is a different
// question from the one the confirmation asks and deserves a shorter budget.
//
// Mutation verified: resolving the pre-knock budget to DefaultConnectTimeout
// collapses the two numbers and fails here.
func TestClient_Open_BudgetsTheConnectBeforeTheKnockBelowAConfirmationAttempt(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded, nil}}

	if _, err := openFixture(t, client.OpenOptions{Dial: d.dial, ConnectAttempts: 1}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	pre, confirm := d.budget(0), d.budget(1)
	if pre > client.DefaultPreConnectTimeout || pre < client.DefaultPreConnectTimeout-time.Second {
		t.Fatalf("the pre-knock connect got %s, want about %s", pre, client.DefaultPreConnectTimeout)
	}
	if confirm > client.DefaultConnectTimeout || confirm < client.DefaultConnectTimeout-time.Second {
		t.Fatalf("the confirmation got %s, want about %s", confirm, client.DefaultConnectTimeout)
	}
	if pre >= confirm {
		t.Fatalf("the pre-knock connect got %s and the confirmation %s; the connect that expects "+
			"silence must not be the longer wait", pre, confirm)
	}
}

// An operator who passes a short --timeout has said how long they are willing
// to wait on this port at all. A pre-knock connect that outlasted that would
// spend more of an incident establishing that the gate was shut than
// establishing that it opened.
//
// Mutation verified: dropping the cap gives the pre-knock connect its full
// five seconds against a 250ms confirmation.
func TestClient_Open_CapsTheConnectBeforeTheKnockAtOneConfirmationAttempt(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded}}

	if _, err := openFixture(t, client.OpenOptions{
		Dial:              d.dial,
		ConnectAttempts:   1,
		ConnectTimeout:    250 * time.Millisecond,
		PreConnectTimeout: 5 * time.Second,
	}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if pre := d.budget(0); pre > 250*time.Millisecond {
		t.Fatalf("the pre-knock connect got %s against a 250ms confirmation attempt", pre)
	}
}

// A budget below the cap is the caller's to set, so the cap is a ceiling
// rather than the only value the field can produce.
//
// Mutation verified: ignoring PreConnectTimeout and always using the default
// gives two seconds here.
func TestClient_Open_HonoursAPreConnectBudgetBelowTheCap(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded, nil}}

	if _, err := openFixture(t, client.OpenOptions{
		Dial: d.dial, ConnectAttempts: 1, PreConnectTimeout: 500 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	pre := d.budget(0)
	if pre > 500*time.Millisecond || pre < 400*time.Millisecond {
		t.Fatalf("the pre-knock connect got %s, want about 500ms", pre)
	}
}

// A negative budget means no pre-knock connect, and then every claim in the
// report has to be exactly as strong as it was before there was one. This is
// the escape hatch for an operator who wants the knock on the wire now.
//
// Mutation verified: treating a negative budget as the default makes two
// connects and replaces the unqualified-success wording.
func TestClient_Open_MakesNoConnectBeforeTheKnockWhenTheBudgetIsNegative(t *testing.T) {
	log := &eventLog{}
	d := &dialScript{replies: []error{nil}, log: log}

	rep, err := openFixture(t, client.OpenOptions{
		Dial: d.dial, Send: log.sender(nil), ConnectAttempts: 1, PreConnectTimeout: -1,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if got := log.events(); len(got) != 2 || got[0] != "knock" {
		t.Fatalf("open produced %v, want the knock first and one connect after it", got)
	}
	if rep.Before.Attempts != 0 {
		t.Fatalf("Before records %d attempts, so something connected before the knock", rep.Before.Attempts)
	}
	if rep.Sent.Prior != client.PriorUnmeasured {
		t.Fatalf("Sent.Prior = %q, want %q", rep.Sent.Prior, client.PriorUnmeasured)
	}
	if !strings.Contains(rep.Advice.Detail, "does not establish that postern did it") {
		t.Fatalf("without a pre-knock connect the report no longer carries the qualification it "+
			"carried before there was one:\n%s", rep.Advice.Detail)
	}
	if rep.Advice.GateOpened {
		t.Fatal("GateOpened was set with nothing measured before the knock")
	}
}

// A pre-knock connect that established nothing must not be read as though it
// had. No route says something about the path and nothing about the gate, so
// the report falls back to what it says when no connect was made at all.
//
// Mutation verified: mapping any non-timeout outcome to PriorAnswering makes
// this report the already-reachable wording.
func TestClient_Open_TreatsAnInconclusivePreConnectAsNoMeasurement(t *testing.T) {
	d := &dialScript{replies: []error{opErr(syscall.EHOSTUNREACH), nil}}

	rep, err := openFixture(t, client.OpenOptions{Dial: d.dial, ConnectAttempts: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if rep.Sent.Prior != client.PriorUnclear {
		t.Fatalf("Sent.Prior = %q, want %q", rep.Sent.Prior, client.PriorUnclear)
	}
	if rep.Advice.GateOpened {
		t.Fatal("a pre-knock connect the network rejected was read as proof the gate was shut")
	}
	// The whole Advice, not one field of it: "treated exactly as unmeasured"
	// is the claim, and a test that only compared the detail would pass an
	// implementation that quietly dropped the Verify pointer here.
	unmeasured := rep.Sent
	unmeasured.Prior = client.PriorUnmeasured
	if want := client.Advise(rep.Result, unmeasured); rep.Advice != want {
		t.Fatalf("an inconclusive measurement produced advice a missing one would not:\n%+v\nwant\n%+v",
			rep.Advice, want)
	}
}

// Silence before and a reset after is what internal/probe calls a passing
// sweep, and it separates the two things an operator most needs separated:
// the gate opened, and the service behind it is down.
func TestClient_Open_SeparatesTheGateFromTheServiceOnARefusalAfterSilence(t *testing.T) {
	d := &dialScript{replies: []error{context.DeadlineExceeded, opErr(syscall.ECONNREFUSED)}}

	rep, err := openFixture(t, client.OpenOptions{Dial: d.dial, ConnectAttempts: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if rep.Result.Outcome != client.Refused {
		t.Fatalf("the confirmation reports %q, want refused", rep.Result.Outcome)
	}
	if !rep.Advice.GateOpened {
		t.Fatalf("a port that was silent before the knock and reset after it did not set "+
			"GateOpened:\n%s", rep.Advice.Detail)
	}
	if rep.Advice.Hint != "check the service on the host" {
		t.Fatalf("Hint = %q; the gate is no longer the thing to look at", rep.Advice.Hint)
	}
	if !strings.Contains(rep.Advice.Detail, "silent before the knock and refused after it") {
		t.Fatalf("the detail does not say the port changed across the knock, which is the whole of "+
			"what separates the gate from the service here:\n%s", rep.Advice.Detail)
	}
}

// A refusal from a port that was already answering is the case most likely to
// be misread. "Not a filter dropping you" is true and, on its own, invites an
// operator to conclude the knock is what let them through when the path was
// open before they sent it.
//
// Mutation verified: giving this branch the wording that applies when nothing
// was measured first leaves every other assertion about it passing and fails
// only here.
func TestClient_Open_SaysARefusalWasNotTheKnockWhenThePortWasAlreadyReachable(t *testing.T) {
	d := &dialScript{replies: []error{opErr(syscall.ECONNREFUSED), opErr(syscall.ECONNREFUSED)}}

	rep, err := openFixture(t, client.OpenOptions{Dial: d.dial, ConnectAttempts: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if rep.Sent.Prior != client.PriorAnswering || rep.Result.Outcome != client.Refused {
		t.Fatalf("prior %q and outcome %q; this test asserts nothing on any other pair",
			rep.Sent.Prior, rep.Result.Outcome)
	}
	if rep.Advice.GateOpened {
		t.Fatal("a port that refused before the knock and after it was reported as a gate this " +
			"command opened")
	}
	for _, want := range []string{"not the knock that let it through", "never armed", "fail-open"} {
		if !strings.Contains(rep.Advice.Detail, want) {
			t.Fatalf("the detail does not mention %q, so an operator reads the refusal as the knock "+
				"working:\n%s", want, rep.Advice.Detail)
		}
	}
}

// Result.Prior has two inputs and only one of them is the outcome. A result
// with no attempts was never made, and classifying its zero outcome as though
// it had been would let a caller that forgot to connect claim it had.
func TestClient_Result_PriorReportsUnmeasuredWithoutAnAttempt(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  client.Result
		want client.Prior
	}{
		{"never attempted", client.Result{}, client.PriorUnmeasured},
		{"never attempted but carrying an outcome", client.Result{Outcome: client.Connected}, client.PriorUnmeasured},
		{"attempted and timed out", client.Result{Outcome: client.TimedOut, Attempts: 1}, client.PriorShut},
		{"attempted and connected", client.Result{Outcome: client.Connected, Attempts: 1}, client.PriorAnswering},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.Prior(); got != tc.want {
				t.Fatalf("Prior() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The allow-list of one. Only a timeout means the port was shut, and every
// other outcome, including one added later that this table does not name,
// must land somewhere that licenses no claim.
func TestClient_PriorFrom_TreatsOnlyATimeoutAsShut(t *testing.T) {
	for _, tc := range []struct {
		outcome client.Outcome
		want    client.Prior
	}{
		{client.TimedOut, client.PriorShut},
		{client.Connected, client.PriorAnswering},
		{client.Refused, client.PriorAnswering},
		{client.NoRoute, client.PriorUnclear},
		{client.Unclassified, client.PriorUnclear},
		{client.Outcome("something added later"), client.PriorUnclear},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			if got := client.PriorFrom(tc.outcome); got != tc.want {
				t.Fatalf("PriorFrom(%q) = %q, want %q", tc.outcome, got, tc.want)
			}
		})
	}
}
