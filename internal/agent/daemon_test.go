package agent_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

// --- fakes -------------------------------------------------------------

// daemonGate is a gate.Gate that counts calls and can be made to block or
// fail on demand. Unlike failclosed_test.go's fakeGate it is mutex-guarded,
// because the daemon calls it from its packet loop while the test asserts
// from another goroutine.
type daemonGate struct {
	mu sync.Mutex
	// order records every call by name, in the order it arrived, so an
	// ordering claim is a testable one. Counting alone cannot tell
	// "silence then close" from "close then silence".
	order      []string
	refreshes  int
	silences   int
	closes     int
	opens      []openCall
	state      gate.ServiceState
	applyOpens int
	refreshErr error
	stateErr   error
	// portRefreshes records every RefreshAgentUpPorts call's port list, in
	// order, so a rotation-mode test (Task 6) can assert what the loop handed
	// the gate each beat.
	portRefreshes [][]uint16
	// agentUpExpiry/agentUpExpiryErr/agentUpSilenced stand in for what the
	// kernel holds for the dead-man element.
	agentUpExpiry    time.Duration
	agentUpExpiryErr error
	agentUpSilenced  bool
	openBlockOn      chan struct{}
	applyOpenErr     error
	// policies records every catalogue this gate was handed through
	// SetPolicy, in order.
	policies     []*config.Policy
	setPolicyErr error
}

type openCall struct {
	service string
	src     gate.Source
	ttl     time.Duration
}

func (g *daemonGate) Open(_ context.Context, service string, src gate.Source, ttl time.Duration) error {
	g.mu.Lock()
	block := g.openBlockOn
	g.opens = append(g.opens, openCall{service, src, ttl})
	g.mu.Unlock()
	if block != nil {
		<-block // wedge the packet loop inside handling, exactly where a real stall would be
	}
	return nil
}

func (g *daemonGate) State(_ context.Context, service string) (gate.ServiceState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stateErr != nil {
		return gate.ServiceState{}, g.stateErr
	}
	st := g.state
	st.Service = service
	return st, nil
}

// AgentUpExpiry answers what the fake's own lease bookkeeping says. A test
// that never touches it gets a healthy lease, so the read-back the daemon
// performs every beat does not have to be set up by every test that never
// cared about it.
func (g *daemonGate) AgentUpExpiry(context.Context) (time.Duration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.agentUpExpiryErr != nil {
		return 0, g.agentUpExpiryErr
	}
	if g.agentUpSilenced {
		return 0, nil
	}
	if g.agentUpExpiry != 0 {
		return g.agentUpExpiry, nil
	}
	return time.Minute, nil
}

// setAgentUpExpiry stands in for what the kernel actually holds, so a test can
// produce the state that made this read-back necessary: a refresh that
// returned nil and left the lease where it was.
func (g *daemonGate) setAgentUpExpiry(d time.Duration, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.agentUpExpiry, g.agentUpExpiryErr = d, err
}

// setStateErr makes the gate-state read fail, which is what a flushed
// postern_boot looks like from the metrics path.
func (g *daemonGate) setStateErr(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stateErr = err
}

// setState replaces what State reports, so a test can stand in for elements
// the kernel is holding — including elements that expired on their own
// timeout, which is the case a count maintained from Open could not produce.
func (g *daemonGate) setState(st gate.ServiceState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = st
}

func (g *daemonGate) Health(context.Context) (gate.Health, error) {
	return gate.Health{Healthy: true, IPv4CIDRCapable: true, IPv6CIDRCapable: true}, nil
}

func (g *daemonGate) Close(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "Close")
	g.closes++
	return nil
}

func (g *daemonGate) RefreshAgentUp(context.Context, time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "RefreshAgentUp")
	g.refreshes++
	return g.refreshErr
}

func (g *daemonGate) SilenceAgentUp(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "SilenceAgentUp")
	g.silences++
	g.agentUpSilenced = true
	return nil
}

// RefreshAgentUpPorts is rotation mode's RefreshAgentUp: it shares the same
// call counter and refreshErr, and additionally records the port list so a
// rotation-loop test can assert what was refreshed each beat.
func (g *daemonGate) RefreshAgentUpPorts(_ context.Context, ports []uint16, _ time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "RefreshAgentUpPorts")
	g.refreshes++
	g.portRefreshes = append(g.portRefreshes, append([]uint16(nil), ports...))
	return g.refreshErr
}

// AgentUpExpiryFor answers the same fake lease bookkeeping AgentUpExpiry
// does, regardless of which port is asked about: no test yet needs per-port
// state, only that the rotation loop's readback path works at all.
func (g *daemonGate) AgentUpExpiryFor(context.Context, uint16) (time.Duration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.agentUpExpiryErr != nil {
		return 0, g.agentUpExpiryErr
	}
	if g.agentUpSilenced {
		return 0, nil
	}
	if g.agentUpExpiry != 0 {
		return g.agentUpExpiry, nil
	}
	return time.Minute, nil
}

// portRefreshCalls returns every RefreshAgentUpPorts call's port list, in
// order.
func (g *daemonGate) portRefreshCalls() [][]uint16 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][]uint16(nil), g.portRefreshes...)
}

func (g *daemonGate) ApplyOpen(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "ApplyOpen")
	g.applyOpens++
	return g.applyOpenErr
}

// SetPolicy makes this fake satisfy agent.PolicyReloader, the optional
// interface the daemon uses to hand a Gate a new service catalogue. The real
// *gate.NFTables rebuilds its RulesetPlan here; this records what it was
// given, so a test can assert the gate was told at all — the half of the
// bundle-swap defect that ends in "%q is not a known gate service" rather
// than in a datagram that never decrypts.
func (g *daemonGate) SetPolicy(policy *config.Policy) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "SetPolicy")
	g.policies = append(g.policies, policy)
	return g.setPolicyErr
}

func (g *daemonGate) adoptedPolicies() []*config.Policy {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]*config.Policy(nil), g.policies...)
}

var _ agent.PolicyReloader = (*daemonGate)(nil)

func (g *daemonGate) callOrder() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.order...)
}

func (g *daemonGate) counts() (refreshes, silences, closes, applyOpens int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refreshes, g.silences, g.closes, g.applyOpens
}

func (g *daemonGate) openCalls() []openCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]openCall(nil), g.opens...)
}

func (g *daemonGate) setRefreshErr(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refreshErr = err
}

var _ gate.Gate = (*daemonGate)(nil)

// fakeReceiver is the daemon's whole network surface, so a test can deliver
// a datagram on the public path or the always-allow path and observe every
// byte the daemon would have transmitted.
type fakeReceiver struct {
	in      chan agent.Datagram
	mu      sync.Mutex
	replies [][]byte
	closed  int
}

func newFakeReceiver() *fakeReceiver {
	return &fakeReceiver{in: make(chan agent.Datagram, 8)}
}

func (r *fakeReceiver) Receive(ctx context.Context) (agent.Datagram, error) {
	select {
	case dg := <-r.in:
		return dg, nil
	case <-ctx.Done():
		return agent.Datagram{}, ctx.Err()
	}
}

func (r *fakeReceiver) Reply(_ context.Context, _ netip.AddrPort, _ uint16, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replies = append(r.replies, append([]byte(nil), payload...))
	return nil
}

func (r *fakeReceiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	return nil
}

func (r *fakeReceiver) replyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.replies)
}

func (r *fakeReceiver) lastReply() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.replies) == 0 {
		return nil
	}
	return r.replies[len(r.replies)-1]
}

var _ agent.Receiver = (*fakeReceiver)(nil)

// fakeRotatingReceiver is a fakeReceiver that also satisfies PortRebinder, so
// a rotation-loop test (Task 6) can inject a receiver whose Rebind calls it
// can assert against, without a real socket. agent.New discovers it the same
// way it discovers bindCarriers's own rotatingUDPReceiver: by asking whether
// the configured Receiver also implements PortRebinder.
type fakeRotatingReceiver struct {
	*fakeReceiver
	mu        sync.Mutex
	rebinds   [][]uint16
	rebindErr error
}

func newFakeRotatingReceiver() *fakeRotatingReceiver {
	return &fakeRotatingReceiver{fakeReceiver: newFakeReceiver()}
}

func (r *fakeRotatingReceiver) Rebind(_ context.Context, ports []uint16) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rebinds = append(r.rebinds, append([]uint16(nil), ports...))
	return r.rebindErr
}

func (r *fakeRotatingReceiver) rebindCalls() [][]uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]uint16(nil), r.rebinds...)
}

var _ agent.PortRebinder = (*fakeRotatingReceiver)(nil)

// failingStore wraps a real replay.Store and starts returning a fatal error
// from Reserve once armed, standing in for a disk that filled or a store
// file that became unwritable while the agent was running.
type failingStore struct {
	inner replay.Store
	mu    sync.Mutex
	fail  error
}

func (s *failingStore) Reserve(r replay.Reservation) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail != nil {
		return fail
	}
	return s.inner.Reserve(r)
}

func (s *failingStore) HighWater(k [16]byte) uint64 { return s.inner.HighWater(k) }
func (s *failingStore) Close() error                { return s.inner.Close() }

func (s *failingStore) startFailing(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

// --- harness -----------------------------------------------------------

type daemonHarness struct {
	*fixture
	gate     *daemonGate
	recv     *fakeReceiver
	ticks    chan time.Time
	notified chan string
	store    *failingStore
	daemon   *agent.Daemon
	runErr   chan error
	done     chan struct{}
	cancel   context.CancelFunc
}

// newDaemonHarness builds a daemon over fixture's real crypto, real policy,
// and real replay store, with the firewall, the network, the heartbeat
// clock, and sd_notify all faked.
func newDaemonHarness(t *testing.T, tune func(*agent.Options)) *daemonHarness {
	t.Helper()
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.AlwaysAllowIface = "tailscale0"
	f.policy.RecoveryService = sshName

	h := &daemonHarness{
		fixture:  f,
		gate:     &daemonGate{},
		recv:     newFakeReceiver(),
		ticks:    make(chan time.Time),
		notified: make(chan string, 32),
		store:    &failingStore{inner: f.store},
		runErr:   make(chan error, 1),
		done:     make(chan struct{}),
	}

	opts := agent.Options{
		Policy:   f.policy,
		Gate:     h.gate,
		Opener:   f.opener,
		Store:    h.store,
		Host:     f.host,
		Receiver: h.recv,
		Ticks:    h.ticks,
		Notify: func(state string) error {
			select {
			case h.notified <- state:
			default:
			}
			return nil
		},
		Checks: passingChecks(map[string]bool{sshName: true}),
	}
	if tune != nil {
		tune(&opts)
	}

	d, err := agent.New(opts)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	h.daemon = d
	return h
}

// newRotationHarness is newDaemonHarness's rotation-mode counterpart (Task
// 6): it installs rot as the policy's port_rotation block and swaps in a
// fakeRotatingReceiver so the daemon discovers it as both Receiver and
// PortRebinder (see agent.New), giving the test a place to observe Rebind
// calls that newDaemonHarness's plain fakeReceiver has no way to satisfy.
func newRotationHarness(t *testing.T, rot *config.PortRotation, tune func(*agent.Options)) (*daemonHarness, *fakeRotatingReceiver) {
	t.Helper()
	rr := newFakeRotatingReceiver()
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Policy.PortRotation = rot
		o.Receiver = rr
		if tune != nil {
			tune(o)
		}
	})
	return h, rr
}

func (h *daemonHarness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		h.runErr <- h.daemon.Run(ctx)
		close(h.done)
	}()
	// Run refreshes agent_up once before announcing readiness, so waiting
	// for READY is waiting for a daemon that is actually serving.
	h.awaitNotify(t, "READY=1")
	// Cleanup waits on done rather than on runErr: a test that already read
	// the error (the incapacitation and clean-stop cases both do) would
	// otherwise block here forever waiting for a second send that never
	// comes, and report a shutdown failure that did not happen.
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return within 5s of context cancellation")
		}
	})
}

func (h *daemonHarness) awaitNotify(t *testing.T, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-h.notified:
			if got == want {
				return
			}
		case <-h.done:
			t.Fatalf("Run returned before %q: %v", want, <-h.runErr)
		case <-deadline:
			t.Fatalf("timed out waiting for sd_notify %q", want)
		}
	}
}

// tick delivers one heartbeat tick and waits for the loop to consume it. An
// unconsumed tick is the signal invariant 2 is about, so the send has a
// timeout rather than blocking forever.
func (h *daemonHarness) tick(t *testing.T, consumed bool) {
	t.Helper()
	select {
	case h.ticks <- time.Now():
		if !consumed {
			t.Fatal("the packet loop consumed a heartbeat tick while it was supposed to be wedged")
		}
	case <-time.After(500 * time.Millisecond):
		if consumed {
			t.Fatal("the packet loop did not consume a heartbeat tick within 500ms")
		}
	}
}

// awaitProcessed waits until the loop has finished handling n datagrams.
// This is the synchronisation point for every "and then nothing happened"
// assertion: driving a heartbeat tick through instead would be unreliable,
// because a select with both a queued packet and a ready tick picks between
// them pseudo-randomly, so a consumed tick does not prove the packet was
// handled first.
func (h *daemonHarness) awaitProcessed(t *testing.T, n uint64) {
	t.Helper()
	waitFor(t, "the loop to finish handling packets", func() bool {
		return h.daemon.Stats().Received >= n
	})
}

func (h *daemonHarness) send(t *testing.T, payload []byte, onAlwaysAllow bool) {
	t.Helper()
	select {
	case h.recv.in <- agent.Datagram{
		Payload:           payload,
		Source:            netip.MustParseAddrPort("198.51.100.5:34567"),
		OnAlwaysAllowPath: onAlwaysAllow,
	}:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver queue is full; the daemon is not draining it")
	}
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- tests -------------------------------------------------------------

// Brief invariant 1, at the daemon: an inert agent does not merely report
// inert, it never touches the firewall and never becomes reachable. Asserted
// as three absences — no postern_open created, no agent_up refresh, nothing
// received — rather than as a returned error, because an implementation that
// returned ErrInert after arming would satisfy an error-only check.
func TestAgent_Daemon_InertPreArmArmsNothingAndNeverRefreshesAgentUp(t *testing.T) {
	h := newDaemonHarness(t, func(o *agent.Options) {
		checks := passingChecks(map[string]bool{sshName: true})
		checks.NFTBinary = func() error { return errors.New("nft: not found") }
		o.Checks = checks
	})

	err := h.daemon.Run(context.Background())
	if !errors.Is(err, agent.ErrInert) {
		t.Fatalf("Run() = %v, want ErrInert", err)
	}
	refreshes, _, _, applyOpens := h.gate.counts()
	if refreshes != 0 {
		t.Fatalf("an inert agent refreshed agent_up %d times; the SPA port must stay silent", refreshes)
	}
	if applyOpens != 0 {
		t.Fatalf("an inert agent created postern_open %d times", applyOpens)
	}
	if !h.daemon.PreArm().Inert() {
		t.Fatal("PreArm() does not report inert")
	}
}

// Brief invariant 2. agent_up is refreshed by the packet loop itself, from
// the same health token that satisfies the watchdog. A separate refresh
// goroutine would keep the lease alive while packet processing is wedged,
// leaving the SPA port open and accepting into an agent that does nothing
// with what it receives — worse than silence, because the operator's client
// reports the packet sent and then times out on connect.
//
// The wedge is placed inside gate.Open, which is where a real stall lives
// (a netlink call that never returns). The mutation this catches: moving the
// RefreshAgentUp call into its own `go func() { for range ticker.C {...} }`.
// Under that mutation the refresh count keeps climbing while Open is
// blocked, and the "no refresh while wedged" assertion fails.
func TestAgent_Daemon_AgentUpIsRefreshedByThePacketLoopItself(t *testing.T) {
	block := make(chan struct{})
	h := newDaemonHarness(t, nil)
	h.gate.openBlockOn = block
	h.start(t)

	// Healthy: a tick is consumed and produces a refresh.
	before, _, _, _ := h.gate.counts()
	h.tick(t, true)
	waitFor(t, "a heartbeat refresh while healthy", func() bool {
		n, _, _, _ := h.gate.counts()
		return n > before
	})

	// Wedge the loop by delivering a valid gate packet: gate.Open blocks.
	h.send(t, h.seal(h.gateRequest()), false)
	waitFor(t, "the packet loop to reach gate.Open", func() bool {
		return len(h.gate.openCalls()) == 1
	})
	wedged, _, _, _ := h.gate.counts()

	// While wedged, ticks are not consumed and no refresh happens. The lease
	// therefore lapses on its own and the SPA port goes silent, which is the
	// entire point.
	for i := 0; i < 3; i++ {
		h.tick(t, false)
	}
	if n, _, _, _ := h.gate.counts(); n != wedged {
		t.Fatalf("agent_up was refreshed %d times while the packet loop was wedged (was %d); "+
			"the lease is being kept alive by something other than the packet loop", n-wedged, wedged)
	}

	// Unwedging restores both.
	close(block)
	waitFor(t, "refreshes to resume once the loop is unwedged", func() bool {
		n, _, _, _ := h.gate.counts()
		return n > wedged
	})
}

// Brief invariant 6, and design section 8: a failed agent_up renewal is its
// own immediate red transition, not something drift detection discovers
// later. At the moment the refresh fails, SPA silence is already broken (the
// set the write targets lives in postern_boot, so the write failing means
// that table is gone) and the operator must learn about it now.
//
// The mutation this catches: logging the refresh error and continuing —
// Health() stays green and nothing transitions until the next drift pass.
func TestAgent_Daemon_FailedAgentUpRefreshIsAnImmediateRedTransition(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	if h.daemon.Health().Red {
		t.Fatal("daemon reports red before anything failed")
	}
	h.gate.setRefreshErr(errors.New("no such set: agent_up"))
	h.tick(t, true)

	waitFor(t, "an immediate red transition on the failed refresh", func() bool {
		return h.daemon.Health().Red
	})
	if reason := h.daemon.Health().Reason; reason == "" {
		t.Fatal("the red transition carries no reason; an operator cannot act on it")
	}

	// The watchdog and agent_up share one definition of health, so a beat
	// that could not renew the lease must not feed the watchdog either.
	// Draining what has accumulated and then ticking again is what makes
	// this assertion about the failing beat rather than an earlier one.
	for len(h.notified) > 0 {
		<-h.notified
	}
	h.tick(t, true)
	waitFor(t, "the failing beat to be processed", func() bool {
		return h.daemon.Health().Red
	})
	select {
	case state := <-h.notified:
		if state == "WATCHDOG=1" {
			t.Fatal("the watchdog was fed by a beat that could not renew agent_up; the watchdog and " +
				"the lease must observe the same health, or a wedged agent stays \"healthy\" to systemd")
		}
	case <-time.After(200 * time.Millisecond):
	}

	// Recovery is symmetric: a later successful refresh clears red.
	h.gate.setRefreshErr(nil)
	h.tick(t, true)
	waitFor(t, "red to clear once the refresh succeeds again", func() bool {
		return !h.daemon.Health().Red
	})
}

// Carried forward from Task 2: internal/agent exports StoreUnusable and
// Incapacitate, but nothing forced anyone to call them. This is the call
// site. When the replay store proves unusable mid-run the agent must stop
// accepting, silence agent_up, tear the gate down, and exit — otherwise
// every packet rejects (fail-closed, bounded) while agent_up keeps
// refreshing and the host advertises health it does not have.
//
// The mutation this catches: dropping the StoreUnusable branch from the
// reject path, so a store failure looks like an ordinary rejection. Run then
// never returns and the refresh count keeps climbing.
func TestAgent_Daemon_UnusableStoreSilencesAgentUpStopsAcceptingAndExits(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	// A healthy packet first, so the failure is demonstrably a transition
	// rather than the daemon having never worked.
	h.send(t, h.seal(h.gateRequest()), false)
	waitFor(t, "the first packet to open a gate", func() bool { return len(h.gate.openCalls()) == 1 })

	h.store.startFailing(errors.New("write record: no space left on device"))
	h.send(t, h.seal(h.gateRequest()), false)

	select {
	case err := <-h.runErr:
		if !errors.Is(err, agent.ErrIncapacitated) {
			t.Fatalf("Run() = %v, want ErrIncapacitated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept running with an unusable replay store; it must stop accepting and exit")
	}

	_, silences, closes, _ := h.gate.counts()
	if silences == 0 {
		t.Fatal("agent_up was not silenced; the SPA port stays reachable into an agent that cannot " +
			"reason about replay, advertising health it does not have")
	}
	if closes == 0 {
		t.Fatal("the gate was not closed; fail-closed sets keep their live grants and postern_open stands")
	}
	if len(h.gate.openCalls()) != 1 {
		t.Fatalf("the agent opened %d gates; the packet that broke the store must not have been applied",
			len(h.gate.openCalls()))
	}
}

// The happy path, so every "did not happen" assertion above has something to
// discriminate against: a valid gate packet reaches gate.Open with the
// source and clamped TTL Validate decided.
func TestAgent_Daemon_AcceptedGatePacketOpensTheGate(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	h.send(t, h.seal(h.gateRequest()), false)
	waitFor(t, "the gate to open", func() bool { return len(h.gate.openCalls()) == 1 })

	call := h.gate.openCalls()[0]
	if call.service != sshName {
		t.Fatalf("opened %q, want %q", call.service, sshName)
	}
	if call.src.Kind != gate.SourceObserved || call.src.Prefix.Addr().String() != "198.51.100.5" {
		t.Fatalf("opened %v, want the packet's own observed source", call.src)
	}
	if call.ttl != 120*time.Second {
		t.Fatalf("ttl = %s, want the requested 120s", call.ttl)
	}
	if h.recv.replyCount() != 0 {
		t.Fatal("the daemon replied to a gate packet; the SPA port never replies")
	}
}

// A knock padded past the record still opens the gate: the receiver reads the
// whole padded datagram and TrialOpen parses the DatagramSize prefix, so the
// variable-length padding is invisible to everything downstream. This is the
// end-to-end counterpart to the spa package's TrialOpen padding tests, run
// through the real receiver and packet loop.
func TestAgent_Daemon_PaddedGatePacketOpensTheGate(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	padded, err := spa.Pad(h.seal(h.gateRequest()))
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	if len(padded) < spa.DatagramSize {
		t.Fatalf("padded knock is %d bytes, shorter than the record", len(padded))
	}
	h.send(t, padded, false)
	waitFor(t, "the gate to open", func() bool { return len(h.gate.openCalls()) == 1 })

	call := h.gate.openCalls()[0]
	if call.service != sshName {
		t.Fatalf("opened %q, want %q", call.service, sshName)
	}
}

// Brief invariant 1's consequence at the packet loop: a per-service pre-arm
// failure must actually stop that service being opened. Without this, "only
// that service is disabled" would be a report with no enforcement — the
// packet would still be validated, still be reserved, and still punch a hole
// in a ruleset that was never armed for it.
func TestAgent_Daemon_ADisabledServiceIsNotOpenedEvenForAValidPacket(t *testing.T) {
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Checks = passingChecks(map[string]bool{sshName: false}) // ssh expects a listener; none is up
	})
	h.start(t)

	if h.daemon.PreArm().ServiceEnabled(sshName) {
		t.Fatal("precondition: ssh should be disabled by pre-arm in this test")
	}
	h.send(t, h.seal(h.gateRequest()), false)

	h.awaitProcessed(t, 1)
	if calls := h.gate.openCalls(); len(calls) != 0 {
		t.Fatalf("a disabled service was opened anyway: %v", calls)
	}
}

// The SPA port never replies. Not for garbage, not for a well-formed packet
// that fails validation, and not for a liveness ping that arrived anywhere
// other than the always-allow path — the last of which would turn the one
// exception to never-reply into a scanning oracle.
//
// The mutation this catches is a pair, and saying so is more honest than
// claiming a single one: the property is defended twice, by Validate's
// ErrLivenessOffPath refusal and again by the arrival-path check in the
// daemon's pong, which is the only place postern writes to the network.
// Removing either alone leaves this test green because the other still
// holds; removing BOTH produces a pong on the public path and fails it.
// Defence in depth is why, not an accident: the daemon does not delegate the
// condition that makes transmitting safe to a function it calls.
func TestAgent_Daemon_NeverRepliesOnThePublicPath(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	// Garbage.
	h.send(t, []byte("not a postern packet"), false)
	// A valid liveness ping — the one packet postern would ever answer — but
	// arriving on the public SPA port rather than the always-allow path.
	challenge, err := spa.EncodeLivenessPayload([16]byte{7, 7, 7})
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(livenessName, challenge)), false)

	h.awaitProcessed(t, 2)
	if n := h.recv.replyCount(); n != 0 {
		t.Fatalf("the daemon transmitted %d reply/replies on the public path", n)
	}
}

// The one exception, exercised so the rule above is not vacuous: an
// authenticated, granted liveness ping that did arrive on the always-allow
// path is answered with a pong the client can verify.
func TestAgent_Daemon_LivenessOnTheAlwaysAllowPathIsAnsweredWithAVerifiablePong(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	want := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}
	challenge, err := spa.EncodeLivenessPayload(want)
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}

	ping := h.actionRequest(livenessName, challenge)
	h.send(t, h.seal(ping), true)

	waitFor(t, "a pong", func() bool { return h.recv.replyCount() == 1 })

	pong, err := spa.ParsePong(h.recv.lastReply())
	if err != nil {
		t.Fatalf("ParsePong: %v", err)
	}
	if err := pong.Verify(
		h.host.Public().Signing,
		h.policy.HostID,
		ping.RequestID,
		want,
		uint64(time.Now().UnixMilli()),
		60_000,
	); err != nil {
		t.Fatalf("the pong does not verify against the ping that produced it: %v", err)
	}
}

// A clean stop silences agent_up rather than leaving the SPA port reachable
// for the remainder of the lease, pointing at a process that has exited.
// ExecStopPost cannot do this — it only reaches the firewall's gate sets and
// postern_open — so if the daemon does not do it, the residual window exists
// on every ordinary restart, not only on a crash.
func TestAgent_Daemon_CleanStopSilencesAgentUpAndClosesTheGate(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	h.cancel()
	select {
	case <-h.runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	_, silences, closes, _ := h.gate.counts()
	if silences == 0 {
		t.Fatal("a clean stop left agent_up standing; the SPA port stays reachable into a dead agent " +
			"until the lease lapses")
	}
	if closes == 0 {
		t.Fatal("a clean stop did not close the gate")
	}
}

// postern_open is created by the agent at startup and removed when it exits
// (design section 4). Nothing else creates it: it has no on-disk form and no
// boot persistence.
func TestAgent_Daemon_CreatesPosternOpenAtStartup(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	if _, _, _, applyOpens := h.gate.counts(); applyOpens != 1 {
		t.Fatalf("postern_open was created %d times at startup, want exactly 1", applyOpens)
	}
}

// New must refuse a policy it cannot serve rather than starting and
// discovering it later: a daemon that started against a policy with no SPA
// port would bind nothing and look healthy.
func TestAgent_New_RejectsAnUnservablePolicy(t *testing.T) {
	f := newFixture(t)
	_, err := agent.New(agent.Options{
		Policy: f.policy, // SPAPort and AlwaysAllowIface unset
		Gate:   &daemonGate{},
		Opener: f.opener,
		Store:  f.store,
		Host:   f.host,
	})
	if err == nil {
		t.Fatal("New accepted a policy with no spa_port and no always_allow_iface")
	}
}

// A console-recovery host has no mesh interface to name as always_allow_iface
// at all, so the always-allow refusal must not apply to it: Console is its
// declared, acknowledged last resort instead. Without this special case
// agent.New could never construct a Daemon for such a host and posternd
// would not start.
//
// The mutation this catches: dropping "&& !opts.Policy.ConsoleRecovery" from
// the always_allow_iface refusal in New.
func TestAgent_New_ConsoleRecoveryPolicyConstructsWithoutAnAlwaysAllowIface(t *testing.T) {
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.ConsoleRecovery = true
	f.policy.Console = "https://provider.example/console"

	d, err := agent.New(agent.Options{
		Policy:    f.policy, // AlwaysAllowIface deliberately unset
		Gate:      &daemonGate{},
		Opener:    f.opener,
		Store:     f.store,
		Host:      f.host,
		StorePath: "/var/lib/postern/replay.db",
		Receiver:  newFakeReceiver(),
	})
	if err != nil {
		t.Fatalf("New rejected a console-recovery policy with no always_allow_iface: %v", err)
	}
	if d == nil {
		t.Fatal("New returned a nil Daemon alongside a nil error")
	}
}

// Console-recovery is an explicit, per-host opt-in (design section on
// console-recovery mode). A policy that merely lacks an always_allow_iface,
// without also setting ConsoleRecovery, is the ordinary misconfiguration New
// has always refused, and must still be refused.
func TestAgent_New_StillRefusesAnEmptyAlwaysAllowIfaceWithoutConsoleRecovery(t *testing.T) {
	f := newFixture(t)
	f.policy.SPAPort = 62201
	// ConsoleRecovery left false; AlwaysAllowIface left unset.

	_, err := agent.New(agent.Options{
		Policy:    f.policy,
		Gate:      &daemonGate{},
		Opener:    f.opener,
		Store:     f.store,
		Host:      f.host,
		StorePath: "/var/lib/postern/replay.db",
		Receiver:  newFakeReceiver(),
	})
	if err == nil {
		t.Fatal("New accepted a policy with no always_allow_iface and no console-recovery opt-in")
	}
}

var _ = config.KindGate // keep the config import honest across edits

// A malformed datagram must not be able to take the agent down. This is the
// seam between Task 2's two exports: StoreUnusable's contract is "an error
// from replay.Store.Reserve or HighWater that is not ErrDuplicate or
// ErrCapacity", and applied to a *Validate* error that contract classifies
// every ordinary rejection — wrong length, bad signature, unknown service —
// as a fatal store failure. An unauthenticated attacker who can reach the
// SPA port would then shut the agent down with one packet, and on a
// fail-closed host that means locking the operator out with a single
// datagram.
//
// The mutation this catches: dropping the errors.Is(err, ErrStore) guard
// from the reject path in handle, leaving StoreUnusable(err) alone. Each
// case below then ends the run.
func TestAgent_Daemon_MalformedPacketsDoNotIncapacitateTheAgent(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	replayed := h.seal(h.gateRequest())

	wrongLength := make([]byte, spa.DatagramSize+1)
	undecryptable := make([]byte, spa.DatagramSize)
	for i := range undecryptable {
		undecryptable[i] = byte(i)
	}

	for _, dg := range [][]byte{
		nil,               // empty
		[]byte("garbage"), // short
		wrongLength,       // one byte over
		undecryptable,     // right length, no operator key opens it
		replayed,          // accepted once...
		replayed,          // ...then a genuine ErrDuplicate from the store
	} {
		h.send(t, dg, false)
	}

	h.awaitProcessed(t, 6)

	select {
	case err := <-h.runErr:
		t.Fatalf("a malformed or duplicate packet took the agent down: %v", err)
	default:
	}
	if h.daemon.Health().Red {
		t.Fatalf("a malformed or duplicate packet drove the agent red: %q", h.daemon.Health().Reason)
	}
	if _, silences, _, _ := h.gate.counts(); silences != 0 {
		t.Fatal("a malformed or duplicate packet silenced agent_up")
	}
	if n := h.recv.replyCount(); n != 0 {
		t.Fatalf("the daemon answered %d malformed packet(s)", n)
	}
}

// --- rotation, at the beat loop (Task 6) --------------------------------

func testRotationSecret(fill byte) []byte {
	s := make([]byte, knockport.SecretSize)
	for i := range s {
		s[i] = fill
	}
	return s
}

// A daemon built with a rotation policy and a fixed Now: one beat must call
// RefreshAgentUpPorts with exactly knockport.LiveSet for the current window,
// and must never call the fixed-mode RefreshAgentUp.
func TestAgent_Beat_RotationRefreshesAgentUpWithTheLiveSet(t *testing.T) {
	clock := &testClock{at: time.Unix(1_700_000_000, 0).UTC()}
	rot := &config.PortRotation{
		Secret:  testRotationSecret(7),
		Window:  30 * time.Second,
		RangeLo: 20000,
		RangeHi: 20100,
	}
	h, _ := newRotationHarness(t, rot, func(o *agent.Options) {
		o.Now = clock.Now
	})
	h.start(t) // Run's own startup beat is the first rotation beat.

	wantWindow := knockport.Window(clock.Now().Unix(), rot.Window)
	wantLive := knockport.LiveSet(rot.Secret, wantWindow, rot.RangeLo, rot.RangeHi)

	waitFor(t, "a RefreshAgentUpPorts call with the current window's live set", func() bool {
		calls := h.gate.portRefreshCalls()
		return len(calls) > 0 && slices.Equal(calls[len(calls)-1], wantLive)
	})

	for _, c := range h.gate.callOrder() {
		if c == "RefreshAgentUp" {
			t.Fatal("beat called the fixed-mode RefreshAgentUp under port rotation")
		}
	}
}

// Beat at time t (window w): Rebind called once with the live set. Beat again
// still inside window w: Rebind NOT called again. Beat after Now advances
// into window w+1: Rebind called with the new set.
func TestAgent_Beat_RotationRebindsOnlyWhenTheWindowAdvances(t *testing.T) {
	clock := &testClock{at: time.Unix(1_700_000_000, 0).UTC()}
	rot := &config.PortRotation{
		Secret:  testRotationSecret(3),
		Window:  30 * time.Second,
		RangeLo: 20000,
		RangeHi: 20100,
	}
	h, rr := newRotationHarness(t, rot, func(o *agent.Options) {
		o.Now = clock.Now
	})
	h.start(t) // the startup beat is the first window's Rebind.

	windowA := knockport.Window(clock.Now().Unix(), rot.Window)
	liveA := knockport.LiveSet(rot.Secret, windowA, rot.RangeLo, rot.RangeHi)
	waitFor(t, "Rebind called once for the first window", func() bool {
		return len(rr.rebindCalls()) == 1
	})
	if got := rr.rebindCalls()[0]; !slices.Equal(got, liveA) {
		t.Fatalf("first Rebind call = %v, want the first window's live set %v", got, liveA)
	}

	// Still inside window A: a beat must refresh agent_up but must not
	// rebind again.
	h.tick(t, true)
	waitFor(t, "a second RefreshAgentUpPorts call while still inside window A", func() bool {
		return len(h.gate.portRefreshCalls()) >= 2
	})
	if n := len(rr.rebindCalls()); n != 1 {
		t.Fatalf("Rebind was called %d times while still inside one window, want 1", n)
	}

	// Advance past the window boundary and beat again: Rebind fires with the
	// new window's live set.
	clock.advance(rot.Window)
	windowB := knockport.Window(clock.Now().Unix(), rot.Window)
	if windowB == windowA {
		t.Fatalf("advancing by the window period did not change the window (still %d); test setup is wrong", windowA)
	}
	liveB := knockport.LiveSet(rot.Secret, windowB, rot.RangeLo, rot.RangeHi)
	h.tick(t, true)

	waitFor(t, "Rebind called again for the new window", func() bool {
		return len(rr.rebindCalls()) == 2
	})
	if got := rr.rebindCalls()[1]; !slices.Equal(got, liveB) {
		t.Fatalf("second Rebind call = %v, want the new window's live set %v", got, liveB)
	}
}

// A fixed-port daemon must call RefreshAgentUp and never RefreshAgentUpPorts
// or Rebind. Guards the branch beat's rotation check adds.
func TestAgent_Beat_FixedModeStillUsesRefreshAgentUp(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)
	h.tick(t, true)

	waitFor(t, "at least one RefreshAgentUp call", func() bool {
		refreshes, _, _, _ := h.gate.counts()
		return refreshes > 0
	})
	if calls := h.gate.portRefreshCalls(); len(calls) != 0 {
		t.Fatalf("a fixed-mode beat called RefreshAgentUpPorts %d time(s); it must only call RefreshAgentUp", len(calls))
	}
}

// A failed RefreshAgentUpPorts under rotation must drive the identical
// immediate red transition a failed fixed-mode RefreshAgentUp does (see
// TestAgent_Daemon_FailedAgentUpRefreshIsAnImmediateRedTransition): beat's
// rotation branch returns the error from rotateAndRefresh rather than
// swallowing it, so the watchdog goes unfed and Health() turns red at once
// rather than waiting on a later drift pass.
func TestAgent_Beat_RotationFailedRefreshIsAnImmediateRedTransition(t *testing.T) {
	rot := &config.PortRotation{
		Secret:  testRotationSecret(5),
		Window:  30 * time.Second,
		RangeLo: 20000,
		RangeHi: 20100,
	}
	h, _ := newRotationHarness(t, rot, nil)
	h.start(t)

	if h.daemon.Health().Red {
		t.Fatal("daemon reports red before anything failed")
	}
	h.gate.setRefreshErr(errors.New("no such set: agent_up"))
	h.tick(t, true)

	waitFor(t, "an immediate red transition on the failed rotation refresh", func() bool {
		return h.daemon.Health().Red
	})
	if reason := h.daemon.Health().Reason; reason == "" {
		t.Fatal("the red transition carries no reason; an operator cannot act on it")
	}

	for len(h.notified) > 0 {
		<-h.notified
	}
	h.tick(t, true)
	waitFor(t, "the failing beat to be processed", func() bool {
		return h.daemon.Health().Red
	})
	select {
	case state := <-h.notified:
		if state == "WATCHDOG=1" {
			t.Fatal("the watchdog was fed by a rotation beat that could not refresh agent_up")
		}
	case <-time.After(200 * time.Millisecond):
	}

	h.gate.setRefreshErr(nil)
	h.tick(t, true)
	waitFor(t, "red to clear once the refresh succeeds again", func() bool {
		return !h.daemon.Health().Red
	})
}

// A Rebind failure is logged, not fatal (see rotateAndRefresh), and it must
// not advance lastWindow: agent_up already holds the new live set from the
// RefreshAgentUpPorts call that preceded it, but the sockets are still on the
// old window, so the next beat has to retry the bind rather than concluding
// the window is already handled.
func TestAgent_Beat_RotationRebindFailureRetriesOnTheNextBeat(t *testing.T) {
	clock := &testClock{at: time.Unix(1_700_000_000, 0).UTC()}
	rot := &config.PortRotation{
		Secret:  testRotationSecret(11),
		Window:  30 * time.Second,
		RangeLo: 20000,
		RangeHi: 20100,
	}
	h, rr := newRotationHarness(t, rot, func(o *agent.Options) {
		o.Now = clock.Now
	})
	rr.mu.Lock()
	rr.rebindErr = errors.New("bind: address already in use")
	rr.mu.Unlock()

	h.start(t) // the startup beat's Rebind fails.

	waitFor(t, "the startup beat's failed Rebind call", func() bool {
		return len(rr.rebindCalls()) == 1
	})
	// The failed Rebind must not have stopped agent_up from renewing: a
	// rebind failure is not a refresh failure.
	if h.daemon.Health().Red {
		t.Fatalf("a Rebind failure alone drove the daemon red: %q", h.daemon.Health().Reason)
	}

	// A beat still inside the same window retries the bind, because
	// haveWindow was never set true by the failed attempt.
	h.tick(t, true)
	waitFor(t, "a retried Rebind call for the same window", func() bool {
		return len(rr.rebindCalls()) == 2
	})

	windowA := knockport.Window(clock.Now().Unix(), rot.Window)
	liveA := knockport.LiveSet(rot.Secret, windowA, rot.RangeLo, rot.RangeHi)
	for i, got := range rr.rebindCalls() {
		if !slices.Equal(got, liveA) {
			t.Fatalf("Rebind call %d = %v, want the same window's live set %v on every retry", i, got, liveA)
		}
	}
}

// --- confirm-or-revert, at the daemon ----------------------------------

// testClock is a hand-advanced clock, so the dead-man deadline is crossed
// because the test says so rather than because a sleep happened to be long
// enough. The daemon and the transaction manager share it, which is what
// makes "the window elapsed" a single, controllable fact.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// newTxnDaemon wires a daemon to a staged transaction harness, so the
// dead-man timer and the confirm binding are exercised over real files and a
// real validation pipeline rather than over the manager alone. clock is
// optional: pass one to control the confirmation deadline, or nil to leave
// both the daemon and the manager on the real clock (which packet-carrying
// tests need, since Validate measures a packet's freshness against it).
func newTxnDaemon(t *testing.T, window time.Duration, clock *testClock, tune ...func(*agent.Options)) (*daemonHarness, *txnHarness) {
	t.Helper()
	tx := newTxnHarness(t)
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.ConfirmWindow = window
		// The harness stages a host that already recorded revision 41 as
		// confirmed, and these tests drive BeginTransaction themselves. Naming
		// the same revision in the policy is what keeps startup out of it: the
		// arm step arms only a configuration whose revision differs from the
		// recorded one, so an already-confirmed host restarting arms nothing.
		o.Policy.Revision = txnHarnessRecordedRevision
		if clock != nil {
			o.Now = clock.Now
			tx.txns.Now = clock.Now
		}
		for _, extra := range tune {
			extra(o)
		}
	})
	return h, tx
}

// A prepared transaction that is never confirmed is reverted by the dead-man
// timer, and the revert restores every artifact — the daemon's timer and the
// manager's four-artifact restore are the two halves of "confirm-or-revert
// is transactional", and only wiring them together shows the daemon actually
// calls the complete one.
func TestAgent_Daemon_DeadManRevertsAnUnconfirmedTransaction(t *testing.T) {
	clock := &testClock{at: time.Now()}
	h, tx := newTxnDaemon(t, 5*time.Minute, clock)

	if err := tx.unit.SetEnabled(context.Background(), false); err != nil {
		t.Fatalf("stage the boot unit: %v", err)
	}
	h.start(t)

	pending, err := h.daemon.BeginTransaction(context.Background(), 42)
	if err != nil {
		t.Fatalf("BeginTransaction: %v", err)
	}
	if !pending.Pending || pending.Revision != 42 {
		t.Fatalf("BeginTransaction returned %+v", pending)
	}
	tx.arm(t)

	// No confirm arrives, and the window elapses.
	clock.advance(6 * time.Minute)
	h.tick(t, true)

	// Wait on the red transition rather than on the first artifact Revert
	// touches: setHealth runs after all four restores, so it is the only
	// signal that the whole revert finished.
	waitFor(t, "the dead-man revert to complete", func() bool {
		return h.daemon.Health().Red
	})
	if got := tx.ruleset.live(); got != "table inet postern_boot { OLD }\n" {
		t.Fatalf("live table after the dead-man revert = %q", got)
	}
	if got, _ := readFile(t, tx.paths.BootNFT); got != "OLD BOOT NFT\n" {
		t.Fatalf("boot.nft after the dead-man revert = %q; the host re-locks at the next reboot", got)
	}
	if tx.unit.state() {
		t.Fatal("the boot unit is still enabled after the dead-man revert")
	}
}

// A confirm bound to the pending transaction commits it, and the dead-man
// timer then has nothing to revert. The confirm carries the revision and
// nonce BeginTransaction produced — Validate refuses any other pair, which
// is what makes the binding real rather than a null check.
func TestAgent_Daemon_ConfirmBoundToThePendingTransactionCommitsIt(t *testing.T) {
	h, tx := newTxnDaemon(t, time.Hour, nil)
	h.start(t)

	pending, err := h.daemon.BeginTransaction(context.Background(), 42)
	if err != nil {
		t.Fatalf("BeginTransaction: %v", err)
	}
	tx.arm(t)

	payload, err := spa.EncodeConfirmPayload(pending.Revision, pending.Nonce)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(confirmName, payload)), false)
	h.awaitProcessed(t, 1)

	raw, present := readFile(t, tx.paths.State)
	if !present {
		t.Fatal("the confirm did not record state")
	}
	var st agent.State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Revision != 42 {
		t.Fatalf("recorded revision = %d, want 42", st.Revision)
	}
	// Nothing was reverted: the armed configuration is still live.
	if got := tx.ruleset.live(); got != "table inet postern_boot { NEW }\n" {
		t.Fatalf("live table = %q, want the armed one to still be live after a confirm", got)
	}
}

// A confirm naming a different transaction is refused, including when one is
// genuinely pending — the case that proves binding exists, since an unbound
// confirm ("ratify whatever is pending") would pass a test that only ever
// sent the right nonce.
func TestAgent_Daemon_ConfirmNamingAnotherTransactionIsRefused(t *testing.T) {
	h, tx := newTxnDaemon(t, time.Hour, nil)
	h.start(t)

	pending, err := h.daemon.BeginTransaction(context.Background(), 42)
	if err != nil {
		t.Fatalf("BeginTransaction: %v", err)
	}
	tx.arm(t)

	wrongNonce := pending.Nonce
	wrongNonce[0] ^= 0xff
	payload, err := spa.EncodeConfirmPayload(pending.Revision, wrongNonce)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(confirmName, payload)), false)
	h.awaitProcessed(t, 1)

	raw, _ := readFile(t, tx.paths.State)
	var st agent.State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Revision != 42 || st.BootNFTSHA256 != "new-nft" {
		t.Fatalf("a confirm with the wrong nonce committed the transaction anyway: %+v", st)
	}
}

// #46. Validate proves a confirm names the pending transaction; the commit
// must ratify that same transaction, not whatever is pending by the time it
// runs. A bundle arm landing between a confirm's validation and its commit
// swaps d.pending to a newer revision — modelled here by preparing 43 before
// the commit bound to 42 runs. Committing 43 would ratify a configuration no
// operator confirmed, and 43's dead-man would then never fire, leaving a host
// armed on rules nothing can confirm or revert. The commit is bound to the
// (revision, nonce) the Decision carries, so it refuses.
func TestAgent_Daemon_ConfirmCommitsTheTransactionItWasBoundToNotWhateverIsPending(t *testing.T) {
	h, tx := newTxnDaemon(t, time.Hour, nil)
	h.start(t)

	// Deploy 42: the transaction whose confirm the operator will send.
	p42, err := h.daemon.BeginTransaction(context.Background(), 42)
	if err != nil {
		t.Fatalf("BeginTransaction 42: %v", err)
	}
	tx.arm(t)

	// Deploy 43 lands in the window before 42's confirm commits. d.pending now
	// names 43, not the 42 the confirm was bound to.
	p43, err := h.daemon.BeginTransaction(context.Background(), 43)
	if err != nil {
		t.Fatalf("BeginTransaction 43: %v", err)
	}

	// The commit is bound to 42 — what Validate proved this confirm named. It
	// must refuse rather than ratify the pending 43.
	err = agent.CommitTransactionForTest(h.daemon, context.Background(), p42.Revision, p42.Nonce)
	if !errors.Is(err, agent.ErrConfirmSuperseded) {
		t.Fatalf("commit bound to 42 while 43 is pending = %v, want ErrConfirmSuperseded", err)
	}

	// Nothing was committed: the recorded revision is still the host's
	// last-confirmed 41, never the unconfirmed 43.
	raw, _ := readFile(t, tx.paths.State)
	var st agent.State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state after the refused commit: %v", err)
	}
	if st.Revision == 43 {
		t.Fatal("the commit ratified revision 43, which no operator confirmed")
	}

	// 43 is still pending and confirmable: a confirm correctly bound to it
	// commits, proving the refused 42-commit left 43's confirm-or-revert intact
	// rather than consuming or clobbering it.
	if err := agent.CommitTransactionForTest(h.daemon, context.Background(), p43.Revision, p43.Nonce); err != nil {
		t.Fatalf("commit bound to the pending 43: %v", err)
	}
	raw, _ = readFile(t, tx.paths.State)
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state after committing 43: %v", err)
	}
	if st.Revision != 43 {
		t.Fatalf("recorded revision after committing the pending 43 = %d, want 43", st.Revision)
	}
}

// #52. On a confirm the running policy is persisted, so a restart runs the
// confirmed configuration rather than the enrollment-time bootstrap. A revert
// persists nothing, which is what leaves the persisted policy and boot.nft
// rolling back together: a confirm makes both name the new revision, a revert
// leaves both at the old one. Testing the pair is what proves the write is
// coupled to a commit rather than to a transaction resolving either way.
func TestAgent_Daemon_AConfirmPersistsTheRunningPolicyAndARevertDoesNot(t *testing.T) {
	// --- a confirm persists it ---
	confirmPath := filepath.Join(t.TempDir(), "policy.yaml")
	h, tx := newTxnDaemon(t, time.Hour, nil, func(o *agent.Options) {
		o.RunningPolicyPath = confirmPath
	})
	h.start(t)

	pending, err := h.daemon.BeginTransaction(context.Background(), 42)
	if err != nil {
		t.Fatalf("BeginTransaction: %v", err)
	}
	tx.arm(t)
	if _, present := readFile(t, confirmPath); present {
		t.Fatal("the running policy was persisted before any confirm arrived")
	}

	payload, err := spa.EncodeConfirmPayload(pending.Revision, pending.Nonce)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(confirmName, payload)), false)
	h.awaitProcessed(t, 1)

	raw, present := readFile(t, confirmPath)
	if !present {
		t.Fatal("the confirm did not persist the running policy; a restart would fall back to bootstrap")
	}
	got, err := config.ParseStandalone([]byte(raw))
	if err != nil {
		t.Fatalf("the persisted policy does not parse back through the pull path: %v", err)
	}
	if got.Revision != txnHarnessRecordedRevision {
		t.Fatalf("persisted policy revision = %d, want the daemon's running %d", got.Revision, txnHarnessRecordedRevision)
	}

	// --- a revert persists nothing ---
	revertPath := filepath.Join(t.TempDir(), "policy.yaml")
	clock := &testClock{at: time.Now()}
	h2, tx2 := newTxnDaemon(t, 5*time.Minute, clock, func(o *agent.Options) {
		o.RunningPolicyPath = revertPath
	})
	if err := tx2.unit.SetEnabled(context.Background(), false); err != nil {
		t.Fatalf("stage the boot unit: %v", err)
	}
	h2.start(t)

	if _, err := h2.daemon.BeginTransaction(context.Background(), 42); err != nil {
		t.Fatalf("BeginTransaction: %v", err)
	}
	tx2.arm(t)
	clock.advance(6 * time.Minute)
	h2.tick(t, true)
	waitFor(t, "the dead-man revert to complete", func() bool { return h2.daemon.Health().Red })

	if _, present := readFile(t, revertPath); present {
		t.Fatal("a reverted transaction persisted a running policy; the file must roll back with " +
			"boot.nft, not race ahead of it")
	}
}

// disarm removes both tables and clears persistence, so the host does not
// re-lock at the next reboot.
func TestAgent_Daemon_DisarmClearsBothTablesAndPersistence(t *testing.T) {
	h, tx := newTxnDaemon(t, time.Hour, nil)
	h.start(t)

	payload, err := spa.EncodeDisarmPayload()
	if err != nil {
		t.Fatalf("EncodeDisarmPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(disarmName, payload)), false)
	h.awaitProcessed(t, 1)

	if _, _, closes, _ := h.gate.counts(); closes == 0 {
		t.Fatal("disarm did not tear down the agent's tables")
	}
	if got := tx.ruleset.live(); got != "" {
		t.Fatalf("the live %s table survived disarm: %q", "postern_boot", got)
	}
	if content, present := readFile(t, tx.paths.BootNFT); present {
		t.Fatalf("boot.nft survived disarm (%q); the host re-locks at the next reboot", content)
	}
	if tx.unit.state() {
		t.Fatal("the boot unit is still enabled after disarm")
	}
}

// --- fix round 1 -------------------------------------------------------

// C1. Both checkDeadMan and commitTransaction read d.pending under the lock,
// do slow I/O with the lock released, then clear it. If a BeginTransaction
// lands in that window, an unconditional clear destroys a transaction the
// call never touched: the operator's correctly-bound confirm for the new
// revision is refused as unbound, no dead-man will ever fire for it, and the
// host is left in an armed and possibly locking configuration that can be
// neither confirmed nor auto-reverted — strictly worse than either outcome
// the mechanism is meant to produce.
//
// The mutation this catches: replacing clearPending's compare with a bare
// `d.pending = nil` in checkDeadMan. The confirm below is then refused and
// the state file still reads revision 41.
func TestAgent_Daemon_DeadManDoesNotDestroyATransactionPreparedWhileItReverted(t *testing.T) {
	clock := &testClock{at: time.Now()}
	h, tx := newTxnDaemon(t, 5*time.Minute, clock)
	h.start(t)

	// Deploy 1, never confirmed.
	if _, err := h.daemon.BeginTransaction(context.Background(), 42); err != nil {
		t.Fatalf("BeginTransaction 42: %v", err)
	}
	tx.arm(t)

	// Deploy 2 arrives in the one window that matters: after deploy 1's
	// revert has finished its I/O and before the pending slot is cleared.
	// The hook is how that ordering is made deterministic — Transactions now
	// serializes Prepare against Revert, so a goroutine racing the clear
	// would lose almost every time and the test would prove nothing.
	var pending2 PendingTransactionForTest
	var once sync.Once
	agent.SetAfterResolveHook(h.daemon, func() {
		once.Do(func() {
			p, err := h.daemon.BeginTransaction(context.Background(), 43)
			pending2.set(p, err)
		})
	})

	clock.advance(6 * time.Minute) // deploy 1's window elapses
	h.tick(t, true)

	// tick returns as soon as the loop accepts the tick, not when it has
	// finished the work the tick triggers, so wait for the hook rather than
	// reading straight through.
	waitFor(t, "the dead-man revert to reach the after-resolve hook", pending2.ready)

	p2, err := pending2.get(t)
	if err != nil {
		t.Fatalf("BeginTransaction 43: %v", err)
	}
	if !p2.Pending || p2.Revision != 43 {
		t.Fatalf("BeginTransaction 43 returned %+v", p2)
	}

	// Deploy 2's operator confirms, correctly bound. The packet is stamped at
	// the daemon's current time rather than the fixture's construction time:
	// the clock was advanced past the confirmation window above, and an
	// action's freshness is measured against freshness_window (60s), so a
	// packet stamped six minutes in the past would be refused as stale for a
	// reason that has nothing to do with the binding under test.
	h.now = clock.Now()
	payload, err := spa.EncodeConfirmPayload(p2.Revision, p2.Nonce)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(confirmName, payload)), false)
	h.awaitProcessed(t, 1)

	raw, present := readFile(t, tx.paths.State)
	if !present {
		t.Fatal("no state file after the confirm")
	}
	var st agent.State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state: %v", err)
	}
	if st.Revision != 43 {
		t.Fatalf("recorded revision = %d, want 43: the first transaction's revert cleared the second "+
			"transaction's pending slot, so its bound confirm was refused as unbound and the host is "+
			"left armed with nothing able to confirm or revert it", st.Revision)
	}
}

// PendingTransactionForTest carries a BeginTransaction result out of the
// hook goroutine.
type PendingTransactionForTest struct {
	mu   sync.Mutex
	p    agent.PendingTransaction
	err  error
	set_ bool
}

func (r *PendingTransactionForTest) set(p agent.PendingTransaction, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.p, r.err, r.set_ = p, err, true
}

func (r *PendingTransactionForTest) ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.set_
}

func (r *PendingTransactionForTest) get(t *testing.T) (agent.PendingTransaction, error) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.set_ {
		t.Fatal("the after-resolve hook never ran; the dead-man revert did not happen")
	}
	return r.p, r.err
}

// I4. A failed first agent_up renewal means the write into postern_boot did
// not land, which means that table is not there — and design section 6 is
// explicit that an absent postern_boot leaves the SPA port unconcealed as
// well as unreachable, because the guard rules are gone and the chain policy
// is accept. Announcing READY=1 from there hands systemd an active, ready
// unit for up to WatchdogSec while the host advertises a service it cannot
// provide and no longer hides.
//
// The mutation this catches: beat returning nil unconditionally, which was
// the shipped behaviour and made both of Run's error checks dead code.
func TestAgent_Daemon_DoesNotAnnounceReadyWhenTheFirstAgentUpRenewalFails(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.gate.setRefreshErr(errors.New("no such table: postern_boot"))

	// A cancellable context with a bounded wait rather than Background():
	// under the bug this test names, Run does not return at all — it
	// announces readiness and enters the packet loop — and a test that
	// blocked there would report a timeout twenty minutes later instead of
	// the assertion it is actually about.
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- h.daemon.Run(ctx) }()

	var err error
	select {
	case err = <-runErr:
	case <-time.After(2 * time.Second):
		cancel()
		<-runErr
		t.Fatal("Run kept going after the initial agent_up renewal failed; the SPA port is neither " +
			"concealed nor openable and the agent is serving anyway")
	}
	cancel()

	if err == nil {
		t.Fatal("Run returned nil after the initial agent_up renewal failed")
	}
	// Sentinelled, because Task 4 maps Run's returns to exit codes and
	// cannot errors.Is an unclassified error. ErrInert rather than a fourth
	// sentinel: the observable state is identical to a failed global
	// precondition — nothing armed, nothing reachable, a cause that may
	// clear on its own — so a caller would give both the same exit code.
	if !errors.Is(err, agent.ErrInert) {
		t.Fatalf("Run returned an unclassified error (%v); a caller mapping returns to exit codes "+
			"has nothing to match on", err)
	}
	if !strings.Contains(err.Error(), "agent_up") {
		t.Fatalf("the error does not say which precondition failed: %v", err)
	}
	for {
		select {
		case state := <-h.notified:
			if state == "READY=1" {
				t.Fatal("READY=1 was announced from a host whose SPA port is neither concealed nor " +
					"openable; systemd sees an active, ready unit for up to WatchdogSec")
			}
		default:
			return
		}
	}
}

// The other half, so the fix above cannot be "fatal on every failure": once
// the agent has proven it can renew, a later failure is ridden out rather
// than ending the run. A transient netlink error must not turn into an
// outage for every service on the host.
func TestAgent_Daemon_SurvivesARenewalFailureAfterStartupSucceeded(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t) // start() waits for READY=1, so the first beat succeeded

	h.gate.setRefreshErr(errors.New("transient netlink failure"))
	h.tick(t, true)
	waitFor(t, "the red transition", func() bool { return h.daemon.Health().Red })

	select {
	case err := <-h.runErr:
		t.Fatalf("a single failed renewal ended the run: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	h.gate.setRefreshErr(nil)
	h.tick(t, true)
	waitFor(t, "recovery", func() bool { return !h.daemon.Health().Red })
}

// M3. shutdown silences agent_up BEFORE closing the gate, so the SPA port
// stops being reachable at once rather than for the remainder of the lease
// pointing at a process that is tearing itself down. Counting the two calls
// cannot distinguish that from the reverse; the order can.
//
// The mutation this catches: swapping the two calls in shutdown.
func TestAgent_Daemon_ShutdownSilencesAgentUpBeforeClosingTheGate(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.start(t)

	h.cancel()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}

	order := h.gate.callOrder()
	var silence, closed = -1, -1
	for i, call := range order {
		if call == "SilenceAgentUp" && silence == -1 {
			silence = i
		}
		if call == "Close" && closed == -1 {
			closed = i
		}
	}
	if silence == -1 || closed == -1 {
		t.Fatalf("shutdown did not both silence and close: %v", order)
	}
	if silence > closed {
		t.Fatalf("shutdown closed the gate before silencing agent_up (%v); the SPA port stays "+
			"reachable into an agent that is already tearing down its tables", order)
	}
}

// I6. The default replay-store writability probe has no way to learn which
// filesystem to ask about other than StorePath, and filepath.Dir("") is
// ".", so an unset path made a global precondition report success about the
// working directory — "/" under systemd, writable as root on every host.
// A read-only /var/lib/postern would have sailed through.
//
// The mutation this catches: removing the StorePath check from New.
func TestAgent_New_RequiresAStorePathWhenItWillBuildTheDefaultProbe(t *testing.T) {
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.AlwaysAllowIface = "tailscale0"

	base := agent.Options{
		Policy: f.policy,
		Gate:   &daemonGate{},
		Opener: f.opener,
		Store:  f.store,
		Host:   f.host,
		// Supplied so the successful cases below do not each bind the real
		// SPA port and collide with one another.
		Receiver: newFakeReceiver(),
	}

	if _, err := agent.New(base); err == nil {
		t.Fatal("New accepted an empty StorePath; the writability precondition would answer about " +
			"the working directory rather than the store's own filesystem")
	}

	withPath := base
	withPath.StorePath = "/var/lib/postern/replay.db"
	if _, err := agent.New(withPath); err != nil {
		t.Fatalf("New rejected a valid StorePath: %v", err)
	}

	// A caller that supplied its own probe has already answered the
	// question and is not asked for a path it would not use.
	withProbe := base
	withProbe.Checks = agent.PreArmChecks{StoreWritable: func() error { return nil }}
	if _, err := agent.New(withProbe); err != nil {
		t.Fatalf("New demanded a StorePath from a caller that supplied its own probe: %v", err)
	}
}

// The wiring mistake that shipped: postern's arm step enabled
// postern-boot.service and nothing anywhere enabled posternd.service, so
// every reboot brought a host up with the fail-closed drop rules loaded and
// no agent alive to open them. Transactions cannot express that combination
// any more, but a caller can still leave AgentUnit nil, which is the same
// host by a different route — so New refuses it at construction rather than
// at the first reboot after the first arm.
//
// The mutation this catches: removing the AgentUnit check from New. The
// "rejected" case then builds a daemon that locks the host out.
func TestAgent_New_RefusesATransactionManagerThatCanEnableOnlyTheBootUnit(t *testing.T) {
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.AlwaysAllowIface = "tailscale0"

	base := agent.Options{
		Policy:    f.policy,
		Gate:      &daemonGate{},
		Opener:    f.opener,
		Store:     f.store,
		Host:      f.host,
		StorePath: "/var/lib/postern/replay.db",
		Receiver:  newFakeReceiver(),
	}

	bootOnly := base
	bootOnly.Transactions = &agent.Transactions{BootUnit: &fakeUnit{}}
	if _, err := agent.New(bootOnly); err == nil {
		t.Fatal("New accepted a transaction manager with a BootUnit and no AgentUnit; every arm would " +
			"enable postern-boot.service alone, and the host would come up after each reboot dropping " +
			"the SPA port with nothing running to open it")
	}

	both := base
	both.Transactions = &agent.Transactions{BootUnit: &fakeUnit{}, AgentUnit: &fakeUnit{}}
	if _, err := agent.New(both); err != nil {
		t.Fatalf("New rejected a correctly wired transaction manager: %v", err)
	}

	// Neither is legitimate: internal/agent's own tests and the demo drive
	// Transactions with no units at all, and there is nothing to keep
	// consistent.
	neither := base
	neither.Transactions = &agent.Transactions{}
	if _, err := agent.New(neither); err != nil {
		t.Fatalf("New rejected a transaction manager that manages no units: %v", err)
	}
}

// I6, second lock: ProductionChecks is exported and a caller can reach the
// probe without going through New at all.
func TestAgent_ProductionChecks_StoreWritableRefusesAnEmptyPath(t *testing.T) {
	checks := agent.ProductionChecks(agent.PreArmChecks{}, &daemonGate{}, "", "")
	if checks.StoreWritable == nil {
		t.Fatal("ProductionChecks did not build a StoreWritable probe")
	}
	if err := checks.StoreWritable(); err == nil {
		t.Fatal("the writability probe reported success with no store path configured; it just " +
			"tested the working directory and called it the replay store")
	}
}

// I5. PortsArmable was documented as a per-service precondition and tested
// against an injected probe, but ProductionChecks never built one — so the
// check did not exist on any real host and its test guarded nothing.
//
// The mutation this catches: removing the PortsArmable block from
// ProductionChecks. checks.PortsArmable is then nil and the first assertion
// fails.
func TestAgent_ProductionChecks_WiresPortsArmableForFailClosedServices(t *testing.T) {
	g := &statefulGate{failFor: "postgres"}
	checks := agent.ProductionChecks(agent.PreArmChecks{}, g, "/tmp/replay.db", "")

	if checks.PortsArmable == nil {
		t.Fatal("ProductionChecks did not wire PortsArmable; a documented per-service precondition " +
			"never runs on a real host and the test covering it guards nothing")
	}

	closed := config.Service{Name: "postgres", Kind: config.KindGate, FailPosture: config.PostureClosed}
	if err := checks.PortsArmable(context.Background(), closed); err == nil {
		t.Fatal("a fail-closed service whose sets are missing from postern_boot was reported armable; " +
			"every knock for it would fail at Open time while the service looked armed")
	}

	// A fail-open service's sets live in postern_open, which the agent
	// creates itself after pre-arm, so there is nothing to reconcile
	// against yet and the probe must not invent a failure.
	open := config.Service{Name: "postgres", Kind: config.KindGate, FailPosture: config.PostureOpen}
	if err := checks.PortsArmable(context.Background(), open); err != nil {
		t.Fatalf("a fail-open service was refused by a probe that cannot yet answer for it: %v", err)
	}
	if g.stateCalls() != 1 {
		t.Fatalf("State was called %d times; the fail-open service must not be probed", g.stateCalls())
	}
}

// statefulGate answers State with an error for one named service, standing
// in for a boot.nft that predates that service and so left its sets absent.
type statefulGate struct {
	daemonGate
	failFor string
	mu2     sync.Mutex
	states  int
}

func (g *statefulGate) State(_ context.Context, service string) (gate.ServiceState, error) {
	g.mu2.Lock()
	g.states++
	g.mu2.Unlock()
	if service == g.failFor {
		return gate.ServiceState{}, errors.New("look up set gate_postgres_v4_obs: no such file or directory")
	}
	return gate.ServiceState{Service: service}, nil
}

func (g *statefulGate) stateCalls() int {
	g.mu2.Lock()
	defer g.mu2.Unlock()
	return g.states
}

// Round 3. Run's contract says three non-nil returns and a caller maps them
// to exit codes, so an unsentinelled fourth is a return Task 4 would
// mis-attribute — the handoff table describes the unwrapped row as a socket
// failure, and a host that could not create postern_open is not that.
//
// The mutation this catches: dropping the ErrInert wrap from the ApplyOpen
// failure path.
func TestAgent_Daemon_AFailureToCreatePosternOpenIsReportedAsInert(t *testing.T) {
	h := newDaemonHarness(t, nil)
	h.gate.applyOpenErr = errors.New("netlink: operation not permitted")

	err := h.daemon.Run(context.Background())
	if err == nil {
		t.Fatal("Run returned nil after postern_open could not be created")
	}
	if !errors.Is(err, agent.ErrInert) {
		t.Fatalf("Run returned an unclassified error (%v); a caller matching the documented returns "+
			"would attribute a firewall failure to the SPA socket", err)
	}
	if refreshes, _, _, _ := h.gate.counts(); refreshes != 0 {
		t.Fatalf("agent_up was refreshed %d times despite postern_open never being created", refreshes)
	}
}

// --- the arm step ------------------------------------------------------

// The ordering property design section 5 exists for, asserted at the one
// instant it is checkable: when the dangerous ruleset goes live, the nonce a
// confirm must carry has ALREADY been published. The observer runs inside
// Ruleset.Restore, before the new table lands, and reads what an operator
// would have been able to read at that moment.
//
// Publishing after arming would satisfy every other assertion here — the
// transaction exists, the file appears, the confirm works — while delivering
// the nonce over a channel the new rules may have just cut. That is why the
// assertion is on the file's contents at that instant rather than on its
// contents afterwards.
func TestAgent_Daemon_PublishesThePendingRevisionAndNonceBeforeArming(t *testing.T) {
	tx := newTxnHarness(t)
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision + 1
	})

	type seen struct {
		rec     agent.ArmRecord
		present bool
	}
	var observed seen
	tx.ruleset.hook(func([]byte) error {
		// Read the published file the way an operator would, rather than
		// through Transactions.LastArm: this hook runs inside Arm, which holds
		// the manager's mutex, so going back through the manager would
		// deadlock instead of observing anything.
		raw, present := readFile(t, tx.paths.Pending)
		observed.present = present
		if !present {
			return nil
		}
		return json.Unmarshal([]byte(raw), &observed.rec)
	})

	h.start(t)

	if !observed.present {
		t.Fatal("nothing was published when the ruleset was armed; the operator has no nonce to " +
			"confirm with, and by the time one appears it travels over a channel the new rules may have broken")
	}
	if observed.rec.Revision != txnHarnessRecordedRevision+1 {
		t.Fatalf("published revision at arm time = %d, want %d", observed.rec.Revision, txnHarnessRecordedRevision+1)
	}
	if observed.rec.Outcome != agent.ArmPending {
		t.Fatalf("published outcome at arm time = %q, want %q", observed.rec.Outcome, agent.ArmPending)
	}
	nonce, err := hex.DecodeString(observed.rec.Nonce)
	if err != nil || len(nonce) != 16 {
		t.Fatalf("published nonce %q is not 16 hex-encoded bytes (%v)", observed.rec.Nonce, err)
	}
	// And what was published is the binding the agent actually enforces: a
	// confirm carrying it is accepted, which is the only proof that the
	// published pair is the same pair the daemon is holding.
	var n16 [16]byte
	copy(n16[:], nonce)
	payload, err := spa.EncodeConfirmPayload(observed.rec.Revision, n16)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	h.send(t, h.seal(h.actionRequest(confirmName, payload)), false)
	h.awaitProcessed(t, 1)
	if _, present := readFile(t, tx.paths.State); !present {
		t.Fatal("the confirm carrying the published pair was refused; the published nonce is not " +
			"the one the agent is waiting for")
	}
}

// The arm is both halves against the real seams: the generated ruleset
// becomes live, and the boot unit is enabled so it comes back at the next
// boot.
func TestAgent_Daemon_ArmingANewRevisionLoadsTheRulesetAndEnablesTheBootUnit(t *testing.T) {
	tx := newTxnHarness(t)
	if err := tx.unit.SetEnabled(context.Background(), false); err != nil {
		t.Fatalf("stage the boot unit disabled: %v", err)
	}
	writeFile(t, tx.paths.BootNFT, "NEW BOOT NFT\n")
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision + 1
	})
	h.start(t)

	if got := tx.ruleset.live(); got != "NEW BOOT NFT\n" {
		t.Fatalf("live table after the arm step = %q, want the generated ruleset", got)
	}
	if !tx.unit.state() {
		t.Fatal("the boot unit was not enabled by the arm step; the armed posture vanishes at the next boot")
	}
}

// An unchanged, already-confirmed host restarting arms nothing and starts no
// transaction. Without this the dead-man timer would fire on every ordinary
// restart — every reboot would put the host into a confirmation window
// nobody asked for, and an unattended host would revert its own working
// configuration.
func TestAgent_Daemon_AConfirmedRevisionArmsNothingOnRestart(t *testing.T) {
	tx := newTxnHarness(t)
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision
	})
	before := tx.ruleset.restoreCount()
	h.start(t)

	if got := tx.ruleset.restoreCount(); got != before {
		t.Fatalf("the ruleset was rewritten %d time(s) on a restart of a confirmed host", got-before)
	}
	if _, ok, err := tx.txns.LastArm(); ok || err != nil {
		t.Fatalf("a transaction was published on a restart of a confirmed host (%v, %v)", ok, err)
	}
	if h.daemon.Health().Red {
		t.Fatalf("a confirmed host restarted red: %s", h.daemon.Health().Reason)
	}
}

// A revision that was already armed and reverted is not armed again. The
// failure this prevents is a loop: systemd restarts the agent, the agent
// re-arms the same unconfirmed configuration, the host locks for another
// confirmation window, and the dead-man reverts it again — for as long as
// nobody is watching. "First arm reverts to open" has to mean the host stays
// open.
func TestAgent_Daemon_ARevertedRevisionIsNotArmedAgain(t *testing.T) {
	tx := newTxnHarness(t)
	revision := uint64(txnHarnessRecordedRevision + 1)
	writeFile(t, tx.paths.Pending,
		`{"revision":42,"deployment_nonce":"00112233445566778899aabbccddeeff","outcome":"reverted"}`)
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = revision
	})
	before := tx.ruleset.restoreCount()
	h.start(t)

	if got := tx.ruleset.restoreCount(); got != before {
		t.Fatalf("a reverted revision was armed again (%d ruleset writes)", got-before)
	}
	health := h.daemon.Health()
	if !health.Red {
		t.Fatal("refusing to re-arm a reverted revision was not reported; an operator has no way to " +
			"learn why postern is running and not armed")
	}
	if !strings.Contains(health.Reason, "reverted") {
		t.Fatalf("health reason = %q; it should name what happened to that revision", health.Reason)
	}
}

// An arm that fails does not leave the host half-armed and does not wait ten
// minutes for the dead-man: there is a snapshot in hand, so it is used at
// once. The agent then reports inert, which is a startup failure systemd
// retries.
func TestAgent_Daemon_AFailedArmRevertsAtOnceAndIsReportedAsInert(t *testing.T) {
	tx := newTxnHarness(t)
	if err := os.Remove(tx.paths.BootNFT); err != nil {
		t.Fatalf("remove boot.nft: %v", err)
	}
	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision + 1
	})

	err := h.daemon.Run(context.Background())
	if !errors.Is(err, agent.ErrInert) {
		t.Fatalf("Run() after a failed arm = %v, want ErrInert", err)
	}
	if refreshes, _, _, applyOpens := h.gate.counts(); refreshes != 0 || applyOpens != 0 {
		t.Fatalf("a failed arm still refreshed agent_up %d time(s) and created postern_open %d time(s)",
			refreshes, applyOpens)
	}
	if rec, ok, _ := tx.txns.LastArm(); ok && rec.Outcome == agent.ArmPending {
		t.Fatalf("a failed arm left a pending record (%+v); nothing will ever confirm or revert it", rec)
	}
}
