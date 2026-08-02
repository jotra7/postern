package agent_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/metrics"
)

// stubIfaceAddrs stands in for the always-allow interface, so the bind rules
// are exercised on a machine that has no mesh interface on it.
func stubIfaceAddrs(name string) ([]netip.Addr, error) {
	if name != "tailscale0" {
		return nil, errors.New("no such interface")
	}
	return []netip.Addr{netip.MustParseAddr("100.64.0.7")}, nil
}

// gateStateWith builds a ServiceState holding the given number of observed
// and asserted elements.
func gateStateWith(observed, asserted int) gate.ServiceState {
	st := gate.ServiceState{}
	for i := 0; i < observed; i++ {
		st.Elements = append(st.Elements, gate.ElementState{
			Source: gate.Source{
				Kind:   gate.SourceObserved,
				Prefix: netip.MustParsePrefix("198.51.100.5/32"),
			},
			Expires: time.Minute,
		})
	}
	for i := 0; i < asserted; i++ {
		st.Elements = append(st.Elements, gate.ElementState{
			Source: gate.Source{
				Kind:   gate.SourceAsserted,
				Prefix: netip.MustParsePrefix("203.0.113.0/24"),
			},
			Expires: time.Minute,
		})
	}
	return st
}

// These tests drive the real Daemon over a real HTTP scrape of a real
// listener. Nothing here injects a recorder and asserts against it: a metric
// that is defined, documented and tested but never written by the running
// agent is precisely the defect that would survive that kind of test, and it
// is the failure mode of a metrics package in the first place.

// metricsHarness is newDaemonHarness with the exposition endpoint bound to an
// ephemeral loopback port.
func newMetricsHarness(t *testing.T, tune func(*agent.Options)) *daemonHarness {
	t.Helper()
	return newDaemonHarness(t, func(o *agent.Options) {
		o.MetricsListen = "127.0.0.1:0"
		if tune != nil {
			tune(o)
		}
	})
}

// scrapeAgent fetches /metrics from the daemon's own listener.
func scrapeAgent(t *testing.T, h *daemonHarness) string {
	t.Helper()
	addr := h.daemon.MetricsAddr()
	if !addr.IsValid() || addr.Port() == 0 {
		t.Fatalf("daemon reports metrics address %v; nothing is bound", addr)
	}
	if addr.Addr().IsUnspecified() {
		t.Fatalf("the daemon bound its /metrics endpoint to the wildcard address %v", addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr.String()+"/metrics", nil)
	if err != nil {
		t.Fatalf("build scrape request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("scrape %s: %v", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read scrape body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape returned %d", resp.StatusCode)
	}
	return string(body)
}

func wantScraped(t *testing.T, h *daemonHarness, want string) {
	t.Helper()
	var last string
	waitFor(t, "the scrape to contain "+want, func() bool {
		last = scrapeAgent(t, h)
		return strings.Contains(last, want)
	})
	if !strings.Contains(last, want) {
		t.Fatalf("scrape never contained %q\n--- scrape ---\n%s", want, last)
	}
}

// scrapedValue reads one unlabelled sample out of the exposition text.
func scrapedValue(t *testing.T, h *daemonHarness, name string) float64 {
	t.Helper()
	body := scrapeAgent(t, h)
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, name+" ")), 64)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		return v
	}
	t.Fatalf("no sample named %s in the scrape\n--- scrape ---\n%s", name, body)
	return 0
}

func refuteScraped(t *testing.T, h *daemonHarness, unwanted string) {
	t.Helper()
	body := scrapeAgent(t, h)
	if strings.Contains(body, unwanted) {
		t.Fatalf("scrape contains %q and should not\n--- scrape ---\n%s", unwanted, body)
	}
}

// TestAgent_Metrics_AGateOpenMovesTheLastOpenTimestamp is the 3am panel's
// wiring. It also pins what "successful end-to-end open" means from the
// agent's side: authorization alone is not enough, the timestamp moves only
// after the gate backend installed an element.
func TestAgent_Metrics_AGateOpenMovesTheLastOpenTimestamp(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	refuteScraped(t, h, "postern_gate_opens_total")
	before := scrapeAgent(t, h)
	if !strings.Contains(before, "postern_gate_last_open_timestamp_seconds 0") {
		t.Fatalf("a daemon that has opened nothing should report a zero last-open timestamp"+
			"\n--- scrape ---\n%s", before)
	}

	h.send(t, h.seal(h.gateRequest()), false)
	h.awaitProcessed(t, 1)

	wantScraped(t, h, `postern_spa_accepted_total{service="ssh"} 1`)
	wantScraped(t, h, `postern_gate_opens_total{service="ssh"} 1`)

	body := scrapeAgent(t, h)
	if strings.Contains(body, "postern_gate_last_open_timestamp_seconds 0") {
		t.Fatalf("the last-open timestamp did not move after a gate element was installed"+
			"\n--- scrape ---\n%s", body)
	}
	// The admitted source travelled through the daemon on this path. It must
	// not have travelled into the exposition.
	if strings.Contains(body, "198.51.100.5") {
		t.Fatalf("the admitted source address reached the scrape\n--- scrape ---\n%s", body)
	}
}

// TestAgent_Metrics_ARejectionIsCountedByReason proves the reason mapping is
// wired into the packet loop rather than only unit-tested beside it.
func TestAgent_Metrics_ARejectionIsCountedByReason(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	// Too short to be a record at all: the cheapest rejection there is.
	h.send(t, []byte("nowhere near a datagram"), false)
	h.awaitProcessed(t, 1)

	wantScraped(t, h, `postern_spa_rejections_total{reason="wrong_size"} 1`)
	wantScraped(t, h, "postern_spa_datagrams_total 1")
	refuteScraped(t, h, "postern_spa_accepted_total")
}

// TestAgent_Metrics_ADriftedClockIsVisible is the load-bearing one. A host
// whose clock has drifted past freshness_window but not past
// freshness_window_max keeps admitting gate packets, because the counter path
// carries them, and nothing else in the system reports that. Here the drift
// is simulated from the packet's side — a timestamp two hours old — which is
// indistinguishable to the agent from its own clock running two hours fast.
func TestAgent_Metrics_ADriftedClockIsVisible(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	req := h.gateRequest()
	drift := 2 * time.Hour
	req.TimestampMS = uint64(h.now.Add(-drift).UnixMilli())
	// Above the high-water mark, so the counter path admits it. That is the
	// whole point: the packet is accepted, the gate opens, and the only
	// evidence anything is wrong is the metric.
	req.Counter = uint64(h.now.UnixMilli()) + 1

	h.send(t, h.seal(req), false)
	h.awaitProcessed(t, 1)

	wantScraped(t, h, `postern_spa_accepted_total{service="ssh"} 1`)
	wantScraped(t, h, "postern_spa_accepted_beyond_freshness_window_total 1")
	// Two hours of drift lands between the 3600 and 10800 second boundaries,
	// which is only distinguishable because the buckets run past
	// freshness_window all the way to freshness_window_max.
	wantScraped(t, h, `postern_spa_clock_skew_seconds_bucket{le="3600"} 0`)
	wantScraped(t, h, `postern_spa_clock_skew_seconds_bucket{le="10800"} 1`)
	// Positive, and roughly the drift: this host's clock is ahead of the
	// timestamp it was sent. A magnitude-only histogram cannot say that, which
	// is why the signed gauge exists alongside it.
	if got := scrapedValue(t, h, "postern_spa_clock_skew_last_seconds"); got < 7100 || got > 7300 {
		t.Fatalf("postern_spa_clock_skew_last_seconds = %v, want roughly +%v seconds", got, drift.Seconds())
	}
}

// TestAgent_Metrics_AFreshPacketDoesNotCountAsDrift is the other half: the
// counter-path counter must not simply track every accepted packet.
func TestAgent_Metrics_AFreshPacketDoesNotCountAsDrift(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	h.send(t, h.seal(h.gateRequest()), false)
	h.awaitProcessed(t, 1)

	wantScraped(t, h, `postern_spa_accepted_total{service="ssh"} 1`)
	wantScraped(t, h, "postern_spa_accepted_beyond_freshness_window_total 0")
}

// TestAgent_Metrics_AFailedRenewalGoesRed covers the transition design
// section 8 calls the agent's own immediate signal: the write targets a set
// inside postern_boot, so a failure means SPA silence is already broken.
func TestAgent_Metrics_AFailedRenewalGoesRed(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	wantScraped(t, h, `postern_agent_health_red{source="agent_up"} 0`)
	wantScraped(t, h, `postern_agent_up_renewals_total{result="ok"} 1`)

	h.gate.setRefreshErr(errors.New("no such set: agent_up"))
	h.tick(t, true)

	wantScraped(t, h, `postern_agent_health_red{source="agent_up"} 1`)
	wantScraped(t, h, `postern_agent_up_renewals_total{result="failed"} 1`)
	// The failure reason is netlink text and must not have become a label.
	refuteScraped(t, h, "no such set")
}

// TestAgent_Metrics_PreArmVerdictsAreExported checks the per-service half of
// pre-arm reaches the exposition, including the services that are fine — an
// alert cannot distinguish "ssh is not armed" from "this label never existed".
func TestAgent_Metrics_PreArmVerdictsAreExported(t *testing.T) {
	h := newMetricsHarness(t, func(o *agent.Options) {
		o.Checks = passingChecks(map[string]bool{sshName: false})
	})
	h.start(t)

	wantScraped(t, h, `postern_gate_service_armed{service="ssh"} 0`)
	wantScraped(t, h, "postern_agent_inert 0")
}

func TestAgent_Metrics_ArmedServicesAreExported(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	wantScraped(t, h, `postern_gate_service_armed{service="ssh"} 1`)
}

// TestAgent_Metrics_GateStateIsReadBackFromTheGate proves the open-sources
// gauge follows what the firewall actually holds rather than being counted up
// from Open — gate elements expire on their own timeout, so a counter
// maintained from the agent's side would only ever grow.
func TestAgent_Metrics_GateStateIsReadBackFromTheGate(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	wantScraped(t, h, `postern_gate_open_sources{service="ssh",source_kind="observed"} 0`)

	h.gate.setState(gateStateWith(2, 1))
	h.tick(t, true)

	wantScraped(t, h, `postern_gate_open_sources{service="ssh",source_kind="observed"} 2`)
	wantScraped(t, h, `postern_gate_open_sources{service="ssh",source_kind="asserted"} 1`)
}

// TestAgent_New_RefusesAWildcardMetricsBind is the bind constraint asserted on
// the production path rather than only on the helper: design section 8 binds
// the agent's endpoint to the always-allow interface or localhost, and a root
// daemon holding the fleet's gate state must not be able to publish it on
// every interface because someone typed the address everyone types.
func TestAgent_New_RefusesAWildcardMetricsBind(t *testing.T) {
	_, err := agent.New(metricsOptions(t, "0.0.0.0:9873"))
	if !errors.Is(err, metrics.ErrWildcardBind) {
		t.Fatalf("agent.New with a wildcard --metrics-listen returned %v, want ErrWildcardBind", err)
	}
}

func TestAgent_New_RefusesAMetricsBindOffTheAlwaysAllowInterface(t *testing.T) {
	_, err := agent.New(metricsOptions(t, "203.0.113.9:9873"))
	if !errors.Is(err, metrics.ErrBindNotPermitted) {
		t.Fatalf("agent.New with an off-interface --metrics-listen returned %v, want ErrBindNotPermitted", err)
	}
}

func TestAgent_New_AcceptsAMetricsBindOnTheAlwaysAllowInterface(t *testing.T) {
	d, err := agent.New(metricsOptions(t, "100.64.0.7:9873"))
	if err != nil {
		t.Fatalf("agent.New with an on-interface --metrics-listen: %v", err)
	}
	if got := d.MetricsAddr().String(); got != "100.64.0.7:9873" {
		t.Fatalf("MetricsAddr() = %s, want 100.64.0.7:9873", got)
	}
}

func TestAgent_New_WithoutAMetricsListenServesNothing(t *testing.T) {
	opts := metricsOptions(t, "")
	d, err := agent.New(opts)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	if d.MetricsAddr().IsValid() {
		t.Fatalf("MetricsAddr() = %v with no --metrics-listen; the endpoint is opt-in", d.MetricsAddr())
	}
	if d.Metrics() != nil {
		t.Fatal("a daemon with no --metrics-listen and no injected recorder built one anyway")
	}
}

// metricsOptions builds the minimum valid Options with a stubbed always-allow
// interface, so the bind rules are exercised without a host that happens to
// have a mesh interface on it.
func metricsOptions(t *testing.T, listen string) agent.Options {
	t.Helper()
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.AlwaysAllowIface = "tailscale0"
	return agent.Options{
		Policy:                f.policy,
		Gate:                  &daemonGate{},
		Opener:                f.opener,
		Store:                 f.store,
		Host:                  f.host,
		Receiver:              newFakeReceiver(),
		StorePath:             t.TempDir() + "/replay.db",
		MetricsListen:         listen,
		MetricsInterfaceAddrs: stubIfaceAddrs,
	}
}

// syncBuffer is a log sink that survives -race: slog writes from the packet
// loop's goroutine and the assertions read from the test's.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) count(sub string) int {
	return strings.Count(s.String(), sub)
}

// TestAgent_UnreadableGateState_LogsTheTransitionAndNotEveryBeat.
//
// The gate-state read runs once per service per heartbeat, and a gate whose
// set is missing does not heal on its own — so an unconditional line here
// repeats forever. The state it repeats through is exactly the one an operator
// would be reading the journal in, where the thing they need is buried under a
// page of it.
//
// Mutation verified: logging unconditionally instead of on the transition
// makes the count assertion fail, and dropping the recovery line makes the
// second half fail.
func TestAgent_UnreadableGateState_LogsTheTransitionAndNotEveryBeat(t *testing.T) {
	logs := &syncBuffer{}
	h := newMetricsHarness(t, func(o *agent.Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	h.gate.setStateErr(errors.New("open /var/empty/postern_boot: no such file or directory"))
	h.start(t)

	waitFor(t, "the unreadable gate state to be reported once", func() bool {
		return logs.count("gate state is unreadable") == 1
	})

	// Six ticks, so at least five whole beats have finished: the loop is
	// single-threaded, so a tick the loop accepts means the previous beat
	// returned.
	for i := 0; i < 6; i++ {
		h.tick(t, true)
	}
	if got := logs.count("gate state is unreadable"); got != 1 {
		t.Fatalf("the unreadable gate state was logged %d times across seven beats; it is a state, not "+
			"an event, and repeating it floods the journal an operator reads in exactly this "+
			"situation\n--- log ---\n%s", got, logs.String())
	}
	// The error itself is still there once, because the first line is the one
	// that has to be actionable.
	if !strings.Contains(logs.String(), "no such file or directory") {
		t.Fatalf("the transition does not carry the error, so it says nothing actionable\n--- log ---\n%s",
			logs.String())
	}

	// Recovery is logged too. An error that stops without a line saying so
	// leaves a reader with a permanent last-known-bad.
	h.gate.setStateErr(nil)
	h.tick(t, true)
	waitFor(t, "the recovery to be reported", func() bool {
		return logs.count("gate state is readable again") == 1
	})
	h.tick(t, true)
	h.tick(t, true)
	if got := logs.count("gate state is readable again"); got != 1 {
		t.Fatalf("the recovery was logged %d times; it is a transition too\n--- log ---\n%s", got, logs.String())
	}
	if got := logs.count("gate state is unreadable"); got != 1 {
		t.Fatalf("the unreadable line reappeared after recovery (%d total)\n--- log ---\n%s", got, logs.String())
	}
}

// TestAgent_Metrics_PublishTheHostIDTheProbeJoinsOn is the join key, asserted
// against a real scrape of the real daemon.
//
// The probe is a client role and does not run on the host, so its series and
// the agent's arrive from two scrape targets. Without an identifier both sides
// hold, "health is the join" would need an operator to hand-write a matching
// label into their scrape config — a join that is documented and never wired,
// which is the failure this whole piece of work exists to remove.
func TestAgent_Metrics_PublishTheHostIDTheProbeJoinsOn(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	body := scrapeAgent(t, h)
	want := hex.EncodeToString(h.policy.HostID[:])
	if !strings.Contains(body, `host_id="`+want+`"`) {
		t.Fatalf("the daemon's scrape does not carry host_id=%q, so no probe series can be joined to "+
			"it\n--- scrape ---\n%s", want, body)
	}
	// And only one candidate: a group_left join against two info series on one
	// target matches neither cleanly.
	if strings.Contains(body, `host_id=""`) {
		t.Fatalf("the daemon publishes an empty host_id alongside the real one\n--- scrape ---\n%s", body)
	}
}

// TestAgent_AgentUpLease_RedWhenTheRenewalSucceedsButTheLeaseDidNotMove is the
// agent-side regression test for the worst bug this project has had.
//
// The renewal returning nil is not evidence the lease moved. A re-add of a
// live nftables element with an identical ttl is silently ignored, so for the
// whole life of this daemon every beat "succeeded", extended nothing, and the
// SPA port lapsed on the first add's clock — with agent_up health green,
// up_renewals_total{result="ok"} climbing, and not one log line. The gate-level
// fix stops it happening; this stops it happening again unnoticed, from the
// other side, by checking that the daemon looks at what the firewall holds
// rather than at what its own call returned.
func TestAgent_AgentUpLease_RedWhenTheRenewalSucceedsButTheLeaseDidNotMove(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	if h.daemon.Health().Red {
		t.Fatal("the daemon started red")
	}
	// The renewal keeps succeeding. Only the effect is missing.
	h.gate.setAgentUpExpiry(-1, nil) // negative: read back, element absent
	h.tick(t, true)
	waitFor(t, "the daemon to go red on a lease that did not move", func() bool {
		return h.daemon.Health().Red
	})
	if reason := h.daemon.Health().Reason; !strings.Contains(reason, "SPA port") {
		t.Fatalf("the red reason does not name the consequence: %q", reason)
	}

	body := scrapeAgent(t, h)
	// The renewal counter is still climbing, which is exactly why it could
	// never have been the signal.
	mustHaveSample(t, body, `postern_agent_up_renewals_total{result="ok"}`)
	if !strings.Contains(body, "postern_agent_up_expires_timestamp_seconds 0") {
		t.Fatalf("the lease gauge does not publish 0 for an absent element, so an alert cannot match "+
			"the one state that means the door is shut\n--- scrape ---\n%s", body)
	}

	// And it clears when the lease actually starts moving again, because a
	// standing red on a recovered host is its own way of being ignored.
	h.gate.setAgentUpExpiry(2*time.Minute, nil)
	h.tick(t, true)
	waitFor(t, "the daemon to recover once the lease moves", func() bool {
		return !h.daemon.Health().Red
	})
}

// TestAgent_AgentUpLease_AFailedReadBackIsNotRed keeps the read-back from
// becoming a way for the metrics path to take the SPA port down. It is the
// same reasoning recordGateState carries: a read that exists to publish a
// number must not decide whether the door stays open.
func TestAgent_AgentUpLease_AFailedReadBackIsNotRed(t *testing.T) {
	h := newMetricsHarness(t, nil)
	h.start(t)

	h.gate.setAgentUpExpiry(0, errors.New("netlink: no such file or directory"))
	h.tick(t, true)
	h.tick(t, true)
	if h.daemon.Health().Red {
		t.Fatalf("a failed agent_up read-back turned the daemon red: %q", h.daemon.Health().Reason)
	}
}

func mustHaveSample(t *testing.T, body, prefix string) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return
		}
	}
	t.Fatalf("no sample named %s\n--- scrape ---\n%s", prefix, body)
}
