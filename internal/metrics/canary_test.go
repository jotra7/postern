package metrics_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/metrics"
	"github.com/jotra7/postern/internal/probe"
)

// The probe's series are asserted by driving a real probe.Runner with a
// scripted dialer, never by calling the Canary's methods directly.
//
// That is the whole point of this file. The defect this work exists to fix is
// a check that is defined, documented and tested and never wired into the
// thing that runs — so a test that calls c.ObserveSweep by hand would pass
// just as happily against a Runner that had never been given a Metrics at
// all. What is under test here is emit(): that the production loop calls all
// four methods, with the values it holds, every sweep.
//
// Every timing bound below is injected and every scripted connect returns
// immediately. A probe made of timeouts is unusually good at producing a test
// whose failure under mutation is a hang, and a hang emits neither a pass nor
// a --- FAIL.

// probeHostID is the identity enrollment issued. It is the join key: the same
// 32 hex characters appear in the host's own standalone config, in every
// operator's client config, and — after this work — in both halves of the
// scrape.
const probeHostID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

// A real X25519 public key, so Seal succeeds. Its private half is nobody's.
const probeHostEncryptionB64 = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr06H5F9wKgcHU="

func probeTestHost(t *testing.T) *client.Host {
	t.Helper()
	enc, err := base64.StdEncoding.DecodeString(probeHostEncryptionB64)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	yaml := "" +
		"operator: probe-local\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: " + probeHostID + "\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(enc) + "\n" +
		"    recovery_service: ssh\n" +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n" +
		"      canary: { port: 62202, ttl: 30s }\n"
	cfg, err := client.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

// dialResult is one scripted connect outcome, all of them instant.
type dialResult func() (net.Conn, error)

func timedOut() (net.Conn, error) { return nil, context.DeadlineExceeded }

// refused is a TCP RST wrapped the way the standard library wraps it, so
// client.Classify's errors.Is walk is what runs.
func refused() (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

// unclassifiable carries an address in its text, which is what makes it the
// right probe for "does an error string reach a label value".
func unclassifiable() (net.Conn, error) {
	return nil, errors.New("dial tcp 100.64.0.7:62202: some future error postern does not classify")
}

// scriptedDialer answers connects from a list, cycling so a multi-sweep run
// repeats the same sweep rather than falling off the end of the script.
type scriptedDialer struct {
	mu      sync.Mutex
	n       int
	results []dialResult
}

func (d *scriptedDialer) dial(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	fn := timedOut
	if len(d.results) > 0 {
		fn = d.results[d.n%len(d.results)]
	}
	d.n++
	d.mu.Unlock()
	return fn()
}

// canaryFixture is a real Runner wired to a real Canary, with the two things
// a sweep needs from the network replaced and nothing else.
type canaryFixture struct {
	runner *probe.Runner
	canary *metrics.Canary
	// serve renders the exposition text of whichever registry the canary
	// publishes into.
	serve func(t *testing.T) string
}

func newCanaryFixture(t *testing.T, r *metrics.Recorder, results ...dialResult) *canaryFixture {
	t.Helper()
	signer, err := identity.Generate("probe-local")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	canary, err := metrics.NewCanary(r)
	if err != nil {
		t.Fatalf("NewCanary: %v", err)
	}
	host := probeTestHost(t)
	canary.SetTarget(host.Name, host.RawHostID)

	dialer := &scriptedDialer{results: results}
	base := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	var ticks int
	now := func() time.Time { ticks++; return base.Add(time.Duration(ticks) * time.Second) }

	return &canaryFixture{
		canary: canary,
		serve:  func(t *testing.T) string { return serveHandler(t, canary.Handler()) },
		runner: &probe.Runner{
			Prober: &probe.Prober{
				Builder:      client.Builder{Signer: signer},
				Host:         host,
				Counter:      client.NewCounter(t.TempDir() + "/counter.json"),
				Send:         func(context.Context, netip.AddrPort, []byte) error { return nil },
				Dial:         dialer.dial,
				Now:          now,
				Sleep:        func(context.Context, time.Duration) error { return nil },
				Settle:       time.Nanosecond,
				OpenAttempts: 1,
			},
			Now:     now,
			Metrics: canary,
		},
	}
}

func (f *canaryFixture) once(t *testing.T) probe.Sweep {
	t.Helper()
	sw, _, err := f.runner.Once(context.Background())
	if err != nil {
		t.Fatalf("Runner.Once: %v", err)
	}
	return sw
}

// run drives the production loop — probe.Runner.Run, not Once — for exactly n
// sweeps, by cancelling from inside the injected sleep.
//
// The 5-second backstop is deliberate. Run's termination is the thing being
// leaned on here, and a mutation that broke it would otherwise turn this test
// into a hang, which emits neither a pass nor a --- FAIL and is invisible in a
// batch run.
func (f *canaryFixture) run(t *testing.T, n int) probe.State {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	swept := 0
	f.runner.Sleep = func(context.Context, time.Duration) error {
		swept++
		if swept >= n {
			cancel()
		}
		return nil
	}
	st, err := f.runner.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Runner.Run returned %v, want context.Canceled after %d sweeps", err, n)
	}
	if swept != n {
		t.Fatalf("Runner.Run performed %d sweeps, want %d", swept, n)
	}
	return st
}

func serveHandler(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// passing scripts a healthy sweep: phase 1 silent, phase 2 reset.
func passing() []dialResult { return []dialResult{timedOut, refused} }

// gateNotOpened is the ordinary red — the gate is shut and the knock did not
// open it, which is what an operator sees when the agent is fine and the path
// to it is not.
func gateNotOpened() []dialResult { return []dialResult{timedOut, timedOut} }

// TestMetrics_Canary_RunnerPublishesEverySweepThroughTheRealLoop is the wiring
// test. probe.Runner.emit is the only thing that calls the Metrics interface
// in production; if the Canary were registered and never driven, every series
// below would be absent or frozen, which is exactly how "the metric exists and
// nothing updates it" looks from a dashboard.
func TestMetrics_Canary_RunnerPublishesEverySweepThroughTheRealLoop(t *testing.T) {
	f := newCanaryFixture(t, nil, passing()...)

	sw := f.once(t)
	if !sw.Passed() {
		t.Fatalf("scripted healthy sweep did not pass: %s (%s)", sw.Reason, sw.Summary)
	}

	body := f.serve(t)
	mustContain(t, body, `postern_probe_target_info{host="web-01",host_id="`+probeHostID+`"} 1`)
	mustContain(t, body, `postern_probe_sweeps_total{host="web-01",reason="none",service="canary",verdict="pass"} 1`)
	mustContain(t, body, `postern_probe_health{host="web-01",state="green"} 1`)
	mustContain(t, body, `postern_probe_consecutive_failures{host="web-01"} 0`)
	// The clock the fixture injects starts at 2026-07-29T12:00:00Z, so any
	// nonzero value here came from the runner's own now(), not from a
	// hard-coded zero.
	if strings.Contains(body, `postern_probe_last_pass_timestamp_seconds{host="web-01"} 0`) {
		t.Fatalf("a passing sweep left last_pass at 0, which reads as never\n--- scrape ---\n%s", body)
	}
	mustContain(t, body, `postern_probe_last_pass_timestamp_seconds{host="web-01"} 1.7`)
}

// TestMetrics_Canary_RedIsReachableAndCarriesItsReason covers the state the
// join exists for from the probe's side: the agent is fine, the path is not.
func TestMetrics_Canary_RedIsReachableAndCarriesItsReason(t *testing.T) {
	f := newCanaryFixture(t, nil, gateNotOpened()...)
	f.runner.FailureThreshold = 3

	// One failed sweep is a packet-loss story: amber, and not yet a page.
	amber := newCanaryFixture(t, nil, gateNotOpened()...)
	amber.runner.FailureThreshold = 3
	amber.run(t, 1)
	body := amber.serve(t)
	mustContain(t, body, `postern_probe_health{host="web-01",state="amber"} 1`)
	mustContain(t, body, `postern_probe_health{host="web-01",state="red"} 0`)
	mustContain(t, body, `postern_probe_consecutive_failures{host="web-01"} 1`)

	// Three is red. Not four, and not two.
	f.run(t, 3)
	body = f.serve(t)
	mustContain(t, body, `postern_probe_health{host="web-01",state="red"} 1`)
	mustContain(t, body, `postern_probe_health{host="web-01",state="amber"} 0`)
	mustContain(t, body, `postern_probe_health{host="web-01",state="green"} 0`)
	mustContain(t, body, `postern_probe_consecutive_failures{host="web-01"} 3`)
	mustContain(t, body,
		`postern_probe_sweeps_total{host="web-01",reason="gate_not_opened",service="canary",verdict="fail"} 3`)
	// Never proven reachable is 0, not absent: an alert cannot tell a missing
	// series from a scrape target that is down.
	mustContain(t, body, `postern_probe_last_pass_timestamp_seconds{host="web-01"} 0`)
}

// TestMetrics_Canary_HealthPublishesEveryStateOnEverySweep is what makes
// `postern_probe_health{state="red"} == 1` a safe alert. If only the current
// state had a series, "red" would be absent on a healthy host and an alert
// could not distinguish that from a probe that has stopped reporting.
func TestMetrics_Canary_HealthPublishesEveryStateOnEverySweep(t *testing.T) {
	f := newCanaryFixture(t, nil, passing()...)
	f.once(t)

	body := f.serve(t)
	for _, state := range []string{"unknown", "green", "amber", "red"} {
		want := `postern_probe_health{host="web-01",state="` + state + `"} `
		if !strings.Contains(body, want) {
			t.Fatalf("no series for state %q; a state with no series cannot be alerted on\n--- scrape ---\n%s",
				state, body)
		}
	}
}

// TestMetrics_Canary_TheStreakComesFromTheRunnerNotFromASecondCount is the
// design disagreement, pinned. probe.Runner already keeps the streak that
// decides HealthRed; deriving a second one here from the sweep results would
// give the dashboard a number that can drift from the one that alerts.
func TestMetrics_Canary_TheStreakComesFromTheRunnerNotFromASecondCount(t *testing.T) {
	f := newCanaryFixture(t, nil, gateNotOpened()...)
	f.run(t, 2)
	mustContain(t, f.serve(t), `postern_probe_consecutive_failures{host="web-01"} 2`)

	// A second Runner over the same Canary — the shape a probe restarted by
	// systemd produces — starts its own state at zero, and the gauge must
	// follow it rather than continuing to climb from a count this package kept.
	fresh := newCanaryFixture(t, nil, gateNotOpened()...)
	fresh.runner.Metrics = f.canary
	fresh.run(t, 1)
	mustContain(t, f.serve(t), `postern_probe_consecutive_failures{host="web-01"} 1`)
}

// TestMetrics_CanaryReason_EveryProbeReasonHasItsOwnLabelToken walks the
// probe's own exported set rather than a list written here, so a reason added
// to internal/probe without a token fails this instead of silently recording
// itself as "other" — which would fold "the port answers with no gate at all"
// into the same bucket as everything else.
func TestMetrics_CanaryReason_EveryProbeReasonHasItsOwnLabelToken(t *testing.T) {
	seen := map[string]probe.Reason{}
	for _, r := range probe.Reasons {
		token := metrics.CanaryReason(r)
		if token == metrics.ReasonOther {
			t.Errorf("probe reason %q has no label token of its own and falls to %q", r, metrics.ReasonOther)
			continue
		}
		if prev, dup := seen[token]; dup {
			t.Errorf("probe reasons %q and %q share the label token %q", prev, r, token)
		}
		seen[token] = r
	}
	if len(seen) == 0 {
		t.Fatal("probe.Reasons is empty, so this test asserted nothing")
	}
	if got := metrics.CanaryReason(probe.Reason("dial tcp 100.64.0.7:62202: i/o timeout")); got != metrics.ReasonOther {
		t.Fatalf("CanaryReason(unknown) = %q, want %q", got, metrics.ReasonOther)
	}
}

// TestMetrics_Canary_AConnectErrorNeverReachesALabel drives the real sweep to
// an unclassified outcome whose error text carries an address, because that is
// where an unbounded, attacker-influenced label value would actually come from.
func TestMetrics_Canary_AConnectErrorNeverReachesALabel(t *testing.T) {
	f := newCanaryFixture(t, nil, unclassifiable)
	sw := f.once(t)
	if sw.Reason != probe.ReasonUnclassified {
		t.Fatalf("sweep reason = %q, want %q; the fixture is not exercising the path under test",
			sw.Reason, probe.ReasonUnclassified)
	}

	body := f.serve(t)
	mustContain(t, body,
		`postern_probe_sweeps_total{host="web-01",reason="unclassified",service="canary",verdict="fail"} 1`)
	if strings.Contains(body, "100.64.0.7") {
		t.Fatalf("a connect error's address reached the exposition text\n--- scrape ---\n%s", body)
	}
}

// TestMetrics_Canary_JoinsToTheAgentOnHostID is the join key, asserted across
// the two scrapes an operator actually has.
//
// The agent's target is identified by the address Prometheus scrapes; the
// probe's series are identified by the name an operator typed. Neither can be
// derived from the other, so without a shared identifier "health is the join"
// would need a label hand-written into a scrape config — documented, and never
// wired. host_id is what both sides already hold.
func TestMetrics_Canary_JoinsToTheAgentOnHostID(t *testing.T) {
	agent := metrics.New()
	agent.SetHostID(probeHostID)

	// Deliberately a *separate* registry, because that is the deployment: the
	// probe is not on the host.
	f := newCanaryFixture(t, nil, passing()...)
	f.once(t)

	agentBody := scrape(t, agent)
	probeBody := f.serve(t)

	if !strings.Contains(agentBody, `host_id="`+probeHostID+`"`) {
		t.Fatalf("the agent's scrape carries no host_id, so nothing can join to it\n--- scrape ---\n%s", agentBody)
	}
	if !strings.Contains(probeBody, `host_id="`+probeHostID+`"`) {
		t.Fatalf("the probe's scrape carries no host_id, so it cannot be joined to an agent"+
			"\n--- scrape ---\n%s", probeBody)
	}
	// And the two halves of the state design section 8 calls the most valuable
	// one are simultaneously readable: the agent says it is fine, the probe
	// says it cannot be reached.
	mustContain(t, agentBody, `postern_agent_health_red{source="agent_up"} 0`)
	mustContain(t, probeBody, `postern_probe_health{host="web-01",state="red"} 0`)
}

// TestMetrics_SetHostID_LeavesNoUnlabelledSeriesBehind matters because a
// group_left join with two candidate info series on one target matches
// neither cleanly.
func TestMetrics_SetHostID_LeavesNoUnlabelledSeriesBehind(t *testing.T) {
	r := metrics.New()
	r.SetHostID(probeHostID)

	body := scrape(t, r)
	mustContain(t, body, `host_id="`+probeHostID+`"`)
	if strings.Contains(body, `host_id=""`) {
		t.Fatalf("the seeded empty host_id series survived SetHostID, giving a join two candidates"+
			"\n--- scrape ---\n%s", body)
	}
}

// TestMetrics_NewCanary_StandaloneDoesNotClaimToBeAnAgent covers the probe's
// own endpoint. A probe serving postern_agent_* families at zero would show an
// operator a healthy agent on a machine that is not one.
func TestMetrics_NewCanary_StandaloneDoesNotClaimToBeAnAgent(t *testing.T) {
	f := newCanaryFixture(t, nil, passing()...)
	f.once(t)

	body := f.serve(t)
	mustContain(t, body, "postern_probe_sweeps_total")
	// Samples only. HELP text mentions the agent's families by name on purpose
	// — that is where the join is documented — and a substring match over the
	// whole body would read those as exported series.
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, unwanted := range []string{"postern_agent_", "postern_gate_", "postern_spa_", "postern_transaction_"} {
			if strings.HasPrefix(line, unwanted) {
				t.Fatalf("the probe's own endpoint serves %q, which would report an agent on a host that "+
					"has none\n--- scrape ---\n%s", line, body)
			}
		}
	}
}

// TestMetrics_NewCanary_CoLocatedSharesTheAgentRegistry is the other supported
// deployment: a probe running beside an agent stays one scrape target.
func TestMetrics_NewCanary_CoLocatedSharesTheAgentRegistry(t *testing.T) {
	r := metrics.New()
	f := newCanaryFixture(t, r, passing()...)
	f.once(t)

	for _, body := range []string{scrape(t, r), f.serve(t)} {
		mustContain(t, body, "postern_probe_sweeps_total")
		mustContain(t, body, "postern_agent_info")
	}
}

// TestMetrics_Canary_NilIsSafe lets the probe call the interface
// unconditionally, the same reason the Recorder's methods are nil-safe.
func TestMetrics_Canary_NilIsSafe(t *testing.T) {
	var c *metrics.Canary
	c.SetTarget("web-01", probeHostID)
	c.ObserveSweep(probe.Sweep{Host: "web-01"})
	c.SetHealth("web-01", probe.HealthRed)
	c.SetConsecutiveFailures("web-01", 3)
	c.SetLastPass("web-01", time.Now())
	if c.Handler() == nil {
		t.Fatal("Handler on a nil Canary returned nil")
	}
}

// TestMetrics_ResolveProbeBind_RefusesAWildcardAndAName keeps the probe's
// endpoint off every interface by accident. Its exposition says which hosts
// are unreachable right now, which is a shopping list.
func TestMetrics_ResolveProbeBind_RefusesAWildcardAndAName(t *testing.T) {
	for _, spec := range []string{"0.0.0.0:9874", "[::]:9874", "probe.example.com:9874"} {
		if _, err := metrics.ResolveProbeBind(spec); err == nil {
			t.Errorf("ResolveProbeBind(%q) was accepted", spec)
		}
	}
	if _, err := metrics.ResolveProbeBind("0.0.0.0:9874"); !errors.Is(err, metrics.ErrWildcardBind) {
		t.Errorf("ResolveProbeBind(0.0.0.0) error = %v, want ErrWildcardBind", err)
	}
}

// TestMetrics_ResolveProbeBind_DefaultsToLoopbackAndKeepsAnExplicitAddress
// pins the one place it deliberately differs from the agent's rule: there is
// no always-allow interface on a monitoring box, so ":port" is loopback rather
// than an interface lookup, and any literal address is allowed because no
// interface membership rule could be checked against.
func TestMetrics_ResolveProbeBind_DefaultsToLoopbackAndKeepsAnExplicitAddress(t *testing.T) {
	got, err := metrics.ResolveProbeBind(":9874")
	if err != nil {
		t.Fatalf("ResolveProbeBind(:9874): %v", err)
	}
	if !got.Addr().IsLoopback() || got.Port() != 9874 {
		t.Fatalf("ResolveProbeBind(:9874) = %s, want loopback:9874", got)
	}
	got, err = metrics.ResolveProbeBind("192.0.2.9:9874")
	if err != nil {
		t.Fatalf("ResolveProbeBind(192.0.2.9:9874): %v", err)
	}
	if got.String() != "192.0.2.9:9874" {
		t.Fatalf("ResolveProbeBind(192.0.2.9:9874) = %s", got)
	}
}
