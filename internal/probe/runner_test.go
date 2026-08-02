package probe_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/probe"
)

// stopAfter is a Sleep that lets the loop run exactly n times and then ends
// it. Every Runner test uses one: a loop driven by a real timer cannot be
// tested without waiting, and a test that waits is a test whose failure
// under mutation is a hang rather than a FAIL.
type stopAfter struct {
	n      int
	waits  []time.Duration
	cancel context.CancelFunc
}

func (s *stopAfter) sleep(_ context.Context, d time.Duration) error {
	s.waits = append(s.waits, d)
	if len(s.waits) >= s.n {
		s.cancel()
		return context.Canceled
	}
	return nil
}

// recordingMetrics captures what the probe expects to emit, so the wiring to
// internal/metrics has a shape a test has already pinned.
type recordingMetrics struct {
	sweeps   []probe.Sweep
	health   []probe.Health
	streaks  []int
	lastPass []time.Time
}

func (m *recordingMetrics) ObserveSweep(sw probe.Sweep)            { m.sweeps = append(m.sweeps, sw) }
func (m *recordingMetrics) SetHealth(_ string, h probe.Health)     { m.health = append(m.health, h) }
func (m *recordingMetrics) SetConsecutiveFailures(_ string, n int) { m.streaks = append(m.streaks, n) }
func (m *recordingMetrics) SetLastPass(_ string, t time.Time)      { m.lastPass = append(m.lastPass, t) }

// newRunner wires a runner whose sweeps all fail the same way (phase 1
// refused, the no-firewall case) unless the dialer says otherwise.
func newRunner(t *testing.T, results ...dialResult) (*probe.Runner, *stopAfter, *recordingMetrics) {
	t.Helper()
	p := newProber(t, newDialer(t, results...), &countingSender{})
	stop := &stopAfter{n: 1}
	m := &recordingMetrics{}
	return &probe.Runner{
		Prober:   p,
		Interval: 137 * time.Second,
		Rand:     func() float64 { return 0.5 },
		Sleep:    stop.sleep,
		Metrics:  m,
	}, stop, m
}

// Three consecutive failures turn a host red — and, just as load-bearing,
// one and two do not.
//
// Mutation verified: changing the comparison to `>` (red on the fourth)
// leaves the amber assertions passing and fails the red one.
func TestProbe_Runner_TurnsRedOnTheThirdConsecutiveFailure(t *testing.T) {
	r, stop, m := newRunner(t, refused)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop.n = 3
	stop.cancel = cancel

	st, err := r.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if st.Sweeps != 3 {
		t.Fatalf("sweeps = %d, want 3", st.Sweeps)
	}
	want := []probe.Health{probe.HealthAmber, probe.HealthAmber, probe.HealthRed}
	if len(m.health) != 3 {
		t.Fatalf("health transitions = %v, want 3", m.health)
	}
	for i, w := range want {
		if m.health[i] != w {
			t.Errorf("after %d consecutive failures health = %s, want %s", i+1, m.health[i], w)
		}
	}
	if st.Health != probe.HealthRed || st.ConsecutiveFailures != 3 {
		t.Errorf("final state = %s with %d failures, want red with 3", st.Health, st.ConsecutiveFailures)
	}
	if st.LastReason != probe.ReasonGateNotClosed {
		t.Errorf("last reason = %q, want %q", st.LastReason, probe.ReasonGateNotClosed)
	}
}

// A pass resets the streak. Without this a host that fails twice a week is
// red by Thursday and the signal is worthless.
func TestProbe_Runner_ResetsTheStreakOnAPass(t *testing.T) {
	// Sweep 1 fails at phase 1 (one connect). Sweep 2 passes (two connects).
	// Sweep 3 fails at phase 1 again.
	r, stop, _ := newRunner(t, refused, timedOut, refused, refused)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop.n = 3
	stop.cancel = cancel

	st, _ := r.Run(ctx)
	if st.Passes != 1 || st.Failures != 2 {
		t.Fatalf("passes = %d, failures = %d, want 1 and 2", st.Passes, st.Failures)
	}
	if st.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1: the pass did not reset the streak", st.ConsecutiveFailures)
	}
	if st.Health != probe.HealthAmber {
		t.Errorf("health = %s, want amber", st.Health)
	}
	if st.LastPass.IsZero() {
		t.Error("LastPass is zero after a passing sweep")
	}
}

// The wait between sweeps is the jittered interval, drawn once per sweep.
// A runner that slept a constant would pass every other test here.
func TestProbe_Runner_WaitsAJitteredIntervalBetweenSweeps(t *testing.T) {
	r, stop, _ := newRunner(t, refused)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop.n = 3
	stop.cancel = cancel

	draws := []float64{0, 0.5, 1}
	i := 0
	r.Rand = func() float64 {
		v := draws[i%len(draws)]
		i++
		return v
	}
	if _, err := r.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	want := []time.Duration{
		time.Duration(float64(137*time.Second) * 0.90),
		137 * time.Second,
		time.Duration(float64(137*time.Second) * 1.10),
	}
	if len(stop.waits) != len(want) {
		t.Fatalf("waits = %v, want %d of them", stop.waits, len(want))
	}
	for j := range want {
		if stop.waits[j] != want[j] {
			t.Errorf("wait %d = %s, want %s", j, stop.waits[j], want[j])
		}
	}
}

// The sweep opens a real gate with a real lease. An interval short enough
// that the lease is still live when the next sweep's phase 1 runs makes the
// probe poison its own evidence: it would report a permanently red host
// whose gate works perfectly.
func TestProbe_Runner_RefusesAnIntervalShorterThanTheGateItOpens(t *testing.T) {
	r, _, _ := newRunner(t, timedOut, refused)
	r.Interval = 20 * time.Second // the host entry's canary ttl is 30s
	err := r.Validate()
	if err == nil {
		t.Fatal("Validate accepted a sweep interval shorter than the gate the sweep itself opens")
	}
	for _, want := range []string{"20s", "30s"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	// The boundary is the jittered minimum, not the nominal interval: a 33s
	// interval with ±10% jitter can wait only 29.7s, which is inside a 30s
	// lease.
	r.Interval = 33 * time.Second
	if err := r.Validate(); err == nil {
		t.Error("Validate accepted an interval whose jittered minimum falls inside the gate's lease")
	}
	r.Interval = 60 * time.Second
	if err := r.Validate(); err != nil {
		t.Errorf("Validate refused a comfortable interval: %v", err)
	}
}

// A reporting sink that is down must not be able to stop the probe.
// Detecting a red host matters more than announcing one.
func TestProbe_Runner_KeepsSweepingWhenTheReporterFails(t *testing.T) {
	r, stop, _ := newRunner(t, refused)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop.n = 3
	stop.cancel = cancel

	var seen []error
	r.Reporter = failingReporter{}
	r.OnError = func(err error) { seen = append(seen, err) }

	st, _ := r.Run(ctx)
	if st.Sweeps != 3 {
		t.Errorf("sweeps = %d, want 3: a failing reporter stopped the loop", st.Sweeps)
	}
	if len(seen) != 3 {
		t.Errorf("reporter errors surfaced = %d, want 3", len(seen))
	}
	if len(seen) > 0 && !strings.Contains(seen[0].Error(), "web-01") {
		t.Errorf("the surfaced error does not name the host: %v", seen[0])
	}
}

type failingReporter struct{}

func (failingReporter) Report(context.Context, probe.Sweep, probe.State) error {
	return errors.New("sink is down")
}

// Once runs exactly one sweep and reports its verdict, which is what the
// CLI's --once and any cron-shaped caller depend on.
func TestProbe_Runner_OnceRunsASingleSweep(t *testing.T) {
	r, _, m := newRunner(t, timedOut, refused)
	sw, st, err := r.Once(context.Background())
	if err != nil {
		t.Fatalf("Once: %v", err)
	}
	if !sw.Passed() || st.Sweeps != 1 || st.Health != probe.HealthGreen {
		t.Fatalf("Once produced %s / %d sweeps / %s", sw.Verdict, st.Sweeps, st.Health)
	}
	if len(m.sweeps) != 1 {
		t.Errorf("metrics observed %d sweeps, want 1", len(m.sweeps))
	}
}

// The whole point of a probe is that it is wired to something. A runner with
// no metrics must not panic, and a runner with metrics must emit every
// series the package documents.
func TestProbe_Runner_EmitsEverySeriesItDocuments(t *testing.T) {
	r, _, m := newRunner(t, timedOut, refused)
	if _, _, err := r.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(m.sweeps) != 1 || len(m.health) != 1 || len(m.streaks) != 1 || len(m.lastPass) != 1 {
		t.Fatalf("emitted sweeps=%d health=%d streaks=%d lastPass=%d, want 1 of each",
			len(m.sweeps), len(m.health), len(m.streaks), len(m.lastPass))
	}
	if m.lastPass[0].IsZero() {
		t.Error("SetLastPass got the zero time after a passing sweep")
	}

	r.Metrics = nil
	if _, _, err := r.Once(context.Background()); err != nil {
		t.Fatalf("a runner with no metrics wired: %v", err)
	}
}

// Design section 8: cached status must never render as plain green. The
// rule is enforced on the rendering itself, because that is where a reader
// forms the belief.
func TestProbe_State_NeverRendersHealthWithoutTheAgeOfTheEvidence(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	never := probe.State{Host: "web-01", Health: probe.HealthUnknown}
	line := never.Line(now)
	if !strings.Contains(line, "never proven reachable") {
		t.Errorf("a host that has never passed renders as %q", line)
	}
	if _, ok := never.Age(now); ok {
		t.Error("Age reported a value for a host that has never passed")
	}

	stale := probe.State{
		Host: "web-01", Health: probe.HealthGreen, Sweeps: 100,
		LastPass: now.Add(-4 * time.Hour),
	}
	line = stale.Line(now)
	if !strings.Contains(line, "4h0m0s ago") {
		t.Errorf("a four-hour-old green renders without its age: %q", line)
	}
	age, ok := stale.Age(now)
	if !ok || age != 4*time.Hour {
		t.Errorf("Age = %s (%v), want 4h", age, ok)
	}
}

// A misconfigured probe fails at startup rather than reporting a red host
// forever, and Run refuses before it sends anything.
func TestProbe_Runner_RefusesToStartWithoutAProber(t *testing.T) {
	r := &probe.Runner{}
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("Run started with no prober")
	}
	if _, _, err := r.Once(context.Background()); err == nil {
		t.Fatal("Once started with no prober")
	}
}
