package probe

import (
	"context"
	"fmt"
	"time"
)

// Health is what the probe says about a host.
type Health string

const (
	// HealthUnknown: no sweep has completed. Never rendered as green, and
	// distinct from red — nothing has been measured, which is not the same
	// as something having been measured and found broken.
	HealthUnknown Health = "unknown"
	// HealthGreen: the last sweep supplied both halves of the proof.
	HealthGreen Health = "green"
	// HealthAmber: at least one sweep has failed but the streak has not
	// reached the threshold. A single failed sweep is a packet loss story,
	// so it is worth showing and not worth paging on.
	HealthAmber Health = "amber"
	// HealthRed: the streak reached the threshold. Design section 8: this is
	// the state that alerts.
	HealthRed Health = "red"
)

// State is the probe's running verdict on one host.
type State struct {
	Host   string
	Health Health
	// ConsecutiveFailures is the current streak. Reset by any pass.
	ConsecutiveFailures int
	// Sweeps counts every completed sweep, and doubles as the monotonic
	// sequence a report carries (design section 8). Epoch handling belongs
	// with the hub, which M1 does not have.
	Sweeps   int
	Passes   int
	Failures int
	// LastSweep is when the most recent sweep finished; LastPass when the
	// most recent passing one did. The zero time means never.
	LastSweep time.Time
	LastPass  time.Time
	// LastReason is the most recent failure's reason, kept after the streak
	// resets so a flapping host still shows what it was flapping on.
	LastReason Reason
}

// Age is how long it has been since this host last supplied the proof. It
// returns false when it never has, because "never" and "0s ago" must not
// render the same way.
func (s State) Age(now time.Time) (time.Duration, bool) {
	if s.LastPass.IsZero() {
		return 0, false
	}
	return now.Sub(s.LastPass), true
}

// Line renders the state for a human, and never renders a health word
// without the age of the evidence behind it.
//
// Design section 8: "cached status must never render as plain green" — the
// client shows "last known healthy 4h ago", never "healthy (cached)". The
// same rule applies here for the same reason, and it applies to a live green
// too: a reader who has to hunt for the timestamp will assume a green word
// is current, and the whole failure mode this tool exists for is a proof
// that quietly stopped being renewed.
func (s State) Line(now time.Time) string {
	age, ok := s.Age(now)
	when := "never proven reachable"
	if ok {
		when = fmt.Sprintf("last proven reachable %s ago", age.Round(time.Second))
	}
	return fmt.Sprintf("%s: %s — %s (%d sweeps, %d consecutive failures)",
		s.Host, s.Health, when, s.Sweeps, s.ConsecutiveFailures)
}

// Reporter ships one sweep somewhere. Webhook is the implementation M1
// ships; the hub aggregates from M2.
type Reporter interface {
	Report(ctx context.Context, sw Sweep, st State) error
}

// Runner drives sweeps on a jittered cadence and keeps the streak.
//
// Every timing bound and every source of nondeterminism is a field. A loop
// with a real timer and a real random source in it cannot be tested without
// waiting, and a test that waits is a test whose failure under mutation is a
// hang rather than a FAIL — which in a batch run is invisible.
type Runner struct {
	Prober *Prober

	// Interval and JitterFraction default to DefaultInterval and
	// DefaultJitterFraction.
	Interval       time.Duration
	JitterFraction float64
	// Rand defaults to CryptoRandFloat.
	Rand RandFloat
	// FailureThreshold defaults to DefaultFailureThreshold.
	FailureThreshold int

	// Sleep and Now default to SleepContext and time.Now.
	Sleep func(ctx context.Context, d time.Duration) error
	Now   func() time.Time

	// Metrics defaults to NopMetrics.
	Metrics Metrics
	// Reporter is optional. A reporter that fails does not stop the loop:
	// losing the ability to report a red host is bad, and losing the ability
	// to detect one is worse.
	Reporter Reporter
	// Observe is called with every sweep before it is reported, for a caller
	// that wants to print. Optional.
	Observe func(sw Sweep, st State)
	// OnError receives reporter failures, which are otherwise swallowed.
	// Optional.
	OnError func(error)
}

func (r *Runner) threshold() int { return orInt(r.FailureThreshold, DefaultFailureThreshold) }

func (r *Runner) interval() time.Duration { return orDuration(r.Interval, DefaultInterval) }

func (r *Runner) jitterFraction() float64 {
	if r.JitterFraction < 0 {
		return 0
	}
	if r.JitterFraction == 0 {
		return DefaultJitterFraction
	}
	return r.JitterFraction
}

func (r *Runner) now() time.Time {
	if r.Now == nil {
		return time.Now()
	}
	return r.Now()
}

// MinInterval is the shortest wait the schedule can produce.
func (r *Runner) MinInterval() time.Duration {
	f := r.jitterFraction()
	if f > 1 {
		f = 1
	}
	return time.Duration(float64(r.interval()) * (1 - f))
}

// Validate checks the whole configuration before the first packet moves.
func (r *Runner) Validate() error {
	if r == nil || r.Prober == nil {
		return fmt.Errorf("probe: no prober")
	}
	if err := r.Prober.Validate(); err != nil {
		return err
	}
	if r.threshold() < 1 {
		return fmt.Errorf("probe: failure threshold must be at least 1")
	}
	// The sweep opens a real gate with a real lease. If the next sweep's
	// phase 1 can run while that lease is still live, phase 1 finds the port
	// answering and the probe reports a permanently red host whose gate is
	// working perfectly — the probe poisoning its own evidence. Caught here,
	// where it is a startup error naming both numbers, rather than at 3am.
	if ttl := r.Prober.CanaryTTL(); ttl > 0 && r.MinInterval() <= ttl {
		return fmt.Errorf("probe: the shortest sweep interval (%s, from %s with %.0f%% jitter) is not longer "+
			"than the %s gate the sweep itself opens, so the next sweep's closed-gate phase would find the "+
			"previous sweep's lease still live and fail — raise the interval or lower the canary ttl",
			r.MinInterval(), r.interval(), r.jitterFraction()*100, ttl)
	}
	return nil
}

// Once performs a single sweep against a fresh state and returns both.
func (r *Runner) Once(ctx context.Context) (Sweep, State, error) {
	if err := r.Validate(); err != nil {
		return Sweep{}, State{}, err
	}
	st := State{Host: r.Prober.Host.Name, Health: HealthUnknown}
	sw := r.Prober.Sweep(ctx)
	st = r.apply(st, sw)
	r.emit(ctx, sw, st)
	return sw, st, nil
}

// Run sweeps until ctx is done, and returns the state it ended with.
//
// The returned error is ctx's: a cancelled context is an ordinary shutdown,
// and a caller that wants to distinguish it from a startup failure checks
// errors.Is(err, context.Canceled).
func (r *Runner) Run(ctx context.Context) (State, error) {
	if err := r.Validate(); err != nil {
		return State{}, err
	}
	sleep := r.Sleep
	if sleep == nil {
		sleep = SleepContext
	}
	st := State{Host: r.Prober.Host.Name, Health: HealthUnknown}
	for {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		sw := r.Prober.Sweep(ctx)
		st = r.apply(st, sw)
		r.emit(ctx, sw, st)
		if err := sleep(ctx, Jitter(r.interval(), r.jitterFraction(), r.randSource())); err != nil {
			return st, err
		}
	}
}

func (r *Runner) randSource() RandFloat {
	if r.Rand == nil {
		return CryptoRandFloat
	}
	return r.Rand
}

// apply folds one sweep into the running state.
func (r *Runner) apply(st State, sw Sweep) State {
	st.Host = sw.Host
	st.Sweeps++
	st.LastSweep = r.now()
	if sw.Passed() {
		st.Passes++
		st.ConsecutiveFailures = 0
		st.LastPass = st.LastSweep
		st.Health = HealthGreen
		return st
	}
	st.Failures++
	st.ConsecutiveFailures++
	st.LastReason = sw.Reason
	if st.ConsecutiveFailures >= r.threshold() {
		st.Health = HealthRed
	} else {
		st.Health = HealthAmber
	}
	return st
}

func (r *Runner) emit(ctx context.Context, sw Sweep, st State) {
	m := r.Metrics
	if m == nil {
		m = NopMetrics{}
	}
	m.ObserveSweep(sw)
	m.SetHealth(st.Host, st.Health)
	m.SetConsecutiveFailures(st.Host, st.ConsecutiveFailures)
	m.SetLastPass(st.Host, st.LastPass)

	if r.Observe != nil {
		r.Observe(sw, st)
	}
	if r.Reporter == nil {
		return
	}
	if err := r.Reporter.Report(ctx, sw, st); err != nil && r.OnError != nil {
		r.OnError(fmt.Errorf("probe: report sweep for %s: %w", st.Host, err))
	}
}
