package probe_test

import (
	"testing"
	"time"

	"github.com/jotra7/postern/internal/probe"
)

// The cadence claim in the design and in the package doc is a countable
// property, so it is counted here. A doc comment asserting a number has been
// wrong four times in this repository.
//
// Mutation verified: DefaultInterval = 120s passes every other test in the
// package and fails this one.
func TestProbe_DefaultInterval_IsNotAMultipleOfTheHeartbeat(t *testing.T) {
	if probe.DefaultInterval != 137*time.Second {
		t.Errorf("DefaultInterval = %s, want 137s (design section 8)", probe.DefaultInterval)
	}
	if probe.HeartbeatInterval != 60*time.Second {
		t.Errorf("HeartbeatInterval = %s, want 60s", probe.HeartbeatInterval)
	}
	if probe.DefaultInterval%probe.HeartbeatInterval == 0 {
		t.Errorf("DefaultInterval %s is a multiple of the %s heartbeat, so the two phase-lock and "+
			"sample the same moment of the agent's cycle forever", probe.DefaultInterval, probe.HeartbeatInterval)
	}
	// Sharing any factor is enough to phase-lock on a coarser cycle, so the
	// stronger property is the one asserted: the two periods are coprime.
	if g := gcd(int64(probe.DefaultInterval/time.Second), int64(probe.HeartbeatInterval/time.Second)); g != 1 {
		t.Errorf("the sweep and heartbeat periods share a factor of %d, so their relative phase repeats "+
			"every %ds rather than drifting through the whole cycle", g, int64(probe.HeartbeatInterval/time.Second)/g)
	}
}

func gcd(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// "Three consecutive failures — roughly seven minutes of confirmed
// unreachability" is the design's own arithmetic, and it is only true for
// some pairings of threshold and interval. Asserted rather than trusted.
func TestProbe_DefaultThreshold_IsRoughlySevenMinutesOfFailure(t *testing.T) {
	if probe.DefaultFailureThreshold != 3 {
		t.Errorf("DefaultFailureThreshold = %d, want 3", probe.DefaultFailureThreshold)
	}
	span := time.Duration(probe.DefaultFailureThreshold) * probe.DefaultInterval
	if span < 6*time.Minute || span > 8*time.Minute {
		t.Errorf("%d sweeps at %s is %s, which is not the 'roughly seven minutes' the design promises",
			probe.DefaultFailureThreshold, probe.DefaultInterval, span)
	}
	// The jittered extremes have to stay in the same neighbourhood, or the
	// promise is only true on average.
	lo := time.Duration(float64(span) * (1 - probe.DefaultJitterFraction))
	hi := time.Duration(float64(span) * (1 + probe.DefaultJitterFraction))
	if lo < 5*time.Minute || hi > 9*time.Minute {
		t.Errorf("with ±%.0f%% jitter the red transition lands between %s and %s", probe.DefaultJitterFraction*100, lo, hi)
	}
}

// Jitter's whole job is to be random in production and pinned in a test, so
// the source is a parameter. The three draws below are the endpoints and the
// middle, which is what makes this able to fail: an implementation that
// ignored the source and returned base would pass an assertion on the middle
// alone.
func TestProbe_Jitter_SpansTheFractionAroundTheBase(t *testing.T) {
	const base = 100 * time.Second
	cases := []struct {
		name string
		draw float64
		want time.Duration
	}{
		{"lowest draw is the shortest interval", 0, 90 * time.Second},
		{"middle draw is the base interval", 0.5, 100 * time.Second},
		{"highest draw is the longest interval", 1, 110 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probe.Jitter(base, 0.10, func() float64 { return tc.draw })
			if got != tc.want {
				t.Errorf("Jitter(%s, 0.10, %v) = %s, want %s", base, tc.draw, got, tc.want)
			}
		})
	}
}

// A source that misbehaves must not be able to produce a zero or negative
// interval: the sweep loop would become a hot loop knocking the host as fast
// as the network allows, which against a 20/second kernel rate limit is
// indistinguishable from an attack.
func TestProbe_Jitter_NeverReturnsANonPositiveInterval(t *testing.T) {
	for _, draw := range []float64{-5, 0, 0.5, 1, 5} {
		if got := probe.Jitter(time.Second, 1, func() float64 { return draw }); got <= 0 {
			t.Errorf("Jitter with draw %v returned %s", draw, got)
		}
	}
	if got := probe.Jitter(-time.Second, 0.1, func() float64 { return 0 }); got <= 0 {
		t.Errorf("Jitter with a negative base returned %s", got)
	}
	if got := probe.Jitter(0, 0.1, nil); got != probe.DefaultInterval {
		t.Errorf("Jitter with no source returned %s, want the base %s", got, probe.DefaultInterval)
	}
}

// The production source has to actually vary and has to stay in range.
// Bounded by construction: 512 draws of an arithmetic function, no I/O.
func TestProbe_CryptoRandFloat_IsInRangeAndVaries(t *testing.T) {
	first := probe.CryptoRandFloat()
	varied := false
	for i := 0; i < 512; i++ {
		v := probe.CryptoRandFloat()
		if v < 0 || v >= 1 {
			t.Fatalf("CryptoRandFloat returned %v, want [0,1)", v)
		}
		if v != first {
			varied = true
		}
	}
	if !varied {
		t.Error("512 draws were all identical, so the schedule would be fixed on every host")
	}
}
