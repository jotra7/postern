package probe

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// HeartbeatInterval is the agent's self-attestation period (design section
// 8). It is spelled here only so DefaultInterval's relationship to it can be
// asserted by a test rather than asserted by a comment.
const HeartbeatInterval = 60 * time.Second

// DefaultInterval is the sweep period: 137 seconds.
//
// The value is prime and deliberately not a multiple of HeartbeatInterval.
// Two schedules whose periods share a factor phase-lock, and a probe that
// phase-locks with the heartbeat samples the same moment of the agent's
// cycle forever — so a fault that only exists in the other part of the cycle
// is invisible to both, permanently, rather than being caught on the next
// sweep.
const DefaultInterval = 137 * time.Second

// DefaultJitterFraction spreads each interval by ±10%. The offset alone is
// not enough: two fixed periods still produce a fixed relative phase that
// only drifts, and a fleet of probes started by the same deploy would
// otherwise knock every host in lockstep.
const DefaultJitterFraction = 0.10

// DefaultFailureThreshold is how many consecutive failing sweeps turn a host
// red — roughly seven minutes of confirmed unreachability at the default
// interval. One failed sweep is a packet loss story; three in a row is not.
const DefaultFailureThreshold = 3

// RandFloat returns a value in [0,1). It is an injection point rather than a
// call to a package-level generator so a test can pin the schedule: a
// jittered interval is otherwise untestable except by assertions loose
// enough to pass on a broken implementation.
type RandFloat func() float64

// CryptoRandFloat is the production source.
//
// crypto/rand rather than math/rand: not because the jitter is a security
// parameter, but because it removes the seeding question entirely. A
// math/rand generator left unseeded — or seeded from a clock that several
// probe hosts booted from the same image share — produces the identical
// schedule on every host, which is the one thing jitter exists to prevent.
func CryptoRandFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read does not fail on any platform postern builds for;
		// if it somehow did, an unjittered interval is a far better outcome
		// than a probe that stops sweeping.
		return 0.5
	}
	// 53 bits is float64's mantissa, so every value below is exactly
	// representable and the distribution stays uniform.
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(uint64(1)<<53)
}

// Jitter spreads base by ±fraction using one draw from r.
//
// The result is clamped to at least one nanosecond. A zero or negative
// interval would turn the sweep loop into a hot loop knocking the host as
// fast as the network allows, which on a service with a 20/second kernel
// rate limit is indistinguishable from an attack.
func Jitter(base time.Duration, fraction float64, r RandFloat) time.Duration {
	if base <= 0 {
		base = DefaultInterval
	}
	if r == nil || fraction <= 0 {
		return base
	}
	if fraction > 1 {
		fraction = 1
	}
	u := r()
	switch {
	case u < 0:
		u = 0
	case u > 1:
		u = 1
	}
	d := time.Duration(float64(base) * (1 + fraction*(2*u-1)))
	if d < 1 {
		d = 1
	}
	return d
}
