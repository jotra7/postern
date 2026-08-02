// Package knockport derives the SPA UDP destination port from a per-host
// secret and a rotating time window, so the port is a value only the host and
// its operators can compute. It is the one implementation the client, the
// agent, and any future monitor share: two copies of this formula are two ways
// for the sides to silently disagree about where the knock lands.
package knockport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"time"
)

const (
	// DefaultWindow is the rotation period. A longer window does not weaken
	// unpredictability (each window's port is still an unguessable keyed-PRF
	// output); it only widens clock-skew tolerance and cuts rebind churn.
	DefaultWindow = 10 * time.Minute
	// DefaultRangeLo and DefaultRangeHi bound the candidate band. The default
	// sits below the kernel ephemeral range (32768-60999) so the agent's fixed
	// binds never collide with a source port the kernel hands an outbound socket.
	DefaultRangeLo uint16 = 20000
	DefaultRangeHi uint16 = 30000
	// SecretSize is the length of K in bytes.
	SecretSize = 32
)

// Port is the keyed pseudorandom function of the window:
//
//	port(w) = lo + ( HMAC_SHA256(K, be64(w))[0:4] as be32 ) mod (hi - lo + 1)
//
// HMAC-SHA256 is a PRF, so observing outputs reveals nothing about K and one
// window's output says nothing about another's. The result is always in the
// inclusive band [lo, hi]; a caller must pass lo <= hi (config validation
// guarantees it).
func Port(secret []byte, window uint64, lo, hi uint16) uint16 {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], window)
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	span := uint32(hi) - uint32(lo) + 1
	n := binary.BigEndian.Uint32(sum[0:4]) % span
	return lo + uint16(n)
}

// Window is the window index for a wall-clock time: floor(unixSeconds / W).
func Window(unixSeconds int64, period time.Duration) uint64 {
	secs := int64(period / time.Second)
	if secs <= 0 {
		secs = 1
	}
	return uint64(unixSeconds / secs)
}

// LiveSet is the ports simultaneously live at window w: the current window plus
// its two neighbors, { port(w-1), port(w), port(w+1) }, deduplicated on
// collision and returned sorted. On window 0 the w-1 neighbor is omitted rather
// than wrapping uint64.
func LiveSet(secret []byte, window uint64, lo, hi uint16) []uint16 {
	seen := map[uint16]bool{}
	add := func(w uint64) {
		seen[Port(secret, w, lo, hi)] = true
	}
	if window > 0 {
		add(window - 1)
	}
	add(window)
	add(window + 1)
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
