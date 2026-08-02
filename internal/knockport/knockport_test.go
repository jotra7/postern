package knockport_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/knockport"
)

// key32 is a fixed 32-byte secret so the vectors below are reproducible.
func key32(t *testing.T) []byte {
	t.Helper()
	k, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKnockport_Port_MatchesKnownAnswerVectors(t *testing.T) {
	k := key32(t)
	// Vectors are HMAC_SHA256(k, be64(window))[0:4] as be32 mod (hi-lo+1) + lo,
	// with lo=20000 hi=30000 (span 10001). Regenerate with a spare tool if the
	// derivation ever legitimately changes; a change here is a wire break.
	for _, tc := range []struct {
		window uint64
		want   uint16
	}{
		{0, 22698},
		{1, 29436},
		{4_000_000, 27003},
	} {
		got := knockport.Port(k, tc.window, 20000, 30000)
		if got != tc.want {
			t.Errorf("Port(window=%d) = %d, want %d", tc.window, got, tc.want)
		}
	}
}

func TestKnockport_Port_StaysInRangeInclusive(t *testing.T) {
	k := key32(t)
	const lo, hi = 20000, 30000
	for w := uint64(0); w < 100000; w++ {
		p := knockport.Port(k, w, lo, hi)
		if p < lo || p > hi {
			t.Fatalf("Port(window=%d) = %d, outside [%d,%d]", w, p, lo, hi)
		}
	}
}

func TestKnockport_Port_SingletonRangeAlwaysReturnsLo(t *testing.T) {
	k := key32(t)
	for w := uint64(0); w < 8; w++ {
		if p := knockport.Port(k, w, 40000, 40000); p != 40000 {
			t.Fatalf("Port on a one-port range = %d, want 40000", p)
		}
	}
}

func TestKnockport_Port_DifferentSecretsAreUncorrelated(t *testing.T) {
	a := key32(t)
	b := make([]byte, 32)
	copy(b, a)
	b[0] ^= 0xff
	same := 0
	const n = 4096
	for w := uint64(0); w < n; w++ {
		if knockport.Port(a, w, 20000, 30000) == knockport.Port(b, w, 20000, 30000) {
			same++
		}
	}
	// Two independent PRFs collide at about 1/span. Anything near a constant
	// offset or a shared subsequence would blow past a loose multiple of that.
	if same > n/1000+16 {
		t.Fatalf("two secrets agreed on %d/%d windows; the sequences are not independent", same, n)
	}
}

func TestKnockport_Window_FloorsBySeconds(t *testing.T) {
	if w := knockport.Window(600, 10*time.Minute); w != 1 {
		t.Fatalf("Window(600s, 10m) = %d, want 1", w)
	}
	if w := knockport.Window(1199, 10*time.Minute); w != 1 {
		t.Fatalf("Window(1199s, 10m) = %d, want 1", w)
	}
	if w := knockport.Window(1200, 10*time.Minute); w != 2 {
		t.Fatalf("Window(1200s, 10m) = %d, want 2", w)
	}
}

func TestKnockport_LiveSet_IsThreeNeighborsDeduped(t *testing.T) {
	k := key32(t)
	got := knockport.LiveSet(k, 5, 20000, 30000)
	want := map[uint16]bool{
		knockport.Port(k, 4, 20000, 30000): true,
		knockport.Port(k, 5, 20000, 30000): true,
		knockport.Port(k, 6, 20000, 30000): true,
	}
	if len(got) != len(want) {
		t.Fatalf("LiveSet has %d ports, want %d (%v)", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("LiveSet returned unexpected port %d (%v)", p, got)
		}
	}
	// Sorted, so two calls and two renderers never disagree on order.
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("LiveSet is not sorted: %v", got)
		}
	}
}

func TestKnockport_LiveSet_RotatesByOneAcrossABoundary(t *testing.T) {
	k := key32(t)
	// port(w) is live in windows w-1, w, w+1, so advancing one window keeps the
	// two shared neighbors and swaps exactly one endpoint.
	a := knockport.LiveSet(k, 100, 20000, 30000)
	b := knockport.LiveSet(k, 101, 20000, 30000)
	shared := 0
	set := map[uint16]bool{}
	for _, p := range a {
		set[p] = true
	}
	for _, p := range b {
		if set[p] {
			shared++
		}
	}
	if shared < 2 {
		t.Fatalf("adjacent windows shared %d ports, want at least 2: %v vs %v", shared, a, b)
	}
}

func TestKnockport_LiveSet_WindowZeroDoesNotUnderflow(t *testing.T) {
	k := key32(t)
	// w-1 on window 0 must not wrap to 2^64-1. In practice unix time never puts
	// us at window 0, but a function that panics or wraps on it is a landmine.
	got := knockport.LiveSet(k, 0, 20000, 30000)
	if len(got) == 0 || len(got) > 3 {
		t.Fatalf("LiveSet(0) = %v, want the current window plus w+1 (w-1 omitted)", got)
	}
}
