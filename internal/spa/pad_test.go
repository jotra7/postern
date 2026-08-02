package spa_test

import (
	"testing"

	"github.com/jotra7/postern/internal/spa"
)

func TestSPA_Pad_KeepsRecordPrefixIntact(t *testing.T) {
	// Whatever length Pad draws, the first CORE bytes must be the record
	// verbatim: the receiver slices exactly that prefix off and verifies it.
	record := make([]byte, spa.DatagramSize)
	for i := range record {
		record[i] = byte(i)
	}
	for i := 0; i < 200; i++ {
		out, err := spa.Pad(record)
		if err != nil {
			t.Fatalf("Pad: %v", err)
		}
		if len(out) < len(record) || len(out) > spa.MaxDatagram {
			t.Fatalf("Pad produced %d bytes, want in [%d, %d]", len(out), len(record), spa.MaxDatagram)
		}
		for j := range record {
			if out[j] != record[j] {
				t.Fatalf("Pad corrupted the record at byte %d", j)
			}
		}
	}
}

func TestSPA_Pad_LengthsVaryAndSpanTheRange(t *testing.T) {
	// A statistical test over many crypto/rand draws: lengths must vary, stay
	// within [CORE, MaxDatagram], and both endpoints must be reachable (CORE
	// with no padding, and a length near MaxDatagram).
	const draws = 20_000
	record := make([]byte, spa.PongSize) // the smaller CORE, so the range is widest
	seen := make(map[int]int)
	minLen, maxLen := spa.MaxDatagram+1, -1
	for i := 0; i < draws; i++ {
		out, err := spa.Pad(record)
		if err != nil {
			t.Fatalf("Pad: %v", err)
		}
		n := len(out)
		if n < spa.PongSize || n > spa.MaxDatagram {
			t.Fatalf("Pad produced %d bytes, outside [%d, %d]", n, spa.PongSize, spa.MaxDatagram)
		}
		seen[n]++
		if n < minLen {
			minLen = n
		}
		if n > maxLen {
			maxLen = n
		}
	}
	if len(seen) < 100 {
		t.Errorf("Pad produced only %d distinct lengths over %d draws; expected wide variation", len(seen), draws)
	}
	if seen[spa.PongSize] == 0 {
		t.Errorf("Pad never produced the unpadded length %d over %d draws", spa.PongSize, draws)
	}
	// The nested draw makes the top of the range rare, so assert the observed
	// maximum climbed well past the midpoint rather than demanding exactly
	// MaxDatagram.
	if maxLen < spa.MaxDatagram-spa.MaxDatagram/4 {
		t.Errorf("Pad's largest draw was %d over %d draws; expected it to approach MaxDatagram %d", maxLen, draws, spa.MaxDatagram)
	}
	if minLen != spa.PongSize {
		t.Errorf("Pad's smallest draw was %d, want the unpadded length %d", minLen, spa.PongSize)
	}
}

func TestSPA_Pad_NeverExceedsMaxDatagram(t *testing.T) {
	// The tightest input: a record already at MaxDatagram can only pad to
	// itself, and nothing may push it over.
	record := make([]byte, spa.MaxDatagram)
	for i := 0; i < 1000; i++ {
		out, err := spa.Pad(record)
		if err != nil {
			t.Fatalf("Pad: %v", err)
		}
		if len(out) != spa.MaxDatagram {
			t.Fatalf("Pad(MaxDatagram record) = %d bytes, want exactly %d", len(out), spa.MaxDatagram)
		}
	}
}

func TestSPA_Pad_RejectsOversizeRecord(t *testing.T) {
	if _, err := spa.Pad(make([]byte, spa.MaxDatagram+1)); err == nil {
		t.Fatal("Pad accepted a record larger than MaxDatagram")
	}
}
