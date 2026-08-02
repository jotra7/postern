package hub

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/attest"
)

var testHostID = [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

// beat builds an *attest.Beat for testHostID, with epoch and sequence set by
// the given options. It never touches attest.Encode/Verify — Beats trusts
// whatever it is handed, which is the point: the signature check is a
// server.go concern, exercised in server_test.go, and these tests are only
// about the epoch/sequence ordering.
func beat(opts ...func(*attest.Beat)) *attest.Beat {
	b := &attest.Beat{HostID: testHostID, SentAt: time.Now()}
	for _, o := range opts {
		o(b)
	}
	return b
}

func epoch(e uint64) func(*attest.Beat) { return func(b *attest.Beat) { b.Epoch = e } }
func seq(s uint64) func(*attest.Beat)   { return func(b *attest.Beat) { b.Sequence = s } }
func forHost(id [16]byte) func(*attest.Beat) {
	return func(b *attest.Beat) { b.HostID = id }
}

func mustAccept(t *testing.T, b *Beats, beat *attest.Beat) {
	t.Helper()
	if err := b.Accept(beat, time.Now()); err != nil {
		t.Fatalf("Accept(epoch=%d, sequence=%d): %v", beat.Epoch, beat.Sequence, err)
	}
}

// Section 8: within an epoch the hub requires strictly increasing sequence,
// or a captured healthy beat replayed forever holds a dead host green.
func TestHub_Beats_RejectsAReplayedSequence(t *testing.T) {
	b := NewBeats()
	mustAccept(t, b, beat(epoch(1), seq(5)))

	if err := b.Accept(beat(epoch(1), seq(5)), time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("replayed sequence: err = %v, want ErrStale", err)
	}
	if err := b.Accept(beat(epoch(1), seq(4)), time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("backwards sequence: err = %v, want ErrStale", err)
	}
}

// And the recovery case that a bare monotonic sequence cannot survive: a
// host reinstalled, restored from a snapshot, or cloned comes back with a
// lower sequence and would be rejected forever. A higher epoch is accepted
// with any sequence, which is the whole reason epoch exists.
func TestHub_Beats_AcceptsAHigherEpochWithALowerSequence(t *testing.T) {
	b := NewBeats()
	mustAccept(t, b, beat(epoch(1), seq(9000)))

	if err := b.Accept(beat(epoch(2), seq(1)), time.Now()); err != nil {
		t.Fatalf("a reinstalled host cannot report: %v", err)
	}
}

// A lower epoch is rejected regardless of sequence — including a sequence
// that would otherwise look like clean forward progress within the old
// epoch. Epoch only ever moves forward.
func TestHub_Beats_RejectsALowerEpoch(t *testing.T) {
	b := NewBeats()
	mustAccept(t, b, beat(epoch(5), seq(1)))

	if err := b.Accept(beat(epoch(4), seq(9999)), time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
}

// Equal epoch and equal sequence is not an increase either — the boundary
// case the ordering check above the "<=" cutoff, not the "<" one.
func TestHub_Beats_RejectsAnEqualSequenceAtTheSameEpoch(t *testing.T) {
	b := NewBeats()
	mustAccept(t, b, beat(epoch(1), seq(7)))

	if err := b.Accept(beat(epoch(1), seq(7)), time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
}

// A host with no prior record at all is always accepted, whatever epoch or
// sequence it first reports at.
func TestHub_Beats_AcceptsTheFirstBeatFromAHostUnconditionally(t *testing.T) {
	b := NewBeats()
	if err := b.Accept(beat(epoch(0), seq(0)), time.Now()); err != nil {
		t.Fatalf("first beat ever, epoch 0 sequence 0: %v", err)
	}
}

// Two different hosts' sequence counters are independent: one host's replay
// must not affect another's standing.
func TestHub_Beats_TracksEachHostIndependently(t *testing.T) {
	hostB := [16]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0}
	b := NewBeats()
	mustAccept(t, b, beat(forHost(testHostID), epoch(1), seq(100)))

	// hostB has never reported, so a low epoch/sequence must still be
	// accepted rather than being compared against testHostID's standing.
	if err := b.Accept(beat(forHost(hostB), epoch(1), seq(1)), time.Now()); err != nil {
		t.Fatalf("hostB's first beat was rejected against hostA's standing: %v", err)
	}
	// And accepting hostB's beat must not have disturbed testHostID's own
	// recorded sequence.
	if err := b.Accept(beat(forHost(testHostID), epoch(1), seq(100)), time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("testHostID's standing was affected by hostB's beat: err = %v, want ErrStale", err)
	}
}

// Absence is a signal. A host whose last beat is older than BeatMaxAge is
// not green, and the hub must not let a stale beat hold it there. Latest
// reports the hub's own receipt time for that comparison — not the beat's
// self-reported SentAt, which a host with a fast or skewed clock could use
// to make itself look fresher than this hub actually observed.
func TestHub_Beats_LatestReportsAgeSoStaleCannotReadAsHealthy(t *testing.T) {
	b := NewBeats()
	recordedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// SentAt is deliberately far from recordedAt, simulating a host whose
	// own clock disagrees with the hub's — Latest must report the hub's
	// clock, not this.
	claimed := beat(epoch(1), seq(1))
	claimed.SentAt = recordedAt.Add(24 * time.Hour)

	if err := b.Accept(claimed, recordedAt); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	got, at, ok := b.Latest(testHostID)
	if !ok {
		t.Fatal("Latest reports no beat for a host that was just accepted")
	}
	if got.Sequence != 1 {
		t.Errorf("Latest returned sequence %d, want 1", got.Sequence)
	}
	if !at.Equal(recordedAt) {
		t.Fatalf("Latest reported receipt time %v, want the hub's own clock at Accept (%v); "+
			"using beat.SentAt instead would let a host with a fast clock look fresher than it is",
			at, recordedAt)
	}

	// A caller checking staleness computes age against its own now. Nothing
	// in Beats itself decides "healthy" — it only ever reports the receipt
	// time truthfully, which is what makes staleness detectable at all.
	muchLater := recordedAt.Add(2 * time.Hour)
	if age := muchLater.Sub(at); age < 2*time.Hour {
		t.Errorf("age computed from Latest = %v, want >= 2h", age)
	}
}

// A host that has never sent a beat has no entry at all, distinct from a
// beat that merely happens to be old.
func TestHub_Beats_LatestReportsAbsentForAnUnknownHost(t *testing.T) {
	b := NewBeats()
	if _, _, ok := b.Latest(testHostID); ok {
		t.Fatal("Latest reported a beat for a host that never sent one")
	}
}

// Count is the fleet-size number metrics.go publishes only on the private
// listener. It counts distinct hosts, not total beats accepted.
func TestHub_Beats_CountsDistinctHostsNotTotalBeats(t *testing.T) {
	hostB := [16]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	b := NewBeats()
	if got := b.Count(); got != 0 {
		t.Fatalf("Count on an empty Beats = %d, want 0", got)
	}
	mustAccept(t, b, beat(forHost(testHostID), epoch(1), seq(1)))
	mustAccept(t, b, beat(forHost(testHostID), epoch(1), seq(2)))
	mustAccept(t, b, beat(forHost(hostB), epoch(1), seq(1)))

	if got := b.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 (two distinct hosts, one of them beat twice)", got)
	}
}

// The map is shared mutable state behind a mutex. Hammer Accept and Latest
// concurrently, across many hosts, and let -race find anything unguarded.
func TestHub_Beats_ConcurrentAccessIsRaceFree(t *testing.T) {
	b := NewBeats()
	const goroutines = 32
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var hostID [16]byte
			hostID[0] = byte(g) //nolint:gosec // G115: goroutines is 32, well within byte range
			for i := 1; i <= perGoroutine; i++ {
				_ = b.Accept(beat(forHost(hostID), epoch(1), seq(uint64(i))), time.Now())
				_, _, _ = b.Latest(hostID)
				_ = b.Count()
			}
		}(g)
	}
	wg.Wait()

	if got := b.Count(); got != goroutines {
		t.Fatalf("Count = %d, want %d", got, goroutines)
	}
}

// Snapshot is Latest for every host at once, and it carries the same two
// facts: the beat itself and the hub's own receipt time for it.
func TestHub_Beats_SnapshotCarriesEveryHostsLatestAndReceiptTime(t *testing.T) {
	hostB := [16]byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
	b := NewBeats()
	firstAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	secondAt := firstAt.Add(90 * time.Second)

	if err := b.Accept(beat(forHost(testHostID), epoch(2), seq(7)), firstAt); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := b.Accept(beat(forHost(testHostID), epoch(2), seq(8)), secondAt); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := b.Accept(beat(forHost(hostB), epoch(1), seq(1)), firstAt); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	snap := b.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot has %d hosts, want 2", len(snap))
	}
	got, ok := snap[testHostID]
	if !ok {
		t.Fatal("Snapshot has no entry for a host that beat twice")
	}
	if got.Beat.Epoch != 2 || got.Beat.Sequence != 8 {
		t.Errorf("Snapshot carries epoch %d sequence %d, want the latest accepted (2, 8)",
			got.Beat.Epoch, got.Beat.Sequence)
	}
	if !got.At.Equal(secondAt) {
		t.Errorf("Snapshot receipt time = %v, want the hub's clock at the latest Accept (%v)", got.At, secondAt)
	}
}

// The returned map is a copy. A caller ranging over it while the hub keeps
// accepting must not see the fleet change under it, and must not be able to
// write back into the hub's own state by assigning into what it was handed.
func TestHub_Beats_SnapshotIsACopyTakenWhenItWasCalled(t *testing.T) {
	hostB := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	b := NewBeats()
	takenAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if err := b.Accept(beat(forHost(testHostID), epoch(1), seq(1)), takenAt); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	snap := b.Snapshot()
	snap[hostB] = Observation{At: takenAt}
	delete(snap, testHostID)

	if err := b.Accept(beat(forHost(testHostID), epoch(1), seq(2)), takenAt.Add(time.Minute)); err != nil {
		t.Fatalf("Accept after Snapshot: %v", err)
	}

	again := b.Snapshot()
	if _, ok := again[hostB]; ok {
		t.Error("writing into a Snapshot added a host to the hub's own records")
	}
	rec, ok := again[testHostID]
	if !ok {
		t.Fatal("deleting from a Snapshot removed a host from the hub's own records")
	}
	if rec.Beat.Sequence != 2 {
		t.Errorf("second Snapshot sequence = %d, want 2 (the beat accepted after the first snapshot)", rec.Beat.Sequence)
	}
	// And the first snapshot's own copy is unchanged by that later Accept.
	if len(snap) != 1 {
		t.Fatalf("the first Snapshot now has %d entries, want the 1 the test left in it", len(snap))
	}
}
