package hub

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/attest"
)

// ErrStale means a beat's (epoch, sequence) is not newer than the last one
// recorded for its host_id: a lower epoch, or the same epoch with a sequence
// that is not strictly greater.
var ErrStale = errors.New("hub: beat is not newer than the last recorded one")

// beatRecord is one host's latest accepted beat, plus the hub's own receipt
// time for it.
type beatRecord struct {
	beat attest.Beat
	// at is when this hub accepted the beat, by its own clock — not
	// beat.SentAt. See Latest.
	at time.Time
}

// Beats holds the latest accepted heartbeat per host, in memory only. See
// doc.go for why nothing here is written to disk.
type Beats struct {
	mu     sync.Mutex
	latest map[[16]byte]beatRecord
}

// NewBeats returns an empty Beats.
func NewBeats() *Beats {
	return &Beats{latest: make(map[[16]byte]beatRecord)}
}

// Accept records beat if it is newer than the last one recorded for
// beat.HostID: a strictly higher epoch is accepted with any sequence, and
// within the same epoch the sequence must be strictly greater. A host with
// no prior record is always accepted.
//
// now is the hub's own clock, supplied by the caller rather than read here,
// so a test can drive it and so this method performs no I/O of its own.
//
// This must only ever be called with a beat that has already passed
// attest.Verify — see doc.go's "signature before sequence" section. Accept
// itself has no way to check that; it trusts every field of beat because
// checking is the caller's job, done exactly once, before this is reached.
func (b *Beats) Accept(beat *attest.Beat, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	prev, ok := b.latest[beat.HostID]
	if ok {
		switch {
		case beat.Epoch < prev.beat.Epoch:
			return fmt.Errorf("%w: epoch %d, last recorded epoch %d", ErrStale, beat.Epoch, prev.beat.Epoch)
		case beat.Epoch == prev.beat.Epoch && beat.Sequence <= prev.beat.Sequence:
			return fmt.Errorf("%w: epoch %d sequence %d, last recorded sequence %d",
				ErrStale, beat.Epoch, beat.Sequence, prev.beat.Sequence)
		}
		// A strictly higher epoch reaches here regardless of beat.Sequence —
		// that "any sequence" is the entire reason epoch exists (a
		// reinstalled or restored host's own sequence counter goes
		// backward, and a bare monotonic sequence can never recover from
		// that on its own).
	}
	b.latest[beat.HostID] = beatRecord{beat: *beat, at: now}
	return nil
}

// Latest returns the most recently accepted beat for hostID, the hub's own
// receipt time for it, and whether one exists at all.
//
// The returned time is when this hub accepted the beat — not the beat's own
// SentAt field. SentAt is the reporting host's clock, which is exactly what
// design section 5's freshness window exists to distrust; using it here
// would let a host with a fast or attacker-influenced clock report itself
// fresher than this hub actually observed. A caller checking staleness
// (age := now.Sub(at) against BeatMaxAge) is checking this hub's own
// timeline, which is the one thing it can vouch for.
func (b *Beats) Latest(hostID [16]byte) (*attest.Beat, time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rec, ok := b.latest[hostID]
	if !ok {
		return nil, time.Time{}, false
	}
	beat := rec.beat
	return &beat, rec.at, true
}

// Observation is one host's most recently accepted beat together with this
// hub's own receipt time for it.
type Observation struct {
	Beat attest.Beat
	// At is when this hub accepted Beat, by its own clock. See Latest for
	// why freshness is measured from this rather than from Beat.SentAt.
	At time.Time
}

// Snapshot returns every host with an accepted beat: the same two values
// Latest gives for one host, for all of them at once.
//
// The map and the beats in it are copies taken under the lock, so a caller
// can range over the result without holding anything and without it changing
// underneath. A fleet's worth of records is small, and the alternative, a
// callback invoked with the lock held, would run a caller's own code inside
// this type's critical section, on the same process that has to keep
// accepting beats while an operator reads.
func (b *Beats) Snapshot() map[[16]byte]Observation {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make(map[[16]byte]Observation, len(b.latest))
	for id, rec := range b.latest {
		out[id] = Observation{Beat: rec.beat, At: rec.at}
	}
	return out
}

// Count returns the number of distinct hosts with at least one accepted
// beat. It exists for metrics.go: fleet size is exactly the kind of thing
// design section 6 says a compromised hub can leak, which is why this
// number is published only on the private metrics listener and never the
// public one.
func (b *Beats) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.latest)
}
