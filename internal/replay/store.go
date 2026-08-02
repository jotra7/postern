// Package replay persists the state that bounds packet replay: accepted
// request identifiers and per-key counter high-water marks.
//
// Retention is a guarantee rather than a best effort. An entry is never
// evicted before its packet can no longer pass any freshness path, because a
// plain LRU under pressure can drop an entry while its packet is still inside
// the freshness window — and the timestamp path would then accept the very
// same packet a second time.
//
// Open takes an exclusive advisory lock (flock) on the store file, so a
// second Open against the same path — a systemd restart race, or a future
// dump tool run alongside a live agent — fails loudly instead of silently
// producing two independent openers that clobber each other's writes and
// each hold their own in-memory dedup map, which would let the same
// request_id be accepted twice. This makes the package Unix-only, which is
// the correct scope for an agent whose other job is managing nftables.
package replay

import "errors"

var (
	// ErrDuplicate means this request_id has already been accepted.
	ErrDuplicate = errors.New("replay: request already accepted")
	// ErrCapacity means this key's reservation budget is full of live entries.
	// Callers fail closed on the bound and report red rather than evicting.
	ErrCapacity = errors.New("replay: per-key capacity exhausted")
)

// DefaultPerKeyCapacity bounds one key's live reservations. At honest rates a
// canary sweep is roughly 630 accepts per day, so this is generous; its job is
// to stop one compromised key exhausting storage shared with operators.
const DefaultPerKeyCapacity = 4096

// Reservation is one accepted packet's durable footprint.
type Reservation struct {
	KeyID     [16]byte
	RequestID [16]byte
	// Counter is the packet's counter. Ignored for actions, which always
	// carry zero and must never move the high-water mark.
	Counter uint64
	// IsGate distinguishes gate requests from actions.
	IsGate bool
	// ExpiresAtMS is when this entry may be dropped: the latest moment its
	// packet could still pass a freshness path.
	//
	// This package trusts the value it is given; it does not compute it.
	// The correct value depends on the packet's kind and
	// config.Policy.FreshnessWindow/FreshnessWindowMax — three inputs from
	// three packages that nothing in this branch wires together yet. See
	// docs/phase-b-carry-forward.md, item 1, for the formula and the
	// concrete silent-double-acceptance failure mode if it is computed once
	// and cached rather than read live from Policy on every gate Reserve.
	ExpiresAtMS uint64
}

// Options configures a store.
type Options struct {
	// PerKeyCapacity bounds live entries per key. Zero selects the default.
	PerKeyCapacity int
	// NowMS supplies the clock. Tests inject a controllable one; the agent
	// passes a real one.
	NowMS func() uint64
}

// Store records accepted requests durably before the caller applies any
// effect. Reserve commits to disk before returning, so a crash between
// reserving and applying consumes a request without executing it — which is
// recoverable, unlike executing an action whose authorization stays replayable.
//
// Implementations are safe for concurrent use: Reserve, HighWater, and Close
// may be called from multiple goroutines simultaneously. This is a
// requirement, not an incidental property — Reserve's entire job is deciding
// whether a request_id has been seen before, and an implementation that let
// two concurrent Reserve calls both observe "unseen" before either recorded
// it would let a captured packet through twice.
type Store interface {
	// Reserve durably records a reservation, or returns ErrDuplicate or
	// ErrCapacity. On success the high-water mark for the key is raised to
	// max(existing, Counter) for gates only.
	Reserve(r Reservation) error
	// HighWater returns the largest gate counter accepted for a key.
	HighWater(keyID [16]byte) uint64
	// Close flushes and releases the store.
	Close() error
}
