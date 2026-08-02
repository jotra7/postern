package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/replay"
)

// ErrStore marks an error that reached the caller from the replay store
// rather than from the packet. Without it, StoreUnusable — whose contract is
// "anything that is not ErrDuplicate or ErrCapacity is fatal" — cannot be
// applied to a Validate error at all: every ordinary rejection (a wrong
// length, a bad signature, an unknown service) is also "not ErrDuplicate or
// ErrCapacity", so an unauthenticated attacker could incapacitate the agent
// with one malformed datagram. Validate wraps the store's error with this
// sentinel so a caller can ask "did this come from the store?" before asking
// "is the store unusable?".
var ErrStore = errors.New("agent: replay store")

// StoreUnusable reports whether an error returned from replay.Store.Reserve
// or replay.Store.HighWater means the store itself is no longer trustworthy,
// as opposed to an ordinary per-packet rejection. ErrDuplicate and
// ErrCapacity are expected outcomes of a healthy store doing its job; any
// other non-nil error — a write failure, a sync failure, a corrupted file —
// means the agent can no longer durably reason about replay, and design
// section 5 requires it declare itself incapable rather than keep accepting
// on faith.
func StoreUnusable(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, replay.ErrDuplicate) && !errors.Is(err, replay.ErrCapacity)
}

// Incapacitate runs the shutdown sequence design section 5 requires the
// moment the replay store is declared unusable: the SPA port goes silent
// immediately (agent_up removed, rather than left to lapse at its next
// refresh), then every fail-closed gate set is emptied while its drop rules
// are left standing and postern_open is torn down. Both of those last two
// are g.Close's contract (see internal/gate.Gate).
//
// Incapacitate does not stop the agent from accepting further packets or
// exit the process — those are the caller's job (the daemon built in
// Task 3), which must stop its receive loop and exit after this returns, so
// that systemd runs the established failure path rather than a second,
// invented one. Incapacitate attempts every step even if an earlier one
// fails, and returns every error it saw joined together, so a caller
// logging this on the way out sees the whole picture rather than only the
// first failure.
func Incapacitate(ctx context.Context, g gate.Gate) error {
	var errs []error
	if err := g.SilenceAgentUp(ctx); err != nil {
		errs = append(errs, fmt.Errorf("silence agent_up: %w", err))
	}
	if err := g.Close(ctx); err != nil {
		errs = append(errs, fmt.Errorf("close gate: %w", err))
	}
	return errors.Join(errs...)
}
