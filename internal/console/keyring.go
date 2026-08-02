package console

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/identity"
)

// DefaultIdleTimeout is how long an unlocked key stays usable with nothing
// happening.
//
// Fifteen minutes is sized against what this key is for. An operator opens
// this console during an outage, knocks a host, waits for a connect, reads a
// diagnosis, knocks again — a sequence measured in minutes, where a
// five-minute window would mean typing the passphrase into a browser form
// repeatedly, which is its own exposure. It is short enough that a laptop
// left on a desk over lunch holds nothing.
const DefaultIdleTimeout = 15 * time.Minute

// Slot names one key the console may hold.
type Slot string

const (
	// SlotOperator is the everyday key from the client config: the one that
	// signs knocks, confirms and liveness pings. It is deliberately not a key
	// that can disarm — see the package doc.
	SlotOperator Slot = "operator"
	// SlotSigner is the bundle-signing key, which `postern sign` requires as
	// an explicit --key-file and never takes from the client config. It is
	// kept as its own slot for the same reason: the machine that signs
	// bundles may hold a fleet operator's key distinct from the one that
	// knocks, and conflating them would let unlocking one silently unlock the
	// other.
	SlotSigner Slot = "signer"
)

// ErrLocked means the requested slot holds no unlocked key, either because
// it was never unlocked or because its idle window expired.
var ErrLocked = errors.New("console: no key is unlocked")

// Keyring holds decrypted operator keys in process memory for a bounded idle
// window.
//
// This is the one place the console's exposure genuinely differs from the
// CLI's, and it is a deliberate trade rather than an oversight. `postern
// open` prompts for a passphrase, holds the decrypted key for the length of
// one knock, and exits. A web console cannot do that without putting the
// passphrase into a browser form on every single action, which is a worse
// exposure than the one it would be avoiding. So the key is unlocked once,
// explicitly, and held.
//
// What is held, and what bounds it:
//
//   - The decrypted key lives only as an identity.Signer in memory. Nothing
//     here writes it, the passphrase, or anything derived from either to
//     disk, and no code path passes a Signer into a template context — the
//     view models in fleet.go carry no key material at all, so a rendering
//     mistake has nothing to print.
//   - Nothing here logs. The passphrase is read from a request body, handed
//     to identity.LoadFile, and dropped; a Signer's own String is never
//     taken.
//   - Every use resets the idle window; a slot untouched for IdleTimeout is
//     dropped and must be unlocked again. Lock drops one slot now, LockAll
//     drops every slot now.
//
// What this does not defend against is the same thing the CLI does not
// defend against: anything already running as this user can read this
// process's memory. The window bounds how long that is worth doing.
type Keyring struct {
	mu    sync.Mutex
	slots map[Slot]*keySlot
	// idle is the window; zero selects DefaultIdleTimeout.
	idle time.Duration
	// now is the clock, injected so a test can expire a slot without waiting.
	now func() time.Time
}

type keySlot struct {
	signer identity.Signer
	// path is the key file it came from, kept only so the console can tell
	// the operator which file is unlocked.
	path string
	// touched is the last time this slot was unlocked or used.
	touched time.Time
}

// NewKeyring returns an empty keyring. A zero idle selects
// DefaultIdleTimeout; a nil now selects the wall clock.
func NewKeyring(idle time.Duration, now func() time.Time) *Keyring {
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	if now == nil {
		now = time.Now
	}
	return &Keyring{slots: map[Slot]*keySlot{}, idle: idle, now: now}
}

// Unlock decrypts the key at path and holds it in slot.
//
// pass is used and not retained. identity.LoadFile returns
// ErrIncorrectPassphrase for a wrong one, which the caller turns into a
// message naming the file — the same error the CLI gives, for the same
// reason.
func (k *Keyring) Unlock(slot Slot, path string, pass []byte) error {
	signer, err := identity.LoadFile(path, pass)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.slots[slot] = &keySlot{signer: signer, path: path, touched: k.now()}
	return nil
}

// Signer returns the unlocked key in slot and resets its idle window.
//
// A slot whose window has expired is dropped here rather than by a timer:
// there is no goroutine to leak, expiry is observed at exactly the moment it
// matters, and a test can drive it with a clock instead of a sleep.
func (k *Keyring) Signer(slot Slot) (identity.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.slots[slot]
	if !ok {
		return nil, fmt.Errorf("%w in the %s slot", ErrLocked, slot)
	}
	now := k.now()
	if now.Sub(s.touched) >= k.idle {
		delete(k.slots, slot)
		return nil, fmt.Errorf("%w in the %s slot: it was idle for %s and was dropped", ErrLocked, slot, k.idle)
	}
	s.touched = now
	return s.signer, nil
}

// Lock drops one slot immediately.
func (k *Keyring) Lock(slot Slot) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.slots, slot)
}

// LockAll drops every slot immediately. It is what the console calls on
// shutdown and what the page's "lock" button reaches.
func (k *Keyring) LockAll() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.slots = map[Slot]*keySlot{}
}

// SlotState is what a page may say about a slot. It carries no key material
// by construction: a name, a path, and a deadline.
type SlotState struct {
	Slot     Slot
	Unlocked bool
	// Operator is the name on the identity, which is public material and is
	// already printed by `postern operator init`.
	Operator string
	// KeyFile is the path the key came from.
	KeyFile string
	// ExpiresIn is how long the slot has left if nothing touches it.
	ExpiresIn time.Duration
}

// State reports every slot's condition. It does not RESET an idle window, so
// rendering a page cannot keep a key alive, but it does DROP a slot whose
// window has already elapsed, so rendering a page cannot report a key locked
// while the process still holds it decrypted. Those are the same one
// definition of expired Signer uses, applied wherever the state is observed,
// rather than a second copy that only reports and leaves the key resident.
func (k *Keyring) State() []SlotState {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	out := make([]SlotState, 0, 2)
	for _, slot := range []Slot{SlotOperator, SlotSigner} {
		st := SlotState{Slot: slot}
		if s, ok := k.slots[slot]; ok {
			if now.Sub(s.touched) >= k.idle {
				// Expired: drop the decrypted key here rather than report it
				// locked and leave it in memory. A page that shows "locked"
				// must mean the process is not holding the key.
				delete(k.slots, slot)
			} else {
				st.Unlocked = true
				st.Operator = s.signer.Public().Name
				st.KeyFile = s.path
				st.ExpiresIn = (k.idle - now.Sub(s.touched)).Round(time.Second)
			}
		}
		out = append(out, st)
	}
	return out
}
