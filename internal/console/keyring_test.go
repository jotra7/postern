package console_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/console"
	"github.com/jotra7/postern/internal/identity"
)

// keyFixture writes one passphrase-protected key file and returns its path.
func keyFixture(t *testing.T) string {
	t.Helper()
	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := identity.SaveFile(path, s, []byte(testPassphrase)); err != nil {
		t.Fatalf("identity.SaveFile: %v", err)
	}
	return path
}

func TestConsole_Keyring_LockedUntilUnlocked(t *testing.T) {
	k := console.NewKeyring(time.Minute, nil)
	if _, err := k.Signer(console.SlotOperator); !errors.Is(err, console.ErrLocked) {
		t.Fatalf("Signer on a fresh keyring = %v, want ErrLocked", err)
	}
}

func TestConsole_Keyring_UnlockRefusesTheWrongPassphrase(t *testing.T) {
	k := console.NewKeyring(time.Minute, nil)
	err := k.Unlock(console.SlotOperator, keyFixture(t), []byte("not the passphrase"))
	if !errors.Is(err, identity.ErrIncorrectPassphrase) {
		t.Fatalf("Unlock with a wrong passphrase = %v, want ErrIncorrectPassphrase", err)
	}
}

func TestConsole_Keyring_DropsAKeyAfterItsIdleWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	k := console.NewKeyring(15*time.Minute, func() time.Time { return now })
	if err := k.Unlock(console.SlotOperator, keyFixture(t), []byte(testPassphrase)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	now = now.Add(14 * time.Minute)
	if _, err := k.Signer(console.SlotOperator); err != nil {
		t.Fatalf("Signer inside the idle window = %v, want the key", err)
	}
	// That use reset the window, which is the behaviour an operator working
	// through an incident depends on.
	now = now.Add(14 * time.Minute)
	if _, err := k.Signer(console.SlotOperator); err != nil {
		t.Fatalf("Signer after a use reset the window = %v, want the key", err)
	}
	now = now.Add(15 * time.Minute)
	if _, err := k.Signer(console.SlotOperator); !errors.Is(err, console.ErrLocked) {
		t.Fatalf("Signer past the idle window = %v, want ErrLocked: a decrypted operator key held "+
			"indefinitely is the exposure this window exists to bound", err)
	}
}

func TestConsole_Keyring_StateDoesNotResetTheIdleWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	k := console.NewKeyring(10*time.Minute, func() time.Time { return now })
	if err := k.Unlock(console.SlotOperator, keyFixture(t), []byte(testPassphrase)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// Rendering a page calls State. A browser tab refreshing on a timer would
	// otherwise hold the key open forever without the operator touching
	// anything.
	for i := 0; i < 20; i++ {
		now = now.Add(time.Minute)
		_ = k.State()
	}
	if _, err := k.Signer(console.SlotOperator); !errors.Is(err, console.ErrLocked) {
		t.Fatalf("Signer after 20 minutes of page renders = %v, want ErrLocked", err)
	}
}

func TestConsole_Keyring_StateCarriesNoKeyMaterial(t *testing.T) {
	k := console.NewKeyring(time.Minute, nil)
	path := keyFixture(t)
	if err := k.Unlock(console.SlotOperator, path, []byte(testPassphrase)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// The whole point of SlotState is that it is the only thing a template
	// sees: a name, a path and a deadline. Anything a rendering mistake could
	// print is here, and none of it is secret.
	for _, st := range k.State() {
		if st.Slot != console.SlotOperator {
			continue
		}
		if !st.Unlocked || st.Operator != "laptop-primary" || st.KeyFile != path {
			t.Fatalf("State() = %+v, want the unlocked operator slot naming %s", st, path)
		}
	}
}

func TestConsole_Keyring_LockAllDropsEverythingNow(t *testing.T) {
	k := console.NewKeyring(time.Hour, nil)
	path := keyFixture(t)
	if err := k.Unlock(console.SlotOperator, path, []byte(testPassphrase)); err != nil {
		t.Fatalf("Unlock operator: %v", err)
	}
	if err := k.Unlock(console.SlotSigner, path, []byte(testPassphrase)); err != nil {
		t.Fatalf("Unlock signer: %v", err)
	}
	k.LockAll()
	for _, slot := range []console.Slot{console.SlotOperator, console.SlotSigner} {
		if _, err := k.Signer(slot); !errors.Is(err, console.ErrLocked) {
			t.Fatalf("Signer(%s) after LockAll = %v, want ErrLocked", slot, err)
		}
	}
}

// State bounds residency, not just reachability. Past the idle window it must
// drop the decrypted key, not merely stop reporting it unlocked: a page that
// shows "locked" while the process still holds the key tells an operator who
// walked away that the key is gone when it is not.
//
// The residency is checked through Signer's own two messages rather than a
// test-only accessor. Signer says "was dropped" only when Signer itself finds
// an expired slot and deletes it; if State already removed the slot, Signer
// sees nothing there and says plain "locked". So a plain-locked message after
// State ran is proof State did the removal, and a "was dropped" message is
// proof State left the key resident, which is the bug.
func TestConsole_Keyring_StateDropsAnExpiredKeyRatherThanOnlyReportingIt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	k := console.NewKeyring(15*time.Minute, func() time.Time { return now })
	if err := k.Unlock(console.SlotOperator, keyFixture(t), []byte(testPassphrase)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	now = now.Add(16 * time.Minute) // past the window

	st := k.State()
	for _, s := range st {
		if s.Slot == console.SlotOperator && s.Unlocked {
			t.Fatal("State reports the operator slot unlocked past its window")
		}
	}

	_, err := k.Signer(console.SlotOperator)
	if !errors.Is(err, console.ErrLocked) {
		t.Fatalf("Signer after State = %v, want ErrLocked", err)
	}
	if strings.Contains(err.Error(), "was dropped") {
		t.Fatalf("Signer reported %q: the slot was still resident when Signer ran, so State reported the "+
			"key locked while the process still held it decrypted", err.Error())
	}
}
