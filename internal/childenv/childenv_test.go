package childenv_test

import (
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/jotra7/postern/internal/childenv"
)

// The whole point of the package, at the level where it can be stated
// exactly: the variable goes, and nothing else does.
//
// The mutation this catches: returning cmd.Env untouched.
func TestChildenv_Sanitize_RemovesNotifySocketAndKeepsTheRest(t *testing.T) {
	cmd := exec.Command("/nonexistent")
	cmd.Env = []string{
		"PATH=/usr/bin",
		"NOTIFY_SOCKET=/run/systemd/notify",
		"POSTERN_CONFIG=/etc/postern/postern.yaml",
	}

	childenv.Sanitize(cmd)

	want := []string{"PATH=/usr/bin", "POSTERN_CONFIG=/etc/postern/postern.yaml"}
	if !slices.Equal(cmd.Env, want) {
		t.Fatalf("Sanitize produced %q, want %q", cmd.Env, want)
	}
}

// A nil cmd.Env is os/exec's "inherit everything this process has", so it is
// the case the daemon's spawn sites are actually in: none of them build an
// environment, they just did not think about the one they were passing on.
// Filling it is therefore not a convenience, it is the fix.
//
// The mutation this catches: returning early when cmd.Env is nil.
func TestChildenv_Sanitize_FillsANilEnvFromTheParentWithoutNotifySocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	t.Setenv("POSTERN_CHILDENV_CANARY", "present")

	cmd := exec.Command("/nonexistent")
	childenv.Sanitize(cmd)

	if cmd.Env == nil {
		t.Fatal("Sanitize left cmd.Env nil, which os/exec reads as \"inherit the parent's environment\", " +
			"so the child gets NOTIFY_SOCKET after all")
	}
	if slices.Contains(cmd.Env, "NOTIFY_SOCKET=/run/systemd/notify") {
		t.Fatalf("NOTIFY_SOCKET survived: %q", cmd.Env)
	}
	if !slices.Contains(cmd.Env, "POSTERN_CHILDENV_CANARY=present") {
		t.Fatalf("Sanitize dropped more than NOTIFY_SOCKET; the parent's environment did not reach the child: %q", cmd.Env)
	}
}

// An environment with nothing to remove must still come back as a non-nil
// slice. This is the same defect as the nil case wearing different clothes:
// "there was no NOTIFY_SOCKET when I looked" is not the same claim as "the
// child will not receive one", because os/exec resolves a nil Env at Start.
//
// The mutation this catches: assigning cmd.Env only when an entry was
// dropped.
func TestChildenv_Sanitize_AssignsEnvEvenWhenNothingWasRemoved(t *testing.T) {
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		t.Fatalf("unset NOTIFY_SOCKET: %v", err)
	}

	cmd := exec.Command("/nonexistent")
	childenv.Sanitize(cmd)

	if cmd.Env == nil {
		t.Fatal("Sanitize left cmd.Env nil because it found nothing to remove; a NOTIFY_SOCKET " +
			"appearing between here and Start would then be inherited")
	}
}

// Only the variable itself, matched whole. A prefix match without the "="
// would also take a NOTIFY_SOCKET_DIR or similar, which is somebody else's
// configuration and not postern's to delete.
//
// The mutation this catches: dropping the "=" from the compared prefix.
func TestChildenv_Sanitize_LeavesAVariableThatMerelyStartsWithTheName(t *testing.T) {
	cmd := exec.Command("/nonexistent")
	cmd.Env = []string{"NOTIFY_SOCKET_DIR=/run/systemd", "NOTIFY_SOCKET=/run/systemd/notify"}

	childenv.Sanitize(cmd)

	want := []string{"NOTIFY_SOCKET_DIR=/run/systemd"}
	if !slices.Equal(cmd.Env, want) {
		t.Fatalf("Sanitize produced %q, want %q", cmd.Env, want)
	}
}
