package gate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each case below holds every control but one satisfied, so a failure is
// attributable to the control it names. Testing a world-writable script owned
// by the wrong user would pass whichever check ran first and prove nothing
// about the other; this project has found real defects that way.

func TestGate_CheckScriptPath_AcceptsARootOwnedPrivateScript(t *testing.T) {
	path := installScript(t, "ok.sh", 0o700)
	if err := CheckScriptPath(path, os.Getuid()); err != nil {
		t.Fatalf("CheckScriptPath on a mode 0700 script owned by the caller: %v", err)
	}
}

// Ownership is satisfied — the file belongs to the caller and is checked
// against the caller's own uid — so only the mode control can produce this
// refusal.
func TestGate_CheckScriptPath_RefusesAWorldWritableScript(t *testing.T) {
	path := installScript(t, "world-writable.sh", 0o777)

	err := CheckScriptPath(path, os.Getuid())
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("refusal does not name the mode as the reason: %v", err)
	}
}

func TestGate_CheckScriptPath_RefusesAGroupWritableScript(t *testing.T) {
	path := installScript(t, "world-writable.sh", 0o770)

	err := CheckScriptPath(path, os.Getuid())
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("refusal does not name the mode as the reason: %v", err)
	}
}

// The mirror image: the mode is beyond reproach at 0700, so only the
// ownership control can refuse this. The expected uid is one the caller
// cannot be, which is how the check is exercised without a root test suite.
func TestGate_CheckScriptPath_RefusesAScriptOwnedBySomeoneElse(t *testing.T) {
	path := installScript(t, "ok.sh", 0o700)

	err := CheckScriptPath(path, os.Getuid()+1)
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("refusal does not name the owner as the reason: %v", err)
	}
}

// The production caller passes no OwnerUID at all, and the zero value has to
// be the strict answer rather than a permissive one. Skipped when the suite
// really is running as root, where the caller and the requirement coincide.
func TestGate_CheckScriptPath_DefaultOwnerRequirementIsRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: uid 0 satisfies the default, so there is nothing to distinguish")
	}
	path := installScript(t, "ok.sh", 0o700)

	if err := CheckScriptPath(path, 0); !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe: the zero OwnerUID must mean root, not 'unset'", err)
	}
}

// A symlink is refused rather than followed. os.Stat would report the
// target's ownership while the link — the thing exec actually resolves — is
// owned separately, so following it would check a file nobody is going to run.
func TestGate_CheckScriptPath_RefusesASymlink(t *testing.T) {
	target := installScript(t, "ok.sh", 0o700)
	link := filepath.Join(t.TempDir(), "link.sh")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := CheckScriptPath(link, os.Getuid())
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refusal does not name the symlink as the reason: %v", err)
	}
}

func TestGate_CheckScriptPath_RefusesANonExecutableFile(t *testing.T) {
	path := installScript(t, "ok.sh", 0o600)

	err := CheckScriptPath(path, os.Getuid())
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Errorf("refusal does not name executability as the reason: %v", err)
	}
}

func TestGate_CheckScriptPath_RefusesARelativePath(t *testing.T) {
	if err := CheckScriptPath("testdata/ok.sh", os.Getuid()); !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
}

func TestGate_CheckScriptPath_RefusesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-there.sh")
	if err := CheckScriptPath(path, os.Getuid()); !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
}

func TestGate_CheckScriptPath_RefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := CheckScriptPath(dir, os.Getuid()); !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
}

// Write on a directory is permission to replace the files in it, so a
// flawless script in a world-writable directory is a script anyone can swap.
// The file's own mode and owner are correct here, so only the directory
// control can refuse this.
func TestGate_CheckScriptPath_RefusesAScriptInAWorldWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	//nolint:gosec // G301: a permissive mode is the input under test
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	//nolint:gosec // G302: a permissive mode is the input under test
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	path := filepath.Join(dir, "gate.sh")
	//nolint:gosec // G306: the script has to be executable for this check to reach the directory rule
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := CheckScriptPath(path, os.Getuid())
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("refusal does not name the directory as the reason: %v", err)
	}
}

// Sticky is exactly the bit that withdraws permission to replace files you do
// not own, so /tmp-shaped directories are not refused for being shared.
func TestGate_CheckScriptPath_AcceptsAStickyWorldWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sticky")
	//nolint:gosec // G301: a permissive mode is the input under test
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	path := filepath.Join(dir, "gate.sh")
	//nolint:gosec // G306: the script has to be executable for this check to reach the directory rule
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write: %v", err)
	}
	//nolint:gosec // G302: the script has to be executable for this check to reach the directory rule
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("chmod script: %v", err)
	}

	if err := CheckScriptPath(path, os.Getuid()); err != nil {
		t.Fatalf("CheckScriptPath in a sticky world-writable directory: %v", err)
	}
}
