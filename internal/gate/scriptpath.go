package gate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrScriptPathUnsafe marks a gate script this host refuses to execute.
//
// It is a distinct sentinel because the refusal has to be attributable: a
// caller that cannot tell "your script is world-writable" from "your script
// is missing" will report the wrong thing to the operator at the exact moment
// they are trying to work out why their gate will not arm.
var ErrScriptPathUnsafe = errors.New("gate: script is not safe to execute as root")

// CheckScriptPath refuses a gate script that anyone but its owner could
// rewrite before the agent runs it.
//
// This is sudoers' discipline, and it is applied at config load rather than
// at first knock on purpose. A knock is the one moment the operator has no
// attention to spare, and a check that first fires there converts a
// misconfigured file mode into a failed break-glass attempt. Refusing at load
// means the host either starts with an executable it trusts or does not start
// that service at all, and the operator finds out while they still have
// another way in.
//
// ownerUID is the uid the file must belong to. Production passes 0: the
// script runs as root with the whole firewall in reach, so an owner who is
// not root is an owner who can escalate to root by editing it. The zero value
// being the production value is deliberate — a caller that forgets to set it
// gets the strict answer, not the permissive one. Tests pass their own uid,
// because a test suite that had to run as root to exercise this control would
// be a test suite nobody runs.
//
// What is checked, and what is not:
//
//   - the path is absolute, and names a regular file. A symlink is refused
//     outright rather than followed: os.Stat would report the target's
//     ownership while the link itself — the thing actually resolved at exec
//     time — could belong to anyone.
//   - the file is owned by ownerUID, is executable by its owner, and is
//     writable by nobody else.
//   - the immediate parent directory is not group- or world-writable unless
//     it carries the sticky bit, since write on a directory is permission to
//     replace the files in it. Sticky is accepted because it is exactly the
//     bit that withdraws that permission for files you do not own.
//
// The ancestor chain above the immediate parent is NOT walked. A world-
// writable grandparent can still have the parent renamed out from under it,
// and this check will not notice; put gate scripts somewhere root-owned.
// Stated rather than implied, because a control that is documented as
// covering more than it does is worse than no control.
func CheckScriptPath(path string, ownerUID int) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %q is not an absolute path", ErrScriptPathUnsafe, path)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrScriptPathUnsafe, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %q is a symlink; the link itself is what exec resolves, and a link "+
			"is owned separately from what it points at", ErrScriptPathUnsafe, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %q is not a regular file", ErrScriptPathUnsafe, path)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %q is mode %04o; group- or world-writable, so anyone in that set "+
			"chooses what this host runs as root", ErrScriptPathUnsafe, path, perm)
	}
	if perm := fi.Mode().Perm(); perm&0o100 == 0 {
		return fmt.Errorf("%w: %q is mode %04o and is not executable by its owner", ErrScriptPathUnsafe, path, perm)
	}
	if uid, ok := fileOwnerUID(fi); !ok {
		return fmt.Errorf("%w: %q ownership could not be read on this platform", ErrScriptPathUnsafe, path)
	} else if uid != ownerUID {
		return fmt.Errorf("%w: %q is owned by uid %d, want uid %d", ErrScriptPathUnsafe, path, uid, ownerUID)
	}

	return checkScriptParentDir(filepath.Dir(path))
}

func checkScriptParentDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: directory %q: %v", ErrScriptPathUnsafe, dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrScriptPathUnsafe, dir)
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%w: directory %q is mode %04o without the sticky bit, so the script in it "+
			"can be replaced by anyone with write access to the directory",
			ErrScriptPathUnsafe, dir, fi.Mode().Perm())
	}
	return nil
}
