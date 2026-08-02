//go:build unix

package gate

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// lockExclusive takes a non-blocking exclusive advisory lock, the same
// discipline internal/replay's store uses and for the same reason: two
// openers of one durable file each hold their own in-memory view, and the
// second one's writes silently contradict the first's. For the lease store
// that means two reapers with two different ideas of which admissions are
// live, one of which will close leases the other still believes in.
//
// flock ties the lock to this file descriptor's open file description, so it
// releases when the file is closed or the process dies — no separate unlock
// path to get wrong.
func lockExclusive(f *os.File) error {
	//nolint:gosec // G115: Fd() is a small, non-negative OS file-descriptor
	// number bounded by the process's descriptor table, not attacker-
	// controlled input; the conversion cannot overflow in practice.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("already locked by another process: %w", err)
	}
	return nil
}

// fileOwnerUID reports the uid owning fi. The second return distinguishes
// "not owned by that uid" from "this platform does not report an owner",
// which CheckScriptPath must not conflate: the second answer is a refusal to
// judge, and treating it as a pass would silently disable the control on any
// platform where it does not apply.
func fileOwnerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// isolateProcessGroup puts the child in its own process group and makes
// cancellation kill the whole group rather than the direct child alone.
//
// It matters because the direct child is almost never the process doing the
// work. An operator's gate script is a shell that execs a provider CLI, and
// killing the shell leaves that CLI running, holding the pipe this package
// reads from — so a "timed out" invocation would go on occupying the
// service's single in-flight slot after the timeout that was supposed to free
// it. Killing the group is what makes the timeout mean what it says.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid addresses the process group. The child was made a
		// group leader above, so its pid is the group id.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			// Fall back to the direct child: the group kill fails if the
			// child already exited, and killing nothing is not an error worth
			// propagating into a gate decision.
			return cmd.Process.Kill()
		}
		return nil
	}
}
