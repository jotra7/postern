//go:build !unix

package gate

import (
	"os"
	"os/exec"
)

// lockExclusive is a no-op off unix, matching the build split internal/replay
// already draws: postern's agent is a unix daemon, and this stub exists so
// the package still compiles for a cross-platform `go vet ./...` rather than
// to claim the guarantee.
func lockExclusive(*os.File) error { return nil }

// fileOwnerUID reports that this platform has no uid to report, so
// CheckScriptPath refuses rather than passing a check it cannot perform.
func fileOwnerUID(os.FileInfo) (int, bool) { return 0, false }

// isolateProcessGroup is a no-op off unix. exec.CommandContext still kills the
// direct child on timeout; only the grandchild sweep described in the unix
// implementation is absent.
func isolateProcessGroup(*exec.Cmd) {}
