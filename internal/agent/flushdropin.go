package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jotra7/postern/internal/childenv"
	"github.com/jotra7/postern/internal/gate"
)

// FlushDropIn keeps posternd.service's per-set flush drop-in in step with the
// live gate catalogue. The main unit's teardown is revision-independent (it
// deletes postern_open and nothing else); the per-set "flush set" lines that
// empty a fail-closed gate on a crash name one set each, and a bundle can add
// or drop a fail-closed service after the host was enrolled. Without this, the
// enrollment-time enumeration systemd loaded stayed frozen while boot.nft was
// regenerated per revision, so a bundle-added set had no ExecStopPost line and
// its granted hole outlived a SIGKILLed agent until the grant's own timeout
// expired (#47).
//
// A zero Path disables it: a standalone host never applies a bundle, so its
// catalogue is fixed at enrollment and the drop-in init wrote is never
// regenerated. Only a fleet host is handed a Path, and only a fleet host
// reaches Sync.
type FlushDropIn struct {
	// Path is <unit-dir>/posternd.service.d/flush.conf. Empty disables the
	// whole mechanism.
	Path string
	// NFTPath is the nft(8) the flush lines name; it must match the one the
	// main unit was rendered with so both halves of the teardown invoke a
	// binary that exists. Empty selects gate.DefaultNFTPath.
	NFTPath string
	// Systemctl defaults to "systemctl" resolved on PATH. A field so a test can
	// point it at a stub, the same reason SystemdUnit.Systemctl is one.
	Systemctl string
}

// Enabled reports whether a drop-in path was configured. Standalone mode
// leaves it empty.
func (f FlushDropIn) Enabled() bool { return f.Path != "" }

func (f FlushDropIn) systemctl() string {
	if f.Systemctl == "" {
		return "systemctl"
	}
	return f.Systemctl
}

// Sync rewrites the drop-in from plan's fail-closed gate sets and reloads
// systemd so a subsequent stop, however it happens, runs the updated
// ExecStopPost lines. The write comes first: a daemon-reload that picked up a
// half-written file would be worse than one over a file that still names the
// previous catalogue, and the file is renamed into place atomically so no
// reload ever sees a partial one.
//
// daemon-reload is not optional. systemd reads a unit's ExecStopPost into
// memory at load time; without the reload a crash right after would run the
// lines from before this bundle, which is the exact frozen-enumeration failure
// this exists to close.
//
// A disabled drop-in (empty Path) is a no-op, so a standalone or test daemon
// can call this unconditionally.
func (f FlushDropIn) Sync(ctx context.Context, plan *gate.RulesetPlan) error {
	if !f.Enabled() {
		return nil
	}
	content := gate.RenderFlushDropIn(plan, f.NFTPath)
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
		return fmt.Errorf("agent: create the drop-in directory %s: %w", filepath.Dir(f.Path), err)
	}
	// 0644, matching the units and the drop-in enrollment wrote: systemd reads
	// it, and it holds only gate-set names, which the main unit's ExecStopPost
	// carried at 0644 before this file existed.
	if err := writeBlob(f.Path, blob{data: []byte(content), present: true}, 0o644); err != nil {
		return fmt.Errorf("agent: write the flush drop-in %s: %w", f.Path, err)
	}
	cmd := exec.CommandContext(ctx, f.systemctl(), "daemon-reload") //nolint:gosec // the operand is this type's own configuration
	childenv.Sanitize(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("agent: systemctl daemon-reload after rewriting %s: %w: %s",
			f.Path, err, string(out))
	}
	return nil
}
