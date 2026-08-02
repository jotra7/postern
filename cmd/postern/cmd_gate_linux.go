//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

func init() {
	register(&command{
		name:    "gate-teardown",
		usage:   "gate-teardown [--config PATH] [flags]",
		summary: "remove postern_open and empty every fail-closed gate set (Linux, root)",
		run:     func(ctx context.Context, e *env, args []string) error { return runGateOp(ctx, e, args, true) },
	})
	register(&command{
		name:    "gate-flush",
		usage:   "gate-flush [--config PATH] [flags]",
		summary: "empty every fail-closed gate set, leaving its drop rules standing (Linux, root)",
		run:     func(ctx context.Context, e *env, args []string) error { return runGateOp(ctx, e, args, false) },
	})
}

// runGateOp performs the teardown design section 7 specifies, from the same
// single source the rendered unit uses.
//
// A caution that is easy to get backwards: posternd.service does NOT invoke
// these subcommands. Its ExecStopPost lines name nft(8) by absolute path,
// deliberately, because a bad upgrade that replaced the postern binary
// followed by a crash must still remove postern_open — a teardown that
// depends on the binary fails closed on the break-glass service. These
// commands exist for the operator's hands, and they run exactly
// gate.TeardownCommands so what an operator runs and what the unit runs
// cannot drift.
//
// "flush set" per set, never "flush table": flushing the table would delete
// postern_boot's drop rules and invert the posture, which is the silent
// failure I3 exists to prevent.
func runGateOp(ctx context.Context, e *env, args []string, includeOpen bool) error {
	name := "gate-flush"
	if includeOpen {
		name = "gate-teardown"
	}
	fs := newFlagSet(e, name, name+" [--config PATH] [flags]")
	configPath := fs.String("config", filepath.Join(defaultStateDirs.etc, "postern.yaml"), "standalone config path")
	nftPath := fs.String("nft", gate.DefaultNFTPath, "absolute path to nft(8)")
	dryRun := fs.Bool("dry-run", false, "print the commands instead of running them")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	data, err := os.ReadFile(*configPath) //nolint:gosec // the operator named this path
	if err != nil {
		return usagef("read %s: %v", *configPath, err)
	}
	policy, err := config.ParseStandalone(data)
	if err != nil {
		return usageError{err}
	}
	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		return usageError{err}
	}

	cmds := gateCommands(plan, *nftPath, includeOpen)

	for _, argv := range cmds {
		if *dryRun {
			outln(e.stdout, strings.Join(argv, " "))
			continue
		}
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // argv comes from gate.TeardownCommands and a flag
		if err != nil {
			// Tolerated the same way the unit's leading "-" tolerates it: an
			// already-absent table or set is the state this command wants.
			outf(e.stderr, "%s: %v: %s\n", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
			continue
		}
		outln(e.stdout, strings.Join(argv, " "))
	}
	return nil
}
