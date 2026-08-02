package gate

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// This file renders the third artifact invariant 6 requires to agree with
// the other two: the systemd units. It sits beside RenderBootNFT and
// RenderSystemdFlushLines deliberately (design section 11, "internal/gate
// holds all three renderers ... because divergence between them inverts a
// posture silently"), and like them it is a pure function over a
// *RulesetPlan — the unit file is config-dependent precisely because its
// teardown names one set per fail-closed gate set, so renderer equivalence
// has to cover it.

// DefaultNFTPath is where nft(8) lives on the distributions postern targets.
// systemd resolves no PATH for unit commands, so every command a unit runs
// must be absolute.
const DefaultNFTPath = "/usr/sbin/nft"

// Unit file names, as installed by enrollment (design section 6).
const (
	PosterndUnitName = "posternd.service"
	BootUnitName     = "postern-boot.service"
)

// The per-set flush half of posternd.service's teardown lives in a drop-in
// the AGENT owns, not in the main unit. The main unit's teardown is
// revision-independent (it deletes postern_open and nothing else), so
// enrollment writes it once; the flush lines name one gate set each and the
// set catalogue changes every time a bundle adds or drops a fail-closed
// service, so they are regenerated as that catalogue changes and reloaded
// with `systemctl daemon-reload`. Splitting them out this way is what stops
// the frozen-at-enrollment drift: a bundle-added set that had no flush line
// left its granted hole standing on the live host until its own timeout
// expired, because the main unit systemd loaded still named only the sets
// that existed when the host was enrolled.
//
// PosterndDropInDir is the ".d" directory systemd reads drop-ins from, and
// FlushDropInName is the one file in it postern writes. Callers join them
// under the unit directory: <unit-dir>/posternd.service.d/flush.conf.
const (
	PosterndDropInDir = PosterndUnitName + ".d"
	FlushDropInName   = "flush.conf"
)

// DefaultWatchdogInterval is the WatchdogSec the agent's heartbeat is sized
// against: the agent_up lease is 90s refreshed every 30s (design section 4),
// and the watchdog observes the same health token from the same packet loop
// (design section 7), so a wedged loop loses both at the same cadence.
const DefaultWatchdogInterval = 90 * time.Second

// UnitOptions is the host-specific detail the renderers cannot derive from a
// RulesetPlan.
type UnitOptions struct {
	// ExecStart is the full posternd command line, binary first, absolute.
	// It appears in exactly one directive — ExecStart — and never in a
	// teardown or boot command, because both of those must keep working
	// when this binary does not.
	ExecStart string
	// NFTPath is nft(8)'s absolute path. Empty selects DefaultNFTPath.
	NFTPath string
	// BootNFTPath is the generated ruleset the boot oneshot loads.
	BootNFTPath string
	// WatchdogInterval is systemd's WatchdogSec. Zero selects
	// DefaultWatchdogInterval.
	WatchdogInterval time.Duration
}

func (o UnitOptions) nftPath() string {
	if o.NFTPath == "" {
		return DefaultNFTPath
	}
	return o.NFTPath
}

func (o UnitOptions) watchdog() time.Duration {
	if o.WatchdogInterval <= 0 {
		return DefaultWatchdogInterval
	}
	return o.WatchdogInterval
}

func (o UnitOptions) validate(needExecStart bool) error {
	if needExecStart && strings.TrimSpace(o.ExecStart) == "" {
		return fmt.Errorf("gate: UnitOptions.ExecStart is empty")
	}
	if needExecStart && !filepath.IsAbs(strings.Fields(o.ExecStart)[0]) {
		return fmt.Errorf("gate: UnitOptions.ExecStart %q is not absolute; systemd resolves no PATH for units", o.ExecStart)
	}
	if !filepath.IsAbs(o.nftPath()) {
		return fmt.Errorf("gate: UnitOptions.NFTPath %q is not absolute; a relative teardown command is a teardown that does not run", o.nftPath())
	}
	if o.BootNFTPath != "" && !filepath.IsAbs(o.BootNFTPath) {
		return fmt.Errorf("gate: UnitOptions.BootNFTPath %q is not absolute", o.BootNFTPath)
	}
	return nil
}

// TeardownCommands is the single source for what must happen to the firewall
// when posternd stops, however it stops. Each element is an argv, absolute
// binary first. RenderPosterndUnit renders exactly this list into
// ExecStopPost directives, and the container test executes exactly these
// argvs against a live ruleset — so "what the unit says" and "what was
// tested" cannot drift apart.
//
// Order and shape are both load-bearing:
//
//   - postern_open is deleted outright. It has no on-disk form and no boot
//     persistence, so leaving it behind would leave drop rules standing with
//     nothing alive to open them — failing closed on a service configured
//     open (design section 7, fail-open enforcement).
//   - postern_boot is never deleted and never flushed as a table. Its drop
//     rules ARE the fail-closed posture. Only its gate sets are emptied, one
//     "flush set" per set, so an operator's live grant does not outlive the
//     agent that granted it while the drops it was punched through stay put.
func TeardownCommands(plan *RulesetPlan, nftPath string) [][]string {
	return append(TeardownOpenCommands(nftPath), TeardownFlushCommands(plan, nftPath)...)
}

// TeardownOpenCommands is the revision-independent half of TeardownCommands:
// the single delete of postern_open. It names no gate set, so it is the same
// on every revision, and it is what RenderPosterndUnit renders into the main
// unit's ExecStopPost — the half that never has to be regenerated.
func TeardownOpenCommands(nftPath string) [][]string {
	if nftPath == "" {
		nftPath = DefaultNFTPath
	}
	return [][]string{{nftPath, "delete", "table", "inet", TableOpen}}
}

// TeardownFlushCommands is the revision-dependent half: one "flush set" per
// fail-closed gate set, in FlushSetNames order. It is what RenderFlushDropIn
// renders, and the agent regenerates that drop-in whenever this list changes.
// Concatenated after TeardownOpenCommands it is exactly TeardownCommands, so
// what an operator runs, what systemd runs across the unit and its drop-in,
// and what the container test executes all still come from one source.
func TeardownFlushCommands(plan *RulesetPlan, nftPath string) [][]string {
	if nftPath == "" {
		nftPath = DefaultNFTPath
	}
	var cmds [][]string
	for _, name := range FlushSetNames(plan) {
		cmds = append(cmds, []string{nftPath, "flush", "set", "inet", TableBoot, name})
	}
	return cmds
}

// RenderPosterndUnit renders posterndUnitName. Every teardown directive
// invokes nft(8) by absolute path; none of them names the postern binary,
// because a bad upgrade that replaced it followed by a crash must still tear
// postern_open down (design section 7, "teardown must not depend on the
// postern binary").
func RenderPosterndUnit(plan *RulesetPlan, opts UnitOptions) (string, error) {
	if err := opts.validate(true); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=postern single-packet authorization agent\n")
	fmt.Fprintf(&b, "Documentation=man:%s\n", PosterndUnitName)
	// After, deliberately without Wants. The boot unit runs because it is
	// ENABLED, which is a state the agent's own arm step owns: a fresh host
	// has it installed and disabled, and nothing may drop traffic until a
	// configuration has been armed and confirmed. Pulling it in from here
	// would load the fail-closed ruleset the moment posternd is started, so
	// the transaction the agent then prepares would snapshot an
	// already-armed host — and its revert would restore the very rules it
	// exists to roll back, silently.
	fmt.Fprintf(&b, "After=%s network-pre.target\n", BootUnitName)
	b.WriteString("\n[Service]\n")
	// Type=notify is what makes WatchdogSec mean anything: without it the
	// watchdog never arms and a wedged packet loop is restarted by nothing.
	b.WriteString("Type=notify\n")
	// =main, never =all. Widening this is the tempting way to silence the
	// "notification message from PID N, but reception only permitted for main
	// PID M" lines that posternd's systemctl and nft children used to
	// provoke, and it would trade a log line for the watchdog: under =all a
	// WATCHDOG=1 from any descendant resets the timer on behalf of a packet
	// loop that has wedged. The children lost the socket instead; see
	// internal/childenv.
	b.WriteString("NotifyAccess=main\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", opts.ExecStart)
	fmt.Fprintf(&b, "WatchdogSec=%ds\n", int(opts.watchdog().Seconds()))
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5s\n")

	b.WriteString("\n")
	b.WriteString("# Firewall teardown on ANY exit, including a crash. nft(8) is invoked by\n")
	b.WriteString("# absolute path and the postern binary is deliberately absent from this\n")
	b.WriteString("# line: a bad upgrade that replaced it, followed by a crash, must still\n")
	b.WriteString("# remove postern_open. The leading \"-\" tolerates an already-absent table.\n")
	b.WriteString("#\n")
	b.WriteString("# The per-set \"flush set\" lines are NOT here: they name a gate set each,\n")
	b.WriteString("# the catalogue changes with every bundle, and a frozen enumeration would\n")
	b.WriteString("# leave a bundle-added set's grant standing after a crash. They live in\n")
	b.WriteString("# " + PosterndDropInDir + "/" + FlushDropInName + ", which the agent regenerates as the catalogue\n")
	b.WriteString("# changes; systemd appends a drop-in's ExecStopPost after this one, so the\n")
	b.WriteString("# postern_open delete still runs first.\n")
	for _, cmd := range TeardownOpenCommands(opts.nftPath()) {
		fmt.Fprintf(&b, "ExecStopPost=-%s\n", strings.Join(cmd, " "))
	}

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String(), nil
}

// RenderBootUnit renders bootUnitName: the oneshot that loads the persistent
// fail-closed ruleset before the network comes up, independently of the
// agent. It runs nft(8) rather than a postern subcommand on purpose — a
// corrupt or half-upgraded binary that failed to load the table would
// silently fail *open* on a host configured closed (design section 7).
func RenderBootUnit(opts UnitOptions) (string, error) {
	if err := opts.validate(false); err != nil {
		return "", err
	}
	if opts.BootNFTPath == "" {
		return "", fmt.Errorf("gate: UnitOptions.BootNFTPath is required to render %s", BootUnitName)
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=postern boot-time firewall posture\n")
	// DefaultDependencies=no plus Before=network-pre.target is what puts the
	// drop rules in place before anything can reach a gated port on a host
	// whose agent may never start.
	b.WriteString("DefaultDependencies=no\n")
	b.WriteString("Before=network-pre.target\n")
	b.WriteString("Wants=network-pre.target\n")
	fmt.Fprintf(&b, "ConditionPathExists=%s\n", opts.BootNFTPath)
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=oneshot\n")
	b.WriteString("RemainAfterExit=yes\n")
	fmt.Fprintf(&b, "ExecStart=%s -f %s\n", opts.nftPath(), opts.BootNFTPath)
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=sysinit.target\n")
	return b.String(), nil
}
