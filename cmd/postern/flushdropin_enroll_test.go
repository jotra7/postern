package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/gate"
)

// initForDropIn runs the real init-standalone with an AUTO-GENERATED ExecStart
// (no --exec-start), so the --flush-dropin the daemon needs is baked or not
// baked by the command itself rather than written by the test. It returns the
// unit directory. extra carries the fleet flags, or nothing for standalone.
func initForDropIn(t *testing.T, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	unitDir := filepath.Join(dir, "units")
	args := append([]string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", unitDir,
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}, extra...)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	return unitDir
}

func readUnitFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// A fleet host must be handed its own drop-in path, because the daemon
// rewrites that file as bundles change the catalogue (#47). init writes the
// first drop-in and bakes --flush-dropin into the ExecStart so the agent knows
// where it is; the main unit keeps only the revision-independent postern_open
// delete, its flush-set lines having moved to the drop-in.
func TestMain_InitStandalone_FleetModeWritesTheDropInAndBakesItIntoExecStart(t *testing.T) {
	unitDir := initForDropIn(t,
		"--hub-url", "https://hub.example.com",
		"--bundle-signers", fleetSignerHex(t),
		"--enrollment-floor", "0")

	dropInPath := filepath.Join(unitDir, gate.PosterndDropInDir, gate.FlushDropInName)
	dropIn := readUnitFile(t, dropInPath)
	if !strings.HasPrefix(dropIn, "[Service]\n") {
		t.Fatalf("the flush drop-in is not a [Service] override:\n%s", dropIn)
	}
	if !strings.Contains(dropIn, "flush set inet "+gate.TableBoot+" ") {
		t.Fatalf("the enrolled host has fail-closed services but the drop-in flushes none:\n%s", dropIn)
	}

	unit := readUnitFile(t, filepath.Join(unitDir, gate.PosterndUnitName))
	if !strings.Contains(unit, "--flush-dropin "+dropInPath) {
		t.Fatalf("the fleet ExecStart does not point the agent at its drop-in, so the daemon could not "+
			"keep the flush lines in step with the catalogue:\n%s", unit)
	}
	// The flush lines belong in the drop-in now; the main unit carrying them
	// too is the frozen enumeration this fix removed. Scanned over ExecStopPost
	// directives, not the whole file: the unit carries a comment that names
	// "flush set" to explain why the lines are elsewhere.
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ExecStopPost=") && strings.Contains(line, "flush set") {
			t.Fatalf("the main posternd.service still carries a flush-set directive:\n%s", line)
		}
	}
}

// The case the fleet e2e caught: a fleet host is often enrolled with an
// operator-supplied --exec-start (to add --confirm-window, --debug,
// --metrics-listen). --flush-dropin is required wiring #47 needs, not an
// operator preference, so it must be appended even there — otherwise the
// daemon never regenerates the drop-in and the fleet host keeps the frozen
// enumeration this fix removed. Break it by only baking the flag in the
// auto-generated ExecStart branch and this fails.
func TestMain_InitStandalone_FleetModeAppendsFlushDropInToAnOperatorExecStart(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	unitDir := filepath.Join(dir, "units")
	if code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", unitDir,
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--operator", "laptop-primary="+sign+","+enc,
		"--exec-start", "/usr/local/bin/postern agent --config /etc/postern/postern.yaml --debug",
		"--hub-url", "https://hub.example.com",
		"--bundle-signers", fleetSignerHex(t),
		"--enrollment-floor", "0",
	); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}

	dropInPath := filepath.Join(unitDir, gate.PosterndDropInDir, gate.FlushDropInName)
	unit := readUnitFile(t, filepath.Join(unitDir, gate.PosterndUnitName))
	if !strings.Contains(unit, "--debug") {
		t.Fatalf("the operator's ExecStart was discarded:\n%s", unit)
	}
	if !strings.Contains(unit, "--flush-dropin "+dropInPath) {
		t.Fatalf("a fleet host with a custom --exec-start did not get --flush-dropin, so its daemon would "+
			"never regenerate the teardown flush lines:\n%s", unit)
	}
}

// A standalone host never applies a bundle, so its catalogue is fixed and the
// daemon must never rewrite the drop-in. init still writes the file (the
// teardown flush has to exist) but leaves --flush-dropin off the ExecStart, so
// the daemon's regeneration path stays disabled.
func TestMain_InitStandalone_StandaloneWritesTheDropInButLeavesTheAgentDisabled(t *testing.T) {
	unitDir := initForDropIn(t)

	dropInPath := filepath.Join(unitDir, gate.PosterndDropInDir, gate.FlushDropInName)
	dropIn := readUnitFile(t, dropInPath)
	if !strings.HasPrefix(dropIn, "[Service]\n") {
		t.Fatalf("a standalone host was not given a flush drop-in:\n%s", dropIn)
	}

	unit := readUnitFile(t, filepath.Join(unitDir, gate.PosterndUnitName))
	if strings.Contains(unit, "--flush-dropin") {
		t.Fatalf("a standalone ExecStart carries --flush-dropin, so the daemon would rewrite a drop-in "+
			"for a catalogue that can never change:\n%s", unit)
	}
}
