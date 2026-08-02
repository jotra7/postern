package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/gate"
)

// fakeRuleset records what a disarm did to one nftables table.
type fakeRuleset struct {
	name     string
	restored [][]byte
	err      error
}

func (f *fakeRuleset) Snapshot(context.Context) ([]byte, error) { return nil, nil }

func (f *fakeRuleset) Restore(_ context.Context, snapshot []byte) error {
	f.restored = append(f.restored, snapshot)
	return f.err
}

// deleted reports whether the table was removed. Restore(nil) means "this
// table did not exist", which for the real NFTRuleset is a delete.
func (f *fakeRuleset) deleted() bool {
	for _, s := range f.restored {
		if len(s) == 0 {
			return true
		}
	}
	return false
}

type fakeUnit struct {
	enabled bool
	sets    []bool
}

func (f *fakeUnit) Enabled(context.Context) (bool, error) { return f.enabled, nil }

func (f *fakeUnit) SetEnabled(_ context.Context, enabled bool) error {
	f.sets = append(f.sets, enabled)
	f.enabled = enabled
	return nil
}

func testEnv() (*env, *bytes.Buffer, *bytes.Buffer) {
	var out, errBuf bytes.Buffer
	return &env{
		stdout: &out,
		stderr: &errBuf,
		stdin:  strings.NewReader(""),
		getenv: func(string) string { return "" },
	}, &out, &errBuf
}

// Invariant 3. A disarm must clear all four artifacts, and the units are the
// ones that are easy to leave behind: removing the live tables and the
// generated ruleset looks successful — the host is reachable, the operator
// moves on — and then the boot unit re-locks it at the next reboot as soon as
// anything writes that path again, or the agent unit recreates postern_open
// on a host the operator explicitly cleared.
//
// Mutations verified, each failing a different assertion here:
//
//   - BootUnit or AgentUnit left nil in runDisarm's wiring: that unit's
//     SetEnabled is never called and its assertion fails.
//   - Open left nil: postern_open survives and "postern_open removed" fails.
//   - Paths.BootNFT left empty: boot.nft survives and its assertion fails.
//   - Paths.State left empty: state.json survives, so the next agent start
//     compares drift against a revision that was disarmed.
func TestMain_LocalDisarm_ClearsBothTablesTheBootFileAndBothUnits(t *testing.T) {
	dir := t.TempDir()
	bootNFT := filepath.Join(dir, "boot.nft")
	state := filepath.Join(dir, "state.json")
	for _, p := range []string{bootNFT, state} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	boot := &fakeRuleset{name: gate.TableBoot}
	open := &fakeRuleset{name: gate.TableOpen}
	unit := &fakeUnit{enabled: true}
	agentUnit := &fakeUnit{enabled: true}

	e, out, _ := testEnv()
	err := runLocalDisarm(context.Background(), e, localDisarm{
		Boot:      boot,
		Open:      open,
		BootUnit:  unit,
		AgentUnit: agentUnit,
		Paths:     agent.Paths{BootNFT: bootNFT, State: state},
	})
	if err != nil {
		t.Fatalf("runLocalDisarm: %v", err)
	}

	if !boot.deleted() {
		t.Error("postern_boot was not removed")
	}
	if !open.deleted() {
		t.Error("postern_open was not removed; the agent's drop rules outlive the disarm")
	}
	if _, err := os.Stat(bootNFT); !os.IsNotExist(err) {
		t.Error("boot.nft survived the disarm; the host re-locks at the next reboot")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Error("state.json survived the disarm")
	}
	if len(unit.sets) == 0 {
		t.Fatal("the boot unit's enabled state was never touched; a disarm that leaves it enabled " +
			"re-locks the host the moment anything writes boot.nft again")
	}
	if unit.enabled {
		t.Error("the boot unit is still enabled after a disarm")
	}
	if len(agentUnit.sets) == 0 {
		t.Fatal("the agent unit's enabled state was never touched; a disarmed host would still start " +
			"posternd at the next boot and recreate the table the operator just cleared")
	}
	if agentUnit.enabled {
		t.Error("the agent unit is still enabled after a disarm")
	}
	for _, want := range []string{gate.TableBoot, gate.TableOpen, gate.BootUnitName, gate.PosterndUnitName} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the disarm report does not mention %q:\n%s", want, out.String())
		}
	}
}

func TestMain_LocalDisarm_ReportsAFailureRatherThanClaimingSuccess(t *testing.T) {
	dir := t.TempDir()
	boot := &fakeRuleset{err: errors.New("nft: permission denied")}
	e, out, _ := testEnv()

	err := runLocalDisarm(context.Background(), e, localDisarm{
		Boot:      boot,
		Open:      &fakeRuleset{},
		BootUnit:  &fakeUnit{enabled: true},
		AgentUnit: &fakeUnit{enabled: true},
		Paths:     agent.Paths{BootNFT: filepath.Join(dir, "boot.nft"), State: filepath.Join(dir, "state.json")},
	})
	if err == nil {
		t.Fatal("a failed table removal was reported as a successful disarm")
	}
	if strings.Contains(out.String(), "disarmed this machine") {
		t.Fatalf("the success report was printed anyway:\n%s", out.String())
	}
}

// SystemdUnit.SetEnabled has never run against a real init system — no
// container in this project has one. This exercises the real exec path
// (fork, argv, exit status) against a recording stub named systemctl, which
// is as far as this can be taken without systemd. It catches a wrong verb, a
// missing unit and a swallowed non-zero exit; it does not prove systemd
// accepts the command. See the task report.
func TestMain_LocalDisarm_InvokesSystemctlDisableOnBothUnits(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "argv.log")
	stub := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil { //nolint:gosec // a test stub must be executable
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, _ := testEnv()
	err := runLocalDisarm(context.Background(), e, localDisarm{
		Boot:      &fakeRuleset{},
		Open:      &fakeRuleset{},
		BootUnit:  agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: stub},
		AgentUnit: agent.SystemdUnit{Name: gate.PosterndUnitName, Systemctl: stub},
		Paths:     agent.Paths{BootNFT: filepath.Join(dir, "boot.nft"), State: filepath.Join(dir, "state.json")},
	})
	if err != nil {
		t.Fatalf("runLocalDisarm: %v", err)
	}
	body, err := os.ReadFile(log) //nolint:gosec // a test reading a file its own stub wrote
	if err != nil {
		t.Fatalf("systemctl was never executed: %v", err)
	}
	// The boot unit first, then the agent: a crash between the two leaves a
	// host that loads no drop rules, rather than one that loads them with
	// nothing left enabled to open them.
	want := "disable " + gate.BootUnitName + "\ndisable " + gate.PosterndUnitName
	if got := strings.TrimSpace(string(body)); got != want {
		t.Fatalf("systemctl argv =\n%s\nwant\n%s", got, want)
	}
}

func TestMain_LocalDisarm_SurfacesANonZeroSystemctlExit(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'Failed to disable unit' >&2\nexit 1\n"), 0o700); err != nil { //nolint:gosec // a test stub must be executable
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, _ := testEnv()
	err := runLocalDisarm(context.Background(), e, localDisarm{
		Boot:      &fakeRuleset{},
		Open:      &fakeRuleset{},
		BootUnit:  agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: stub},
		AgentUnit: agent.SystemdUnit{Name: gate.PosterndUnitName, Systemctl: stub},
		Paths:     agent.Paths{BootNFT: filepath.Join(dir, "boot.nft"), State: filepath.Join(dir, "state.json")},
	})
	if err == nil {
		t.Fatal("systemctl exiting non-zero was reported as a successful disarm; the host would " +
			"re-lock at the next reboot with the operator believing it disarmed")
	}
}

// stubScript writes an executable recorder that appends its argv to log.
func stubScript(t *testing.T, dir, name, log string) string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	path := filepath.Join(dir, name)
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // a test stub must be executable
		t.Fatalf("WriteFile %s: %v", name, err)
	}
	return path
}

// Invariant 3 through the seam an operator actually reaches.
//
// The tests above drive runLocalDisarm with a hand-built localDisarm, which
// covers the function and not the wiring: runDisarm's construction of that
// value is where the boot unit, postern_open, and the boot.nft path are
// bound, and three mutations there each produce a `postern disarm --local`
// that prints "disarmed this machine" and re-locks the host at the next
// reboot. This drives the whole command.
//
// Mutations verified, each failing a different assertion here: BootUnit →
// nil, AgentUnit → nil, Open → nil, and Paths.BootNFT → "".
func TestMain_Disarm_LocalWiresAllFourArtifacts(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	state := filepath.Join(dir, "var")
	for _, d := range []string{etc, state} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	bootNFT := filepath.Join(etc, "boot.nft")
	stateJSON := filepath.Join(state, "state.json")
	for _, p := range []string{bootNFT, stateJSON} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	nftLog := filepath.Join(dir, "nft.log")
	sysLog := filepath.Join(dir, "systemctl.log")
	nft := stubScript(t, dir, "nft", nftLog)
	systemctl := stubScript(t, dir, "systemctl", sysLog)

	e, out, errBuf := testEnv()
	code := runCLI(t, e, "disarm", "--local",
		"--dir", etc, "--state-dir", state, "--nft", nft, "--systemctl", systemctl)
	if code != exitOK {
		t.Fatalf("exit = %d: %s", code, errBuf.String())
	}

	nftCalls := readLines(t, nftLog)
	for _, want := range []string{
		"delete table inet " + gate.TableBoot,
		"delete table inet " + gate.TableOpen,
	} {
		if !containsLine(nftCalls, want) {
			t.Errorf("nft was never asked to %q; the command printed success anyway.\ncalls: %v", want, nftCalls)
		}
	}

	sysCalls := readLines(t, sysLog)
	if !containsLine(sysCalls, "disable "+gate.BootUnitName) {
		t.Errorf("systemctl was never asked to disable %s; the host re-locks at the next reboot "+
			"while `disarm --local` reports success.\ncalls: %v", gate.BootUnitName, sysCalls)
	}
	if !containsLine(sysCalls, "disable "+gate.PosterndUnitName) {
		t.Errorf("systemctl was never asked to disable %s; the panic button leaves the agent starting "+
			"at every boot on a host the operator cleared.\ncalls: %v", gate.PosterndUnitName, sysCalls)
	}

	if _, err := os.Stat(bootNFT); !os.IsNotExist(err) {
		t.Error("boot.nft survived `disarm --local`; the boot unit reloads it at the next reboot")
	}
	if _, err := os.Stat(stateJSON); !os.IsNotExist(err) {
		t.Error("state.json survived `disarm --local`")
	}
	if !strings.Contains(out.String(), "disarmed this machine") {
		t.Errorf("no success report:\n%s", out.String())
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // a test reading a file its own stub wrote
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(body), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}
