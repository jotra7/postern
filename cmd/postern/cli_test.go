package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
)

// runCLI drives the real dispatcher, so the flags, the parsing, and the exit
// codes are all under test rather than the functions behind them.
func runCLI(t *testing.T, e *env, args ...string) int {
	t.Helper()
	return run(context.Background(), e, args)
}

func envWithHome(t *testing.T, home string) (*env, *strings.Builder, *strings.Builder) {
	t.Helper()
	var out, errBuf strings.Builder
	return &env{
		stdout: &out,
		stderr: &errBuf,
		stdin:  strings.NewReader(""),
		getenv: func(k string) string {
			if k == "POSTERN_CONFIG" {
				return filepath.Join(home, "config.yaml")
			}
			return ""
		},
	}, &out, &errBuf
}

// Design section 11 requires the shipped example configuration to satisfy
// validation and arm a fail-closed service. init-standalone is the generator
// of that configuration, so what it writes has to pass the same parser and
// planner the agent runs — an example that cannot arm is the failure mode
// section 1 exists to prevent, arriving through the generator instead of the
// code.
//
// Mutation verified: dropping the liveness action from the generated service
// set leaves a config that still parses, so this test's Validate assertion
// passes — but the operator grant then names an undeclared service and
// Policy.Validate fails, which this catches. Dropping recovery_service fails
// it too, because the canary is fail-closed.
func TestMain_InitStandalone_WritesAConfigThatValidatesAndPlans(t *testing.T) {
	dir := t.TempDir()
	e, out, _ := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--ssh-host", "web-01.example.com",
		"--ssh-user", "ops",
		"--exec-start", "/usr/local/bin/postern agent --config /etc/postern/postern.yaml",
		"--operator", "laptop-primary="+sign+","+enc,
	)
	if code != exitOK {
		t.Fatalf("init-standalone exited %d", code)
	}

	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("no generated config: %v", err)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("the generated config does not parse:\n%v\n%s", err, body)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the generated config does not validate:\n%v\n%s", err, body)
	}
	if !policy.HasFailClosed() {
		t.Fatal("the generated config has no fail-closed service, so nothing exercises the posture " +
			"this whole design is built around")
	}
	if _, err := gate.BuildRulesetPlan(policy); err != nil {
		t.Fatalf("the generated config cannot be planned into a ruleset: %v", err)
	}
	// The revision is what a confirm packet binds to. A generated config
	// without one would leave the agent arming revision 0 on a host that
	// records revision 0 the moment anything confirms — after which no
	// configuration change could ever be armed, because the revision would
	// never differ again.
	if policy.Revision != 1 {
		t.Fatalf("generated revision = %d, want 1 (the default first revision)", policy.Revision)
	}

	// Every artifact enrollment is supposed to leave behind, staged inert.
	for _, p := range []string{
		filepath.Join(dir, "etc", "host.key"),
		filepath.Join(dir, "etc", "boot.nft"),
		filepath.Join(dir, "units", gate.PosterndUnitName),
		filepath.Join(dir, "units", gate.BootUnitName),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}

	// The printed host entry is the client's half and must be complete
	// enough to knock with.
	for _, want := range []string{"host_id:", "knock_addr: 203.0.113.9", "host_encryption:", "host_signing:", "services:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the printed host entry is missing %q:\n%s", want, out.String())
		}
	}
}

// The unit's teardown must never name the postern binary: a bad upgrade that
// replaced it, followed by a crash, would leave postern_open standing and
// fail closed on the break-glass service. The renderer enforces this and is
// tested in internal/gate; this asserts the CLI actually installs what that
// renderer produced rather than a second rendering of its own.
func TestMain_InitStandalone_InstallsTheRenderedUnitsUnchanged(t *testing.T) {
	dir := t.TempDir()
	e, _, _ := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	if code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent --config /etc/postern/postern.yaml",
		"--operator", "laptop-primary="+sign+","+enc,
	); code != exitOK {
		t.Fatalf("init-standalone exited %d", code)
	}

	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	want, err := gate.RenderPosterndUnit(plan, gate.UnitOptions{
		ExecStart:   "/usr/local/bin/postern agent --config /etc/postern/postern.yaml",
		BootNFTPath: filepath.Join(dir, "etc", "boot.nft"),
	})
	if err != nil {
		t.Fatalf("RenderPosterndUnit: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "units", gate.PosterndUnitName)) //nolint:gosec // same
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	if string(got) != want {
		t.Fatalf("the installed unit is not what internal/gate rendered; a second renderer here would "+
			"drift from boot.nft and invert a posture silently.\n--- installed ---\n%s\n--- rendered ---\n%s", got, want)
	}
	if strings.Contains(string(got), "postern gate-teardown") {
		t.Error("the unit's teardown names the postern binary; a corrupt binary would then leave " +
			"postern_open standing and fail closed on the break-glass service")
	}
}

func TestMain_InitStandalone_RefusesWithoutAnAlwaysAllowPath(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--operator", "laptop-primary="+sign+","+enc,
	)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "always-allow") {
		t.Fatalf("the refusal does not name the missing path:\n%s", errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "postern.yaml")); err == nil {
		t.Fatal("a config was written despite the refusal")
	}
}

// The lockout, reproduced at the only point where refusing it is free.
//
// A VM enrolled with `--always-allow-iface lo` satisfied every check postern
// had — both of them were non-emptiness — armed fail-closed, rebooted, and
// was never reachable again. Design section 7's rail 1 was in the ruleset,
// never touched, and never useful, because no remote operator arrives on
// loopback. Enrollment is where the operator still has a working way in and
// nothing has been written, so this is where it is refused outright.
//
// The mutation this catches: removing the loopbackAlwaysAllow guard from
// initStandalone. Every subtest then exits exitOK and writes a config that
// bricks the host at its next reboot.
func TestMain_InitStandalone_RefusesALoopbackAlwaysAllowIface(t *testing.T) {
	// Two mechanisms, asserted separately so neither can cover for the
	// other. The kernel's flag is authoritative and catches a loopback under
	// any name — "loopback0" got through a blocklist. The name list is the
	// fallback for a config being generated off-host, where there are no
	// flags to read. Which one applies depends on the platform: "lo" is real
	// on linux and absent on darwin, "lo0" the reverse, so both branches are
	// exercised across the platforms this is run on.
	real, absent := loopbackNames(t)
	cases := []struct {
		iface string
		want  string
	}{
		{real, "flagged loopback by this kernel"},
		{absent, "a loopback interface name"},
		{"LOOPBACK", "a loopback interface name"}, // and the match is case-insensitive
	}

	for _, tc := range cases {
		t.Run(tc.iface, func(t *testing.T) {
			dir := t.TempDir()
			e, _, errBuf := envWithHome(t, dir)
			sign, enc := publicKeyPairB64(t)

			code := runCLI(t, e, initArgs(dir, tc.iface, sign, enc)...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d: --always-allow-iface %s was accepted, so this host "+
					"would arm fail-closed behind a rail no operator can arrive on", code, exitUsage, tc.iface)
			}
			if !strings.Contains(errBuf.String(), tc.want) {
				t.Fatalf("refused, but not as a loopback via %q — so the other probe covered for "+
					"this one and this one is untested:\n%s", tc.want, errBuf.String())
			}
			for _, p := range []string{"etc/postern.yaml", "etc/host.key", "etc/boot.nft"} {
				if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
					t.Errorf("%s was written despite the refusal; a command that fails must leave "+
						"the host as it found it", p)
				}
			}
		})
	}
}

// loopbackNames returns this kernel's real loopback interface and a loopback
// name that does not resolve here, so the flag probe and the name fallback
// can each be driven through the real command.
func loopbackNames(t *testing.T) (real, absent string) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("enumerate interfaces: %v", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			real = i.Name
			break
		}
	}
	if real == "" {
		t.Skip("this machine reports no loopback interface")
	}
	for _, candidate := range []string{"lo", "lo0", "loopback", "localhost"} {
		if _, err := net.InterfaceByName(candidate); err != nil {
			return real, candidate
		}
	}
	t.Skip("every loopback name this checks for resolves on this machine")
	return "", ""
}

// The typo gate, and the reason a loopback blocklist alone was not enough:
// `tailscale1` is one character from `tailscale0` and is otherwise
// indistinguishable from a correct configuration.
//
// Follow it through. An always-allow interface that resolves to nothing is a
// global pre-arm failure, so the agent goes inert; inert on a fail-closed
// host means boot.nft's drops are live with nothing able to open them and no
// SPA to knock with. A typo at enrollment becomes a lockout at first arm —
// and init-standalone runs on the host, where net.InterfaceByName would have
// caught it while the operator still had a working way in.
//
// Driven through the real CLI rather than through checkAlwaysAllowIface
// directly, for the PortsArmable reason: a check that is tested but not
// reached from the command is a check that does not exist.
//
// The mutation this catches: dropping the existence refusal (returning nil
// instead). Every name below is then written to disk.
func TestMain_InitStandalone_RefusesAnAlwaysAllowIfaceThisHostDoesNotHave(t *testing.T) {
	// The third is a plausible loopback spelling that no blocklist would
	// carry, which is what made name-matching insufficient on its own.
	for _, iface := range []string{"tailscale1", "nosuchiface99", "loopback0"} {
		t.Run(iface, func(t *testing.T) {
			dir := t.TempDir()
			e, _, errBuf := envWithHome(t, dir)
			sign, enc := publicKeyPairB64(t)

			code := runCLI(t, e, initArgs(dir, iface, sign, enc)...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d: --always-allow-iface %s does not exist here and was "+
					"accepted, so this host would go inert at first arm with its drop rules already live",
					code, exitUsage, iface)
			}
			if !strings.Contains(errBuf.String(), "does not exist on this host") {
				t.Fatalf("the refusal does not name the problem:\n%s", errBuf.String())
			}
			// A typo is far easier to fix with the correct spelling on
			// screen, so the refusal has to offer what it did find.
			for _, real := range nonLoopbackIfaceNames() {
				if strings.Contains(errBuf.String(), real) {
					return
				}
			}
			t.Fatalf("the refusal lists none of this host's interfaces (%v), so an operator who "+
				"misspelled one has nothing to correct it against:\n%s",
				nonLoopbackIfaceNames(), errBuf.String())
		})
	}
}

// The off-host escape. init-standalone legitimately generates configurations
// for hosts other than the one running it — --no-nft-check is documented for
// exactly that — so existence-checking must not make that flow impossible.
//
// It is a flag rather than a warning because the consequence is a bricked
// host, and a warning would print among four other "wrote ..." lines and
// scroll past. The flag is the operator asserting the one thing that makes
// the check inapplicable: that these are not the target host's interfaces.
//
// The mutation this catches: ignoring o.noIfaceCheck in
// checkAlwaysAllowIface. Off-host generation then has no way through at all.
func TestMain_InitStandalone_OffHostGenerationSkipsTheExistenceCheck(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e, append(initArgs(dir, "tailscale0", sign, enc), "--no-iface-check")...)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d; --no-iface-check did not permit generating a config for a "+
			"host other than this one:\n%s", code, exitOK, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "NOT verified") {
		t.Fatalf("--no-iface-check passed silently; an unverified always-allow path is the one "+
			"thing the operator has to carry themselves:\n%s", errBuf.String())
	}
}

// And the escape is narrow: it turns off existence, not the loopback rule.
// Loopback is never right on any host, so no flag may reach it.
//
// The mutation this catches: moving the offHost early-return above the
// loopback probes. Both names are then written to disk.
func TestMain_InitStandalone_OffHostGenerationStillRefusesLoopback(t *testing.T) {
	for _, iface := range []string{"lo", "lo0"} {
		t.Run(iface, func(t *testing.T) {
			dir := t.TempDir()
			e, _, errBuf := envWithHome(t, dir)
			sign, enc := publicKeyPairB64(t)

			code := runCLI(t, e, append(initArgs(dir, iface, sign, enc), "--no-iface-check")...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d: --no-iface-check let a loopback always-allow path "+
					"through, and loopback carries no remote operator on any host", code, exitUsage)
			}
			if !strings.Contains(errBuf.String(), "loopback") {
				t.Fatalf("the refusal does not name the problem:\n%s", errBuf.String())
			}
		})
	}
}

// A real, existing, non-loopback interface is accepted — the case that has
// to keep working, and the one e2e.sh exercises for real with mesh0.
//
// The mutation this catches: refusing everything, which would make every
// assertion above pass for the wrong reason.
func TestMain_InitStandalone_AcceptsARealNonLoopbackInterface(t *testing.T) {
	found := nonLoopbackIfaceNames()
	if len(found) == 0 {
		t.Skip("this machine has no non-loopback interface")
	}
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e, initArgs(dir, found[0], sign, enc)...)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d; enrollment refused %q, which exists on this host and is not "+
			"loopback:\n%s", code, exitOK, found[0], errBuf.String())
	}
}

// initArgs is a complete, valid init-standalone invocation with one variable:
// the always-allow interface under test. Deliberately without
// --no-iface-check, so a caller that wants the off-host path has to add it.
func initArgs(dir, iface, sign, enc string) []string {
	return []string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", iface,
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}
}

func TestMain_InitStandalone_RefusesToSilentlyReplaceAnExistingHostIdentity(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	args := []string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}
	e, _, _ := envWithHome(t, dir)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("first init exited %d", code)
	}
	e2, _, errBuf := envWithHome(t, dir)
	if code := runCLI(t, e2, args...); code != exitUsage {
		t.Fatalf("second init exited %d, want a refusal", code)
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Fatalf("the refusal does not say how to proceed deliberately:\n%s", errBuf.String())
	}
}

// publicKeyPairB64 returns base64 public halves of a throwaway identity, the
// form --operator takes.
func publicKeyPairB64(t *testing.T) (signing, encryption string) {
	t.Helper()
	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub := s.Public()
	return base64.StdEncoding.EncodeToString(pub.Signing[:]),
		base64.StdEncoding.EncodeToString(pub.Encryption[:])
}

// Design section 7 requires the generated ruleset to be validated with
// `nft -c -f` before it is written, and the reason is the boot path's
// asymmetry: postern-boot.service loads this file before the agent runs and
// independently of it, so a syntax error does not produce a failed command
// anyone sees — it produces a host that silently fails OPEN on every
// service configured closed, discovered at the next reboot or never.
//
// Driven with a stub nft, so the check is tested rather than nft's parser.
//
// Mutation verified: making checkBootNFT return nil unconditionally passes
// the rejecting row's exit-code assertion and fails its "no boot.nft was
// written" assertion.
func TestMain_InitStandalone_RefusesARulesetNFTRejects(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	sign, enc := publicKeyPairB64(t)

	for _, tc := range []struct {
		name     string
		script   string
		wantExit int
	}{
		{"nft accepts", "#!/bin/sh\nexit 0\n", exitOK},
		{"nft rejects", "#!/bin/sh\necho 'Error: syntax error, unexpected junk' >&2\nexit 1\n", exitFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "nft")
			if err := os.WriteFile(stub, []byte(tc.script), 0o700); err != nil { //nolint:gosec // a test stub must be executable
				t.Fatalf("WriteFile: %v", err)
			}
			e, _, errBuf := envWithHome(t, dir)
			code := runCLI(t, e,
				"init-standalone",
				"--dir", filepath.Join(dir, "etc"),
				"--state-dir", filepath.Join(dir, "var"),
				"--unit-dir", filepath.Join(dir, "units"),
				"--host-name", "web-01",
				"--knock-addr", "203.0.113.9",
				"--always-allow-iface", "tailscale0", "--no-iface-check",
				"--exec-start", "/usr/local/bin/postern agent",
				"--nft", stub,
				"--operator", "laptop-primary="+sign+","+enc,
			)
			if code != tc.wantExit {
				t.Fatalf("exit = %d, want %d: %s", code, tc.wantExit, errBuf.String())
			}
			_, statErr := os.Stat(filepath.Join(dir, "etc", "boot.nft"))
			if tc.wantExit == exitOK && statErr != nil {
				t.Fatalf("no boot.nft written despite nft accepting: %v", statErr)
			}
			if tc.wantExit != exitOK {
				if statErr == nil {
					t.Fatal("boot.nft was written despite nft rejecting it; a ruleset that fails to " +
						"load leaves every fail-closed service open at the next boot")
				}
				if !strings.Contains(errBuf.String(), "fails the host OPEN") {
					t.Fatalf("the refusal does not say what a bad ruleset costs:\n%s", errBuf.String())
				}
			}
		})
	}
}

// nft(8) is a runtime requirement on every postern host — the boot unit runs
// it and so does fail-open teardown — so an --nft that does not exist is a
// finding, not a reason to skip the check.
//
// The check deliberately does not fall back to whichever nft is on PATH: it
// validates with the same binary the generated units will run, so it also
// catches nft being installed somewhere other than --nft names. Which of the
// two refusals fires therefore depends on whether the machine running the
// test has nft at all, and both are asserted through what they have in
// common — a non-zero usage exit that names --nft.
func TestMain_InitStandalone_RefusesWhenNFTIsAbsentRatherThanSkippingTheCheck(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	e, _, errBuf := envWithHome(t, dir)

	code := runCLI(t, e,
		"init-standalone",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--nft", filepath.Join(dir, "no-such-nft"),
		"--operator", "laptop-primary="+sign+","+enc,
	)
	if code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal, got:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "--nft") {
		t.Fatalf("the refusal does not name the flag that fixes it:\n%s", errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "boot.nft")); err == nil {
		t.Fatal("boot.nft was written without being validated")
	}
}

// A command that fails must leave the host as it found it.
//
// An earlier version wrote host.key and postern.yaml before validating the
// ruleset, so a rejected ruleset left both behind — and the operator's next
// attempt, after legitimately fixing the problem, hit the already-exists
// refusal, whose text warns about invalidating cached entries that were
// never issued. The operator's way out was to delete files they did not know
// had been created, on a host they were already worried about.
//
// Mutation verified: moving the identity.SaveFile and postern.yaml writes
// back above checkBootNFT fails both halves of this test.
func TestMain_InitStandalone_LeavesNothingBehindWhenValidationFails(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	rejecting := filepath.Join(dir, "nft-bad")
	accepting := filepath.Join(dir, "nft-good")
	if err := os.WriteFile(rejecting, []byte("#!/bin/sh\necho 'Error: syntax error' >&2\nexit 1\n"), 0o700); err != nil { //nolint:gosec // a test stub must be executable
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(accepting, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // a test stub must be executable
		t.Fatalf("WriteFile: %v", err)
	}

	args := func(nft string) []string {
		return []string{
			"init-standalone",
			"--dir", filepath.Join(dir, "etc"),
			"--state-dir", filepath.Join(dir, "var"),
			"--unit-dir", filepath.Join(dir, "units"),
			"--host-name", "web-01",
			"--knock-addr", "203.0.113.9",
			"--always-allow-iface", "tailscale0", "--no-iface-check",
			"--exec-start", "/usr/local/bin/postern agent",
			"--nft", nft,
			"--operator", "laptop-primary=" + sign + "," + enc,
		}
	}

	e, _, _ := envWithHome(t, dir)
	if code := runCLI(t, e, args(rejecting)...); code == exitOK {
		t.Fatal("a rejected ruleset was accepted")
	}
	for _, p := range []string{"postern.yaml", "host.key", "boot.nft"} {
		if _, err := os.Stat(filepath.Join(dir, "etc", p)); err == nil {
			t.Errorf("%s survived a failed init-standalone; the retry after fixing the problem then "+
				"hits the already-exists refusal", p)
		}
	}

	// The whole point: the operator fixes the problem and tries again.
	e2, _, errBuf := envWithHome(t, dir)
	if code := runCLI(t, e2, args(accepting)...); code != exitOK {
		t.Fatalf("the retry after fixing the problem failed: %s", errBuf.String())
	}
}

// postern.yaml carries the operator key set, the SPA port, and every gated
// port — the inventory design section 6 says a public bundle must never
// leak. Leaving it world-readable publishes it to every local account
// instead. The code says so in a comment; nothing checked it.
//
// Mutation verified: each mode changed to 0o644 in turn fails its row.
func TestMain_InitStandalone_WritesEachArtifactWithTheModeItsContentsNeed(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	e, _, errBuf := envWithHome(t, dir)

	if code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary="+sign+","+enc,
	); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}

	for _, tc := range []struct {
		path string
		mode os.FileMode
		why  string
	}{
		{filepath.Join(dir, "etc", "postern.yaml"), 0o600,
			"it carries the operator key set, the SPA port, and every gated port"},
		{filepath.Join(dir, "etc", "host.key"), 0o600,
			"it holds the host's private keys"},
		{filepath.Join(dir, "etc", "boot.nft"), 0o600,
			"it enumerates every gated port and the SPA port"},
		{filepath.Join(dir, "units", gate.PosterndUnitName), 0o644,
			"systemd's own tooling reads it and it holds nothing `systemctl cat` would not show"},
		{filepath.Join(dir, "units", gate.BootUnitName), 0o644, "same"},
	} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Errorf("Stat %s: %v", tc.path, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != tc.mode {
			t.Errorf("%s mode = %o, want %o: %s", filepath.Base(tc.path), perm, tc.mode, tc.why)
		}
	}
}

// The other half of "leave nothing behind". Validation failures were
// covered; write failures were not, and four separate writes live past the
// point where all decisions are made.
//
// Both cases were reproduced against the real binary before this test
// existed: a --unit-dir that cannot be written and a --unit-dir that is a
// regular file each left postern.yaml, host.key and boot.nft behind, after
// which the retry was refused by the already-exists guard — warning the
// operator about cached entries that were never issued, and leaving them to
// delete files they did not know existed.
//
// Mutation verified: replacing the installer's stage/commit with direct
// writes to the destinations fails both subtests, on the "nothing survives"
// assertion and again on the retry.
func TestMain_InitStandalone_LeavesNothingBehindWhenAWriteFails(t *testing.T) {
	sign, enc := publicKeyPairB64(t)

	for _, tc := range []struct {
		name string
		// breakUnitDir makes the unit directory unusable, and returns a
		// function that repairs it.
		breakUnitDir func(t *testing.T, path string) func()
	}{
		{
			// The reviewer's variant: MkdirAll fails outright because the
			// path is not a directory at all.
			name: "unit dir is a regular file",
			breakUnitDir: func(t *testing.T, path string) func() {
				t.Helper()
				if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return func() {
					if err := os.Remove(path); err != nil {
						t.Fatalf("Remove: %v", err)
					}
				}
			},
		},
		{
			// The originally reported case: the directory exists and cannot
			// be written, so the failure lands mid-install rather than at the
			// first step.
			name: "unit dir is not writable",
			breakUnitDir: func(t *testing.T, path string) func() {
				t.Helper()
				if os.Geteuid() == 0 {
					// The container suite runs as root, where mode bits do not
					// apply. Skipped rather than quietly asserting nothing.
					t.Skip("running as root: a read-only directory is still writable")
				}
				if err := os.MkdirAll(path, 0o500); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				return func() {
					if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // restoring a test directory to writable
						t.Fatalf("Chmod: %v", err)
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			etc := filepath.Join(dir, "etc")
			units := filepath.Join(dir, "units")
			repair := tc.breakUnitDir(t, units)

			args := []string{
				"init-standalone", "--no-nft-check",
				"--dir", etc,
				"--state-dir", filepath.Join(dir, "var"),
				"--unit-dir", units,
				"--host-name", "web-01",
				"--knock-addr", "203.0.113.9",
				"--always-allow-iface", "tailscale0", "--no-iface-check",
				"--exec-start", "/usr/local/bin/postern agent",
				"--operator", "laptop-primary=" + sign + "," + enc,
			}

			e, _, errBuf := envWithHome(t, dir)
			if code := runCLI(t, e, args...); code == exitOK {
				t.Fatalf("init-standalone succeeded with an unusable --unit-dir: %s", errBuf.String())
			}

			for _, name := range []string{"postern.yaml", "host.key", "boot.nft"} {
				if _, err := os.Stat(filepath.Join(etc, name)); err == nil {
					t.Errorf("%s survived a failed init-standalone; the retry then hits the "+
						"already-exists guard and the operator is told to --force past a warning "+
						"about cached entries that were never issued", name)
				}
			}
			// Not merely empty: absent. The installer's doc claims a failed run
			// leaves the host exactly as it was found, and an /etc/postern
			// this command created and then abandoned is not that. Both
			// directories are checked because a failure mid-stage has created
			// all three by then.
			for _, d := range []string{etc, filepath.Join(dir, "var")} {
				if _, err := os.Stat(d); err == nil {
					entries, _ := os.ReadDir(d)
					t.Errorf("%s was created by a run that failed and left behind: %v", d, entries)
				}
			}

			// The whole point: fix the problem, run the same command, and it
			// works — with no --force and no manual cleanup.
			repair()
			e2, _, errBuf2 := envWithHome(t, dir)
			if code := runCLI(t, e2, args...); code != exitOK {
				t.Fatalf("the retry after repairing --unit-dir failed: %s", errBuf2.String())
			}
			for _, name := range []string{"postern.yaml", "host.key", "boot.nft"} {
				if _, err := os.Stat(filepath.Join(etc, name)); err != nil {
					t.Errorf("the successful retry did not write %s: %v", name, err)
				}
			}
		})
	}
}

// Staging must not survive a successful install either: a .postern-install-*
// directory left in /etc/postern holds a second copy of the host key.
func TestMain_InitStandalone_LeavesNoStagingDirectoryBehind(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	units := filepath.Join(dir, "units")
	sign, enc := publicKeyPairB64(t)

	e, _, errBuf := envWithHome(t, dir)
	if code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", etc,
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", units,
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary="+sign+","+enc,
	); code != exitOK {
		t.Fatalf("exit = %d: %s", code, errBuf.String())
	}

	for _, d := range []string{etc, units} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatalf("ReadDir %s: %v", d, err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".postern-install-") {
				t.Errorf("staging directory %s survived in %s; it holds a second copy of the host key",
					entry.Name(), d)
			}
		}
	}
}

// initStandaloneExportArgs is the flag set every --export test builds on, so
// each test only states what it adds or overrides.
func initStandaloneExportArgs(dir, sign, enc string) []string {
	return []string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}
}

// --export exists so a file this process writes deliberately can replace one
// the invoking shell created under sudo, and the whole value of that trade
// is that it is the same entry, not a second one. hostEntry is computed once
// in initStandalone and handed to both stdout and the staged file; this is
// the test that would catch a regression back to rendering it twice, which
// host_id and the per-run generated keys would turn into two different
// entries from one invocation.
//
// Mutation verified: reverting initStandalone to call renderHostEntry a
// second time for the export write passes every other test in this file
// (the config it produces still validates, still plans, still installs) and
// fails only this byte-comparison.
func TestMain_InitStandalone_ExportWritesTheSameEntryAsStdout(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "entry.yaml")
	e, out, errBuf := envWithHome(t, dir)

	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}

	got, err := os.ReadFile(exportPath) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read exported entry: %v", err)
	}
	if string(got) != out.String() {
		t.Fatalf("the exported file does not match stdout:\n--- file ---\n%s\n--- stdout ---\n%s", got, out.String())
	}
	if out.String() == "" {
		t.Fatal("stdout is empty; --export is meant to be additive, not a replacement for the documented " +
			"redirection flow")
	}
	if !strings.Contains(errBuf.String(), exportPath) {
		t.Errorf("stderr does not mention the export path:\n%s", errBuf.String())
	}
}

// Re-running init-standalone mints a new host identity, which is exactly the
// operation that makes an old entry.yaml wrong. --export must not overwrite
// one without being told to, on the same reasoning postern.yaml and host.key
// already get: the file may be the operator's only local copy.
//
// Mutation verified: dropping the export existence check leaves the "with
// --force" test below unaffected and this one succeeds when it must refuse.
func TestMain_InitStandalone_ExportRefusesToOverwriteAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "entry.yaml")
	const stale = "stale entry from a previous host\n"
	if err := os.WriteFile(exportPath, []byte(stale), 0o644); err != nil { //nolint:gosec // a test fixture, deliberately world-readable like the real entry
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, errBuf := envWithHome(t, dir)
	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath)
	if code := runCLI(t, e, args...); code != exitUsage {
		t.Fatalf("exit = %d, want a refusal: %s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Fatalf("the refusal does not say how to proceed deliberately:\n%s", errBuf.String())
	}
	got, err := os.ReadFile(exportPath) //nolint:gosec // a test reading a file it just wrote
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != stale {
		t.Fatalf("the existing export file changed despite the refusal: %q", got)
	}
	// The refusal runs before anything is written, alongside the config/key
	// check it is modeled on, so a stale --export target must not have cost
	// the operator a working retry.
	for _, p := range []string{"postern.yaml", "host.key", "boot.nft"} {
		if _, err := os.Stat(filepath.Join(dir, "etc", p)); err == nil {
			t.Errorf("%s was written despite the --export refusal", p)
		}
	}
}

// The one override that lets --export replace a file that is there: the same
// --force that already lets postern.yaml and host.key be replaced, reused
// rather than duplicated because both refusals guard the same act of
// deliberately re-enrolling.
func TestMain_InitStandalone_ExportOverwritesWithForce(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "entry.yaml")
	if err := os.WriteFile(exportPath, []byte("stale entry from a previous host\n"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("WriteFile: %v", err)
	}

	e, out, errBuf := envWithHome(t, dir)
	args := append(initStandaloneExportArgs(dir, sign, enc), "--force", "--export", exportPath)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d with --force: %s", code, errBuf.String())
	}
	got, err := os.ReadFile(exportPath) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != out.String() {
		t.Fatalf("--force did not replace the stale export file with the new entry:\n%s", got)
	}
}

// --export is given a bare filename in the documented form, and the
// directory it names may not exist yet: the operator naming a fresh
// handoff directory is the ordinary case, not an error.
func TestMain_InitStandalone_ExportCreatesADirectoryThatDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "handoff", "entry.yaml")

	e, _, errBuf := envWithHome(t, dir)
	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited: %s", errBuf.String())
	}
	if _, err := os.Stat(exportPath); err != nil {
		t.Fatalf("--export did not create its directory: %v", err)
	}
}

// The entry carries only public material, the same fact README gives an
// operator as the reason it is fine to hand to anyone; a restrictive mode
// here would protect nothing and would just as easily break a workflow that
// scp's the file back with a non-root account.
//
// Mutation verified: changing the export write's mode to 0600 fails this and
// nothing else, since no other test reads this file's permissions.
func TestMain_InitStandalone_ExportWritesTheEntryWorldReadable(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "entry.yaml")

	e, _, errBuf := envWithHome(t, dir)
	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited: %s", errBuf.String())
	}
	info, err := os.Stat(exportPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("exported entry mode = %o, want 0644; it carries only public material", perm)
	}
}

// The other half of "leave nothing behind" (see
// TestMain_InitStandalone_LeavesNothingBehindWhenAWriteFails), now for
// --export: a write that fails after a new host identity has already been
// minted must not leave that identity installed with no captured entry and
// no clean retry.
func TestMain_InitStandalone_ExportFailureLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	// A regular file sitting where --export needs a directory, the same
	// shape of failure already covered for --unit-dir.
	blocker := filepath.Join(dir, "handoff")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	exportPath := filepath.Join(blocker, "entry.yaml")

	e, _, errBuf := envWithHome(t, dir)
	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath)
	if code := runCLI(t, e, args...); code == exitOK {
		t.Fatalf("init-standalone succeeded with an unusable --export directory: %s", errBuf.String())
	}
	for _, name := range []string{"postern.yaml", "host.key", "boot.nft"} {
		if _, err := os.Stat(filepath.Join(dir, "etc", name)); err == nil {
			t.Errorf("%s survived a failed --export; the retry then hits the already-exists guard and "+
				"the operator is told to --force past a warning about cached entries that were never "+
				"issued", name)
		}
	}
	for _, d := range []string{filepath.Join(dir, "etc"), filepath.Join(dir, "var"), filepath.Join(dir, "units")} {
		if _, err := os.Stat(d); err == nil {
			entries, _ := os.ReadDir(d)
			t.Errorf("%s was created by a run that failed and left behind: %v", d, entries)
		}
	}

	// The whole point: fix the problem, run the same command, and it works
	// with no --force and no manual cleanup.
	if err := os.Remove(blocker); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	e2, _, errBuf2 := envWithHome(t, dir)
	if code := runCLI(t, e2, args...); code != exitOK {
		t.Fatalf("the retry after removing the blocking file failed: %s", errBuf2.String())
	}
	if _, err := os.Stat(exportPath); err != nil {
		t.Errorf("the successful retry did not write the export file: %v", err)
	}
}

func TestMain_InitStandalone_GoLiveArmsAndPrintsTheConfirmLine(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "var")

	orig := systemctlRun
	t.Cleanup(func() { systemctlRun = orig })
	var reloaded, restarted bool
	systemctlRun = func(_ context.Context, args ...string) ([]byte, error) {
		switch {
		case len(args) == 1 && args[0] == "daemon-reload":
			reloaded = true
		case len(args) == 2 && args[0] == "restart" && args[1] == gate.PosterndUnitName:
			restarted = true
			// stand in for posternd: publish the pair a confirm must carry.
			rec := agent.ArmRecord{Revision: 1, Nonce: strings.Repeat("ab", 16), Outcome: agent.ArmPending}
			b, _ := json.Marshal(rec)
			if err := os.MkdirAll(stateDir, 0o750); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(stateDir, "pending.json"), b, 0o600); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	e, _, errOut := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	code := runCLI(t, e, "init-standalone", "--no-nft-check", "--go-live",
		"--dir", filepath.Join(dir, "etc"), "--state-dir", stateDir, "--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01", "--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent --config /etc/postern/postern.yaml",
		"--operator", "laptop="+sign+","+enc,
	)
	if code != exitOK {
		t.Fatalf("init-standalone --go-live exited %d\n%s", code, errOut.String())
	}
	if !reloaded || !restarted {
		t.Fatalf("go-live did not daemon-reload and restart posternd: reloaded=%v restarted=%v", reloaded, restarted)
	}
	want := "postern confirm web-01 --revision 1 --nonce " + strings.Repeat("ab", 16)
	if !strings.Contains(errOut.String(), want) {
		t.Fatalf("go-live did not print the confirm line %q:\n%s", want, errOut.String())
	}
}

func TestMain_InitStandalone_GoLiveReportsAStartFailureWithNoConfirmLine(t *testing.T) {
	dir := t.TempDir()
	orig := systemctlRun
	t.Cleanup(func() { systemctlRun = orig })
	systemctlRun = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) >= 1 && args[0] == "restart" {
			return []byte("Job for posternd.service failed"), fmt.Errorf("exit status 1")
		}
		return nil, nil
	}

	e, _, errOut := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	code := runCLI(t, e, "init-standalone", "--no-nft-check", "--go-live",
		"--dir", filepath.Join(dir, "etc"), "--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01", "--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent --config /etc/postern/postern.yaml",
		"--operator", "laptop="+sign+","+enc,
	)
	if code == exitOK {
		t.Fatal("init-standalone --go-live returned success despite a failed systemctl start")
	}
	if strings.Contains(errOut.String(), "postern confirm") {
		t.Fatalf("a failed arm still printed a confirm line:\n%s", errOut.String())
	}
	// The staged files are still on disk: a failed arm is not a failed enrollment.
	if _, err := os.Stat(filepath.Join(dir, "etc", "host.key")); err != nil {
		t.Fatalf("staged host.key missing after a failed --go-live arm: %v", err)
	}
}

// Rotation is the default (task 8): with no rotation flags at all,
// init-standalone must generate a port_rotation block with a full-size
// secret, the package defaults for window and range, and the generated
// config must still parse and validate through the same path the agent
// uses. The exported host entry has to carry the identical secret, byte for
// byte, or the client and the agent would derive different ports from the
// same window and neither would ever knock the other open.
//
// Mutation verified: generating the secret twice (once for the config, once
// for the entry) instead of resolving it once into o.portRotation before
// either render call makes the byte-for-byte comparison below fail.
func TestMain_InitStandalone_DefaultsToPortRotation(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "entry.yaml")
	e, _, errBuf := envWithHome(t, dir)

	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}

	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("the generated config does not parse:\n%v\n%s", err, body)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the generated config does not validate:\n%v\n%s", err, body)
	}
	if policy.PortRotation == nil {
		t.Fatalf("the generated config has no port_rotation block; rotation is supposed to be the default:\n%s", body)
	}
	if len(policy.PortRotation.Secret) != knockport.SecretSize {
		t.Fatalf("secret is %d bytes, want %d", len(policy.PortRotation.Secret), knockport.SecretSize)
	}
	if policy.PortRotation.Window != knockport.DefaultWindow {
		t.Fatalf("window = %s, want the default %s", policy.PortRotation.Window, knockport.DefaultWindow)
	}
	if policy.PortRotation.RangeLo != knockport.DefaultRangeLo || policy.PortRotation.RangeHi != knockport.DefaultRangeHi {
		t.Fatalf("range = %d-%d, want the default %d-%d", policy.PortRotation.RangeLo, policy.PortRotation.RangeHi,
			knockport.DefaultRangeLo, knockport.DefaultRangeHi)
	}

	entryBody, err := os.ReadFile(exportPath) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read exported entry: %v", err)
	}
	entry, _, err := parseHostEntry(entryBody)
	if err != nil {
		t.Fatalf("the exported host entry does not parse: %v\n%s", err, entryBody)
	}
	if entry.RawPortRotation == nil {
		t.Fatalf("the exported host entry has no port_rotation block:\n%s", entryBody)
	}
	entrySecret, err := base64.StdEncoding.DecodeString(entry.RawPortRotation.Secret)
	if err != nil {
		t.Fatalf("the entry's port_rotation secret is not base64: %v", err)
	}
	if !bytes.Equal(entrySecret, policy.PortRotation.Secret) {
		t.Fatalf("the config and the exported entry carry different secrets; the client and the agent "+
			"would derive different ports and never agree on a knock port.\nconfig secret:  %x\nentry secret:   %x",
			policy.PortRotation.Secret, entrySecret)
	}
}

// --no-port-rotation is the escape hatch: with it, the generated config has
// no port_rotation block at all and keeps a fixed spa_port, and the
// exported host entry keeps a fixed knock_port and carries no port_rotation
// either.
func TestMain_InitStandalone_NoPortRotationFallsBackToFixedSPAPort(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	exportPath := filepath.Join(dir, "entry.yaml")
	e, _, errBuf := envWithHome(t, dir)

	args := append(initStandaloneExportArgs(dir, sign, enc), "--export", exportPath, "--no-port-rotation")
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}

	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(body), "port_rotation") {
		t.Fatalf("--no-port-rotation still emitted a port_rotation block:\n%s", body)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("the generated config does not parse:\n%v\n%s", err, body)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the generated config does not validate:\n%v\n%s", err, body)
	}
	if policy.PortRotation != nil {
		t.Fatal("the parsed policy carries a port_rotation block despite --no-port-rotation")
	}
	if policy.SPAPort != 62201 {
		t.Fatalf("spa_port = %d, want the default 62201", policy.SPAPort)
	}

	entryBody, err := os.ReadFile(exportPath) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read exported entry: %v", err)
	}
	if strings.Contains(string(entryBody), "port_rotation") {
		t.Fatalf("--no-port-rotation still emitted a port_rotation block in the host entry:\n%s", entryBody)
	}
	if !strings.Contains(string(entryBody), "knock_port: 62201") {
		t.Fatalf("the host entry does not carry the fixed knock_port:\n%s", entryBody)
	}
}

// A rotation band that swallows a fixed service port would silently take
// that port away on whichever window happens to land on it. This is
// Policy.Validate's job (see validatePortRotation in internal/config), and
// the generator relies on it rather than duplicating the check: the config
// is fully rendered and parsed before init-standalone writes anything, so
// the refusal fires before the host is touched.
func TestMain_InitStandalone_RotationRangeOverlappingAServiceIsRefused(t *testing.T) {
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	e, _, errBuf := envWithHome(t, dir)

	args := append(initStandaloneExportArgs(dir, sign, enc), "--port-range", "20-30")
	if code := runCLI(t, e, args...); code == exitOK {
		t.Fatal("a rotation range covering ssh's port 22 was accepted")
	}
	if !strings.Contains(errBuf.String(), "ssh") || !strings.Contains(errBuf.String(), "22") {
		t.Fatalf("the refusal does not name the overlapping service:\n%s", errBuf.String())
	}
	for _, p := range []string{"postern.yaml", "host.key", "boot.nft"} {
		if _, err := os.Stat(filepath.Join(dir, "etc", p)); err == nil {
			t.Errorf("%s was written despite the refusal", p)
		}
	}
}
