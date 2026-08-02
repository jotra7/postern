package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/gate"
)

// metricsInitArgs is initArgs without --exec-start, so the generated command
// line is the one under test rather than one the operator supplied.
func metricsInitArgs(dir, sign, enc string, extra ...string) []string {
	args := []string{
		"init-standalone", "--no-nft-check", "--no-iface-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}
	return append(args, extra...)
}

func posterndExecStart(t *testing.T, dir string) string {
	t.Helper()
	unit, err := os.ReadFile(filepath.Join(dir, "units", gate.PosterndUnitName)) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("no generated %s: %v", gate.PosterndUnitName, err)
	}
	for _, line := range strings.Split(string(unit), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			return line
		}
	}
	t.Fatalf("no ExecStart in the generated unit:\n%s", unit)
	return ""
}

// TestMain_InitStandalone_MetricsListenReachesTheGeneratedUnit is the wiring
// between the enrollment flag and the thing systemd actually runs. Without
// it, --metrics-listen is a flag that parses and changes nothing about the
// host it was aimed at.
func TestMain_InitStandalone_MetricsListenReachesTheGeneratedUnit(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e, metricsInitArgs(dir, sign, enc, "--metrics-listen", ":9873")...)
	if code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	if got := posterndExecStart(t, dir); !strings.Contains(got, "--metrics-listen :9873") {
		t.Fatalf("generated %s, want it to carry --metrics-listen :9873", got)
	}
}

// TestMain_InitStandalone_WithoutMetricsListenTheUnitServesNothing keeps the
// endpoint opt-in. /metrics on a root daemon publishes gate state, so a host
// that was never asked to serve it must not.
func TestMain_InitStandalone_WithoutMetricsListenTheUnitServesNothing(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e, metricsInitArgs(dir, sign, enc)...)
	if code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	if got := posterndExecStart(t, dir); strings.Contains(got, "--metrics-listen") {
		t.Fatalf("generated %s with no --metrics-listen asked for", got)
	}
}

// TestMain_InitStandalone_RefusesAWildcardMetricsListen refuses at the only
// point where refusing is free: the operator still has a working way in and
// nothing has been written. The same shape as the loopback always-allow
// refusal, for the same reason.
func TestMain_InitStandalone_RefusesAWildcardMetricsListen(t *testing.T) {
	for _, spec := range []string{"0.0.0.0:9873", "[::]:9873", "metrics.example.com:9873"} {
		t.Run(spec, func(t *testing.T) {
			dir := t.TempDir()
			e, _, errBuf := envWithHome(t, dir)
			sign, enc := publicKeyPairB64(t)

			code := runCLI(t, e, metricsInitArgs(dir, sign, enc, "--metrics-listen", spec)...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d: --metrics-listen %s was accepted, so this host would "+
					"publish a root daemon's gate state where it was never meant to go", code, exitUsage, spec)
			}
			for _, p := range []string{"etc/postern.yaml", "etc/host.key", "etc/boot.nft"} {
				if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
					t.Errorf("%s was written despite the refusal; a command that fails must leave the "+
						"host as it found it", p)
				}
			}
			if errBuf.Len() == 0 {
				t.Error("the refusal said nothing")
			}
		})
	}
}

// TestMain_InitStandalone_DoesNotEditAnOperatorSuppliedExecStart: someone who
// wrote the whole command line owns what is on it. Appending to it is how a
// duplicate or contradictory argument ends up in a unit nobody reads again
// until the day it matters.
func TestMain_InitStandalone_DoesNotEditAnOperatorSuppliedExecStart(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e, metricsInitArgs(dir, sign, enc,
		"--exec-start", "/usr/local/bin/postern agent --metrics-listen 100.64.0.7:9999",
		"--metrics-listen", ":9873")...)
	if code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	got := posterndExecStart(t, dir)
	if strings.Contains(got, ":9873") {
		t.Fatalf("generated %s; the operator's own --exec-start was appended to", got)
	}
	if !strings.Contains(got, "100.64.0.7:9999") {
		t.Fatalf("generated %s, want the operator's command line unchanged", got)
	}
}
