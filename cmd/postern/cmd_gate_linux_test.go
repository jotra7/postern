//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// generatedConfig runs init-standalone and returns the host config path plus
// its parsed plan, so these tests drive the same artifact an operator would
// actually point --config at.
func generatedConfig(t *testing.T) (string, *gate.RulesetPlan) {
	t.Helper()
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
	path := filepath.Join(dir, "etc", "postern.yaml")
	body, err := os.ReadFile(path) //nolint:gosec // a test reading a file it just generated
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
	return path, plan
}

// The two commands, driven end to end through the dispatcher with --dry-run,
// so what they would run is observable without touching the container's
// netfilter state.
//
// gateops_test.go pins the selection property portably; this pins that the
// commands are actually wired to it — that gate-flush is not accidentally
// registered with includeOpen true, and that both resolve --nft and --config
// the way an operator would pass them.
func TestMain_GateCommands_DryRunPrintsWhatTheUnitWouldRun(t *testing.T) {
	configPath, plan := generatedConfig(t)

	for _, tc := range []struct {
		name        string
		includeOpen bool
	}{
		{"gate-teardown", true},
		{"gate-flush", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, out, errBuf := testEnv()
			if code := runCLI(t, e, tc.name, "--config", configPath, "--nft", "/usr/sbin/nft", "--dry-run"); code != exitOK {
				t.Fatalf("exit = %d: %s", code, errBuf.String())
			}
			var want []string
			for _, argv := range gateCommands(plan, "/usr/sbin/nft", tc.includeOpen) {
				want = append(want, strings.Join(argv, " "))
			}
			got := splitNonEmptyLines(out.String())
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("%s would run:\n%s\nwant:\n%s", tc.name, strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if tc.name == "gate-flush" {
				for _, line := range got {
					if strings.Contains(line, "delete table") {
						t.Fatalf("gate-flush would delete a table: %q", line)
					}
				}
			}
		})
	}
}

// A dry run must not touch anything. This is the flag an operator reaches
// for when they are not yet sure, on a host they are already worried about.
func TestMain_GateTeardown_DryRunLeavesTheRulesetAlone(t *testing.T) {
	configPath, _ := generatedConfig(t)
	e, out, _ := testEnv()
	if code := runCLI(t, e, "gate-teardown", "--config", configPath, "--nft", "/nonexistent/nft", "--dry-run"); code != exitOK {
		t.Fatalf("a dry run with a nonexistent nft failed, so it was trying to execute it")
	}
	if !strings.Contains(out.String(), "/nonexistent/nft") {
		t.Fatalf("the dry run did not print the commands:\n%s", out.String())
	}
}

func TestMain_GateCommands_RefuseAConfigTheyCannotRead(t *testing.T) {
	for _, name := range []string{"gate-teardown", "gate-flush"} {
		t.Run(name, func(t *testing.T) {
			e, _, errBuf := testEnv()
			if code := runCLI(t, e, name, "--config", "/nonexistent.yaml"); code != exitUsage {
				t.Fatalf("exit = %d, want a usage refusal", code)
			}
			if !strings.Contains(errBuf.String(), "nonexistent.yaml") {
				t.Fatalf("the refusal does not name the file:\n%s", errBuf.String())
			}
		})
	}
}

// splitNonEmptyLines is readLines for a buffer rather than a file.
func splitNonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
