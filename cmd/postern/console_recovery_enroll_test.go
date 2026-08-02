package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/config"
)

// init-standalone --console-recovery writes a config that validates with no
// always_allow_iface and records the console route.
func TestMain_InitStandalone_ConsoleRecoveryWritesAValidNoAlwaysAllowConfig(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	if code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--no-iface-check",
		"--console-recovery", "https://provider.example/console",
		"--operator", "laptop="+sign+","+enc,
	); code != exitOK {
		t.Fatalf("init-standalone --console-recovery exited nonzero: %s", errBuf.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // test's own path
	if err != nil {
		t.Fatalf("no config written: %v", err)
	}
	if !strings.Contains(string(body), "console_recovery: true") {
		t.Fatalf("config does not record console_recovery:\n%s", body)
	}
	if strings.Contains(string(body), "always_allow_iface:") {
		t.Fatalf("console-recovery config wrote an always_allow_iface:\n%s", body)
	}
	p, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("generated console-recovery config does not validate: %v", err)
	}
}

// init-standalone accepts --console-recovery alongside --always-allow-iface:
// the iface is not suppressed, and both the iface and the console route land
// in the generated config.
func TestMain_InitStandalone_ConsoleRecoveryWithAnAlwaysAllowIfaceEmitsBoth(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	if code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--no-iface-check",
		"--always-allow-iface", "tailscale0",
		"--console-recovery", "https://provider.example/console",
		"--operator", "laptop="+sign+","+enc,
	); code != exitOK {
		t.Fatalf("init-standalone --console-recovery --always-allow-iface exited nonzero: %s", errBuf.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // test's own path
	if err != nil {
		t.Fatalf("no config written: %v", err)
	}
	if !strings.Contains(string(body), "always_allow_iface:") {
		t.Fatalf("config does not record always_allow_iface even though it was given:\n%s", body)
	}
	if !strings.Contains(string(body), "console_recovery: true") {
		t.Fatalf("config does not record console_recovery:\n%s", body)
	}
	if !strings.Contains(string(body), "console:") {
		t.Fatalf("config does not record console:\n%s", body)
	}
	p, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("generated config does not validate: %v", err)
	}
}
