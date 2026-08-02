package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --max-ttl exists because design section 6's example configuration cannot be
// generated without it: the admin operator's grant is capped at 300s and the
// probe operator's at 30s, in one file. Before this flag the generated grant
// was the literal "300s" for everybody.
//
// The blast radius today is nil, and that is the point rather than an excuse.
// agent/validate.go clamps a request against the *service's* max_ttl first, so
// the canary's own 60s already binds a probe key however wide its grant is. A
// value whose wrongness is masked by another value is one that becomes wrong
// silently, the first time somebody declares a service with a looser ceiling.

// initStandaloneArgs is the smallest invocation that writes a config off-host.
func initStandaloneArgs(t *testing.T, dir, sign, enc string, extra ...string) []string {
	t.Helper()
	return append([]string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}, extra...)
}

func generatedStandaloneConfig(t *testing.T, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	sign, enc := publicKeyPairB64(t)
	e, _, errBuf := envWithHome(t, dir)
	if code := runCLI(t, e, initStandaloneArgs(t, dir, sign, enc, extra...)...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(raw)
}

// TestMain_InitStandalone_MaxTTLReachesTheGeneratedGrant is the wiring: a flag
// that parsed and never reached the file would be a flag accepted and ignored.
func TestMain_InitStandalone_MaxTTLReachesTheGeneratedGrant(t *testing.T) {
	if got := generatedStandaloneConfig(t); !strings.Contains(got, "max_ttl: 300s") {
		t.Fatalf("the default grant ceiling is not 300s:\n%s", got)
	}
	got := generatedStandaloneConfig(t, "--max-ttl", "45s")
	if !strings.Contains(got, "max_ttl: 45s") {
		t.Fatalf("--max-ttl 45s did not reach the grant:\n%s", got)
	}
	if strings.Contains(got, "grants: [{ services: [\"ssh\", \"confirm\", \"disarm\", \"liveness\"], max_ttl: 300s") {
		t.Fatalf("the hardcoded 300s survived --max-ttl:\n%s", got)
	}
}

// TestMain_InitStandalone_MaxTTLIsPerOperator is design section 6's example,
// which a single global value cannot express: one file, two operators, two
// ceilings — and the probe's is the tighter one precisely because a stolen
// probe key should hold a gate for as little time as possible.
func TestMain_InitStandalone_MaxTTLIsPerOperator(t *testing.T) {
	signB, encB := publicKeyPairB64(t)
	got := generatedStandaloneConfig(t,
		"--operator", "probe-local="+signB+","+encB+":canary",
		"--max-ttl", "probe-local=30s")

	if !strings.Contains(got, `services: ["canary"], max_ttl: 30s`) {
		t.Fatalf("the probe operator's grant is not capped at 30s:\n%s", got)
	}
	if !strings.Contains(got, `"liveness"], max_ttl: 300s`) {
		t.Fatalf("naming one operator changed another's ceiling:\n%s", got)
	}
}

// TestMain_InitStandalone_MaxTTLBareFormThenNamedFormNarrowsOne covers the
// order the flag documents: a bare value sets everybody, a later named value
// overrides one of them.
func TestMain_InitStandalone_MaxTTLBareFormThenNamedFormNarrowsOne(t *testing.T) {
	signB, encB := publicKeyPairB64(t)
	got := generatedStandaloneConfig(t,
		"--operator", "probe-local="+signB+","+encB+":canary",
		"--max-ttl", "120s", "--max-ttl", "probe-local=30s")

	if !strings.Contains(got, `services: ["canary"], max_ttl: 30s`) {
		t.Fatalf("the named form did not override the bare one:\n%s", got)
	}
	if !strings.Contains(got, `"liveness"], max_ttl: 120s`) {
		t.Fatalf("the bare form did not reach the operator the named form did not mention:\n%s", got)
	}
}

// The refusals are here, on the host, with the operator watching and nothing
// written — the same position as every other enrollment-time refusal in this
// command.
func TestMain_InitStandalone_RefusesMaxTTLValuesThatBoundNothingOrCannotLoad(t *testing.T) {
	sign, enc := publicKeyPairB64(t)
	for _, tc := range []struct {
		name  string
		extra []string
		says  string
	}{
		{"not a duration", []string{"--max-ttl", "300"}, "not a duration"},
		{"zero", []string{"--max-ttl", "0s"}, "not positive"},
		{"negative", []string{"--max-ttl", "-30s"}, "not positive"},
		{"finer than a second", []string{"--max-ttl", "1500ms"}, "whole seconds"},
		{"beyond the wire limit", []string{"--max-ttl", "70000s"}, "65535"},
		{"a name matching no operator", []string{"--max-ttl", "laptop-primry=30s"}, "laptop-primary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			e, _, errBuf := envWithHome(t, dir)
			if code := runCLI(t, e, initStandaloneArgs(t, dir, sign, enc, tc.extra...)...); code != exitUsage {
				t.Fatalf("exit = %d, want a usage refusal: %s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tc.says) {
				t.Fatalf("the refusal does not mention %q, so an operator cannot act on it:\n%s",
					tc.says, errBuf.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "etc", "postern.yaml")); err == nil {
				t.Fatal("a config was written despite the refusal; the retry after fixing the flag then " +
					"hits the already-exists guard")
			}
		})
	}
}
