package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/client"
)

// host add is #28's split of the host-registering half of the old combined
// enroll. See cmd_operator_test.go for the identity-minting half.
//
// The ssh-orchestration this file used to drive is gone entirely (#28's
// follow-up): `host add` only ever reads a file now, and the destructive
// re-key has no verb at all anymore. Both surfaces must be
// recognised-and-rejected, not silently accepted.

// cannedHostEntry is the minimum an entry needs to become a loadable client
// config, for tests whose subject is host add rather than what
// init-standalone produces.
const cannedHostEntry = "" +
	"name: web-01\n" +
	"host_id: 3a713a713a713a713a713a713a713a71\n" +
	"knock_addr: 203.0.113.9\n" +
	"knock_port: 62201\n" +
	"host_encryption: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
	"services:\n" +
	"  ssh: { port: 22 }\n"

// A non-exitOK code alone is not proof --ssh is gone: the old --ssh flag
// really did shell out to ssh(1), and in a sandbox with no route to
// "root@web-01" that shells out and fails on its own, for a reason that has
// nothing to do with the flag being recognised. So this asserts the actual
// failure reason — the flag package rejecting an unknown flag — which is
// the one thing that cannot happen if --ssh were still wired up.
func TestMain_HostAdd_SSHFlagIsGone(t *testing.T) {
	dir := t.TempDir()
	e, _, errOut := envWithHome(t, dir)
	if code := runCLI(t, e, "operator", "init", "--operator", "laptop", "--no-passphrase"); code != exitOK {
		t.Fatalf("operator init exited %d", code)
	}
	code := runCLI(t, e, "host", "add", "web-01", "--ssh", "root@web-01")
	if code == exitOK {
		t.Fatalf("host add --ssh still succeeds; the ssh path must be gone:\n%s", errOut.String())
	}
	said := errOut.String()
	if !strings.Contains(said, "flag provided but not defined") || !strings.Contains(said, "-ssh") {
		t.Fatalf("host add --ssh failed, but not visibly because --ssh is an unknown flag — this must "+
			"fail at flag parsing, not for some incidental reason (like a real ssh attempt failing on a "+
			"network this sandbox does not have):\n%s", said)
	}
}

// Same reasoning as above: the refusal has to be "rotate-key is not a verb
// this command knows", not merely some non-zero exit. The command's own
// usage lists its real verbs, so rotate-key must be both called out as
// unknown and absent from that list.
func TestMain_HostRotateKey_VerbIsGone(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	code := runCLI(t, e, "host", "rotate-key", "web-01", "--ssh", "root@web-01")
	if code == exitOK {
		t.Fatal("host rotate-key still exists; it must be removed with the ssh layer")
	}
	said := errBuf.String()
	if !strings.Contains(said, "unknown verb") {
		t.Fatalf("host rotate-key failed, but not visibly because the verb is unrecognised:\n%s", said)
	}
	verbsStart := strings.Index(said, "verbs:")
	if verbsStart < 0 {
		t.Fatalf("the refusal did not print the usage naming the valid verbs:\n%s", said)
	}
	verbsBlock := said[verbsStart:]
	if end := strings.Index(verbsBlock, "\n\n"); end >= 0 {
		verbsBlock = verbsBlock[:end]
	}
	if strings.Contains(verbsBlock, "rotate-key") {
		t.Fatalf("the printed verb list still names rotate-key as a real verb:\n%s", said)
	}
}

// host add assumes operator init already ran; unlike the old combined
// enroll it never mints an identity, so a missing one is a refusal naming
// the command that creates one.
func TestMain_HostAdd_RefusesWithoutAnOperatorIdentity(t *testing.T) {
	home := t.TempDir()
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(cannedHostEntry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "host", "add", "web-01", "--from", entryPath); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "postern operator init") {
		t.Fatalf("the refusal does not name the command that creates one:\n%s", errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(home, "config.yaml")); err == nil {
		t.Fatal("a client config was written despite there being no operator identity")
	}
}

// host add needs --from; unlike the deprecated enroll it does not fall back
// to printing setup instructions, because "add" that adds nothing is not the
// same command as "print what I would need to add".
func TestMain_HostAdd_RequiresFrom(t *testing.T) {
	home := operatorInitHome(t)
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "host", "add", "web-01"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "--from") {
		t.Fatalf("the refusal does not mention --from:\n%s", errBuf.String())
	}
}

// operatorInitHome mints an operator identity in a fresh home directory the
// way `postern operator init` does, for tests whose subject is host add
// rather than the identity itself.
func operatorInitHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "operator", "init", "--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("operator init exited %d: %s", code, errBuf.String())
	}
	return home
}

// The ordinary path: operator init, then host add --from, registers the
// host in a freshly-written client config.
func TestMain_HostAdd_RegistersFromAFile(t *testing.T) {
	home := operatorInitHome(t)
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(cannedHostEntry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "host", "add", "web-01", "--from", entryPath); code != exitOK {
		t.Fatalf("host add exited %d: %s", code, errBuf.String())
	}
	cfg, err := client.LoadConfig(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if _, err := cfg.Host("web-01"); err != nil {
		t.Fatalf("Host: %v", err)
	}
	if cfg.Operator != "laptop-primary" {
		t.Fatalf("config names operator %q, want the identity operator init minted", cfg.Operator)
	}
}

// Re-running host add replaces the entry rather than appending a second one,
// same as the deprecated enroll's equivalent behaviour: a config with two
// web-01 blocks does not load at all.
func TestMain_HostAdd_ReplacesAnExistingHostEntry(t *testing.T) {
	home := operatorInitHome(t)
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(cannedHostEntry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for i := 0; i < 2; i++ {
		e, _, errBuf := envWithHome(t, home)
		if code := runCLI(t, e, "host", "add", "web-01", "--from", entryPath); code != exitOK {
			t.Fatalf("host add #%d exited %d: %s", i, code, errBuf.String())
		}
	}
	cfg, err := client.LoadConfig(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("%d host entries after two host adds, want 1", len(cfg.Hosts))
	}
}

// --no-passphrase only ever matters when minting a key, and host add never
// mints one — see loadOperatorIdentity. Binding it anyway would be a flag
// that is accepted and silently does nothing, which is the same defect as a
// check that is never wired in. So it must not even parse.
//
// Mutation verified: binding the full clientFlags set (cf.bind instead of
// cf.bindForExistingKey) in runHostAdd fails this, because --no-passphrase
// would then be accepted.
func TestMain_HostAdd_DoesNotAcceptNoPassphrase(t *testing.T) {
	home := operatorInitHome(t)
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(cannedHostEntry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "host", "add", "web-01", "--from", entryPath, "--no-passphrase"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal (the flag does not exist here):\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no-passphrase") {
		t.Fatalf("the refusal does not name the flag:\n%s", errBuf.String())
	}
}

func TestMain_Host_UnknownVerbIsAUsageError(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "host", "bogus"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "unknown verb") {
		t.Fatalf("the refusal does not say the verb is unknown:\n%s", errBuf.String())
	}
}
