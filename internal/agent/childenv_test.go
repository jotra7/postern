package agent_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/gate"
)

// posternd runs under Type=notify with NotifyAccess=main, so systemd hands it
// NOTIFY_SOCKET and reads the sender's PID off that socket rather than
// believing the datagram. Every child the prepare and arm paths spawn used to
// inherit the variable, which on a live host produced one "Got notification
// message from PID N, but reception only permitted for main PID M" per child.
// Widening the unit to NotifyAccess=all would silence those and cost the
// watchdog: a WATCHDOG=1 from any descendant would then pet the timer for a
// packet loop that had wedged. The children give up the socket instead.
//
// These tests run the real methods against stub binaries that record the
// environment they were handed, so what is asserted is what a child actually
// received, not what the code was believed to construct.
//
// The canary matters as much as the absence. A spawn site that handed its
// child an empty environment would satisfy "no NOTIFY_SOCKET" while breaking
// every script and tool that reads PATH, so each assertion below also
// requires the parent's other variables to have arrived.
const childEnvCanary = "POSTERN_CHILDENV_CANARY=present"

// envDumpStub writes an executable that appends its environment to a log, one
// NAME=VALUE per line, drains any stdin it is given, and then prints stdout
// and exits zero so the caller under test can finish normally.
//
// stdout is delivered through a file rather than interpolated into the
// script, so the shell never sees it as a word to quote or a format string to
// expand.
func envDumpStub(t *testing.T, stdout string) (path, envLog string) {
	t.Helper()

	dir := t.TempDir()
	path = filepath.Join(dir, "stub")
	envLog = filepath.Join(dir, "env.log")
	outPath := filepath.Join(dir, "stdout")
	if err := os.WriteFile(outPath, []byte(stdout), 0o600); err != nil {
		t.Fatalf("write stub stdout: %v", err)
	}
	script := fmt.Sprintf("#!/bin/sh\nenv >> %q\ncat >/dev/null\ncat %q\nexit 0\n", envLog, outPath)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable stub is the point
		t.Fatalf("write stub: %v", err)
	}
	return path, envLog
}

// notifyingParent puts this process in the state systemd puts posternd in:
// NOTIFY_SOCKET set, alongside an ordinary variable that must still reach
// children.
func notifyingParent(t *testing.T) {
	t.Helper()
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	t.Setenv("POSTERN_CHILDENV_CANARY", "present")
}

// assertChildEnv reads a stub's environment log and requires wantSpawns
// separate invocations, none of which saw NOTIFY_SOCKET and all of which saw
// everything else.
func assertChildEnv(t *testing.T, envLog string, wantSpawns int) {
	t.Helper()

	body, err := os.ReadFile(envLog) //nolint:gosec // this test's own temp path
	if err != nil {
		t.Fatalf("read child environment log: %v", err)
	}
	spawns := 0
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "NOTIFY_SOCKET=") {
			t.Errorf("the child was handed %q; systemd attributes an sd_notify from it to posternd "+
				"and discards it under NotifyAccess=main", line)
		}
		if line == childEnvCanary {
			spawns++
		}
	}
	if spawns != wantSpawns {
		t.Fatalf("the parent's environment reached %d child invocations, want %d; either a spawn did not "+
			"happen or its child was handed a stripped environment rather than a filtered one", spawns, wantSpawns)
	}
}

// The mutation this catches: dropping childenv.Sanitize from Enabled.
func TestAgent_SystemdUnitEnabled_DoesNotPassNotifySocketToSystemctl(t *testing.T) {
	notifyingParent(t)
	stub, envLog := envDumpStub(t, "enabled\n")

	u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: stub}
	if _, err := u.Enabled(context.Background()); err != nil {
		t.Fatalf("Enabled: %v", err)
	}

	assertChildEnv(t, envLog, 1)
}

// The mutation this catches: dropping childenv.Sanitize from SetEnabled.
func TestAgent_SystemdUnitSetEnabled_DoesNotPassNotifySocketToSystemctl(t *testing.T) {
	notifyingParent(t)
	stub, envLog := envDumpStub(t, "")

	u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: stub}
	if err := u.SetEnabled(context.Background(), true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	assertChildEnv(t, envLog, 1)
}

// The mutation this catches: dropping childenv.Sanitize from Snapshot.
func TestAgent_NFTRulesetSnapshot_DoesNotPassNotifySocketToNFT(t *testing.T) {
	notifyingParent(t)
	stub, envLog := envDumpStub(t, "table inet postern_boot {\n}\n")

	r := agent.NFTRuleset{NFT: stub}
	if _, err := r.Snapshot(context.Background()); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	assertChildEnv(t, envLog, 1)
}

// Restore spawns nft twice, a delete and then a load, and the load is the one
// that reads the snapshot on stdin, so a fix applied to only the first would
// still hand the socket to the process that does the work. Both are counted.
//
// The mutation this catches: dropping childenv.Sanitize from either spawn in
// Restore.
func TestAgent_NFTRulesetRestore_DoesNotPassNotifySocketToEitherNFT(t *testing.T) {
	notifyingParent(t)
	stub, envLog := envDumpStub(t, "")

	r := agent.NFTRuleset{NFT: stub}
	if err := r.Restore(context.Background(), []byte("table inet postern_boot {\n}\n")); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	assertChildEnv(t, envLog, 2)
}
