package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// confirmHome builds a host entry, enrolls it, and returns the home directory.
// The recovery service and the knock port both point at a closed port, so the
// arm-time liveness pre-check fails unless it is skipped -- which is exactly
// what these tests turn on and off. extra inserts additional entry lines (an
// always_allow_addr, or nothing for the single-path case).
func confirmHome(t *testing.T, extra string) string {
	t.Helper()
	closed := freePort(t)
	home := t.TempDir()
	entry := fmt.Sprintf(""+
		"name: web-01\n"+
		"host_id: 3a713a713a713a713a713a713a713a71\n"+
		"knock_addr: 127.0.0.1\n"+
		"knock_port: %d\n"+
		"%s"+
		"host_encryption: %s\n"+
		"recovery_service: ssh\n"+
		"services:\n"+
		"  ssh: { port: %d, ttl: 120s }\n", closed, extra, testHostEncryptionB64, closed)
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}
	return home
}

const confirmTestNonce = "0123456789abcdef0123456789abcdef"

// #48. A confirm makes an armed configuration permanent, so it first proves the
// operator still has a way back in (design section 7, I5). With an
// always_allow_addr recorded and nothing listening on the recovery service, the
// pre-check fails and the confirm is refused before a datagram is sent -- the
// lockout postern exists to prevent, stopped at the last point an operator
// still can.
func TestMain_Confirm_RefusesWhenTheRecoveryPathIsNotHealthy(t *testing.T) {
	e, out, errBuf := envWithHome(t, confirmHome(t, "always_allow_addr: 127.0.0.1\n"))
	code := runCLI(t, e, "confirm", "web-01", "--revision", "1", "--nonce", confirmTestNonce,
		"--wait", "200ms", "--timeout", "200ms")
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d: a confirm past a dead recovery path could lock the operator out\n%s",
			code, exitFailed, out.String())
	}
	if strings.Contains(out.String(), "confirm sent") {
		t.Fatalf("the confirm datagram was sent despite the liveness pre-check failing:\n%s", out.String())
	}
	if !strings.Contains(errBuf.String(), "refusing to confirm") || !strings.Contains(errBuf.String(), "--force") {
		t.Fatalf("the refusal does not name itself or the --force escape hatch:\n%s", errBuf.String())
	}
}

// #48. --force overrides the pre-check for an operator confirming from a spot
// the always-allow path does not reach (the split-plane case). The confirm then
// goes out; the dead-man timer is the safety net that remains.
func TestMain_Confirm_ForceSkipsTheLivenessPrecheck(t *testing.T) {
	e, out, _ := envWithHome(t, confirmHome(t, "always_allow_addr: 127.0.0.1\n"))
	code := runCLI(t, e, "confirm", "web-01", "--revision", "1", "--nonce", confirmTestNonce,
		"--force", "--sends", "1")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d with --force:\n%s", code, exitOK, out.String())
	}
	if !strings.Contains(out.String(), "confirm sent") {
		t.Fatalf("--force did not let the confirm through:\n%s", out.String())
	}
}

// #48. A host with no always-allow address recorded has no recovery path to
// prove: the single-path host the design allows to arm anyway. The pre-check is
// skipped and the confirm goes out without --force.
func TestMain_Confirm_SkipsThePrecheckWhenNoAlwaysAllowAddressIsRecorded(t *testing.T) {
	e, out, _ := envWithHome(t, confirmHome(t, "")) // no always_allow_addr line
	code := runCLI(t, e, "confirm", "web-01", "--revision", "1", "--nonce", confirmTestNonce, "--sends", "1")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d: a single-path host must still be confirmable\n%s",
			code, exitOK, out.String())
	}
	if !strings.Contains(out.String(), "confirm sent") {
		t.Fatalf("a single-path host's confirm did not go out:\n%s", out.String())
	}
}

// #console-recovery. A host enrolled with console-recovery records no
// always_allow_addr, so confirm has no recovery path to prove and ratifies over
// the public path without a pre-check, no --force needed.
func TestMain_Confirm_ConsoleRecoveryHostConfirmsWithoutAPrecheck(t *testing.T) {
	// confirmHome with no always_allow_addr line is exactly a console-recovery
	// host from the client's point of view.
	e, out, _ := envWithHome(t, confirmHome(t, ""))
	code := runCLI(t, e, "confirm", "web-01", "--revision", "1", "--nonce", confirmTestNonce, "--sends", "1")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d: a console-recovery host must be confirmable without --force\n%s", code, exitOK, out.String())
	}
	if !strings.Contains(out.String(), "confirm sent") {
		t.Fatalf("the console-recovery confirm did not go out:\n%s", out.String())
	}
}
