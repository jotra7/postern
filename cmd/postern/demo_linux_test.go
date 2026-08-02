//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The whole loop, in the standard container harness: arm, knock, connect,
// expire, confirm, disarm, against real nftables and a real UDP socket.
//
// This is the only automated test in the repository that crosses every layer
// at once. Everything else drives one package with the next one faked, which
// is exactly the arrangement that lets two layers agree with their own tests
// and disagree with each other.
//
// It runs `postern demo`, which makes its own assertions — every one of them
// against `nft list ruleset` in a separate process or a real TCP connect —
// and returns a non-zero exit if any of them failed. What this test adds is
// that a failure becomes a test failure with the demo's output attached, and
// that the loop is re-run on every `scripts/linux-test.sh ./...`.
//
// Mutations verified against it: an arm step that publishes the nonce after
// arming (the demo still passes — the ordering property is asserted in
// internal/agent, not here), a gate.Open that never adds the element (fails
// at "the gate opened"), and a Close that deletes postern_boot's rules rather
// than flushing its sets (fails at the disarm assertions). Recorded in the
// task report.
func TestMain_Demo_RunsTheWholeSequenceAgainstRealNftables(t *testing.T) {
	requireRootAndNFT(t)

	dir := t.TempDir()
	e, out, errBuf := envWithHome(t, dir)
	// A port nothing in the container is using, so the demo brings its own
	// listener up behind the gate; and a short TTL, because the sequence
	// waits for it to lapse.
	code := runCLI(t, e, "demo",
		"--dir", dir,
		"--port", "62022",
		"--spa-port", "62201",
		"--ttl", "8s",
	)
	if code != exitOK {
		t.Fatalf("postern demo exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "all assertions passed") {
		t.Fatalf("demo exited 0 without reporting its assertions:\n%s", out.String())
	}
	t.Logf("demo output:\n%s", out.String())
}

// The demo leaves the machine as it found it. A demonstration that walks away
// from a host with drop rules on it is worse than no demonstration, and this
// is the one property the demo cannot assert about itself: its last assertion
// runs before its own cleanup does.
func TestMain_Demo_LeavesNoRulesBehind(t *testing.T) {
	requireRootAndNFT(t)

	dir := t.TempDir()
	e, out, _ := envWithHome(t, dir)
	if code := runCLI(t, e, "demo", "--dir", dir, "--port", "62022", "--ttl", "8s"); code != exitOK {
		t.Fatalf("postern demo exited %d:\n%s", code, out.String())
	}

	ruleset, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list ruleset: %v: %s", err, ruleset)
	}
	for _, table := range []string{"postern_boot", "postern_open"} {
		if strings.Contains(string(ruleset), "table inet "+table) {
			t.Fatalf("%s is still live after the demo finished:\n%s", table, ruleset)
		}
	}
}

func requireRootAndNFT(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the demo writes real firewall rules; run it through scripts/linux-test.sh")
	}
	if _, err := os.Stat("/usr/sbin/nft"); err != nil {
		t.Skip("nft(8) is not installed here; run this through scripts/linux-test.sh")
	}
}
