//go:build linux

package gate

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests execute the *rendered* ExecStopPost command lines — parsed out
// of the unit text RenderPosterndUnit produces, not a hand-written
// equivalent — against a live ruleset, then assert the resulting posture by
// reading `nft list ruleset` back. Assertions are on the kernel's own view
// of the ruleset rather than on postern's view of what it wrote, per the
// brief: a teardown that postern believes it performed and the kernel did
// not is exactly the failure mode this is guarding.
//
// The end-to-end forms of brief invariants 3 and 5 (corrupt the binary on
// disk then SIGKILL; reboot the container) need a real binary and a real
// systemd, and are carried forward to Task 5. What is verifiable here — and
// is verified here — is that the exact command lines systemd will run leave
// the posture the design specifies.

// runTeardownFromRenderedUnit parses the ExecStopPost directives out of the
// rendered texts and runs each the way systemd would: argv split on spaces,
// the leading "-" meaning failure is tolerated. The texts are given in the
// order systemd runs them — the main unit first, then its flush drop-in — so
// this reproduces the merged teardown a real host runs, where the per-set
// flush lines live in posternd.service.d/flush.conf rather than the unit
// (#47). Passing them separately here is exactly what systemd does with a
// drop-in.
func runTeardownFromRenderedUnit(t *testing.T, texts ...string) {
	t.Helper()
	ran := 0
	for _, text := range texts {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "ExecStopPost=") {
				continue
			}
			cmdline := strings.TrimPrefix(line, "ExecStopPost=")
			tolerate := strings.HasPrefix(cmdline, "-")
			cmdline = strings.TrimPrefix(cmdline, "-")
			argv := strings.Fields(cmdline)
			out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // argv comes from this package's own renderer, not from input
			if err != nil && !tolerate {
				t.Fatalf("ExecStopPost %q failed: %v\n%s", cmdline, err, out)
			}
			ran++
		}
	}
	if ran == 0 {
		t.Fatalf("rendered texts produced no ExecStopPost lines to run:\n%s", strings.Join(texts, "\n---\n"))
	}
}

func nftListRuleset(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list ruleset: %v\n%s", err, out)
	}
	return string(out)
}

// nftListSet returns one set's live definition, or "" if the set is gone.
func nftListSet(t *testing.T, table, name string) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "set", "inet", table, name).CombinedOutput() //nolint:gosec // table and name come from this package's own RulesetPlan, not from input
	if err != nil {
		return ""
	}
	return string(out)
}

// TestGate_UnitTeardown_LeavesFailClosedDropsStandingAndSetsEmpty is brief
// invariants 3 and 4 in the only form this task can verify without a binary:
// run the real rendered ExecStopPost lines against a real ruleset holding
// real open grants, then read the kernel back.
//
// The posture that must hold afterwards, per design section 7's I3 table:
//
//   - postern_open is gone entirely, so the fail-open service's ports are
//     unfiltered rather than dropped by rules nothing is left to open;
//   - postern_boot's drop rules are all still standing, so the fail-closed
//     services stay shut;
//   - postern_boot's gate sets still exist but hold nothing, so a grant
//     issued before the agent died does not outlive it.
//
// Mutating TeardownCommands to `nft flush table inet postern_boot` — the
// shortcut this invariant exists to forbid — leaves the sets empty and the
// drop rules *gone*, which this test catches on the drop-rule assertion.
func TestGate_UnitTeardown_LeavesFailClosedDropsStandingAndSetsEmpty(t *testing.T) {
	policy := fixturePolicy()
	g := newLinuxTestGate(t, policy)
	ctx := context.Background()
	plan := g.Plan()

	// Open a live grant in each table, so the teardown has something to
	// actually remove and "sets are empty" cannot pass vacuously.
	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.5/32")}
	if err := g.Open(ctx, "admin", src, 10*time.Minute); err != nil { // fail-closed, postern_boot
		t.Fatalf("Open admin: %v", err)
	}
	if err := g.Open(ctx, "ssh", src, 10*time.Minute); err != nil { // fail-open, postern_open
		t.Fatalf("Open ssh: %v", err)
	}
	if err := g.RefreshAgentUp(ctx, 90*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}

	before := nftListRuleset(t)
	if !strings.Contains(before, "table inet "+TableOpen) {
		t.Fatalf("precondition: %s is not live before teardown:\n%s", TableOpen, before)
	}
	adminSetBefore := nftListSet(t, TableBoot, "gate_admin_v4_obs")
	if !strings.Contains(adminSetBefore, "198.51.100.5") {
		t.Fatalf("precondition: the fail-closed grant is not live before teardown:\n%s", adminSetBefore)
	}

	nft := nftBinaryPath(t)
	unit, err := RenderPosterndUnit(plan, UnitOptions{
		ExecStart:   "/usr/local/bin/postern agent",
		NFTPath:     nft,
		BootNFTPath: "/etc/postern/boot.nft",
	})
	if err != nil {
		t.Fatalf("RenderPosterndUnit: %v", err)
	}
	// The flush lines live in the drop-in; systemd runs the unit's ExecStopPost
	// and then the drop-in's, so the kernel teardown here has to run both.
	runTeardownFromRenderedUnit(t, unit, RenderFlushDropIn(plan, nft))

	after := nftListRuleset(t)

	// 1. postern_open is gone outright: fail-open means open when postern is
	//    not running, and an nftables table outlives the process that made it.
	if strings.Contains(after, "table inet "+TableOpen) {
		t.Fatalf("%s survived teardown; a fail-open service's drop rules would stand with nothing "+
			"alive to open them:\n%s", TableOpen, after)
	}

	// 2. postern_boot's drop rules all stand. This is the assertion a
	//    `flush table` shortcut fails.
	if !strings.Contains(after, "table inet "+TableBoot) {
		t.Fatalf("%s was removed by teardown; the fail-closed posture is exactly those drop rules:\n%s", TableBoot, after)
	}
	for _, want := range []string{
		"tcp dport 8443 drop",  // admin, fail-closed
		"tcp dport 62202 drop", // canary, fail-closed
		"udp dport 62201 drop", // the SPA port's silence
		`iifname "tailscale0"`, // the always-allow path, never removed
		"ct state established,related accept",
	} {
		if !strings.Contains(after, want) {
			t.Fatalf("teardown removed %q from %s; the fail-closed posture is inverted:\n%s", want, TableBoot, after)
		}
	}

	// 3. Every fail-closed gate set still exists and holds nothing.
	for _, svc := range plan.BootServices() {
		for _, s := range svc.Sets {
			def := nftListSet(t, TableBoot, s.Name)
			if def == "" {
				t.Fatalf("set %s was deleted by teardown, not flushed; the accept rules referencing it "+
					"would fail to load at the next boot", s.Name)
			}
			if strings.Contains(def, "elements = {") {
				t.Fatalf("set %s still holds elements after teardown; a grant issued before the agent "+
					"died outlives it:\n%s", s.Name, def)
			}
		}
	}
}

// nftBinaryPath resolves nft(8) in the test container, which is Debian and
// puts it at /usr/sbin/nft — the same absolute path DefaultNFTPath names.
// Resolved rather than assumed so a container layout change fails loudly
// here instead of silently making every teardown line a tolerated no-op.
func nftBinaryPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("nft")
	if err != nil {
		t.Fatalf("nft(8) is not on PATH in this container: %v", err)
	}
	if path != DefaultNFTPath {
		t.Logf("note: nft resolved to %q, not DefaultNFTPath %q", path, DefaultNFTPath)
	}
	return path
}

// TestGate_UnitTeardown_ToleratesAnAbsentTableAndAbsentSets covers the
// leading "-" on every ExecStopPost line: systemd runs these on any exit,
// including one where postern_boot was never loaded (no fail-closed service
// armed yet) or postern_open was already removed. A teardown that aborts on
// the first "No such file or directory" would skip every line after it.
func TestGate_UnitTeardown_ToleratesAnAbsentTableAndAbsentSets(t *testing.T) {
	dropTablesViaNft(t)
	t.Cleanup(func() { dropTablesViaNft(t) })

	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	nft := nftBinaryPath(t)
	unit, err := RenderPosterndUnit(plan, UnitOptions{
		ExecStart: "/usr/local/bin/postern agent",
		NFTPath:   nft,
	})
	if err != nil {
		t.Fatalf("RenderPosterndUnit: %v", err)
	}

	// Every line fails against an empty ruleset; none of them may be fatal,
	// and all of them must still be attempted — the drop-in's flush lines
	// included, since a set that was never loaded is the exact absence the
	// leading "-" tolerates.
	runTeardownFromRenderedUnit(t, unit, RenderFlushDropIn(plan, nft))
}

// TestGate_RendererEquivalence_UnitTeardownAndCloseAgree extends invariant 6
// to the unit file's operational half. There are two ways postern's firewall
// state comes down — Close(), from inside a process that is stopping
// cleanly, and the unit's ExecStopPost lines, from outside a process that
// crashed — and design section 7 requires that "a crash that never reaches
// this method still lands in the same state via the unit file".
//
// Structural equivalence (render_test.go's
// TestGate_Render_FlushLinesNameExactlyTheBootFailClosedSets) compares the
// two set lists. This compares the two *outcomes*, hashed off `nft list
// table inet postern_boot` after each, which also covers the parts a set
// list cannot: that neither path deleted a set, neither touched a drop rule,
// and both removed postern_open.
//
// The mutation this catches: making Close() delete the sets rather than
// flush them, or making TeardownCommands flush the table. Either diverges
// the hashes.
func TestGate_RendererEquivalence_UnitTeardownAndCloseAgree(t *testing.T) {
	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.5/32")}
	ctx := context.Background()

	// agent_up is deliberately not refreshed in either arm: neither teardown
	// path touches it (the lease is designed to lapse on its own, which is
	// what covers a wedged agent that ExecStopPost never runs for), and its
	// live "expires" counter would differ between the two dumps and defeat
	// the hash comparison for a reason that has nothing to do with the
	// property under test.

	// Arm 1: teardown from inside the process.
	g := newLinuxTestGate(t, fixturePolicy())
	if err := g.Open(ctx, "admin", src, 10*time.Minute); err != nil {
		t.Fatalf("Open admin: %v", err)
	}
	if err := g.Open(ctx, "ssh", src, 10*time.Minute); err != nil {
		t.Fatalf("Open ssh: %v", err)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closeDump := dumpBootTable(t)
	if _, err := exec.Command("nft", "list", "table", "inet", TableOpen).Output(); err == nil {
		t.Fatal("Close left postern_open standing")
	}

	dropTablesViaNft(t)

	// Arm 2: teardown from outside it, through the rendered unit.
	g2 := newLinuxTestGate(t, fixturePolicy())
	if err := g2.Open(ctx, "admin", src, 10*time.Minute); err != nil {
		t.Fatalf("Open admin: %v", err)
	}
	if err := g2.Open(ctx, "ssh", src, 10*time.Minute); err != nil {
		t.Fatalf("Open ssh: %v", err)
	}
	nft := nftBinaryPath(t)
	unit, err := RenderPosterndUnit(g2.Plan(), UnitOptions{
		ExecStart: "/usr/local/bin/postern agent",
		NFTPath:   nft,
	})
	if err != nil {
		t.Fatalf("RenderPosterndUnit: %v", err)
	}
	// The out-of-process teardown is the unit plus its flush drop-in, the two
	// systemd merges; running only the unit would flush nothing and diverge
	// from Close() on every grant.
	runTeardownFromRenderedUnit(t, unit, RenderFlushDropIn(g2.Plan(), nft))
	unitDump := dumpBootTable(t)
	if _, err := exec.Command("nft", "list", "table", "inet", TableOpen).Output(); err == nil {
		t.Fatal("the unit's teardown left postern_open standing")
	}

	if normalizeAndHash(closeDump) != normalizeAndHash(unitDump) {
		t.Fatalf("in-process Close() and the unit's ExecStopPost lines leave different %s postures; "+
			"a crash and a clean stop must be indistinguishable in the firewall:\n"+
			"Close:\n%s\n\nunit:\n%s", TableBoot, closeDump, unitDump)
	}
}
