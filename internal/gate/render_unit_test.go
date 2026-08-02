package gate

import (
	"strings"
	"testing"
	"time"
)

func mustUnitOptions() UnitOptions {
	return UnitOptions{
		ExecStart:        "/usr/local/bin/postern agent --config /etc/postern/postern.yaml",
		BootNFTPath:      "/etc/postern/boot.nft",
		WatchdogInterval: 90 * time.Second,
	}
}

func mustPosterndUnit(t *testing.T) string {
	t.Helper()
	out, err := RenderPosterndUnit(mustPlan(t), mustUnitOptions())
	if err != nil {
		t.Fatalf("RenderPosterndUnit: %v", err)
	}
	return out
}

// mustFlushDropIn renders the flush drop-in for the shared fixture plan. The
// per-set flush lines the main unit used to carry live here now (#47), so the
// properties that were asserted against the unit's flush lines are asserted
// against this instead.
func mustFlushDropIn(t *testing.T) string {
	t.Helper()
	return RenderFlushDropIn(mustPlan(t), DefaultNFTPath)
}

// execStopPostLines returns the command lines the rendered unit's
// ExecStopPost directives will run, with systemd's leading "-" (tolerate
// failure) stripped. Tests parse the rendered text rather than calling
// TeardownCommands directly wherever the property under test is about what
// systemd will actually execute.
func execStopPostLines(t *testing.T, unit string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStopPost=") {
			continue
		}
		out = append(out, strings.TrimPrefix(strings.TrimPrefix(line, "ExecStopPost="), "-"))
	}
	if len(out) == 0 {
		t.Fatalf("rendered unit has no ExecStopPost lines:\n%s", unit)
	}
	return out
}

// Brief invariant 3, the half this task owns: fail-open enforcement is
// carried out by nft(8), invoked by absolute path, and never by the postern
// binary. A bad upgrade that replaces the binary followed by a crash must
// still tear postern_open down. Break it by rendering
// "ExecStopPost=-%s gate-teardown" from opts.ExecStart and this fails.
func TestGate_RenderUnit_TeardownInvokesNFTByAbsolutePathNeverThePosternBinary(t *testing.T) {
	unit := mustPosterndUnit(t)
	opts := mustUnitOptions()
	binary := strings.Fields(opts.ExecStart)[0]

	// Both the main unit and the drop-in run on the same crash path, so the
	// property has to hold across both — a flush line in the drop-in that
	// named the postern binary would be as unrunnable after a bad upgrade as
	// one in the unit.
	for _, line := range append(execStopPostLines(t, unit), execStopPostLines(t, mustFlushDropIn(t))...) {
		argv0 := strings.Fields(line)[0]
		if argv0 != DefaultNFTPath {
			t.Fatalf("ExecStopPost line %q does not invoke %s by absolute path; teardown must not depend "+
				"on anything a bad upgrade could have replaced", line, DefaultNFTPath)
		}
		if strings.Contains(line, binary) || strings.Contains(line, "postern ") {
			t.Fatalf("ExecStopPost line %q names the postern binary; a corrupt binary must not be able "+
				"to prevent fail-open teardown", line)
		}
	}
}

// Brief invariant 4: the fail-closed teardown empties gate sets one at a
// time, one generated "flush set" line per set. "nft flush table inet
// postern_boot" would delete the drop rules out of the chain and invert the
// posture — the exact silent failure I3 exists to prevent. Break it by
// collapsing the per-set lines into a single flush-table line and this
// fails. The flush lines live in the drop-in now (#47), so this asserts the
// property there.
func TestGate_RenderUnit_TeardownFlushesSetsOneAtATimeNeverTheTable(t *testing.T) {
	plan := mustPlan(t)
	dropIn := mustFlushDropIn(t)
	lines := execStopPostLines(t, dropIn)

	// Scanned over directive lines rather than the whole file, matching how
	// the sibling checks read the unit: a "flush table" anywhere in an
	// ExecStopPost is the hazard, a mention in a comment is not.
	for _, line := range strings.Split(dropIn, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "flush table") {
			t.Fatalf("drop-in directive %q flushes a table, which would delete the drop rules "+
				"and invert the fail-closed posture", line)
		}
		if strings.Contains(line, "flush ruleset") {
			t.Fatalf("drop-in directive %q flushes the ruleset", line)
		}
	}

	want := map[string]bool{}
	for _, svc := range plan.BootServices() {
		for _, s := range svc.Sets {
			want[s.Name] = true
		}
	}
	if len(want) == 0 {
		t.Fatal("fixture policy has no fail-closed gate sets; this test would be vacuous")
	}

	got := map[string]bool{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 6 || fields[1] != "flush" || fields[2] != "set" {
			continue
		}
		if fields[3] != "inet" || fields[4] != TableBoot {
			t.Fatalf("flush line %q does not target inet %s", line, TableBoot)
		}
		name := fields[5]
		if !want[name] {
			t.Fatalf("flush line %q names %q, which is not a %s gate set", line, name, TableBoot)
		}
		if got[name] {
			t.Fatalf("set %q is flushed by more than one line", name)
		}
		got[name] = true
	}
	if len(got) != len(want) {
		t.Fatalf("rendered %d flush-set lines, want one per %s gate set (%d): got %v want %v",
			len(got), TableBoot, len(want), got, want)
	}
}

// postern_open is deleted outright (it has no boot persistence, so its drop
// rules must not outlive the agent); postern_boot is never deleted, because
// its drop rules are exactly what fail-closed means when postern is dead.
func TestGate_RenderUnit_TeardownDeletesPosternOpenAndNeverPosternBoot(t *testing.T) {
	unit := mustPosterndUnit(t)
	lines := execStopPostLines(t, unit)

	deletes := 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "delete" {
			continue
		}
		if strings.Contains(line, TableBoot) {
			t.Fatalf("ExecStopPost line %q deletes %s; its drop rules are the fail-closed posture "+
				"and must survive the agent", line, TableBoot)
		}
		if line != DefaultNFTPath+" delete table inet "+TableOpen {
			t.Fatalf("unexpected delete line %q", line)
		}
		deletes++
	}
	if deletes != 1 {
		t.Fatalf("got %d delete lines, want exactly one (delete table inet %s)", deletes, TableOpen)
	}
	if !strings.Contains(unit, "ExecStopPost=-"+DefaultNFTPath+" delete table inet "+TableOpen) {
		t.Fatalf("rendered unit is missing the fail-open teardown line:\n%s", unit)
	}
}

// Renderer equivalence applied to the third artifact (design section 11).
// systemd runs the main unit's ExecStopPost lines and then the drop-in's, in
// that order; that concatenation must be exactly TeardownCommands, which is
// derived from the same RulesetPlan the netlink writer and boot.nft renderer
// consume. This is the property the #47 split has to preserve: the flush
// half moved to a drop-in, but reassembled with the delete half it is still
// one teardown from one source. Break it by having either renderer build its
// lines from its own loop over plan.BootServices() and the reassembly stops
// matching — the divergence invariant 6 exists to make impossible.
func TestGate_RenderUnit_ExecStopPostAcrossUnitAndDropInIsExactlyTeardownCommands(t *testing.T) {
	plan := mustPlan(t)
	unit := mustPosterndUnit(t)
	dropIn := mustFlushDropIn(t)

	cmds := TeardownCommands(plan, DefaultNFTPath)
	lines := append(execStopPostLines(t, unit), execStopPostLines(t, dropIn)...)
	if len(cmds) != len(lines) {
		t.Fatalf("unit+drop-in have %d ExecStopPost lines, TeardownCommands has %d", len(lines), len(cmds))
	}
	for i, cmd := range cmds {
		if strings.Join(cmd, " ") != lines[i] {
			t.Fatalf("ExecStopPost[%d] = %q, TeardownCommands[%d] = %q", i, lines[i], i, strings.Join(cmd, " "))
		}
	}

	// The order the split must not get wrong: the postern_open delete comes
	// from the main unit and runs before any flush the drop-in appends.
	// Leaving a flush standing over live postern_open drops would be a
	// posture the delete is there to clear.
	if !strings.HasPrefix(lines[0], DefaultNFTPath+" delete table inet "+TableOpen) {
		t.Fatalf("first teardown line is %q, want the postern_open delete first", lines[0])
	}
}

// The watchdog and the notify protocol are what make a wedged-but-running
// agent recoverable: without Type=notify, WatchdogSec is inert and a wedged
// packet loop is restarted by nothing.
//
// NotifyAccess is asserted here for the opposite reason, and it is the
// setting most likely to be widened by somebody solving the wrong problem.
// posternd's systemctl and nft children once inherited NOTIFY_SOCKET, and
// systemd logged a discarded notification per child; =all makes those lines
// stop by making systemd accept state strings from every descendant, and a
// WATCHDOG=1 from one of them then resets the timer for a packet loop that
// has wedged. internal/childenv takes the socket away from the children so
// this can stay narrow.
func TestGate_RenderUnit_DeclaresNotifyTypeAndWatchdog(t *testing.T) {
	unit := mustPosterndUnit(t)
	for _, want := range []string{"Type=notify", "NotifyAccess=main", "WatchdogSec=90s"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("rendered unit is missing %q:\n%s", want, unit)
		}
	}
}

// The boot path must not depend on the postern binary either: a corrupt or
// half-upgraded binary that failed to load the table would silently fail
// *open* on a host configured closed (design section 7, "Deliberately not
// postern gate-load").
func TestGate_RenderBootUnit_LoadsBootNFTWithNFTNeverThePosternBinary(t *testing.T) {
	opts := mustUnitOptions()
	unit, err := RenderBootUnit(opts)
	if err != nil {
		t.Fatalf("RenderBootUnit: %v", err)
	}
	want := "ExecStart=" + DefaultNFTPath + " -f " + opts.BootNFTPath
	if !strings.Contains(unit, want) {
		t.Fatalf("boot unit is missing %q:\n%s", want, unit)
	}
	if strings.Contains(unit, strings.Fields(opts.ExecStart)[0]) {
		t.Fatalf("boot unit names the postern binary; a corrupt binary must not stop boot.nft loading:\n%s", unit)
	}
	for _, want := range []string{"DefaultDependencies=no", "Before=network-pre.target", "Type=oneshot"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("boot unit is missing %q:\n%s", want, unit)
		}
	}
}

func TestGate_RenderUnit_RejectsRelativeToolPaths(t *testing.T) {
	plan := mustPlan(t)
	opts := mustUnitOptions()
	opts.NFTPath = "nft"
	if _, err := RenderPosterndUnit(plan, opts); err == nil {
		t.Fatal("RenderPosterndUnit accepted a relative nft path; systemd resolves no PATH for units, " +
			"and a relative teardown command is a teardown that does not run")
	}
	opts = mustUnitOptions()
	opts.ExecStart = ""
	if _, err := RenderPosterndUnit(plan, opts); err == nil {
		t.Fatal("RenderPosterndUnit accepted an empty ExecStart")
	}
}

// I2. The boot unit's [Install] section is not decoration: `systemctl
// enable` on a unit without one fails with "no installation config
// specified", `is-enabled` then reports "static", SystemdBootUnit.Enabled
// reads that as true, and Revert's SetEnabled(true) fails at the one moment
// it matters — the rollback of a configuration that may have locked the host
// out. Deleting the section left internal/gate entirely green before this
// test existed.
//
// The mutation this catches: removing the [Install]/WantedBy lines from
// RenderBootUnit.
func TestGate_RenderBootUnit_IsEnableable(t *testing.T) {
	unit, err := RenderBootUnit(mustUnitOptions())
	if err != nil {
		t.Fatalf("RenderBootUnit: %v", err)
	}

	install := strings.Index(unit, "[Install]")
	if install == -1 {
		t.Fatalf("the boot unit has no [Install] section, so `systemctl enable` fails with "+
			"\"no installation config specified\" and confirm-or-revert cannot restore its enabled "+
			"state:\n%s", unit)
	}
	wantedBy := strings.Index(unit, "WantedBy=")
	if wantedBy == -1 || wantedBy < install {
		t.Fatalf("the boot unit's [Install] section declares no WantedBy target:\n%s", unit)
	}
	// sysinit.target, not multi-user.target: the drop rules have to be live
	// before the network comes up, which is the same reason the unit carries
	// DefaultDependencies=no and Before=network-pre.target.
	if !strings.Contains(unit[install:], "WantedBy=sysinit.target") {
		t.Fatalf("the boot unit is wanted by something other than sysinit.target; the fail-closed "+
			"drop rules must load before the network does:\n%s", unit)
	}
}

// The same property for posternd.service, for the same reason: a unit with
// no [Install] section cannot be enabled, so a host would come back from a
// reboot with the firewall posture loaded and nothing running to open it.
func TestGate_RenderPosterndUnit_IsEnableable(t *testing.T) {
	unit := mustPosterndUnit(t)
	install := strings.Index(unit, "[Install]")
	if install == -1 {
		t.Fatalf("posternd.service has no [Install] section and cannot be enabled:\n%s", unit)
	}
	if !strings.Contains(unit[install:], "WantedBy=multi-user.target") {
		t.Fatalf("posternd.service declares no multi-user.target install target:\n%s", unit)
	}
}

// posternd.service orders itself after the boot unit but must not pull it
// in. The boot unit runs because it is ENABLED, and enabling it is the arm
// step's job: a host whose configuration has never been confirmed has the
// unit installed and disabled, and nothing on it may drop traffic.
//
// A Wants= here would load the fail-closed ruleset the instant posternd is
// started, so the transaction the agent then prepares would snapshot an
// already-armed host — and its revert would restore exactly the rules it
// exists to roll back. The confirm-or-revert rail would still appear to
// work: a transaction is prepared, a nonce published, a dead-man fires, and
// the host stays locked.
func TestGate_RenderPosterndUnit_OrdersAfterTheBootUnitWithoutPullingItIn(t *testing.T) {
	unit := mustPosterndUnit(t)
	if !strings.Contains(unit, "After="+BootUnitName) {
		t.Fatalf("posternd.service does not order itself after %s:\n%s", BootUnitName, unit)
	}
	for _, dep := range []string{"Wants=" + BootUnitName, "Requires=" + BootUnitName, "BindsTo=" + BootUnitName} {
		if strings.Contains(unit, dep) {
			t.Fatalf("posternd.service carries %q, so starting the agent arms the host before the agent "+
				"can prepare a transaction to roll it back:\n%s", dep, unit)
		}
	}
}
