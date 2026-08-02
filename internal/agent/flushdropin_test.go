package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// failClosedPolicy is a minimal policy that plans a ruleset with exactly one
// named fail-closed gate service, so a test can assert the drop-in names that
// service's sets and nothing else.
func failClosedPolicy(t *testing.T, gateName string) *config.Policy {
	t.Helper()
	return &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		Services: map[string]config.Service{
			gateName: {
				Name: gateName, Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8200},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
			},
		},
	}
}

func planFor(t *testing.T, p *config.Policy) *gate.RulesetPlan {
	t.Helper()
	plan, err := gate.BuildRulesetPlan(p)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	return plan
}

// Sync writes the drop-in for the live catalogue and reloads systemd, so a
// crash after it runs the new ExecStopPost lines rather than the old ones.
// Both halves matter and are asserted: a write with no reload leaves systemd
// on the stale in-memory copy; a reload with no write reloads the stale file.
func TestAgent_FlushDropIn_SyncWritesTheFlushLinesAndReloadsSystemd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, gate.PosterndDropInDir, gate.FlushDropInName)
	stub, argvLog := fakeSystemctlRecording(t, "enabled", 0)

	f := agent.FlushDropIn{Path: path, Systemctl: stub}
	if err := f.Sync(context.Background(), planFor(t, failClosedPolicy(t, "vault"))); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	content, present := readFile(t, path)
	if !present {
		t.Fatal("Sync did not write the drop-in")
	}
	if !strings.HasPrefix(content, "[Service]\n") {
		t.Fatalf("drop-in is not a [Service] override:\n%s", content)
	}
	if !strings.Contains(content, "flush set inet "+gate.TableBoot+" gate_vault") {
		t.Fatalf("drop-in does not flush the fail-closed service's set:\n%s", content)
	}

	var reloaded bool
	for _, line := range readArgvLog(t, argvLog) {
		if strings.TrimSpace(line) == "daemon-reload" {
			reloaded = true
		}
	}
	if !reloaded {
		t.Fatalf("systemctl daemon-reload was not run, so systemd keeps the stale ExecStopPost: %v",
			readArgvLog(t, argvLog))
	}
}

// A disabled drop-in (empty Path) is a no-op: standalone mode, where the
// catalogue is fixed at enrollment, never reaches a regeneration, and every
// daemon test that does not opt in must be able to leave it zero. It must
// neither write a file nor shell out to systemctl.
func TestAgent_FlushDropIn_DisabledSyncTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, gate.PosterndDropInDir, gate.FlushDropInName)
	stub, argvLog := fakeSystemctlRecording(t, "enabled", 0)

	f := agent.FlushDropIn{Systemctl: stub} // no Path
	if err := f.Sync(context.Background(), planFor(t, failClosedPolicy(t, "vault"))); err != nil {
		t.Fatalf("Sync on a disabled drop-in returned %v, want nil", err)
	}
	if _, present := readFile(t, path); present {
		t.Fatal("a disabled drop-in wrote a file")
	}
	// The stub only creates its argv log when it is run at all, so an absent
	// log is the assertion: systemctl was never invoked.
	if _, err := os.Stat(argvLog); !os.IsNotExist(err) {
		t.Fatalf("a disabled drop-in invoked systemctl (argv log exists, stat err=%v): %v",
			err, readArgvLog(t, argvLog))
	}
}

// The apply-path half of #47, end to end: a bundle that adds a fail-closed
// service the host was not enrolled with must rewrite the drop-in so systemd
// gains the ExecStopPost line that empties that service's set on a crash, and
// daemon-reload must run so the new line is not stranded in a file systemd has
// not re-read. Mutation guarded: deleting the syncFlushDropIn call from
// applyBundlePolicy leaves the drop-in without the vault line and this fails.
func TestAgent_Daemon_ABundleAddingAFailClosedServiceRewritesTheFlushDropIn(t *testing.T) {
	srv, set := newBundleServer(t)
	dir := t.TempDir()
	dropInPath := filepath.Join(dir, gate.PosterndDropInDir, gate.FlushDropInName)
	stub, argvLog := fakeSystemctlRecording(t, "enabled", 0)

	h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
		o.FlushDropIn = agent.FlushDropIn{Path: dropInPath, Systemctl: stub}
	})

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	// A fail-closed gate the enrolled host did not have — the shape a bundle
	// adds to a running fleet host.
	svcs := map[string]config.Service{}
	for k, v := range p.Services {
		svcs[k] = v
	}
	svcs["vault"] = config.Service{
		Name: "vault", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8200},
		DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
		FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
	}
	p.Services = svcs
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	set(h.sealValid(t, version, data))

	if err := h.daemon.Puller().PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	if got := h.daemon.Policy().Revision; got != version {
		t.Fatalf("bundle was not applied: revision %d, want %d", got, version)
	}

	content, present := readFile(t, dropInPath)
	if !present {
		t.Fatal("applying a bundle that adds a fail-closed service did not write the flush drop-in")
	}
	if !strings.Contains(content, "flush set inet "+gate.TableBoot+" gate_vault") {
		t.Fatalf("the drop-in has no flush line for the bundle-added set, so a crash would leave its "+
			"grant standing until the grant's own timeout:\n%s", content)
	}

	var reloaded bool
	for _, line := range readArgvLog(t, argvLog) {
		if strings.TrimSpace(line) == "daemon-reload" {
			reloaded = true
		}
	}
	if !reloaded {
		t.Fatalf("the apply did not reload systemd, so the new ExecStopPost line is stranded: %v",
			readArgvLog(t, argvLog))
	}
}

// The revert-path half: a bundle that adds a fail-closed service and is then
// rolled back by the dead-man timer must take its flush line back out of the
// drop-in, so it names the catalogue boot.nft was reverted to. Left in, the
// drop-in flushes a set the restored ruleset no longer has — harmless, but a
// third artifact drifting from the other two, which invariant 6 forbids.
// Mutation guarded: deleting the syncFlushDropIn call from checkDeadMan leaves
// vault's line in the reverted drop-in and this fails.
func TestAgent_Daemon_RevertingABundleRestoresTheFlushDropIn(t *testing.T) {
	srv, set := newBundleServer(t)
	dir := t.TempDir()
	dropInPath := filepath.Join(dir, gate.PosterndDropInDir, gate.FlushDropInName)
	stub, _ := fakeSystemctlRecording(t, "enabled", 0)
	clock := &testClock{at: time.Now()}

	h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
		o.FlushDropIn = agent.FlushDropIn{Path: dropInPath, Systemctl: stub}
		o.ConfirmWindow = 5 * time.Minute
		o.Now = clock.Now
	})
	h.txn.txns.Now = clock.Now

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	svcs := map[string]config.Service{}
	for k, v := range p.Services {
		svcs[k] = v
	}
	svcs["vault"] = config.Service{
		Name: "vault", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8200},
		DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
		FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
	}
	p.Services = svcs
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	set(h.sealValid(t, version, data))

	h.start(t)
	// Wait on the drop-in itself, not on Policy().Revision: the revision is set
	// mid-apply, a few steps before syncFlushDropIn writes the file, so gating
	// on the revision would race the write this test is about. That the arm
	// added vault's line is also the precondition for its removal below meaning
	// anything.
	waitFor(t, "the arm to add vault to the flush drop-in", func() bool {
		content, _ := readFile(t, dropInPath)
		return strings.Contains(content, "gate_vault")
	})

	clock.advance(6 * time.Minute)
	h.tick(t, true)
	waitFor(t, "the dead-man revert to complete", func() bool {
		return h.daemon.Health().Red
	})

	content, present := readFile(t, dropInPath)
	if !present {
		t.Fatal("the drop-in vanished on revert")
	}
	if strings.Contains(content, "gate_vault") {
		t.Fatalf("the reverted drop-in still flushes the rolled-back service's set; it drifted from the "+
			"boot.nft the revert restored:\n%s", content)
	}
}
