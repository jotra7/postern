//go:build linux

package agent_test

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// These run in the privileged, network-isolated container
// scripts/linux-test.sh provides. Everything asserted about the firewall is
// read back from `nft list ...` rather than from postern's own view of what
// it wrote.

func nftDropTables(t *testing.T) {
	t.Helper()
	_ = exec.Command("nft", "delete", "table", "inet", gate.TableBoot).Run() //nolint:gosec // a package constant, not input
	_ = exec.Command("nft", "delete", "table", "inet", gate.TableOpen).Run() //nolint:gosec // a package constant, not input
}

func nftList(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("nft", append([]string{"list"}, args...)...).CombinedOutput() //nolint:gosec // this test's own literal arguments
	return string(out), err
}

// --- arrival-path detection --------------------------------------------

// The always-allow binding for liveness (design section 5) is only as good
// as the agent's ability to tell which interface a datagram arrived on. That
// cannot be recovered from the payload or the source address — an operator's
// address is the same address whichever path carried it — so it comes from
// the kernel's per-packet ancillary data, and this is the test that the
// plumbing works against a real socket.
//
// The mutations this catches: making arrivalInterface return 0, or making
// onAlwaysAllowPath skip the index comparison, or disabling BOTH pktinfo
// socket options. Disabling IP_PKTINFO alone is deliberately not enough —
// the socket is dual-stack, so a v4 packet arrives v4-mapped and the kernel
// answers with IPV6_PKTINFO instead. That is correct behaviour rather than a
// gap in the test, and it is why enablePathDetection treats "neither option
// was accepted" as the failure rather than "either was refused".
func TestAgent_UDPReceiver_ReportsTheArrivalInterface(t *testing.T) {
	const port = 62299

	cases := []struct {
		name             string
		alwaysAllowIface string
		want             bool
	}{
		// The container has only loopback, so a packet sent to 127.0.0.1
		// genuinely arrives on "lo".
		{"arrival on the always-allow interface", "lo", true},
		// tailscale0 does not exist here, which is the ordinary state of a
		// host whose mesh has not come up. A packet must not be credited to
		// an interface that is not there.
		{"always-allow interface absent", "tailscale0", false},
		// A different real interface: arrival on "lo" is not arrival on it.
		{"arrival on a different interface", "nonexistent-iface-xyz", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := agent.NewUDPReceiver(port, tc.alwaysAllowIface)
			if err != nil {
				t.Fatalf("NewUDPReceiver: %v", err)
			}
			defer func() { _ = r.Close() }()

			conn, err := net.Dial("udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dg, err := r.Receive(ctx)
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			if string(dg.Payload) != "ping" {
				t.Fatalf("payload = %q", dg.Payload)
			}
			if dg.OnAlwaysAllowPath != tc.want {
				t.Fatalf("OnAlwaysAllowPath = %v, want %v (always_allow_iface = %q)",
					dg.OnAlwaysAllowPath, tc.want, tc.alwaysAllowIface)
			}
		})
	}
}

// A datagram larger than the wire record must reach Validate's exact-length
// check intact rather than being truncated into a correctly-sized one by the
// receive buffer — the length check is validation step 1 and the cheapest
// rejection there is, and a buffer sized to the record would silently
// disarm it.
func TestAgent_UDPReceiver_DoesNotTruncateAnOversizedDatagramIntoAValidLength(t *testing.T) {
	const port = 62298
	r, err := agent.NewUDPReceiver(port, "lo")
	if err != nil {
		t.Fatalf("NewUDPReceiver: %v", err)
	}
	defer func() { _ = r.Close() }()

	conn, err := net.Dial("udp", "127.0.0.1:62298")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	oversized := make([]byte, 224+16) // spa.DatagramSize + slack
	if _, err := conn.Write(oversized); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dg, err := r.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(dg.Payload) != len(oversized) {
		t.Fatalf("received %d bytes of a %d-byte datagram; an oversized packet truncated to the "+
			"record size would pass the length check it exists to fail", len(dg.Payload), len(oversized))
	}
}

// --- the live ruleset half of confirm-or-revert -------------------------

// NFTRuleset is what Revert restores the live postern_boot table with, so it
// has to round-trip through nft(8) for real: a snapshot that nft cannot
// reload is a revert that cannot happen, and the failure would only appear
// on the day a rollback was needed.
//
// The mutation this catches: making Restore load over the live table instead
// of deleting it first. nft's table definitions are additive, so the
// transaction's added set would still be there afterwards and the
// post-restore assertion fails.
func TestAgent_NFTRuleset_SnapshotAndRestoreRoundTripThroughNFT(t *testing.T) {
	nftDropTables(t)
	t.Cleanup(func() { nftDropTables(t) })

	policy := linuxGatePolicy()
	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	loadNFT(t, gate.RenderBootNFT(plan))

	rs := agent.NFTRuleset{NFT: nftPath(t), Table: gate.TableBoot}
	ctx := context.Background()

	before, err := rs.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !strings.Contains(string(before), "tcp dport 8443 drop") {
		t.Fatalf("snapshot does not contain the live drop rule:\n%s", before)
	}

	// Arm something else on top, the way a deploy would.
	//nolint:gosec // a package constant and this test's own literals, not input
	if out, err := exec.Command("nft", "add", "set", "inet", gate.TableBoot, "gate_extra_v4_obs",
		"{ type ipv4_addr; flags timeout; }").CombinedOutput(); err != nil {
		t.Fatalf("add set: %v\n%s", err, out)
	}
	if out, err := nftList(t, "table", "inet", gate.TableBoot); err != nil || !strings.Contains(out, "gate_extra_v4_obs") {
		t.Fatalf("precondition: the extra set is not live:\n%s", out)
	}

	if err := rs.Restore(ctx, before); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	after, err := nftList(t, "table", "inet", gate.TableBoot)
	if err != nil {
		t.Fatalf("list after restore: %v\n%s", err, after)
	}
	if strings.Contains(after, "gate_extra_v4_obs") {
		t.Fatalf("the transaction's set survived the restore; nft table definitions are additive, so "+
			"a restore that loads over the live table leaves what it was meant to roll back:\n%s", after)
	}
	if !strings.Contains(after, "tcp dport 8443 drop") {
		t.Fatalf("the restored table is missing the drop rule it was snapshotted with:\n%s", after)
	}
}

// An absent table is a state the design names explicitly, and a transaction
// prepared before postern_boot existed must be able to revert back to it —
// which is a delete, not a load of nothing.
func TestAgent_NFTRuleset_RestoringAnEmptySnapshotRemovesTheTable(t *testing.T) {
	nftDropTables(t)
	t.Cleanup(func() { nftDropTables(t) })

	plan, err := gate.BuildRulesetPlan(linuxGatePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	loadNFT(t, gate.RenderBootNFT(plan))

	rs := agent.NFTRuleset{NFT: nftPath(t), Table: gate.TableBoot}
	ctx := context.Background()

	// A snapshot taken when the table did not exist.
	nftDropTables(t)
	empty, err := rs.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot of an absent table: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("Snapshot of an absent table returned %d bytes", len(empty))
	}

	loadNFT(t, gate.RenderBootNFT(plan)) // arm it
	if err := rs.Restore(ctx, empty); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if out, err := nftList(t, "table", "inet", gate.TableBoot); err == nil {
		t.Fatalf("the table survived a restore to \"absent\":\n%s", out)
	}
}

// --- the daemon against real nftables ----------------------------------

// Everything above this line tests the daemon against a fake Gate. This is
// the one that proves the wiring: a real nftables backend, a real UDP
// socket, a real sealed packet, and the resulting hole read back out of the
// kernel.
func TestAgent_Daemon_OpensARealGateThroughRealNFTables(t *testing.T) {
	nftDropTables(t)
	t.Cleanup(func() { nftDropTables(t) })

	f := newFixture(t)
	policy := f.policy
	policy.SPAPort = 62297
	policy.AlwaysAllowIface = "tailscale0"
	policy.RecoveryService = sshName
	// ssh is fail-closed in the fixture, so it lives in postern_boot, which
	// the boot unit loads. Load it the way the boot path would.
	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	loadNFT(t, gate.RenderBootNFT(plan))

	g, err := gate.NewNFTables(policy)
	if err != nil {
		t.Fatalf("NewNFTables: %v", err)
	}

	recv, err := agent.NewUDPReceiver(policy.SPAPort, policy.AlwaysAllowIface)
	if err != nil {
		t.Fatalf("NewUDPReceiver: %v", err)
	}

	d, err := agent.New(agent.Options{
		Policy:   policy,
		Gate:     g,
		Opener:   f.opener,
		Store:    f.store,
		Host:     f.host,
		Receiver: recv,
		// The container has no tailscale0 and no sshd; pre-arm's production
		// probes would correctly report both. Those decisions have their own
		// tests — what is under test here is the firewall wiring.
		Checks: passingChecks(map[string]bool{sshName: true}),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	waitFor(t, "the daemon to create postern_open and set agent_up", func() bool {
		out, err := nftList(t, "set", "inet", gate.TableBoot, gate.AgentUpSet)
		return err == nil && strings.Contains(out, "62297")
	})

	// postern_open exists, created by the agent and by nothing else.
	if out, err := nftList(t, "table", "inet", gate.TableOpen); err != nil {
		t.Fatalf("the daemon did not create %s: %v\n%s", gate.TableOpen, err, out)
	}

	// A real sealed packet over a real socket.
	conn, err := net.Dial("udp", "127.0.0.1:62297")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(f.seal(f.gateRequest())); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The hole, read back out of the kernel. The source is the packet's own
	// observed address, which over loopback is 127.0.0.1.
	waitFor(t, "the gate to open in the kernel", func() bool {
		out, err := nftList(t, "set", "inet", gate.TableBoot, "gate_ssh_v4_obs")
		return err == nil && strings.Contains(out, "127.0.0.1")
	})

	// Shutdown: agent_up goes at once rather than at lease expiry, and
	// postern_open goes with it.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	out, err := nftList(t, "set", "inet", gate.TableBoot, gate.AgentUpSet)
	if err != nil {
		t.Fatalf("list agent_up after shutdown: %v\n%s", err, out)
	}
	if strings.Contains(out, "62297") {
		t.Fatalf("agent_up survived a clean stop; the SPA port stays reachable into a dead agent "+
			"until the lease lapses:\n%s", out)
	}
	if out, err := nftList(t, "table", "inet", gate.TableOpen); err == nil {
		t.Fatalf("%s survived a clean stop:\n%s", gate.TableOpen, out)
	}
	if out, err := nftList(t, "set", "inet", gate.TableBoot, "gate_ssh_v4_obs"); err != nil {
		t.Fatalf("the fail-closed gate set was deleted rather than emptied: %v", err)
	} else if strings.Contains(out, "elements = {") {
		t.Fatalf("the fail-closed gate set still holds a grant after a clean stop:\n%s", out)
	}
	if out, err := nftList(t, "table", "inet", gate.TableBoot); err != nil {
		t.Fatalf("%s was removed by a clean stop: %v", gate.TableBoot, err)
	} else if !strings.Contains(out, "tcp dport 22 drop") {
		t.Fatalf("the fail-closed drop rule did not survive a clean stop:\n%s", out)
	}
}

// --- helpers -----------------------------------------------------------

// linuxGatePolicy is a small policy with one fail-closed gate, enough to
// produce a postern_boot table to snapshot and restore.
func linuxGatePolicy() *config.Policy {
	return &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		Services: map[string]config.Service{
			"admin": {
				Name: "admin", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8443},
				DefaultTTL: 10 * time.Minute, MaxTTL: 30 * time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
			},
		},
	}
}

func loadNFT(t *testing.T, text string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s\nruleset:\n%s", err, out, text)
	}
}

func nftPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("nft")
	if err != nil {
		t.Fatalf("nft is not on PATH: %v", err)
	}
	return p
}

// I5, against a real kernel. The production PortsArmable probe asks the gate
// backend to resolve each of a fail-closed service's sets by name. This
// stages the situation it exists to catch: a boot.nft that predates a
// service, so postern_boot carries that service's accept rules but not the
// sets they reference. Every knock for it would fail at Open time while the
// service looked armed and reported green.
//
// The mutation this catches: removing the PortsArmable block from
// ProductionChecks. "postgres" is then armed and the first assertion fails.
func TestAgent_PreArm_AFailClosedServiceMissingFromTheLiveTableIsDisabledAlone(t *testing.T) {
	nftDropTables(t)
	t.Cleanup(func() { nftDropTables(t) })

	// The policy the agent is running: two fail-closed gates.
	policy := &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		RecoveryService:  "admin",
		Services: map[string]config.Service{
			"admin": {
				Name: "admin", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8443},
				DefaultTTL: 10 * time.Minute, MaxTTL: 30 * time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
			},
			"postgres": {
				Name: "postgres", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{5432},
				DefaultTTL: 10 * time.Minute, MaxTTL: 30 * time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
			},
		},
	}

	// The boot.nft that actually loaded: an older one, with admin only. This
	// is the ordinary way the two drift apart — a deploy that wrote a new
	// policy without re-writing boot.nft, or a reboot before the new file
	// landed.
	stale := *policy
	stale.Services = map[string]config.Service{"admin": policy.Services["admin"]}
	stalePlan, err := gate.BuildRulesetPlan(&stale)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	loadNFT(t, gate.RenderBootNFT(stalePlan))

	g, err := gate.NewNFTables(policy)
	if err != nil {
		t.Fatalf("NewNFTables: %v", err)
	}

	checks := agent.ProductionChecks(agent.PreArmChecks{
		// Isolate the precondition under test: the container has no
		// tailscale0 and these two have their own coverage.
		AlwaysAllow:   func(*config.Policy) error { return nil },
		StoreWritable: func() error { return nil },
		OperatorKeys:  func(*config.Policy) error { return nil },
	}, g, "/tmp/replay.db", "")

	res := agent.RunPreArm(context.Background(), policy, checks)

	if res.Inert() {
		t.Fatalf("one service missing from the live table made the whole agent inert: %v", res.Global)
	}
	if res.ServiceEnabled("postgres") {
		t.Fatal("postgres has accept rules in postern_boot but no sets for them to reference; " +
			"every knock would fail at Open time while pre-arm reported the service armed")
	}
	if !res.ServiceEnabled("admin") {
		t.Fatalf("admin was disabled by postgres's missing sets: %v", res.Disabled["admin"])
	}
}
