//go:build linux

package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/jotra7/postern/internal/config"
)

// These tests drive real netlink and the real nft(8) binary against the
// live kernel of the privileged, network-isolated container
// scripts/linux-test.sh runs them in (see that script's own comment for why
// --network=none is load-bearing). They run sequentially — no t.Parallel —
// because Apply always creates postern_boot/postern_open under those fixed
// names (design section 4), so two tests holding both tables open at once
// would collide.
//
// --network=none also means this container has no interface named
// "tailscale0" (or anything but loopback), which is exactly the state
// invariant 1 needs: the boot ruleset must load successfully when the
// always-allow interface does not exist yet.

func newLinuxTestGate(t *testing.T, policy *config.Policy) *NFTables {
	t.Helper()
	g, err := NewNFTables(policy)
	if err != nil {
		t.Fatalf("NewNFTables: %v", err)
	}
	t.Cleanup(func() { dropTables(g.conn) })
	dropTables(g.conn) // in case a previous test left state behind on failure
	if err := g.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return g
}

func dropTables(conn *nftables.Conn) {
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableBoot})
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableOpen})
	_ = conn.Flush() // tolerate "no such table" if nothing existed yet
}

// loopbackPolicy is fixturePolicy as-is: AlwaysAllowIface stays
// "tailscale0", which this container does not have. That absence is
// deliberate and load-bearing for every test below that dials over
// loopback — if the always-allow interface were "lo" instead, "iifname lo
// accept" (design section 4) would match every loopback packet and accept
// it before the gate's own rules ever ran, which would make
// TestGate_ClosedCanary_TimesOutRatherThanRST and
// TestGate_EstablishedConnection_SurvivesClose pass for the wrong reason:
// the always-allow bypass, not the gate mechanism under test. Naming the
// function loopbackPolicy documents that these tests dial over loopback,
// not that the policy's always-allow path is loopback.
func loopbackPolicy(t *testing.T) *config.Policy {
	t.Helper()
	return fixturePolicy()
}

// TestGate_BootRuleset_LoadsWithAlwaysAllowInterfaceAbsent is invariant 1's
// load-time half: the rendered boot.nft must load successfully via `nft -f`
// in an environment where the always-allow interface does not exist at
// all (this container has no "tailscale0"). Using iif instead of iifname in
// render.go's iifname literal would fail this load outright, which is the
// specific silent failure invariant 1 exists to prevent.
func TestGate_BootRuleset_LoadsWithAlwaysAllowInterfaceAbsent(t *testing.T) {
	policy := fixturePolicy() // AlwaysAllowIface: "tailscale0", absent in this container
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	text := RenderBootNFT(plan)

	dropTablesViaNft(t)
	t.Cleanup(func() { dropTablesViaNft(t) })

	dir := t.TempDir()
	path := filepath.Join(dir, "boot.nft")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write boot.nft: %v", err)
	}
	out, err := exec.Command("nft", "-f", path).CombinedOutput() //nolint:gosec // path is this test's own t.TempDir() file, not attacker input
	if err != nil {
		t.Fatalf("nft -f %s failed with the always-allow interface absent: %v\n%s\nrendered file:\n%s", path, err, out, text)
	}
}

func dropTablesViaNft(t *testing.T) {
	t.Helper()
	_ = exec.Command("nft", "delete", "table", "inet", TableBoot).Run()
	_ = exec.Command("nft", "delete", "table", "inet", TableOpen).Run()
}

// A re-knock for a source that is already open must extend its lease, and
// must not stack a second element beside it. This is the single most common
// production write there is: an operator whose session is about to lapse
// knocks again.
//
// Both Opens use the SAME ttl, and that is the whole point of the test
// rather than an incidental choice. On 6.12 the kernel refreshes an existing
// element's expiry only when the re-inserted element's timeout VALUE differs
// from the live one; re-inserting with an identical timeout returns success
// and leaves the original schedule running. The spike's
// identical-key-reinsert-refreshes case, and the version of this test written
// from it, both used 3s followed by 9s — the one input shape the kernel does
// refresh — and so reported a refresh that the product's own default flow
// (`postern open host ssh` twice, same configured TTL) never gets. The
// end-to-end run caught it: a second knock left `expires 42s659ms` exactly
// where the first had put it.
//
// The mutation this catches: dropping the SetDeleteElements call from Open.
// The count assertion alone does not catch it — nothing stacks either way.
func TestGate_Open_ARepeatedKnockWithTheSameTTLRefreshesTheLease(t *testing.T) {
	const ttl = 8 * time.Second
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		src  Source
		kind SetKind
	}{
		{"observed address", Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.5/32")}, SetObserved},
		{"asserted prefix", Source{Kind: SourceAsserted, Prefix: netip.MustParsePrefix("203.0.113.0/24")}, SetAsserted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := g.Open(ctx, "admin", tc.src, ttl); err != nil {
				t.Fatalf("first Open: %v", err)
			}
			countBefore := rawElementCount(t, g, "admin", FamilyIPv4, tc.kind)

			time.Sleep(3 * time.Second)
			remainingBefore := remainingFor(t, g, "admin", tc.src)

			if err := g.Open(ctx, "admin", tc.src, ttl); err != nil {
				t.Fatalf("re-open of an identical live source: %v", err)
			}
			countAfter := rawElementCount(t, g, "admin", FamilyIPv4, tc.kind)
			remainingAfter := remainingFor(t, g, "admin", tc.src)

			if countAfter != countBefore {
				t.Fatalf("raw element count went from %d to %d on a re-knock: the source stacked "+
					"instead of refreshing in place", countBefore, countAfter)
			}
			if remainingAfter <= remainingBefore {
				t.Fatalf("the lease was not extended: %s remaining before the re-knock, %s after. "+
					"An operator re-knocking to hold a session open gets a gate that shuts on the "+
					"original schedule anyway, and nothing tells them", remainingBefore, remainingAfter)
			}

			// And it is a real extension rather than a larger number the
			// kernel is not acting on: the element outlives the schedule the
			// first knock set.
			time.Sleep(6 * time.Second) // t=9, one second past the original 8s
			state, err := g.State(ctx, "admin")
			if err != nil {
				t.Fatalf("State: %v", err)
			}
			if !stateContains(state, tc.src) {
				t.Fatalf("the source expired on the first knock's schedule despite being re-knocked at t=3")
			}
		})
	}
}

// TestGate_Open_AssertedOverlapReturnsErrOverlap is the kernel confirmation
// of the spike's overlap-collision findings (checkOverlapNestedSharedBoundary
// et al.): inserting an asserted CIDR whose range overlaps one already live
// must fail distinguishably as ErrOverlap, not as an opaque error, and must
// not silently succeed. It also proves the live element from the first
// Open was left untouched — Open never resolves the collision on its own
// (see ErrOverlap's doc comment).
func TestGate_Open_AssertedOverlapReturnsErrOverlap(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()

	broad := Source{Kind: SourceAsserted, Prefix: netip.MustParsePrefix("198.51.100.0/24")}
	if err := g.Open(ctx, "admin", broad, 30*time.Second); err != nil {
		t.Fatalf("Open broad: %v", err)
	}

	nested := Source{Kind: SourceAsserted, Prefix: netip.MustParsePrefix("198.51.100.128/25")}
	err := g.Open(ctx, "admin", nested, 3*time.Second)
	if err == nil {
		t.Fatal("Open of a nested, overlapping asserted CIDR unexpectedly succeeded")
	}
	if !errors.Is(err, ErrOverlap) {
		t.Fatalf("Open of an overlapping asserted CIDR returned an error not classified as ErrOverlap: %v", err)
	}

	// The broad prefix must still be exactly as it was: the failed nested
	// insert must not have partially applied or displaced it.
	countAfter := rawElementCount(t, g, "admin", FamilyIPv4, SetAsserted)
	if countAfter != 2 { // start + end marker for the one live broad prefix
		t.Fatalf("asserted v4 set has %d raw elements after a rejected overlap, want 2 (the broad prefix's own start/end pair)", countAfter)
	}
}

// TestGate_Open_ElementExpiresOnSchedule covers the kernel test list's
// "elements expire on schedule."
func TestGate_Open_ElementExpiresOnSchedule(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()
	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.9/32")}

	if err := g.Open(ctx, "admin", src, 2*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	state, err := g.State(ctx, "admin")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !stateContains(state, src) {
		t.Fatal("source not present immediately after Open")
	}

	time.Sleep(4 * time.Second)
	state, err = g.State(ctx, "admin")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if stateContains(state, src) {
		t.Fatal("source still present 4s after a 2s ttl")
	}
}

// TestGate_Open_IPv4AndIPv6BehaveIdentically opens both an IPv4 and an IPv6
// observed source on the same service and confirms both are readable back
// with a live remaining TTL, and both independently expire.
func TestGate_Open_IPv4AndIPv6BehaveIdentically(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()

	v4 := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.7/32")}
	v6 := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("2001:db8::7/128")}

	if err := g.Open(ctx, "admin", v4, 3*time.Second); err != nil {
		t.Fatalf("Open v4: %v", err)
	}
	if err := g.Open(ctx, "admin", v6, 3*time.Second); err != nil {
		t.Fatalf("Open v6: %v", err)
	}

	state, err := g.State(ctx, "admin")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !stateContains(state, v4) {
		t.Fatal("ipv4 source not present after Open")
	}
	if !stateContains(state, v6) {
		t.Fatal("ipv6 source not present after Open")
	}

	time.Sleep(5 * time.Second)
	state, err = g.State(ctx, "admin")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if stateContains(state, v4) {
		t.Fatal("ipv4 source still present past its ttl")
	}
	if stateContains(state, v6) {
		t.Fatal("ipv6 source still present past its ttl")
	}
}

// TestGate_ClosedCanary_TimesOutRatherThanRST is invariant 4 exercised at
// the packet level: a connect to a fail-closed, drop-ruled port with
// nothing listening behind it must time out, not return RST. If the drop
// rule were missing (or canary were special-cased out, as
// render_test.go's deliberate-break already proves for the text form),
// the kernel would send RST for "nothing listening" and this test would
// see an immediate connection-refused instead of a timeout.
func TestGate_ClosedCanary_TimesOutRatherThanRST(t *testing.T) {
	newLinuxTestGate(t, loopbackPolicy(t)) // canary's drop rule is live; nothing opened it

	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp4", "127.0.0.1:62202")
	if err == nil {
		_ = conn.Close()
		t.Fatal("connect to closed canary port unexpectedly succeeded")
	}
	var netErr net.Error
	timedOut := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
	if !timedOut {
		t.Fatalf("expected a timeout (dropped SYN) connecting to a closed, drop-ruled port with nothing "+
			"listening; got a different error, which on this rule shape usually means RST/refused instead: %v", err)
	}
}

// TestGate_EstablishedConnection_SurvivesClose opens admin for loopback,
// establishes a real TCP connection through the gate, then closes the gate
// (flushing the source set the same way agent shutdown does) and confirms
// the already-established connection keeps working — the "ct state
// established,related accept" rule (invariant 2) doing its job.
func TestGate_EstablishedConnection_SurvivesClose(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()

	ln, err := net.Listen("tcp4", "127.0.0.1:8443")
	if err != nil {
		t.Fatalf("listen on gated port: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("127.0.0.1/32")}
	if err := g.Open(ctx, "admin", src, 30*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}

	client, err := net.DialTimeout("tcp4", "127.0.0.1:8443", 2*time.Second)
	if err != nil {
		t.Fatalf("dial gated port while open: %v", err)
	}
	defer func() { _ = client.Close() }()

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted the connection")
	}
	defer func() { _ = server.Close() }()

	// Close the gate the way agent shutdown does: flush the fail-closed... — wait,
	// admin is fail_posture closed in fixturePolicy, so this exercises Close's
	// real flush path on a set that is actually live.
	if err := g.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// New connections must now be dropped (SYN dropped -> timeout), but the
	// one already established must still carry data both ways.
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write on established connection after Close: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("server read on established connection after Close: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}
}

// spaReachable sends probe UDP datagrams to the SPA port and reports
// whether the kernel generated an ICMP port-unreachable in response to any
// of them, visible to a connected UDP socket as ECONNREFUSED on a later
// syscall. Nothing ever listens on the SPA port in these tests, so the two
// possible outcomes are: the packet is DROPped by nftables and never
// reaches local delivery, producing no ICMP and no error at all within the
// probe window (silent, the property invariant 1 requires while agent_up
// is empty); or the packet is ACCEPTed by nftables, reaches the IP stack,
// finds nothing bound to the port, and the kernel emits ICMP unreachable
// (reachable, the property invariant 1 requires while agent_up holds the
// port). This mirrors the same accept-vs-drop distinction
// TestGate_ClosedCanary_TimesOutRatherThanRST uses for TCP, adapted to UDP
// having no handshake to time out.
func spaReachable(t *testing.T, plan *RulesetPlan) bool {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", plan.SPAPort)
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := conn.Write([]byte("probe")); refusalErrno(err) {
			return true
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		if err == nil {
			return true // an actual reply is unambiguously reachable
		}
		if refusalErrno(err) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func refusalErrno(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == syscall.ECONNREFUSED
}

// TestGate_AgentUp_PresenceControlsSPAAcceptance is the kernel proof that
// the agent_up dead-man switch (design section 4, invariant 1) actually
// gates the SPA port: silent before RefreshAgentUp is ever called, briefly
// reachable while the element is live, and silent again once its ttl
// lapses — with nothing else touching the ruleset in between. Populating
// and refreshing agent_up on a schedule is Task 3's job (design section 7);
// this test only proves the mechanism RefreshAgentUp/SilenceAgentUp hand to
// it actually controls the accept rule, which is the part that has to be
// right before there is anything to schedule.
func TestGate_AgentUp_PresenceControlsSPAAcceptance(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()
	plan := g.Plan()

	if spaReachable(t, plan) {
		t.Fatal("SPA port answered before agent_up was ever populated; it should start silent")
	}

	if err := g.RefreshAgentUp(ctx, 2*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}
	if !spaReachable(t, plan) {
		t.Fatal("SPA port stayed silent immediately after RefreshAgentUp; the accept rule should now match")
	}

	time.Sleep(3 * time.Second)
	if spaReachable(t, plan) {
		t.Fatal("SPA port still answering 3s after a 2s agent_up ttl; the element should have expired")
	}
}

// TestGate_AgentUp_RefreshWithAnIdenticalTTLExtendsTheLease is the regression
// test for the worst bug this package has had, and it is deliberately shaped
// around why the existing coverage missed it.
//
// TestGate_AgentUp_PresenceControlsSPAAcceptance calls RefreshAgentUp exactly
// once and then waits for the lease to lapse. That proves the *mechanism* —
// the element gates the accept rule — and says nothing about whether a second
// call extends anything. It did not: NFT_MSG_NEWSETELEM for a live key with an
// identical timeout value is silently ignored (see the package doc), and
// Daemon.beat calls this every heartbeat with one constant ttl. So the SPA
// port went silent on the first add's clock, every time, on a healthy agent.
//
// The refresh here uses the SAME ttl as the original add, because that is the
// only case that was broken and the only case production exercises.
func TestGate_AgentUp_RefreshWithAnIdenticalTTLExtendsTheLease(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()
	plan := g.Plan()

	if err := g.RefreshAgentUp(ctx, 3*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}
	time.Sleep(2 * time.Second)

	// The write the packet loop makes on every beat: same key, same ttl.
	if err := g.RefreshAgentUp(ctx, 3*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp (refresh): %v", err)
	}

	// Two more seconds puts us past the ORIGINAL 3s deadline and well inside
	// the refreshed one. A lease running on the first add's clock is silent
	// here; a refreshed lease has a second left.
	time.Sleep(2 * time.Second)
	if !spaReachable(t, plan) {
		t.Fatal("the SPA port went silent 4s after a lease refreshed at t=2s with a 3s ttl: the refresh " +
			"did not extend anything and the dead-man is running on the first add's clock. This is " +
			"invariant 1 failing on a healthy agent, and nothing else in the system reports it.")
	}
}

// TestGate_AgentUp_RefreshWithADifferentTTLExtendsTheLease is kept beside the
// test above for one reason: it passed against the broken implementation.
//
// A different timeout value does reset the kernel's timer, so this is the
// branch the spike measured when it concluded that an identical-key re-insert
// refreshes cleanly. On its own it looks like coverage of "refresh works" and
// is nothing of the kind. Deleting it would leave the next person free to
// re-derive the spike's wrong conclusion; keeping it, named for what it
// actually exercises, makes the distinction the point.
func TestGate_AgentUp_RefreshWithADifferentTTLExtendsTheLease(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()
	plan := g.Plan()

	if err := g.RefreshAgentUp(ctx, 3*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}
	time.Sleep(2 * time.Second)
	if err := g.RefreshAgentUp(ctx, 4*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp (refresh): %v", err)
	}
	time.Sleep(2 * time.Second)
	if !spaReachable(t, plan) {
		t.Fatal("the SPA port went silent even with a differing ttl value, which the kernel does honour")
	}
}

// TestGate_AgentUp_RefreshIsAtomic covers the one way the fix could be worse
// than the bug. The refresh now deletes the element and re-adds it; if those
// reached the kernel as two transactions there would be an instant with no
// agent_up element at all, and a knock arriving in it would be dropped before
// the socket — turning a lease that lapsed every 90s into one that flickered
// every beat.
func TestGate_AgentUp_RefreshIsAtomic(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()
	plan := g.Plan()

	if err := g.RefreshAgentUp(ctx, 30*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}
	for i := 0; i < 20; i++ {
		if err := g.RefreshAgentUp(ctx, 30*time.Second); err != nil {
			t.Fatalf("RefreshAgentUp (refresh %d): %v", i, err)
		}
		if !spaReachable(t, plan) {
			t.Fatalf("the SPA port was unreachable immediately after refresh %d; the delete and the add "+
				"are not landing in one batch", i)
		}
	}
}

// TestGate_AgentUp_SilenceIsImmediate proves SilenceAgentUp removes the
// element without waiting for its ttl — the replay-store-unavailable path
// design section 6 requires: silence the SPA port immediately, not at
// lease expiry.
func TestGate_AgentUp_SilenceIsImmediate(t *testing.T) {
	g := newLinuxTestGate(t, loopbackPolicy(t))
	ctx := context.Background()
	plan := g.Plan()

	if err := g.RefreshAgentUp(ctx, 30*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}
	if !spaReachable(t, plan) {
		t.Fatal("SPA port silent right after RefreshAgentUp with a 30s ttl")
	}

	if err := g.SilenceAgentUp(ctx); err != nil {
		t.Fatalf("SilenceAgentUp: %v", err)
	}
	if spaReachable(t, plan) {
		t.Fatal("SPA port still reachable immediately after SilenceAgentUp, despite a live 30s ttl remaining")
	}

	if err := g.SilenceAgentUp(ctx); err != nil {
		t.Fatalf("second SilenceAgentUp on an already-silent element should be a no-op, got: %v", err)
	}
}

// TestGate_RefreshAgentUpPorts_HoldsTheLiveSet proves RefreshAgentUpPorts adds
// every port passed to it, in one batch, and that AgentUpExpiryFor reads each
// one back live — the rotation loop's replacement for the single fixed
// agent_up element.
func TestGate_RefreshAgentUpPorts_HoldsTheLiveSet(t *testing.T) {
	g := newLinuxTestGate(t, rotationPolicy(t))
	if err := g.RefreshAgentUpPorts(t.Context(), []uint16{20001, 20002, 20003}, time.Minute); err != nil {
		t.Fatalf("RefreshAgentUpPorts: %v", err)
	}
	for _, p := range []uint16{20001, 20002, 20003} {
		left, err := g.AgentUpExpiryFor(t.Context(), p)
		if err != nil {
			t.Fatalf("AgentUpExpiryFor(%d): %v", p, err)
		}
		if left <= 0 {
			t.Fatalf("agent_up does not hold live port %d", p)
		}
	}
}

// TestGate_RefreshAgentUpPorts_OldWindowPortsAgeOut proves a port that drops
// out of the live set on a later call is not refreshed — it keeps only its
// last-given ttl and expires on its own, which is how the rotation design
// lets an expired window's port leave agent_up without a separate delete.
func TestGate_RefreshAgentUpPorts_OldWindowPortsAgeOut(t *testing.T) {
	g := newLinuxTestGate(t, rotationPolicy(t))
	// window w
	if err := g.RefreshAgentUpPorts(t.Context(), []uint16{20001, 20002, 20003}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// window w+1: 20001 drops out of the live set and is NOT refreshed.
	if err := g.RefreshAgentUpPorts(t.Context(), []uint16{20002, 20003, 20004}, time.Minute); err != nil {
		t.Fatal(err)
	}
	// 20004 is now live on the long ttl; 20001 keeps only its short remaining ttl
	// and expires on its own. Assert the new member is live and the dropped one is
	// short-lived, not that it is already gone (timing-independent).
	if left, _ := g.AgentUpExpiryFor(t.Context(), 20004); left <= 0 {
		t.Fatalf("new live port 20004 was not added")
	}
	if left, _ := g.AgentUpExpiryFor(t.Context(), 20001); left > 3*time.Second {
		t.Fatalf("dropped port 20001 was refreshed on the long ttl; it must age out")
	}
}

func rawElementCount(t *testing.T, g *NFTables, service string, family AddrFamily, kind SetKind) int {
	t.Helper()
	plan, ok := g.plan.ServiceByName(service)
	if !ok {
		t.Fatalf("no plan for service %q", service)
	}
	set, ok := plan.SetByFamilyKind(family, kind)
	if !ok {
		t.Fatalf("plan for %q has no %s/%s set", service, family, kind)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: plan.Table}
	kset, err := g.conn.GetSetByName(table, set.Name)
	if err != nil {
		t.Fatalf("GetSetByName(%s): %v", set.Name, err)
	}
	elems, err := g.conn.GetSetElements(kset)
	if err != nil {
		t.Fatalf("GetSetElements(%s): %v", set.Name, err)
	}
	return len(elems)
}

// remainingFor reads how long the kernel says this source has left.
func remainingFor(t *testing.T, g *NFTables, service string, src Source) time.Duration {
	t.Helper()
	state, err := g.State(context.Background(), service)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	for _, e := range state.Elements {
		if e.Source.Prefix == src.Prefix {
			return e.Expires
		}
	}
	t.Fatalf("%s is not open in %s", src.Prefix, service)
	return 0
}

func stateContains(state ServiceState, src Source) bool {
	for _, e := range state.Elements {
		if e.Source.Kind == src.Kind && e.Source.Prefix == src.Prefix {
			return true
		}
	}
	return false
}

// TestGate_RendererEquivalence_NetlinkAndBootNFTAgree is invariant 6: apply
// one policy two of its three ways — netlink directly, and `nft -f` against
// the generated boot.nft text — and assert `nft list table inet
// postern_boot` hashes identically once trivial whitespace is normalised.
// The third way, the systemd flush lines, is asserted structurally against
// the same plan in render_test.go's
// TestGate_Render_FlushLinesNameExactlyTheBootFailClosedSets, since flush
// lines empty existing sets rather than construct a table and so have
// nothing of their own for `nft list ruleset` to show.
func TestGate_RendererEquivalence_NetlinkAndBootNFTAgree(t *testing.T) {
	policy := loopbackPolicy(t)
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}

	dropTablesViaNft(t)
	g := newLinuxTestGate(t, policy) // applies via netlink, including postern_open — dumped table below is scoped to postern_boot only
	netlinkDump := dumpBootTable(t)
	netlinkHash := normalizeAndHash(netlinkDump)

	dropTables(g.conn) // tear down the netlink-applied state before nft -f builds its own
	dropTablesViaNft(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "boot.nft")
	if err := os.WriteFile(path, []byte(RenderBootNFT(plan)), 0o600); err != nil {
		t.Fatalf("write boot.nft: %v", err)
	}
	if out, err := exec.Command("nft", "-f", path).CombinedOutput(); err != nil { //nolint:gosec // path is this test's own t.TempDir() file, not attacker input
		t.Fatalf("nft -f %s: %v\n%s", path, err, out)
	}
	t.Cleanup(func() { dropTablesViaNft(t) })
	textDump := dumpBootTable(t)
	textHash := normalizeAndHash(textDump)

	if netlinkHash != textHash {
		t.Fatalf("netlink-applied and nft -f boot.nft-applied rulesets diverge:\n"+
			"netlink (hash %s):\n%s\n\ntext (hash %s):\n%s", netlinkHash, netlinkDump, textHash, textDump)
	}
}

// TestGate_RendererEquivalence_RangeDropAgreesAcrossNetlinkAndBootNFT is
// TestGate_RendererEquivalence_NetlinkAndBootNFTAgree's rotation-mode
// counterpart: same comparison, but the policy carries a port_rotation block,
// so the artifact under comparison is the "udp dport lo-hi drop" range rule
// dportRangeDropExprs and RenderBootNFT must each produce identically.
func TestGate_RendererEquivalence_RangeDropAgreesAcrossNetlinkAndBootNFT(t *testing.T) {
	policy := rotationPolicy(t)
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}

	dropTablesViaNft(t)
	g := newLinuxTestGate(t, policy) // applies via netlink, including postern_open — dumped table below is scoped to postern_boot only
	netlinkDump := dumpBootTable(t)
	netlinkHash := normalizeAndHash(netlinkDump)

	dropTables(g.conn) // tear down the netlink-applied state before nft -f builds its own
	dropTablesViaNft(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "boot.nft")
	if err := os.WriteFile(path, []byte(RenderBootNFT(plan)), 0o600); err != nil {
		t.Fatalf("write boot.nft: %v", err)
	}
	if out, err := exec.Command("nft", "-f", path).CombinedOutput(); err != nil { //nolint:gosec // path is this test's own t.TempDir() file, not attacker input
		t.Fatalf("nft -f %s: %v\n%s", path, err, out)
	}
	t.Cleanup(func() { dropTablesViaNft(t) })
	textDump := dumpBootTable(t)
	textHash := normalizeAndHash(textDump)

	if netlinkHash != textHash {
		t.Fatalf("netlink-applied and nft -f boot.nft-applied rulesets diverge under port rotation:\n"+
			"netlink (hash %s):\n%s\n\ntext (hash %s):\n%s", netlinkHash, netlinkDump, textHash, textDump)
	}
}

func dumpBootTable(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", TableBoot).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table inet %s: %v\n%s", TableBoot, err, out)
	}
	return string(out)
}

// normalizeAndHash strips leading/trailing whitespace per line and blank
// lines before hashing, since `nft list` and this package's own text
// renderer are not obligated to agree on indentation or blank-line
// placement — only on which tables, sets, and rules exist.
func normalizeAndHash(s string) string {
	lines := strings.Split(s, "\n")
	var norm []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		norm = append(norm, l)
	}
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return hex.EncodeToString(sum[:])
}

// decodeElements must pair an interval's start and end by value, not by the
// order the kernel happened to return them in.
//
// This kernel returns a single /24 as [end, start] — the end marker first —
// so a decoder that pairs each start with the record following it finds
// nothing and falls back to a /32. State() then reports a /24 grant as one
// address, and Open's identical-prefix refresh, which asks this decoder
// whether the source is already live, never matches. Both orders are given
// here because either alone would pass against a decoder that only handles
// that one.
func TestGate_DecodeElements_PairsAnIntervalByValueNotByOrder(t *testing.T) {
	start := []byte{203, 0, 113, 0}
	end := []byte{203, 0, 114, 0}
	set := GateSet{Name: "gate_admin_v4_cidr", Family: FamilyIPv4, Kind: SetAsserted}

	for _, tc := range []struct {
		name  string
		elems []nftables.SetElement
	}{
		{"end first, as this kernel returns it", []nftables.SetElement{
			{Key: end, IntervalEnd: true},
			{Key: start, Timeout: 30 * time.Second, Expires: 25 * time.Second},
		}},
		{"start first", []nftables.SetElement{
			{Key: start, Timeout: 30 * time.Second, Expires: 25 * time.Second},
			{Key: end, IntervalEnd: true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeElements(tc.elems, set)
			if len(got) != 1 {
				t.Fatalf("decoded %d elements, want 1: %+v", len(got), got)
			}
			want := netip.MustParsePrefix("203.0.113.0/24")
			if got[0].Source.Prefix != want {
				t.Fatalf("decoded prefix = %s, want %s — a /24 grant reported as %s understates what is "+
					"open and breaks the refresh path that asks this decoder what is live",
					got[0].Source.Prefix, want, got[0].Source.Prefix)
			}
			if got[0].Expires != 25*time.Second {
				t.Fatalf("decoded expiry = %s, want 25s (it must come from the start record, not the end marker)", got[0].Expires)
			}
		})
	}
}

// A gate service a fleet bundle ADDS must become openable without restarting
// posternd. Before SetPolicy, NFTables answered "%q is not a known gate
// service" from the catalogue it was constructed with — after the agent's own
// validation had already passed and after the replay store had already
// consumed that packet's slot, so the operator saw silence and the packet was
// spent.
//
// Driven against the real kernel, and in the order the agent drives it: the
// new catalogue is adopted, then the tables for it are applied, then the knock
// opens. The "before" half is what makes it attributable — without it, a test
// that only checked the "after" would pass on a gate that had somehow known
// about the service all along.
func TestGate_SetPolicy_MakesAServiceAddedByANewPolicyOpenable(t *testing.T) {
	base := loopbackPolicy(t)
	added := "relay"
	next := loopbackPolicy(t)
	next.Services[added] = config.Service{
		Name: added, Kind: config.KindGate, Proto: "tcp", Ports: []uint16{9443},
		DefaultTTL: 60 * time.Second, MaxTTL: 300 * time.Second,
		FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
	}
	if _, ok := base.Services[added]; ok {
		t.Fatalf("fixture already declares %q; this test asserts nothing", added)
	}

	g := newLinuxTestGate(t, base)
	ctx := context.Background()
	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.5/32")}

	err := g.Open(ctx, added, src, time.Minute)
	if err == nil {
		t.Fatalf("Open(%q) succeeded before the policy declaring it was adopted", added)
	}
	if !strings.Contains(err.Error(), "is not a known gate service") {
		t.Fatalf("Open(%q) before adoption failed with %v, want the unknown-service refusal; this "+
			"test is not isolating the catalogue", added, err)
	}

	if err := g.SetPolicy(next); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	// The agent recreates postern_open and reloads postern_boot around this
	// call; here the equivalent is dropping both and applying the new plan.
	dropTables(g.conn)
	if err := g.Apply(ctx); err != nil {
		t.Fatalf("Apply the adopted policy: %v", err)
	}

	if err := g.Open(ctx, added, src, time.Minute); err != nil {
		t.Fatalf("Open(%q) after adopting the policy that declares it: %v", added, err)
	}
	state, err := g.State(ctx, added)
	if err != nil {
		t.Fatalf("State(%q): %v", added, err)
	}
	if !stateContains(state, src) {
		t.Fatalf("%q was opened for %s but the set does not hold it", added, src.Prefix)
	}
}
