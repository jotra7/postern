//go:build linux

package gate

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These run under the same privileged, network-isolated container the rest of
// this package's kernel tests do; see nft_linux_test.go's header. What they
// exercise is the ruleset a forwarded path produces: that it loads, that both
// renderers produce the same one, that the always-allow accept really sits
// above the drop in the chain the kernel holds, and that the lease is a set
// element with the kernel's own timer on it while the DNAT rule beside it has
// no timer at all.
//
// What they do not exercise is a packet traversing the path. That needs a
// client namespace, a target namespace, and this container as the router
// between them, and it is not built here; see the report accompanying this
// branch.

// The boot ruleset carries a forward's DNAT rule, its forward-chain drop, and
// its sets, and it has to load before the network comes up on a host whose
// always-allow interface does not exist yet. A nat chain and a forward chain
// are two more things that can fail that load.
func TestGate_ForwardBootRuleset_LoadsWithAlwaysAllowInterfaceAbsent(t *testing.T) {
	plan := mustForwardPlan(t)
	text := RenderBootNFT(plan)

	dropTablesViaNft(t)
	t.Cleanup(func() { dropTablesViaNft(t) })

	dir := t.TempDir()
	path := filepath.Join(dir, "boot.nft")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write boot.nft: %v", err)
	}
	if out, err := exec.Command("nft", "-f", path).CombinedOutput(); err != nil { //nolint:gosec // path is this test's own t.TempDir() file, not attacker input
		t.Fatalf("nft -f %s failed with the always-allow interface absent: %v\n%s\nrendered file:\n%s",
			path, err, out, text)
	}
}

// Renderer equivalence (invariant 6) extended to the two chains a forward
// adds. The netlink writer and boot.nft must produce the same ruleset, or a
// host's live posture and its boot-time posture differ on a path that reaches
// another machine.
func TestGate_ForwardRendererEquivalence_NetlinkAndBootNFTAgree(t *testing.T) {
	policy := forwardFixturePolicy()
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}

	dropTablesViaNft(t)
	g := newLinuxTestGate(t, policy)
	netlinkDump := dumpBootTable(t)
	netlinkHash := normalizeAndHash(netlinkDump)

	dropTables(g.conn)
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
		t.Fatalf("netlink-applied and nft -f boot.nft-applied forward rulesets diverge:\n"+
			"netlink (hash %s):\n%s\n\ntext (hash %s):\n%s", netlinkHash, netlinkDump, textHash, textDump)
	}
}

// The always-allow promise as the kernel holds it, not as the renderer wrote
// it. The pure test reads generated text; this one reads the chain back out of
// the kernel after it has been loaded and re-rendered by nft(8), which is the
// form an operator would inspect during an outage.
func TestGate_ForwardChain_AlwaysAllowAcceptPrecedesEveryDropInTheKernel(t *testing.T) {
	newLinuxTestGate(t, forwardFixturePolicy())

	chain := kernelForwardChain(t)
	allow := strings.Index(chain, `iifname "tailscale0" accept`)
	if allow == -1 {
		t.Fatalf("kernel forward chain has no always-allow accept:\n%s", chain)
	}
	firstDrop := strings.Index(chain, "drop")
	if firstDrop == -1 {
		t.Fatalf("kernel forward chain has no drop, so it enforces nothing:\n%s", chain)
	}
	if allow >= firstDrop {
		t.Fatalf("kernel forward chain drops before accepting the always-allow path:\n%s", chain)
	}
}

// The lease is a set element with a per-element timeout, exactly as a local
// gate's is, and the DNAT rule beside it carries no timer at all. That split is
// the whole expiry story for a forwarded path: the kernel closes it by dropping
// the element the DNAT rule tests membership in, so nothing has to remember to
// remove a rule.
func TestGate_ForwardOpen_ElementExpiresWhileTheDNATRuleStands(t *testing.T) {
	g := newLinuxTestGate(t, forwardFixturePolicy())
	ctx := context.Background()

	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.9/32")}
	if err := g.Open(ctx, "dbhost", src, 2*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}

	st, err := g.State(ctx, "dbhost")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if len(st.Elements) != 1 {
		t.Fatalf("after Open the forward holds %d elements, want 1: %+v", len(st.Elements), st.Elements)
	}
	if st.Elements[0].Expires <= 0 {
		t.Fatalf("forward lease carries no kernel timeout: %+v", st.Elements[0])
	}

	time.Sleep(3 * time.Second)

	st, err = g.State(ctx, "dbhost")
	if err != nil {
		t.Fatalf("State after expiry: %v", err)
	}
	if len(st.Elements) != 0 {
		t.Fatalf("forward lease outlived its ttl: %+v", st.Elements)
	}
	if dump := dumpBootTable(t); !strings.Contains(dump, "dnat") {
		t.Fatalf("the DNAT rule expired along with the lease; only the element may:\n%s", dump)
	}
}

// Agent stop empties the fail-closed sets and leaves postern_boot's rules
// standing. For a forward that means the path shuts: the DNAT rule and the
// drop are both still there, and the set they test is empty.
func TestGate_ForwardClose_EmptiesTheLeaseAndLeavesTheDNATAndDropStanding(t *testing.T) {
	g := newLinuxTestGate(t, forwardFixturePolicy())
	ctx := context.Background()

	src := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("198.51.100.9/32")}
	if err := g.Open(ctx, "dbhost", src, time.Hour); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err := g.State(ctx, "dbhost")
	if err != nil {
		t.Fatalf("State after Close: %v", err)
	}
	if len(st.Elements) != 0 {
		t.Fatalf("Close left the forward's lease live, so the path outlives the agent: %+v", st.Elements)
	}
	dump := dumpBootTable(t)
	if !strings.Contains(dump, "dnat ip to 10.0.0.5:22") {
		t.Fatalf("Close removed the DNAT rule; it is postern_boot's and must survive:\n%s", dump)
	}
	if !strings.Contains(dump, "ip daddr 10.0.0.5 tcp dport 22 drop") {
		t.Fatalf("Close removed the forward chain's drop, which is the posture itself:\n%s", dump)
	}
}

// A forward's target address fixes one address family, so a knock from the
// other one resolves a real service, is authorized, and then finds no set to
// go into. That has to be an error the packet loop can log and return, not a
// panic in the agent, and it must not silently succeed into a set no rule
// reads.
func TestGate_ForwardOpen_RefusesASourceFromTheOtherAddressFamily(t *testing.T) {
	g := newLinuxTestGate(t, forwardFixturePolicy())
	ctx := context.Background()

	v6 := Source{Kind: SourceObserved, Prefix: netip.MustParsePrefix("2001:db8::9/128")}
	err := g.Open(ctx, "dbhost", v6, time.Minute)
	if err == nil {
		t.Fatal("Open admitted an IPv6 source into a forward whose target is IPv4")
	}
	if !strings.Contains(err.Error(), "address family") {
		t.Fatalf("refusal does not say why: %v", err)
	}

	// The same source into an ordinary local gate in the same plan is fine, so
	// the refusal is about the forward and not about IPv6 having broken.
	if err := g.Open(ctx, "admin", v6, time.Minute); err != nil {
		t.Fatalf("Open of an IPv6 source into a local gate: %v", err)
	}
}

// kernelForwardChain returns the forward chain as nft(8) renders it back out
// of the kernel, so an ordering assertion cannot be satisfied by a rule that
// lives in another chain.
func kernelForwardChain(t *testing.T) string {
	t.Helper()
	dump := dumpBootTable(t)
	re := regexp.MustCompile(`(?s)chain ` + ChainForward + ` \{(.*?)\n\t\}`)
	m := re.FindStringSubmatch(dump)
	if m == nil {
		t.Fatalf("kernel dump has no %s chain:\n%s", ChainForward, dump)
	}
	return m[1]
}
