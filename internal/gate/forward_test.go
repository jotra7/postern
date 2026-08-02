package gate

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// forwardFixturePolicy is fixturePolicy plus one forwarded path.
//
// Every value that a mixed-up renderer could substitute for another is
// deliberately distinct, and one of them is deliberately not: the forward's
// EXTERNAL port (2222) differs from its INTERNAL port, and the internal port
// (22) is the same number as the local ssh gate's port. A renderer that wrote
// the forward's rules against the wrong end of the path would therefore either
// name 2222 where 22 belongs, which is visible, or collide with an unrelated
// local service, which is also visible. Two axes that must differ, plus one
// collision that must not happen.
func forwardFixturePolicy() *config.Policy {
	p := fixturePolicy()
	p.Services["dbhost"] = config.Service{
		Name: "dbhost", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{2222},
		DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
		FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
		Forward: &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 22},
	}
	return p
}

func mustForwardPlan(t *testing.T) *RulesetPlan {
	t.Helper()
	plan, err := BuildRulesetPlan(forwardFixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	return plan
}

// A forwarded path can only live in postern_boot. The DNAT rule is the path,
// and postern_open is deleted by ExecStopPost on every exit, so a forward
// planned there would take its own path away at the moment the posture it
// declared says the path holds.
func TestGate_Plan_ForwardLandsInTheBootTable(t *testing.T) {
	plan := mustForwardPlan(t)

	svc, ok := plan.ServiceByName("dbhost")
	if !ok {
		t.Fatal("plan has no dbhost service")
	}
	if svc.Table != TableBoot {
		t.Fatalf("forward planned into table %q, want %q", svc.Table, TableBoot)
	}
	if svc.Forward == nil {
		t.Fatal("forward service planned with no ForwardPlan")
	}
	if svc.Forward.To.String() != "10.0.0.5" || svc.Forward.Port != 22 {
		t.Fatalf("planned forward target is %s:%d, want 10.0.0.5:22", svc.Forward.To, svc.Forward.Port)
	}
}

// The posture refusal in config is where an operator meets it; this one is the
// mechanism refusing to generate a shape it cannot deliver, for a Policy
// assembled in code that never passed through a parser.
func TestGate_Plan_RejectsAForwardResolvedFailOpen(t *testing.T) {
	p := forwardFixturePolicy()
	svc := p.Services["dbhost"]
	svc.FailPosture = config.PostureOpen
	p.Services["dbhost"] = svc

	_, err := BuildRulesetPlan(p)
	if err == nil {
		t.Fatal("BuildRulesetPlan accepted a fail-open forward")
	}
	if !strings.Contains(err.Error(), TableBoot) {
		t.Fatalf("refusal does not name the only table a forward can live in: %v", err)
	}
}

// A DNAT rule rewrites the destination to a literal of one address family, so
// the other family's sets would be sets no generated rule ever reads. An
// operator knocking from that family would be admitted into nothing, and told
// it worked.
func TestGate_Plan_ForwardHasSetsForItsTargetFamilyOnly(t *testing.T) {
	plan := mustForwardPlan(t)

	svc, ok := plan.ServiceByName("dbhost")
	if !ok {
		t.Fatal("plan has no dbhost service")
	}
	if len(svc.Sets) != 2 {
		t.Fatalf("forward to an IPv4 target has %d sets, want 2 (observed and asserted, v4 only): %+v",
			len(svc.Sets), svc.Sets)
	}
	for _, s := range svc.Sets {
		if s.Family != FamilyIPv4 {
			t.Fatalf("forward to an IPv4 target carries a %s set %q", s.Family, s.Name)
		}
	}
	if _, ok := svc.SetByFamilyKind(FamilyIPv6, SetObserved); ok {
		t.Fatal("forward to an IPv4 target reports an IPv6 observed set")
	}
	// An ordinary local gate in the same plan keeps all four, so this is a
	// property of forwards rather than of this plan.
	local, ok := plan.ServiceByName("admin")
	if !ok {
		t.Fatal("plan has no admin service")
	}
	if len(local.Sets) != 4 {
		t.Fatalf("local gate has %d sets, want 4", len(local.Sets))
	}
}

// The DNAT target is the one the host configured, and neither end of the path
// is written where the other belongs: the translation is from the external port
// to the internal address and port, the forward chain's rules name the internal
// end, and the input chain's drop names the external one.
func TestGate_Render_ForwardTranslatesTheExternalPortToTheConfiguredTarget(t *testing.T) {
	out := RenderBootNFT(mustForwardPlan(t))

	dnat := "tcp dport 2222 ip saddr @gate_dbhost_v4_obs dnat ip to 10.0.0.5:22"
	if !strings.Contains(out, dnat) {
		t.Fatalf("rendered boot.nft has no DNAT rule %q:\n%s", dnat, out)
	}
	if !strings.Contains(out, "ip daddr 10.0.0.5 tcp dport 22 ip saddr @gate_dbhost_v4_obs accept") {
		t.Fatalf("rendered boot.nft has no forward-chain accept against the internal target:\n%s", out)
	}
	if !strings.Contains(out, "ip daddr 10.0.0.5 tcp dport 22 drop") {
		t.Fatalf("rendered boot.nft has no forward-chain drop against the internal target:\n%s", out)
	}
	if !strings.Contains(out, "    tcp dport 2222 drop\n") {
		t.Fatalf("rendered boot.nft does not silence the external port:\n%s", out)
	}
	// The two ends must not have swapped. "dnat ... to 10.0.0.5:2222" and a
	// forward-chain rule naming 2222 are each what a renderer reaching for
	// svc.Ports where the target's port belongs would emit.
	if strings.Contains(out, "to 10.0.0.5:2222") {
		t.Fatalf("DNAT target port is this host's external port, not the internal one:\n%s", out)
	}
	if strings.Contains(out, "ip daddr 10.0.0.5 tcp dport 2222") {
		t.Fatalf("forward chain matches the external port; prerouting has already rewritten it:\n%s", out)
	}
}

// The external port has no local listener to accept onto: an admitted source is
// translated in prerouting and never reaches the input hook, and a source that
// is not admitted would be accepted onto a closed local port. An accept here
// would also be the one rule that could carry a knock to a port on THIS host
// under a forward's grant.
func TestGate_Render_ForwardsExternalPortGetsADropAndNoAccept(t *testing.T) {
	out := RenderBootNFT(mustForwardPlan(t))

	if strings.Contains(out, "tcp dport 2222 ip saddr @gate_dbhost_v4_obs accept") {
		t.Fatalf("input chain accepts the forward's external port locally:\n%s", out)
	}
	// The equivalent accept for an ordinary local gate is present, so this is a
	// property of forwards and not of the renderer having stopped emitting
	// accepts at all.
	if !strings.Contains(out, "tcp dport 8443 ip saddr @gate_admin_v4_obs accept") {
		t.Fatalf("input chain has no accept for the local admin gate:\n%s", out)
	}
}

// The always-allow promise on the forward hook. A box that forwards is a box
// that routes, so an operator on the mesh reaches the internal machine through
// it directly, with no DNAT involved, and the drop this design puts in the
// forward chain is written against exactly that traffic's destination. Without
// the accept above it, arming a forward would cut the path that exists so that
// arming a forward is survivable.
func TestGate_Render_ForwardChainAcceptsAlwaysAllowBeforeAnyDrop(t *testing.T) {
	out := RenderBootNFT(mustForwardPlan(t))

	chain := forwardChainText(t, out)
	allow := strings.Index(chain, "iifname \"tailscale0\" accept")
	established := strings.Index(chain, "ct state established,related accept")
	if allow == -1 {
		t.Fatalf("forward chain has no always-allow accept:\n%s", chain)
	}
	if established == -1 {
		t.Fatalf("forward chain has no established/related accept:\n%s", chain)
	}
	firstDrop := strings.Index(chain, "drop")
	if firstDrop == -1 {
		t.Fatalf("forward chain has no drop at all, so it enforces nothing:\n%s", chain)
	}
	if allow >= firstDrop || established >= firstDrop {
		t.Fatalf("forward chain drops before it accepts the always-allow path; "+
			"allow=%d established=%d firstDrop=%d:\n%s", allow, established, firstDrop, chain)
	}
}

// No forward configured, no nat chain and no forward chain. A nat chain
// registers conntrack on the host that carries it, so a host with no forwarded
// path must not acquire one because postern generated a chain it never uses.
func TestGate_Render_NoForwardConfiguredEmitsNeitherNewChain(t *testing.T) {
	out := RenderBootNFT(mustPlan(t))

	if strings.Contains(out, "hook prerouting") {
		t.Fatalf("boot.nft for a policy with no forward carries a nat chain:\n%s", out)
	}
	if strings.Contains(out, "hook forward") {
		t.Fatalf("boot.nft for a policy with no forward carries a forward chain:\n%s", out)
	}
	if strings.Contains(out, "dnat") {
		t.Fatalf("boot.nft for a policy with no forward carries a dnat rule:\n%s", out)
	}
}

// The forward's sets are fail-closed sets in postern_boot like any other, so
// agent stop empties them and leaves the DNAT rule and the forward-chain drop
// standing. Left off this list, an operator's forwarded path would outlive the
// agent that granted it.
func TestGate_Render_FlushLinesCoverAForwardsSets(t *testing.T) {
	names := FlushSetNames(mustForwardPlan(t))

	want := map[string]bool{"gate_dbhost_v4_obs": false, "gate_dbhost_v4_cidr": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Fatalf("flush lines do not name the forward's set %q; got %v", n, names)
		}
	}
	for _, n := range names {
		if strings.HasSuffix(n, "_v6_obs") && strings.HasPrefix(n, "gate_dbhost") {
			t.Fatalf("flush lines name %q, a set no forward to an IPv4 target has", n)
		}
	}
}

// Forwards() is what both renderers drive the new chains from, so it must
// report the forwarded paths and only those.
func TestGate_Plan_ForwardsReportsOnlyForwardedServices(t *testing.T) {
	plan := mustForwardPlan(t)

	got := plan.Forwards()
	if len(got) != 1 {
		names := make([]string, 0, len(got))
		for _, s := range got {
			names = append(names, s.Name)
		}
		t.Fatalf("Forwards() returned %d services (%v), want just dbhost", len(got), names)
	}
	if got[0].Name != "dbhost" {
		t.Fatalf("Forwards() returned %q, want dbhost", got[0].Name)
	}
	if len(mustPlan(t).Forwards()) != 0 {
		t.Fatal("Forwards() returned a service for a policy with no forward")
	}
}

// forwardChainText returns just the forward chain's body, so an ordering
// assertion about that chain cannot be satisfied by a rule in the input chain.
func forwardChainText(t *testing.T, out string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)\n  chain ` + ChainForward + ` \{\n(.*?)\n  \}`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("rendered boot.nft has no %s chain:\n%s", ChainForward, out)
	}
	return m[1]
}

// The plan builder holds the target's own shape as well as the table's. It is
// the last thing between a Policy and a generated DNAT rule, and a Policy
// assembled in code reaches it without passing through config validation.
func TestGate_Plan_RejectsAForwardWithNoUsableTarget(t *testing.T) {
	for _, tc := range []struct {
		name string
		fwd  config.Forward
		want string
	}{
		{"no address", config.Forward{Port: 22}, "no target address"},
		{"no port", config.Forward{To: netip.MustParseAddr("10.0.0.5")}, "no target port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := forwardFixturePolicy()
			svc := p.Services["dbhost"]
			fwd := tc.fwd
			svc.Forward = &fwd
			p.Services["dbhost"] = svc

			_, err := BuildRulesetPlan(p)
			if err == nil {
				t.Fatalf("BuildRulesetPlan accepted a forward with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not say %q: %v", tc.want, err)
			}
		})
	}
}
