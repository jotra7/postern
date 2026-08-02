//go:build linux

package gate

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// fakeForeignLister is the injected netlink seam ForeignFirewallChains is
// tested against, so these tests need no privileged container and no real
// kernel (unlike nft_linux_test.go's tests, which do). rules is keyed by
// chain pointer identity, matching how ForeignFirewallChains reads rules
// back: one GetRules call per candidate chain, using the exact
// *nftables.Chain ListChains just handed it.
type fakeForeignLister struct {
	chains []*nftables.Chain
	rules  map[*nftables.Chain][]*nftables.Rule
}

func (f *fakeForeignLister) ListChains() ([]*nftables.Chain, error) { return f.chains, nil }

func (f *fakeForeignLister) GetRules(_ *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	return f.rules[c], nil
}

func dropPolicy() *nftables.ChainPolicy {
	p := nftables.ChainPolicyDrop
	return &p
}

func acceptPolicy() *nftables.ChainPolicy {
	p := nftables.ChainPolicyAccept
	return &p
}

// TestGate_ForeignFirewallChains_FlagsRuleLevelDrop is the motivating bug
// itself, from the brief's own real-world example: a foreign table's input
// chain, accept policy, with a plain rule-level drop on the gated port —
// `table ip filter` / chain INPUT / "tcp dport 22 ... drop" alongside an IP
// allowlist. postern's gate can open perfectly and this rule still kills
// the SYN.
func TestGate_ForeignFirewallChains_FlagsRuleLevelDrop(t *testing.T) {
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: "INPUT", Table: table, Hooknum: nftables.ChainHookInput, Policy: acceptPolicy()}
	dropRule := &nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}}

	lister := &fakeForeignLister{
		chains: []*nftables.Chain{chain},
		rules:  map[*nftables.Chain][]*nftables.Rule{chain: {dropRule}},
	}

	findings := ForeignFirewallChains(lister, mustPlan(t))

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the one rule-level drop", findings)
	}
	f := findings[0]
	if f.Table != "filter" || f.Chain != "INPUT" || f.Hook != ChainInput {
		t.Fatalf("finding = %+v, want table filter chain INPUT hook %s", f, ChainInput)
	}
	if !f.RuleDrop || f.PolicyDrop {
		t.Fatalf("finding = %+v, want RuleDrop true and PolicyDrop false", f)
	}
}

// TestGate_ForeignFirewallChains_FlagsPolicyDrop is invariant 2's other
// shape of risk: no explicit drop rule at all, but the chain's own base
// policy is drop, so anything reaching the end of the chain without an
// earlier accept is dropped exactly as tersely as a rule would have done it
// — firewalld's per-zone chains are the ordinary real-world example.
func TestGate_ForeignFirewallChains_FlagsPolicyDrop(t *testing.T) {
	table := &nftables.Table{Name: "firewalld", Family: nftables.TableFamilyINet}
	chain := &nftables.Chain{Name: "filter_IN_public", Table: table, Hooknum: nftables.ChainHookInput, Policy: dropPolicy()}

	lister := &fakeForeignLister{chains: []*nftables.Chain{chain}}

	findings := ForeignFirewallChains(lister, mustPlan(t))

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the one policy drop", findings)
	}
	if f := findings[0]; !f.PolicyDrop || f.RuleDrop {
		t.Fatalf("finding = %+v, want PolicyDrop true and RuleDrop false", f)
	}
}

// TestGate_ForeignFirewallChains_IgnoresPosternsOwnTables is invariant 2's
// counterpart: TableBoot and TableOpen carry the identical duplicated
// always-allow/established rules and gate drops in every table on the hook
// (applyTable's own comment) by design. Those are the mechanism this
// warning exists to protect, not a foreign firewall to flag.
func TestGate_ForeignFirewallChains_IgnoresPosternsOwnTables(t *testing.T) {
	for _, name := range []string{TableBoot, TableOpen} {
		table := &nftables.Table{Name: name, Family: nftables.TableFamilyINet}
		chain := &nftables.Chain{Name: ChainInput, Table: table, Hooknum: nftables.ChainHookInput, Policy: dropPolicy()}
		lister := &fakeForeignLister{chains: []*nftables.Chain{chain}}

		findings := ForeignFirewallChains(lister, mustPlan(t))
		if len(findings) != 0 {
			t.Fatalf("table %q was flagged as foreign: %+v", name, findings)
		}
	}
}

// TestGate_ForeignFirewallChains_IgnoresChainsWithNoDrop is the ordinary,
// unremarkable case: a foreign chain on the input hook that accepts
// everything reaching it carries none of invariant 2's risk and must not be
// reported — reporting a harmless chain would teach operators to ignore the
// warning.
func TestGate_ForeignFirewallChains_IgnoresChainsWithNoDrop(t *testing.T) {
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: "INPUT", Table: table, Hooknum: nftables.ChainHookInput, Policy: acceptPolicy()}
	acceptRule := &nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}

	lister := &fakeForeignLister{
		chains: []*nftables.Chain{chain},
		rules:  map[*nftables.Chain][]*nftables.Rule{chain: {acceptRule}},
	}

	findings := ForeignFirewallChains(lister, mustPlan(t))
	if len(findings) != 0 {
		t.Fatalf("a chain with no drop risk was flagged: %+v", findings)
	}
}

// TestGate_ForeignFirewallChains_IgnoresUnrelatedHooks confirms the hook
// filter is load-bearing: a chain on the output hook can never override an
// input-hook accept (invariant 2 is specifically about chains sharing a
// hook), so a drop there is somebody else's business, not a finding here.
func TestGate_ForeignFirewallChains_IgnoresUnrelatedHooks(t *testing.T) {
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: "OUTPUT", Table: table, Hooknum: nftables.ChainHookOutput, Policy: dropPolicy()}

	lister := &fakeForeignLister{chains: []*nftables.Chain{chain}}

	findings := ForeignFirewallChains(lister, mustPlan(t))
	if len(findings) != 0 {
		t.Fatalf("an output-hook chain was flagged: %+v", findings)
	}
}

// TestGate_ForeignFirewallChains_ForwardHookOnlyMatteredWhenPolicyForwards
// is the hook-selection half of the design: a foreign chain on the forward
// hook is only in scope when this host's own plan uses that hook too (i.e.
// it has at least one forwarded path, per applyForwardChains). The same
// chain is invisible against a plan with no forward, because nothing
// postern writes shares that hook with it and it cannot override a chain
// that is not there.
func TestGate_ForeignFirewallChains_ForwardHookOnlyMatteredWhenPolicyForwards(t *testing.T) {
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: "FORWARD", Table: table, Hooknum: nftables.ChainHookForward, Policy: dropPolicy()}
	lister := &fakeForeignLister{chains: []*nftables.Chain{chain}}

	noForward := ForeignFirewallChains(lister, mustPlan(t))
	if len(noForward) != 0 {
		t.Fatalf("a forward-hook chain was flagged against a plan with no forwarded path: %+v", noForward)
	}

	withForward := ForeignFirewallChains(lister, mustForwardPlan(t))
	if len(withForward) != 1 {
		t.Fatalf("findings = %+v, want the forward-hook chain flagged once a forward is configured", withForward)
	}
	if withForward[0].Hook != ChainForward {
		t.Fatalf("finding = %+v, want hook %s", withForward[0], ChainForward)
	}
}
