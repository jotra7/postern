//go:build linux

package gate

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// This file is the advisory half of invariant 2 (design section 4,
// applyTable's own comment above): nftables runs every base chain
// registered on a hook, and a drop verdict in any one of them is terminal
// regardless of an accept in another. postern duplicates its own
// always-allow and established/related rules into both its own tables for
// exactly that reason — but nothing here can duplicate itself into a
// firewall postern does not own. A host that also runs iptables-nft, ufw,
// firewalld, or a hand-rolled table can open postern's gate perfectly and
// still drop the knocker's traffic in that other chain, silently: the knock
// reports success (the gate really did open) and the SYN never arrives
// (something else killed it on the same hook). This never blocks arming —
// a foreign firewall is often intentional and correctly configured — it
// only names the chains an operator should go check.

// ForeignChainFinding is one foreign nftables base chain sharing a hook
// postern's own ruleset uses, flagged because it carries invariant 2's
// override risk: its own base policy is drop, a rule inside it carries an
// immediate drop or reject, or both. It names exactly what an operator
// needs to go look at — which table and chain, on which hook, and which of
// the two shapes the risk takes — rather than a bare "something might
// interfere".
type ForeignChainFinding struct {
	// Family is the table's address family rendered the way `nft list`
	// names it ("ip", "ip6", "inet", ...), not the raw nftables.TableFamily
	// byte, so the finding reads the same whether it is printed straight or
	// wrapped into prearm's warning text.
	Family string
	Table  string
	Chain  string
	// Hook is one of ChainInput, ChainForward, ChainPrerouting: always a
	// hook postern's own plan also registers a chain on, never a foreign
	// hook nothing here writes to (e.g. output), because such a chain could
	// not override anything postern's gate does regardless of its policy.
	Hook string
	// PolicyDrop is true when the chain's own base policy is drop: nothing
	// short of an earlier accept keeps a packet reaching the end of the
	// chain alive.
	PolicyDrop bool
	// RuleDrop is true when some rule inside the chain carries an
	// immediate drop verdict or a reject expression, independent of the
	// chain's policy.
	RuleDrop bool
}

// String renders one finding as the line prearm's wiring names in the
// warning text it builds from a slice of these.
func (f ForeignChainFinding) String() string {
	origin := "a rule-level drop or reject"
	switch {
	case f.PolicyDrop && f.RuleDrop:
		origin = "a policy drop and a rule-level drop or reject"
	case f.PolicyDrop:
		origin = "a policy drop"
	}
	return fmt.Sprintf("%s table %q chain %q (hook %s) carries %s", f.Family, f.Table, f.Chain, f.Hook, origin)
}

// foreignChainLister is the minimal netlink surface ForeignFirewallChains
// needs: enough to enumerate every chain in the kernel and read one
// chain's rules back. *nftables.Conn already satisfies this with its
// existing ListChains and GetRules methods, so the production path hands
// it an unmodified *nftables.Conn; a test hands it a fake holding no
// kernel at all. Nothing here wraps the whole Conn, only the two calls
// this file makes.
type foreignChainLister interface {
	ListChains() ([]*nftables.Chain, error)
	GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error)
}

// ForeignFirewallChains enumerates every base chain NOT in TableBoot or
// TableOpen that shares a hook postern's own ruleset registers a chain on,
// and returns the ones that carry invariant 2's override risk.
//
// plan decides which hooks are "in use" on this host: ChainInput always,
// because applyTable puts a chain on it in every table postern writes,
// plus ChainForward and ChainPrerouting when plan has at least one
// forwarded path (applyForwardChains only builds those two chains then).
// A foreign chain on a hook postern never registers a chain on cannot
// override anything postern does, so it is out of scope here regardless of
// its own policy or rules.
//
// This is advisory and best-effort by construction, matching the brief this
// package's doc already states about a foreign firewall being "often
// intentional and correctly configured": a top-level listing failure
// (permissions, no netlink access, a kernel without nftables support)
// returns no findings and no error, never a reason to keep the agent from
// arming. The same tolerance applies per chain to the rule read, so one
// chain this probe cannot read does not hide what it could read about every
// other chain.
func ForeignFirewallChains(lister foreignChainLister, plan *RulesetPlan) []ForeignChainFinding {
	if lister == nil || plan == nil {
		return nil
	}

	hooks := map[nftables.ChainHook]string{
		*nftables.ChainHookInput: ChainInput,
	}
	if len(plan.Forwards()) > 0 {
		hooks[*nftables.ChainHookForward] = ChainForward
		hooks[*nftables.ChainHookPrerouting] = ChainPrerouting
	}

	chains, err := lister.ListChains()
	if err != nil {
		return nil
	}

	var findings []ForeignChainFinding
	for _, c := range chains {
		if c == nil || c.Table == nil {
			continue
		}
		if c.Table.Name == TableBoot || c.Table.Name == TableOpen {
			continue // postern's own tables: the mechanism this warning protects, not a foreign chain
		}
		if c.Hooknum == nil {
			continue // not a base chain: nothing invokes it at this hook on its own
		}
		hookName, onARelevantHook := hooks[*c.Hooknum]
		if !onARelevantHook {
			continue
		}

		policyDrop := c.Policy != nil && *c.Policy == nftables.ChainPolicyDrop
		ruleDrop := chainHasDropOrReject(lister, c)
		if !policyDrop && !ruleDrop {
			continue
		}

		findings = append(findings, ForeignChainFinding{
			Family:     tableFamilyName(c.Table.Family),
			Table:      c.Table.Name,
			Chain:      c.Name,
			Hook:       hookName,
			PolicyDrop: policyDrop,
			RuleDrop:   ruleDrop,
		})
	}
	return findings
}

// chainHasDropOrReject reports whether any rule in chain carries an
// immediate drop verdict or a reject expression. A GetRules failure answers
// false rather than aborting the whole probe: see ForeignFirewallChains'
// own best-effort doc for why one unreadable chain must not hide findings
// about every other one.
func chainHasDropOrReject(lister foreignChainLister, chain *nftables.Chain) bool {
	rules, err := lister.GetRules(chain.Table, chain)
	if err != nil {
		return false
	}
	for _, r := range rules {
		if r == nil {
			continue
		}
		for _, e := range r.Exprs {
			switch v := e.(type) {
			case *expr.Verdict:
				if v.Kind == expr.VerdictDrop {
					return true
				}
			case *expr.Reject:
				// nftables has no VerdictReject: a reject is its own
				// expression type, not an expr.Verdict kind (there is no
				// such constant), so it is matched here by type rather
				// than by comparing a Kind field it does not have.
				return true
			}
		}
	}
	return false
}

// tableFamilyName renders a table family the way `nft list ruleset` names
// it, so a finding reads the same whether printed on its own or folded into
// prearm's warning text.
func tableFamilyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return "unknown"
	}
}

// ForeignFirewallFindings runs ForeignFirewallChains against this Gate's
// own live connection and plan, under the same lock every other method on
// this type takes before touching g.conn or g.plan. It exists so
// internal/agent's pre-arm wiring never has to reach into this type's
// private fields — the same reason Plan() exists — and so the probe always
// runs against this Gate's current policy rather than a snapshot that
// SetPolicy could have replaced out from under a caller.
//
// It returns rendered strings rather than []ForeignChainFinding on purpose.
// agent.ProductionChecks type-asserts a Gate against a small interface that
// asks only for this one method (see that package's foreignFirewallProbe),
// and that interface has to build on every GOOS postern targets — including
// darwin, where this file does not exist at all. A return type of
// []ForeignChainFinding would force the interface declared there to name a
// type this file only defines under //go:build linux, which would break
// exactly the cross-platform build this method exists to keep clean. A
// []string keeps the interface buildable everywhere while this file stays
// the only place in the module that ever imports
// github.com/google/nftables/expr for this feature.
func (g *NFTables) ForeignFirewallFindings() []string {
	g.mu.Lock()
	defer g.mu.Unlock()

	findings := ForeignFirewallChains(g.conn, g.plan)
	if len(findings) == 0 {
		return nil
	}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.String())
	}
	return out
}
