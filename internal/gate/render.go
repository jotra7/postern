package gate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// This file renders two of the three artifacts invariant 6 requires to
// agree: the boot.nft text loaded by the boot-time oneshot unit, and the
// systemd unit's per-set ExecStopPost flush lines (design section 7). Both
// are pure string functions over a *RulesetPlan — no I/O — so the kernel
// test that applies boot.nft with `nft -f` and the pure test that checks
// invariants by inspecting the rendered text both exercise the same
// generator the netlink writer (nft_linux.go) consumes.

// RenderBootNFT renders /etc/postern/boot.nft: the persistent postern_boot
// table only. postern_open has no on-disk form — design section 4 and 7 —
// it is created live by the agent at startup and removed on exit.
func RenderBootNFT(plan *RulesetPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableBoot)

	fmt.Fprintf(&b, "  set %s { type inet_service; flags timeout; }\n", AgentUpSet)
	for _, svc := range plan.BootServices() {
		for _, s := range svc.Sets {
			fmt.Fprintf(&b, "  set %s { type %s; flags %s; }\n", s.Name, nftAddrType(s.Family), nftSetFlags(s))
		}
	}

	fmt.Fprintf(&b, "\n  chain %s {\n", ChainInput)
	b.WriteString("    type filter hook input priority filter; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	if plan.AlwaysAllowIface != "" {
		fmt.Fprintf(&b, "    iifname %q accept\n\n", plan.AlwaysAllowIface)
	}

	fmt.Fprintf(&b, "    udp dport @%s limit rate %d/second accept\n", AgentUpSet, AgentUpRateLimitPerSecond)
	if plan.PortRotation != nil {
		fmt.Fprintf(&b, "    udp dport %d-%d drop\n", plan.PortRotation.RangeLo, plan.PortRotation.RangeHi)
	} else {
		fmt.Fprintf(&b, "    udp dport %d drop\n", plan.SPAPort)
	}
	writeSPAHTTPRules(&b, plan)

	for _, svc := range plan.BootServices() {
		b.WriteString("\n")
		writeServiceRules(&b, svc)
	}

	b.WriteString("  }\n")
	writeNATChain(&b, plan)
	writeForwardChain(&b, plan)
	b.WriteString("}\n")
	return b.String()
}

// writeNATChain emits the prerouting chain carrying every forwarded path's
// DNAT rule, or nothing at all when no service declares a forward.
//
// Nothing rather than an empty chain, for the reason writeSPAHTTPRules emits
// nothing when the carrier is off: a nat chain registers conntrack on the host
// that has it, and a host with no forward should not acquire that because
// postern generated a chain it never uses.
//
// Each rule's destination is a literal from the plan. The only thing a knock
// contributes is an element in the set the rule tests saddr against, so a
// packet can decide whether the translation happens and can never decide what
// it translates to.
func writeNATChain(b *strings.Builder, plan *RulesetPlan) {
	forwards := plan.Forwards()
	if len(forwards) == 0 {
		return
	}
	fmt.Fprintf(b, "\n  chain %s {\n", ChainPrerouting)
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, svc := range forwards {
		f := svc.Forward
		for _, port := range svc.Ports {
			for _, s := range svc.Sets {
				fmt.Fprintf(b, "    %s dport %d %s saddr @%s dnat %s to %s\n",
					svc.Proto, port, nftFamilyKeyword(f.Family), s.Name,
					nftFamilyKeyword(f.Family), netip.AddrPortFrom(f.To, f.Port))
			}
		}
	}
	b.WriteString("  }\n")
}

// writeForwardChain emits the filter chain on the forward hook: the accept and
// drop that carry a forwarded path's posture.
//
// The rules are written against the internal target, not against this host's
// external port, because prerouting has already rewritten the packet by the
// time it arrives here. That also makes the drop cover the other way in: a box
// that forwards is a box that routes, so an internal target is reachable
// through it by ordinary routing with no DNAT involved, and without this drop
// the gate would apply only to traffic that happened to arrive on the external
// port.
//
// Established and always-allow come first, and neither is copied from the input
// chain out of symmetry. Established is here so that a lapsing lease does not
// sever the session it opened and so that return traffic has a rule, both of
// which this package asserts only as the rule's presence and position; no test
// in this tree drives a packet across this hook. Always-allow is what keeps the
// drop below it from cutting the mesh operator who reaches the internal machine
// directly through this box, which is the shape the always-allow promise takes
// here, and its ordering is asserted against both the rendered text and the
// chain the kernel holds.
func writeForwardChain(b *strings.Builder, plan *RulesetPlan) {
	forwards := plan.Forwards()
	if len(forwards) == 0 {
		return
	}
	fmt.Fprintf(b, "\n  chain %s {\n", ChainForward)
	b.WriteString("    type filter hook forward priority filter; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	if plan.AlwaysAllowIface != "" {
		fmt.Fprintf(b, "    iifname %q accept\n", plan.AlwaysAllowIface)
	}
	for _, svc := range forwards {
		f := svc.Forward
		b.WriteString("\n")
		for _, s := range svc.Sets {
			fmt.Fprintf(b, "    %s daddr %s %s dport %d %s saddr @%s accept\n",
				nftFamilyKeyword(f.Family), f.To, svc.Proto, f.Port, nftFamilyKeyword(f.Family), s.Name)
		}
		fmt.Fprintf(b, "    %s daddr %s %s dport %d drop\n",
			nftFamilyKeyword(f.Family), f.To, svc.Proto, f.Port)
	}
	b.WriteString("  }\n")
}

// writeSPAHTTPRules emits the HTTP carrier's accept and drop, or nothing when
// the carrier is not configured — the "off unless configured" rule turned
// into an absence of rules rather than a rule that happens to match nothing.
//
// The accept tests membership in the SAME agent_up set the UDP accept tests,
// which is why the set holds both port numbers (see NFTables.agentUpElements).
// Two carriers on two dead-man sets could disagree about whether the agent is
// alive; on one set they cannot. The rate limit is the same 20/second, applied
// per rule, so a flood down the TCP carrier costs the kernel what a flood down
// the UDP one costs and reaches userspace no faster.
//
// The drop below it is what makes the gating real: without it the chain's
// accept policy would carry every packet the accept rule did not, and the
// listener would answer with the lease expired.
func writeSPAHTTPRules(b *strings.Builder, plan *RulesetPlan) {
	if plan.SPAHTTPPort == 0 {
		return
	}
	fmt.Fprintf(b, "    tcp dport @%s limit rate %d/second accept\n", AgentUpSet, AgentUpRateLimitPerSecond)
	fmt.Fprintf(b, "    tcp dport %d drop\n", plan.SPAHTTPPort)
}

// writeServiceRules emits one accept rule per (port, set) pair and one drop
// rule per port — never a bracketed multi-port list — so this text renderer
// and the netlink writer (nft_linux.go), which builds one Rule per port for
// the same reason, produce the identical rule count and order that renderer
// equivalence (invariant 6) hashes against.
//
// A forward gets the drop and no accept. Its external port has no local
// listener for an accept to reach: an admitted source is translated in
// prerouting and never traverses this chain at all, and a source that is not
// admitted would only be accepted onto a closed local port. The drop is still
// wanted, and it is what keeps the external port silent rather than answering
// with a reset.
func writeServiceRules(b *strings.Builder, svc ServicePlan) {
	for _, port := range svc.Ports {
		if svc.Forward == nil {
			for _, s := range svc.Sets {
				fmt.Fprintf(b, "    %s dport %d %s saddr @%s accept\n", svc.Proto, port, nftFamilyKeyword(s.Family), s.Name)
			}
		}
		fmt.Fprintf(b, "    %s dport %d drop\n", svc.Proto, port)
	}
}

func nftAddrType(f AddrFamily) string {
	if f == FamilyIPv4 {
		return "ipv4_addr"
	}
	return "ipv6_addr"
}

func nftFamilyKeyword(f AddrFamily) string {
	if f == FamilyIPv4 {
		return "ip"
	}
	return "ip6"
}

func nftSetFlags(s GateSet) string {
	if s.Interval() {
		return "interval,timeout"
	}
	return "timeout"
}

// FlushSetNames returns the postern_boot gate set names that must be
// flushed (emptied, drop rules left standing) when the agent stops, sorted
// for determinism. This is the same list Close (nft_linux.go) flushes live
// and RenderSystemdFlushLines renders to text — one source, so the two can
// never name different sets (invariant 6, applied to the third artifact).
func FlushSetNames(plan *RulesetPlan) []string {
	var names []string
	for _, svc := range plan.BootServices() {
		for _, s := range svc.Sets {
			names = append(names, s.Name)
		}
	}
	sort.Strings(names)
	return names
}

// RenderSystemdFlushLines renders the ExecStopPost directives that empty
// every fail-closed gate set on agent stop, leaving TableBoot's drop rules
// intact. Deliberately "flush set", never "flush table" — flushing the table
// would delete the drop rules themselves and invert the posture (design
// section 7). The leading "-" tolerates a set that is already absent (e.g.
// postern_boot never loaded).
//
// These lines are not in the main posternd.service unit; they are the body
// of the flush drop-in (RenderFlushDropIn), because the set catalogue they
// name changes per revision. This function shares TeardownFlushCommands as
// its source so the drop-in, TeardownCommands, and the live Close cannot name
// different sets (invariant 6, applied to the third artifact).
func RenderSystemdFlushLines(plan *RulesetPlan) []string {
	cmds := TeardownFlushCommands(plan, DefaultNFTPath)
	lines := make([]string, len(cmds))
	for i, cmd := range cmds {
		lines[i] = "ExecStopPost=-" + strings.Join(cmd, " ")
	}
	return lines
}

// RenderFlushDropIn renders the content of
// posternd.service.d/flush.conf: a [Service] section whose ExecStopPost
// directives empty every fail-closed gate set when posternd stops, however
// it stops. The agent regenerates this file as the set catalogue changes and
// runs `systemctl daemon-reload`, so a bundle-added fail-closed set gets its
// flush line before its grant can outlive a crashed agent — the drift this
// drop-in exists to close.
//
// systemd appends a drop-in's ExecStopPost after the main unit's, so the
// postern_open delete the main unit carries still runs before any flush here.
// A host with no fail-closed gate sets renders a drop-in with no ExecStopPost
// lines, which is a valid, inert override.
//
// nftPath is threaded through rather than hardcoded so the drop-in names the
// same nft(8) the main unit does when an operator enrolled with a non-default
// --nft path; empty selects DefaultNFTPath.
func RenderFlushDropIn(plan *RulesetPlan, nftPath string) string {
	var b strings.Builder
	b.WriteString("[Service]\n")
	for _, cmd := range TeardownFlushCommands(plan, nftPath) {
		fmt.Fprintf(&b, "ExecStopPost=-%s\n", strings.Join(cmd, " "))
	}
	return b.String()
}
