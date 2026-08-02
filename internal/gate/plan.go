package gate

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/jotra7/postern/internal/config"
)

// Fixed names and values from design section 4. These are not derived from
// policy because they are the same on every host: the table names, the
// dead-man set's name, and the always-allow / established rules that must
// appear identically in both tables (invariant 2).
const (
	// TableBoot is postern_boot: persistent, loaded at boot independent of
	// the agent, holds fail-closed gate services plus the agent_up dead-man
	// SPA guard.
	TableBoot = "postern_boot"
	// TableOpen is postern_open: created by the agent at startup and
	// removed when it exits, holds fail-open gate services.
	TableOpen = "postern_open"
	// AgentUpSet is the dead-man set (design section 4, invariant 1): the
	// SPA port is only reachable while this set holds the SPA port number,
	// refreshed by the packet loop. It lives in TableBoot only.
	AgentUpSet = "agent_up"
	// AgentUpRateLimitPerSecond bounds SPA packets, cheaply, before
	// userspace ever sees them (design section 5).
	AgentUpRateLimitPerSecond = 20
	// ChainInput is the filter chain on the input hook that every table
	// carries: the local gates, the SPA carriers, and the always-allow accept.
	ChainInput = "input"
	// ChainPrerouting is the nat chain holding a forwarded path's DNAT rules.
	// It exists only in TableBoot and only when a forward is configured; see
	// BuildRulesetPlan on why a forward has nowhere else to live.
	ChainPrerouting = "prerouting"
	// ChainForward is the filter chain on the forward hook holding a forwarded
	// path's accept and drop rules, written against the internal target rather
	// than against this host's external port, because that is what the packet
	// carries once prerouting has translated it.
	ChainForward = "forward"
)

// AddrFamily distinguishes the two address families a gate set can hold. An
// nftables named set's key type is fixed, so a service's IPv4 and IPv6
// coverage can never share one set.
type AddrFamily int

const (
	FamilyIPv4 AddrFamily = iota
	FamilyIPv6
)

func (f AddrFamily) String() string {
	if f == FamilyIPv4 {
		return "v4"
	}
	return "v6"
}

// SetKind distinguishes the plain timeout set used for observed addresses
// from the interval+timeout set used for asserted CIDRs. See the package
// doc for why the split exists.
type SetKind int

const (
	// SetObserved holds single addresses only: flags timeout, no interval.
	SetObserved SetKind = iota
	// SetAsserted holds CIDRs: flags interval,timeout.
	SetAsserted
)

func (k SetKind) String() string {
	if k == SetObserved {
		return "obs"
	}
	return "cidr"
}

// GateSet is one nftables named set backing a gate service's saddr match for
// one address family and one source kind.
type GateSet struct {
	Name   string
	Family AddrFamily
	Kind   SetKind
}

// Interval reports whether this set needs "flags interval,timeout" (an
// asserted-CIDR set) rather than plain "flags timeout" (an observed-address
// set).
func (s GateSet) Interval() bool { return s.Kind == SetAsserted }

// ForwardPlan is the resolved internal end of a forwarded path: the literal
// this plan's DNAT rule carries, and the address family that literal fixes the
// whole service to.
//
// BuildRulesetPlan fills it in from config.Service.Forward, and
// BuildRulesetPlan's only argument is the host's policy. Every renderer in this
// package takes a *RulesetPlan and nothing else, so the address a generated
// DNAT rule carries is a function of the host's configuration alone. Threading
// a packet-supplied target through to a rule would mean widening one of those
// signatures, which is where internal/agent's tripwires sit.
type ForwardPlan struct {
	To     netip.Addr
	Port   uint16
	Family AddrFamily
}

// ServicePlan is the resolved sets and rule shape for one config.Service of
// Kind gate.
type ServicePlan struct {
	Name  string
	Table string // TableBoot or TableOpen, chosen by FailPosture
	Proto string
	Ports []uint16
	// Sets holds four entries for an ordinary dual-stack local gate: v4
	// observed, v4 asserted, v6 observed, v6 asserted, in that fixed order
	// (setOrder below) so every renderer produces sets and rules in the
	// same sequence.
	//
	// A forward has two, for its target's family alone. A DNAT rule rewrites a
	// packet's destination to a literal of one family, so a v4 target cannot
	// serve a v6 knock at all; generating the other family's sets would leave
	// an operator's knock landing in a set no rule reads, which is a knock that
	// reports success and opens nothing.
	Sets []GateSet
	// Forward is the internal target, or nil for a gate on this host's own
	// ports.
	Forward *ForwardPlan
}

// SetByFamilyKind returns the one set in p.Sets matching family and kind, and
// whether there is one.
//
// It reports absence rather than panicking because absence became reachable
// from a packet: a forward carries its target's family only, so a knock from
// the other family resolves a real service and then finds no set. That has to
// be an error the caller can return, not a panic in the agent's packet loop.
func (p ServicePlan) SetByFamilyKind(family AddrFamily, kind SetKind) (GateSet, bool) {
	for _, s := range p.Sets {
		if s.Family == family && s.Kind == kind {
			return s, true
		}
	}
	return GateSet{}, false
}

// RulesetPlan is the full, resolved shape of both tables, computed once from
// a config.Policy and consumed identically by the netlink writer, the
// boot.nft text renderer, and the systemd flush-line renderer (design
// section 10, invariant 6). Nothing in this type or in BuildRulesetPlan
// touches netlink or the filesystem, so it is testable without a kernel.
type RulesetPlan struct {
	AlwaysAllowIface string
	SPAPort          uint16
	// SPAHTTPPort is the TCP port carrying the HTTP form of the SPA packet,
	// or zero when the carrier is not configured. It is gated by the same
	// agent_up set and the same rate limit as SPAPort, so both carriers go
	// silent on the same dead-man lease rather than on two that could
	// disagree.
	SPAHTTPPort uint16
	// Services holds only Kind gate services, sorted by name so every
	// renderer emits rules in the same deterministic order (load-bearing
	// for the hash comparison in renderer equivalence).
	Services []ServicePlan
	// PortRotation is the resolved rotating-port band, or nil when this host
	// uses a fixed SPAPort. Non-nil widens the SPA-port concealment drop from
	// a single port to the whole band in both renderers (invariant 6):
	// SPAPort itself is not consulted by either renderer while this is set.
	PortRotation *PortRotationPlan
}

// PortRotationPlan is the resolved rotating-port band the boot table's range
// drop covers, or nil when this host uses a fixed spa_port. It carries no
// secret: the drop only needs the band, and the band is not sensitive.
type PortRotationPlan struct {
	RangeLo uint16
	RangeHi uint16
}

// BootServices returns the plan's fail-closed gate services in TableBoot.
func (p *RulesetPlan) BootServices() []ServicePlan {
	return p.servicesInTable(TableBoot)
}

// OpenServices returns the plan's fail-open gate services in TableOpen.
func (p *RulesetPlan) OpenServices() []ServicePlan {
	return p.servicesInTable(TableOpen)
}

func (p *RulesetPlan) servicesInTable(table string) []ServicePlan {
	var out []ServicePlan
	for _, s := range p.Services {
		if s.Table == table {
			out = append(out, s)
		}
	}
	return out
}

// Forwards returns the plan's forwarded paths, in the same sorted order as
// Services. Every one of them is in TableBoot: BuildRulesetPlan refuses any
// other posture.
func (p *RulesetPlan) Forwards() []ServicePlan {
	var out []ServicePlan
	for _, s := range p.Services {
		if s.Forward != nil {
			out = append(out, s)
		}
	}
	return out
}

// ServiceByName looks up one service's plan.
func (p *RulesetPlan) ServiceByName(name string) (ServicePlan, bool) {
	for _, s := range p.Services {
		if s.Name == name {
			return s, true
		}
	}
	return ServicePlan{}, false
}

// setOrder is the fixed (family, kind) sequence every service's Sets slice
// follows, so two renderers walking the same ServicePlan never disagree on
// order.
var setOrder = [4]struct {
	family AddrFamily
	kind   SetKind
}{
	{FamilyIPv4, SetObserved},
	{FamilyIPv4, SetAsserted},
	{FamilyIPv6, SetObserved},
	{FamilyIPv6, SetAsserted},
}

// BuildRulesetPlan resolves policy into the concrete table/set/rule shape
// every renderer in this package consumes. It is pure: no I/O, no netlink,
// deterministic for a given policy.
func BuildRulesetPlan(policy *config.Policy) (*RulesetPlan, error) {
	if policy == nil {
		return nil, fmt.Errorf("gate: policy is nil")
	}
	if policy.AlwaysAllowIface == "" && !policy.ConsoleRecovery {
		return nil, fmt.Errorf("gate: policy has no always_allow_iface; refusing to plan a ruleset with no always-allow path")
	}
	if policy.SPAPort == 0 && policy.PortRotation == nil {
		return nil, fmt.Errorf("gate: policy has no spa_port and no port_rotation")
	}

	names := make([]string, 0, len(policy.Services))
	for name, svc := range policy.Services {
		if svc.Kind != config.KindGate {
			continue
		}
		// A service whose admissions another backend owns gets no nftables
		// sets and no nftables rules — including no drop rule. Generating one
		// would be worse than useless: nothing would ever add an element to
		// the accept rule's set, so the drop would be the only rule that ever
		// matched and the port would be permanently unreachable through a
		// service the operator declared as openable. The local kernel is
		// simply not in that service's path; see this package's doc for what
		// that costs.
		if svc.Backend != "" && svc.Backend != config.BackendNFTables {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	plan := &RulesetPlan{
		AlwaysAllowIface: policy.AlwaysAllowIface,
		SPAPort:          policy.SPAPort,
		SPAHTTPPort:      policy.SPAHTTPPort,
	}
	if policy.PortRotation != nil {
		plan.PortRotation = &PortRotationPlan{
			RangeLo: policy.PortRotation.RangeLo,
			RangeHi: policy.PortRotation.RangeHi,
		}
	}

	for _, name := range names {
		svc := policy.Services[name]

		var table string
		switch svc.FailPosture {
		case config.PostureClosed:
			table = TableBoot
		case config.PostureOpen:
			table = TableOpen
		default:
			return nil, fmt.Errorf("gate: service %q has unresolved fail_posture %q", svc.Name, svc.FailPosture)
		}

		fwd, err := forwardPlan(svc, table)
		if err != nil {
			return nil, err
		}

		sets := make([]GateSet, 0, len(setOrder))
		for _, fk := range setOrder {
			if fwd != nil && fk.family != fwd.Family {
				continue
			}
			sets = append(sets, GateSet{
				Name:   setName(svc.Name, fk.family, fk.kind),
				Family: fk.family,
				Kind:   fk.kind,
			})
		}

		plan.Services = append(plan.Services, ServicePlan{
			Name:    svc.Name,
			Table:   table,
			Proto:   svc.Proto,
			Ports:   append([]uint16(nil), svc.Ports...),
			Sets:    sets,
			Forward: fwd,
		})
	}

	return plan, nil
}

// forwardPlan resolves a service's declared internal target, or nil for a gate
// on this host's own ports.
//
// The posture refusal here duplicates config.Service.validateForward on
// purpose. That one is where an operator meets it, with the reasoning; this one
// is the mechanism refusing to generate a shape it cannot deliver, and it holds
// for a Policy assembled in code that never went through a parser. The cost of
// getting this wrong is a table assignment: a forward in TableOpen has its DNAT
// rule deleted by ExecStopPost on any exit, so the path an operator was told
// survives the agent's death is precisely the thing that does not.
func forwardPlan(svc config.Service, table string) (*ForwardPlan, error) {
	if svc.Forward == nil {
		return nil, nil
	}
	if table != TableBoot {
		return nil, fmt.Errorf("gate: service %q declares a forward and resolves to table %s; a "+
			"forwarded path is postern's own DNAT rule, and that rule has to survive the agent, "+
			"so it can only live in %s", svc.Name, table, TableBoot)
	}
	if !svc.Forward.To.IsValid() {
		return nil, fmt.Errorf("gate: service %q declares a forward with no target address", svc.Name)
	}
	if svc.Forward.Port == 0 {
		return nil, fmt.Errorf("gate: service %q declares a forward with no target port", svc.Name)
	}
	to := svc.Forward.To.Unmap()
	family := FamilyIPv6
	if to.Is4() {
		family = FamilyIPv4
	}
	return &ForwardPlan{To: to, Port: svc.Forward.Port, Family: family}, nil
}

// setName is the one place a gate set's name is constructed, so the netlink
// writer, the text renderer, and the flush-line renderer can never disagree
// on it.
func setName(service string, family AddrFamily, kind SetKind) string {
	return fmt.Sprintf("gate_%s_%s_%s", service, family, kind)
}
