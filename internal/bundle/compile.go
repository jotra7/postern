package bundle

import (
	"fmt"
	"sort"

	"github.com/jotra7/postern/internal/config"
)

// Compile resolves the inventory down to the policy for one host: the
// fleet's service catalogue narrowed to that host's own services (plus every
// fleet-wide action service), the fleet defaults with that host's overrides
// applied, and every operator grant whose host set matches — flattened into
// exactly the config.Policy that standalone mode produces from a file.
//
// Producing the same type is the requirement, not a convenience. Design
// section 10 puts the agent on one code path for both modes, so anything
// this function can express that ParseStandalone cannot is a divergence that
// will be discovered on a fleet host and not in a test.
func Compile(inv *config.Inventory, hostName string) (*config.Policy, error) {
	host, err := inv.Host(hostName)
	if err != nil {
		return nil, fmt.Errorf("bundle: compile: %w", err)
	}

	p := &config.Policy{
		FleetID:            inv.FleetID,
		HostID:             host.HostID,
		Revision:           inv.Version,
		SPAPort:            firstNonZero(host.SPAPort, inv.Defaults.SPAPort),
		SPAHTTPPort:        firstNonZero(host.SPAHTTPPort, inv.Defaults.SPAHTTPPort),
		AlwaysAllowIface:   firstNonEmpty(host.AlwaysAllowIface, inv.Defaults.AlwaysAllowIface),
		ConsoleRecovery:    host.ConsoleRecovery || inv.Defaults.ConsoleRecovery,
		Console:            host.Console,
		RecoveryService:    firstNonEmpty(host.RecoveryService, inv.Defaults.RecoveryService),
		FreshnessWindow:    inv.Defaults.FreshnessWindow,
		FreshnessWindowMax: inv.Defaults.FreshnessWindowMax,
		Services:           make(map[string]config.Service, len(host.Services)),
		MaxOperators:       config.DefaultMaxOperators,
		PortRotation:       resolvePortRotation(host, inv.Defaults),
	}

	// Only this host's own services. A host must not arm drop rules for ports
	// that some other host in the fleet gates: MarshalStandalone/ParseStandalone
	// turn every declared gate into a port-owning firewall rule, so carrying the
	// whole fleet's catalogue here would silently blackhole ports on hosts that
	// never declared them.
	for _, name := range host.Services {
		svc, ok := inv.Services[name]
		if !ok {
			return nil, fmt.Errorf("bundle: compile %s: service %q is not defined", hostName, name)
		}
		p.Services[name] = svc
	}
	// Action services are fleet-wide by nature: confirm, disarm, and liveness
	// have no ports to own, and a host that cannot be confirmed cannot
	// complete an arm. They are carried whether or not the host's own
	// services list names them.
	for name, svc := range inv.Services {
		if svc.Kind == config.KindAction {
			p.Services[name] = svc
		}
	}

	for _, op := range inv.Operators {
		grants := matchingGrants(op, hostName, p.Services)
		if len(grants) == 0 {
			continue
		}
		p.Operators = append(p.Operators, config.Operator{Identity: op.Identity, Grants: grants})
	}
	sort.Slice(p.Operators, func(i, j int) bool {
		return p.Operators[i].Identity.Name < p.Operators[j].Identity.Name
	})

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("bundle: compile %s: %w", hostName, err)
	}
	return p, nil
}

// matchingGrants keeps the grants that apply to this host, narrowed to the
// services this host actually carries. A grant naming a service the host
// does not carry is dropped from that grant rather than carried inert, and a
// grant left with no surviving services is dropped entirely — an operator
// should never see a grant that authorizes nothing.
func matchingGrants(op config.InventoryOperator, hostName string, svcs map[string]config.Service) []config.Grant {
	var out []config.Grant
	for _, g := range op.Grants {
		if !hostMatches(g.Hosts, hostName) {
			continue
		}
		var kept []string
		for _, s := range g.Services {
			if _, ok := svcs[s]; ok {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			continue
		}
		out = append(out, config.Grant{
			Services:        kept,
			MaxTTL:          g.MaxTTL,
			AllowSourceCIDR: g.AllowSourceCIDR,
			// Both prefixes are carried through even though only one of them
			// applies to any given packet: config.Grant.AllowsSource checks
			// the field matching the packet's address family, so dropping
			// either one here would floor that family at zero while the
			// compiled config still claimed a minimum.
			MinIPv4Prefix: g.MinIPv4Prefix,
			MinIPv6Prefix: g.MinIPv6Prefix,
		})
	}
	return out
}

// hostMatches reports whether a grant's host list covers hostName. Matching
// is "*" or an exact name only — no globbing, no regex. The inventory is
// hand-edited and reviewed by humans reading diffs, and a pattern language
// here is a way to put an operator's key on a machine nobody meant to name.
func hostMatches(hosts []string, hostName string) bool {
	for _, h := range hosts {
		if h == "*" || h == hostName {
			return true
		}
	}
	return false
}

// firstNonZero returns the host's own override when it is set, otherwise the
// fleet default.
func firstNonZero(hostValue, fleetDefault uint16) uint16 {
	if hostValue != 0 {
		return hostValue
	}
	return fleetDefault
}

// firstNonEmpty returns the host's own override when it is set, otherwise
// the fleet default.
func firstNonEmpty(hostValue, fleetDefault string) string {
	if hostValue != "" {
		return hostValue
	}
	return fleetDefault
}

// resolvePortRotation is port_rotation's own override rule, distinct from
// firstNonZero/firstNonEmpty because it has a third state neither of those
// model: a host can opt out of the fleet default entirely
// (PortRotationDisabled), not just decline to override it.
func resolvePortRotation(host *config.InventoryHost, defaults config.InventoryDefaults) *config.PortRotation {
	if host.PortRotationDisabled {
		return nil
	}
	if host.PortRotation != nil {
		return host.PortRotation
	}
	return defaults.PortRotation
}
