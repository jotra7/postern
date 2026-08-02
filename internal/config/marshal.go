package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// MarshalStandalone renders a resolved Policy as the standalone YAML that
// ParseStandalone consumes. It is the inverse of that function for every
// field ParseStandalone reads from the file, and a round-trip test in this
// package holds it to that — with one named exception: Policy.MaxOperators
// has no corresponding YAML key. ParseStandalone always resolves it to
// DefaultMaxOperators regardless of what the input document contains (see
// standalone.go), so there is nothing in the file for this function to
// write it from or for the parser to read it back from; the round trip
// holds only because both sides independently land on the same constant,
// not because the value passed through the bytes.
//
// This is what lets fleet mode reuse standalone's parser rather than growing
// a second one: internal/bundle compiles an inventory down to these bytes,
// and the agent hands them to ParseStandalone without caring which mode
// produced them. Design section 10 requires the single code path; this is
// the seam that gives it.
//
// Output is deterministic — map keys sorted, durations in a fixed form — so
// that a bundle for an unchanged host is byte-identical between runs and a
// config hash means something.
func MarshalStandalone(p *Policy) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("config: MarshalStandalone: nil policy")
	}
	out := yamlStandalone{
		FleetID:            hex.EncodeToString(p.FleetID[:]),
		HostID:             hex.EncodeToString(p.HostID[:]),
		Revision:           p.Revision,
		SPAPort:            p.SPAPort,
		SPAHTTPPort:        p.SPAHTTPPort,
		AlwaysAllowIface:   p.AlwaysAllowIface,
		ConsoleRecovery:    p.ConsoleRecovery,
		Console:            p.Console,
		RecoveryService:    p.RecoveryService,
		FreshnessWindow:    formatDuration(p.FreshnessWindow),
		FreshnessWindowMax: formatDuration(p.FreshnessWindowMax),
		Services:           make(map[string]yamlService, len(p.Services)),
		HubURL:             p.HubURL,
		EnrollmentFloor:    p.EnrollmentFloor,
		PortRotation:       marshalPortRotation(p.PortRotation),
	}
	// Order preserved, not sorted: BundleSigners is a trust set with no
	// ordering semantics of its own, but preserving input order is what makes
	// this function and ParseStandalone exact inverses for any given input,
	// which is the property the round-trip test holds it to.
	for _, k := range p.BundleSigners {
		out.BundleSigners = append(out.BundleSigners, hex.EncodeToString(k[:]))
	}
	// MaxOperators has no key in yamlStandalone: ParseStandalone always
	// resolves it to DefaultMaxOperators and never reads it from the file
	// (see standalone.go), so there is nothing for this marshaller to emit.
	// The round trip still holds because the parser's output value is a
	// constant, not a function of the input bytes.
	for name, svc := range p.Services {
		out.Services[name] = marshalService(svc)
		if svc.Kind == KindGate && svc.FailPosture == PostureOpen {
			out.BreakglassServices = append(out.BreakglassServices, name)
		}
	}
	sort.Strings(out.BreakglassServices)

	for _, op := range p.Operators {
		out.Operators = append(out.Operators, marshalOperator(op))
	}
	sort.Slice(out.Operators, func(i, j int) bool {
		return out.Operators[i].Name < out.Operators[j].Name
	})

	data, err := yaml.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("config: MarshalStandalone: %w", err)
	}
	return data, nil
}

// marshalService is the field-for-field inverse of the per-service decode
// block in ParseStandalone: every field is copied through unconditionally,
// regardless of Kind, because that is exactly how ParseStandalone reads them
// back (see the "parsed unconditionally" comment in standalone.go).
func marshalService(svc Service) yamlService {
	return yamlService{
		Kind:                string(svc.Kind),
		Proto:               svc.Proto,
		Ports:               svc.Ports,
		DefaultTTL:          formatDuration(svc.DefaultTTL),
		MaxTTL:              formatDuration(svc.MaxTTL),
		FailPosture:         string(svc.FailPosture),
		ListenerExpectation: string(svc.ListenerExpectation),
		Verification:        string(svc.Verification),
		Backend:             string(svc.Backend),
		ScriptPath:          svc.ScriptPath,
		ScriptTimeout:       formatDuration(svc.ScriptTimeout),
		Forward:             marshalForward(svc.Forward),
	}
}

// marshalForward is the inverse of decodeService's forward block. A forward
// dropped here would be a forward an operator wrote in the fleet inventory and
// that the compiled bundle silently turned back into a local gate: the host
// would open its own external port instead of the path to the internal machine,
// under a posture that reads the same in both files.
func marshalForward(f *Forward) *yamlForward {
	if f == nil {
		return nil
	}
	out := &yamlForward{Port: f.Port}
	if f.To.IsValid() {
		out.To = f.To.String()
	}
	return out
}

// marshalOperator is the field-for-field inverse of the per-operator decode
// block in ParseStandalone. Grant order is preserved rather than sorted:
// ParseStandalone appends grants in document order and never reorders them,
// so reordering here would make the two functions inverses in content but
// not in position.
func marshalOperator(op Operator) yamlOperator {
	yo := yamlOperator{
		Name:       op.Identity.Name,
		Alg:        string(op.Identity.Alg),
		Signing:    base64.StdEncoding.EncodeToString(op.Identity.Signing[:]),
		Encryption: base64.StdEncoding.EncodeToString(op.Identity.Encryption[:]),
	}
	for _, g := range op.Grants {
		yo.Grants = append(yo.Grants, yamlGrant{
			Services:        g.Services,
			MaxTTL:          formatDuration(g.MaxTTL),
			AllowSourceCIDR: g.AllowSourceCIDR,
			// Both prefixes are carried through even though only one of them
			// applies to any given packet: Grant.AllowsSource checks the field
			// matching the packet's address family, so dropping either one
			// here would floor that family at zero while the marshaled config
			// still claimed a minimum.
			MinIPv4Prefix: g.MinIPv4Prefix,
			MinIPv6Prefix: g.MinIPv6Prefix,
		})
	}
	return yo
}

// marshalPortRotation is the inverse of decodePortRotation. A nil
// *PortRotation produces a nil *yamlPortRotation (the "port_rotation" key
// absent from the output), the same "no block, not an empty block" pointer
// idiom marshalForward already keeps for a service's forward block.
func marshalPortRotation(r *PortRotation) *yamlPortRotation {
	if r == nil {
		return nil
	}
	return &yamlPortRotation{
		Secret: base64.StdEncoding.EncodeToString(r.Secret),
		Window: formatDuration(r.Window),
		Range:  formatRange(r.RangeLo, r.RangeHi),
	}
}

// formatRange renders a port_rotation range in the "lo-hi" form parseRange
// reads back exactly.
func formatRange(lo, hi uint16) string { return fmt.Sprintf("%d-%d", lo, hi) }

// formatDuration renders a duration in the form parseDuration reads back
// exactly. time.Duration.String() emits "1m0s" for a minute, which round
// trips, and "0s" for zero — never the empty string — so a legitimately zero
// duration never falls into parseDuration's fallback substitution, which
// only triggers on "".
func formatDuration(d time.Duration) string { return d.String() }
