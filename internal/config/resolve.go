package config

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
)

// Defaults. FreshnessWindowMax is a security parameter — it is exactly the
// window in which a suppressed packet stays usable — so widening it is a
// per-host decision, never a fleet-wide convenience.
const (
	DefaultFreshnessWindow    = 60 * time.Second
	DefaultFreshnessWindowMax = 24 * time.Hour
	DefaultMaxOperators       = 32
)

// Grant is one operator's permission over a set of services.
type Grant struct {
	Services        []string
	MaxTTL          time.Duration
	AllowSourceCIDR bool
	MinIPv4Prefix   int
	MinIPv6Prefix   int
}

// Allows reports whether this grant covers a named service.
func (g Grant) Allows(service string) bool {
	for _, s := range g.Services {
		if s == service {
			return true
		}
	}
	return false
}

// AllowsSource enforces this grant's asserted-source policy against a
// packet's asserted prefix: config alone (AllowSourceCIDR,
// MinIPv4Prefix/MinIPv6Prefix) declares the rule, but until this method
// existed nothing in the codebase ever compared a packet's asserted prefix
// against it, so the rule Policy.Validate enforces at config-load time
// (validateGrants, below) was never actually applied to a packet. Without
// it an authorised operator could assert 0.0.0.0/0 or ::/0 (design section
// 5) despite the config declaring a floor.
//
// A prefix exactly at the configured minimum is allowed — the minimum is a
// floor, not an exclusive bound — and the check is per address family: an
// IPv6 prefix is checked against MinIPv6Prefix, never MinIPv4Prefix, even
// though both are plain ints and a caller could otherwise pass either
// field to either family by mistake.
//
// It is called from agent.Validate's gate resolution (design section 5,
// validation order step 9), which is the only place a packet's asserted
// prefix is ever compared against a grant — the comparison is never
// re-derived inline, because a second copy of it is exactly how this control
// came to exist in config validation while never being applied to a packet.
func (g Grant) AllowsSource(pfx netip.Prefix) error {
	if !g.AllowSourceCIDR {
		return fmt.Errorf("grant does not permit an asserted source")
	}
	if !pfx.IsValid() {
		return fmt.Errorf("asserted prefix is invalid")
	}
	// Unmap first. An IPv4-mapped IPv6 address reports Is4() == false, so
	// without this ::ffff:0.0.0.0/96 — the entire IPv4 space — would be
	// measured against MinIPv6Prefix and sail past any floor of /96 or less,
	// including the /64 in this project's own fixtures. That is exactly the
	// "an authorised operator could assert 0.0.0.0/0" hole this method exists
	// to close, wearing a v6 costume.
	addr := pfx.Addr().Unmap()
	bits := pfx.Bits()
	if pfx.Addr().Is4In6() {
		bits -= 96 // the mapped prefix carries a 96-bit v4-mapped header
	}
	pfx = netip.PrefixFrom(addr, bits)
	switch {
	case addr.Is4():
		if bits < g.MinIPv4Prefix {
			return fmt.Errorf("asserted prefix %s is narrower than the minimum /%d", pfx, g.MinIPv4Prefix)
		}
	case addr.Is6():
		if bits < g.MinIPv6Prefix {
			return fmt.Errorf("asserted prefix %s is narrower than the minimum /%d", pfx, g.MinIPv6Prefix)
		}
	default:
		return fmt.Errorf("asserted prefix %s has no recognized address family", pfx)
	}
	return nil
}

// Operator is a named identity plus its grants.
type Operator struct {
	Identity identity.PublicIdentity
	Grants   []Grant
}

// Policy is the resolved configuration the agent runs on, identical in shape
// whether it came from a standalone file or a fleet bundle.
type Policy struct {
	FleetID [16]byte
	HostID  [16]byte
	// Revision is this configuration's version, and it is what a confirm
	// packet's pending_revision names. Design section 5 makes it
	// mode-independent: in fleet mode it is the bundle version, in standalone
	// a persisted monotonic local configuration revision, which here is the
	// config file's own `revision:` key. The agent compares it against the
	// revision it last recorded as confirmed to decide whether starting means
	// arming a change that has to be confirmed or reverted.
	//
	// Zero is a legitimate first revision — a host's first configuration is
	// revision 0 unless someone says otherwise — so "no revision recorded" is
	// carried by the absence of the state file, never by a zero value.
	Revision uint64
	SPAPort  uint16
	// SPAHTTPPort is the TCP port carrying the HTTP form of the same SPA
	// packet, for the networks that block outbound UDP entirely — a hotel
	// wifi, a locked-down corporate egress — which is exactly where a
	// break-glass tool is most likely to be needed and, today, exactly where
	// it does not work.
	//
	// Zero means off, and off is the default: an operator who does not need
	// the carrier gains no new listener. The packet it carries is byte for
	// byte the packet the UDP port carries, validated by the same pipeline —
	// this is a second envelope for one payload, not a second protocol.
	//
	// It is gated by the same agent_up dead-man set and the same kernel rate
	// limit as SPAPort (see internal/gate), so it goes silent when the agent
	// is unhealthy exactly as the UDP port does. A permanently-open TCP port
	// on a break-glass host would be a regression, not a feature.
	SPAHTTPPort      uint16
	AlwaysAllowIface string
	// ConsoleRecovery, when true, permits arming with no AlwaysAllowIface: the
	// operator has declared Console as an out-of-band recovery path postern
	// cannot verify. It is set only from the local root config, never from a
	// bundle. See docs/superpowers/specs/2026-07-31-console-recovery-mode-design.md.
	ConsoleRecovery bool
	// Console is the out-of-band recovery route (a provider console URL),
	// required when ConsoleRecovery is set.
	Console            string
	RecoveryService    string
	FreshnessWindow    time.Duration
	FreshnessWindowMax time.Duration
	Services           map[string]Service
	Operators          []Operator
	MaxOperators       int

	// HubURL is the M2 fleet hub this agent pulls its own sealed bundle from.
	// Empty means standalone: no pull loop starts, and BundleSigners and
	// EnrollmentFloor are never consulted. It lives on the standalone form
	// because a fleet-enrolled host still boots from a local, root-owned
	// file — the bundle it fetches is what replaces this Policy's Services
	// and Operators on future pulls, never HubURL itself, or a compromised
	// hub could redirect a host to fetch from somewhere else entirely.
	HubURL string
	// BundleSigners is the set of raw Ed25519 public keys whose signature
	// over a fetched bundle this host accepts. These are keys, not operator
	// names: the agent has no inventory to resolve a name against at pull
	// time, and a name it cannot resolve is a trust decision made on a
	// string rather than on the key itself.
	BundleSigners [][32]byte
	// EnrollmentFloor is the bundle version stamped into this file at
	// enrollment. A freshly enrolled host holds no current bundle version, so
	// without a floor an old but validly-signed bundle — one still naming a
	// since-removed operator — would replay against it cleanly.
	EnrollmentFloor uint64

	// PortRotation, when set, replaces the fixed SPAPort with a knock port
	// derived from Secret and the current time window (see
	// internal/knockport). Nil means fixed-port mode: SPAPort is used exactly
	// as it is today, and Secret/Window/RangeLo/RangeHi are never consulted.
	PortRotation *PortRotation
}

// PortRotation is the resolved rotating-port configuration, or nil on a
// fixed-port host. Secret is K (32 bytes), Window is the rotation period, and
// [RangeLo, RangeHi] is the inclusive candidate band. See internal/knockport.
type PortRotation struct {
	Secret  []byte
	Window  time.Duration
	RangeLo uint16
	RangeHi uint16
}

// HasFailClosed reports whether any gate service persists its drop rule
// without the agent.
func (p *Policy) HasFailClosed() bool {
	for _, s := range p.Services {
		if s.Kind == KindGate && s.FailPosture == PostureClosed {
			return true
		}
	}
	return false
}

// HasScriptBackend reports whether any gate service hands its admissions to
// an operator-supplied executable. Callers use it to decide whether to build
// a script backend at all: a host with none should not open a lease store or
// start a reaper for a backend it will never call.
func (p *Policy) HasScriptBackend() bool {
	for _, s := range p.Services {
		if s.Kind == KindGate && s.Backend == BackendScript {
			return true
		}
	}
	return false
}

// ServiceByID resolves the packet's service_id to a service.
//
// The caller is responsible for checking that the resolved Service.Kind
// agrees with the packet's own kind byte before trusting service_id to
// decide how to interpret the packet's payload — this method has no packet
// to compare against, so it cannot enforce that itself. See
// docs/phase-b-carry-forward.md, item 2, for why that check currently has
// no owner and the concrete kind=gate/service=confirm case it needs to
// reject.
func (p *Policy) ServiceByID(id [ServiceIDSize]byte) (Service, bool) {
	for _, s := range p.Services {
		if s.ID() == id {
			return s, true
		}
	}
	return Service{}, false
}

// Grants returns the first grant covering service for the operator identified
// by keyID.
func (p *Policy) Grants(keyID [identity.KeyIDSize]byte, service string) (Grant, bool) {
	for _, op := range p.Operators {
		if op.Identity.KeyID() != keyID {
			continue
		}
		for _, g := range op.Grants {
			if g.Allows(service) {
				return g, true
			}
		}
		return Grant{}, false
	}
	return Grant{}, false
}

// Validate applies every rule that needs more than one service to see.
func (p *Policy) Validate() error {
	var errs ErrorList

	if p.PortRotation == nil {
		if p.SPAPort == 0 {
			errs.Addf("spa_port is required")
		}
	} else {
		p.validatePortRotation(&errs)
	}
	if p.AlwaysAllowIface == "" && !p.ConsoleRecovery {
		// Postern refuses to generate a ruleset without an always-allow path:
		// under fail-closed it is the only route into the host. Console-recovery
		// is the explicit, acknowledged exception.
		errs.Addf("always_allow_iface is required; postern will not arm without a path it cannot remove (or set console_recovery)")
	}
	if p.ConsoleRecovery && p.Console == "" {
		errs.Addf("console_recovery requires a console route to record as the last resort")
	}
	if p.FreshnessWindow <= 0 {
		errs.Addf("freshness_window must be positive")
	}
	if p.FreshnessWindowMax < p.FreshnessWindow {
		errs.Addf("freshness_window_max (%s) is below freshness_window (%s)", p.FreshnessWindowMax, p.FreshnessWindow)
	}
	if p.MaxOperators <= 0 {
		p.MaxOperators = DefaultMaxOperators
	}
	if len(p.Operators) > p.MaxOperators {
		errs.Addf("%d operators configured, limit is %d; trial-decrypt cost is linear in this count",
			len(p.Operators), p.MaxOperators)
	}

	for name, svc := range p.Services {
		if name != svc.Name {
			errs.Addf("service map key %q does not match service name %q", name, svc.Name)
		}
		// AddAll, not Addf("%v", err): svc.Validate() returns its own
		// accumulated ErrorList, and wrapping it as a single formatted item
		// would nest a "N validation error(s):" block inside one bullet here
		// and undercount the top-level total (see errors.go).
		errs.AddAll(svc.Validate())
		// Service.Validate() (Task 4) deliberately accepts an empty
		// FailPosture on a gate, because ParseStandalone is meant to resolve
		// it before Validate ever runs. But Policy is documented as the
		// resolved shape for both the standalone file and a future fleet
		// bundle, and a hand-built Policy (or a resolver bug) can still
		// reach Validate with the posture unresolved. Left unchecked,
		// HasFailClosed sees an unresolved gate as not-fail-closed and the
		// entire recovery_service requirement below goes unenforced.
		if svc.Kind == KindGate && svc.FailPosture == "" {
			errs.Addf("service %q has no resolved fail_posture; a resolver must assign open or closed before Validate", svc.Name)
		}
		// Same shape, same reason as the fail_posture check above: Service
		// itself tolerates an empty Backend because a single Service must stay
		// validatable before resolution, but a Policy is the resolved form.
		// Left unchecked, an unresolved backend reads as nftables everywhere
		// downstream — including in the ruleset planner, which would generate
		// a drop rule for a port whose admissions a script was supposed to own
		// and nothing would ever open it.
		if svc.Kind == KindGate && svc.Backend == "" {
			errs.Addf("service %q has no resolved backend; a resolver must assign %q or %q before Validate",
				svc.Name, BackendNFTables, BackendScript)
		}
	}

	p.validatePortOwnership(&errs)
	p.validateForwardTargetOwnership(&errs)
	p.validateServiceIDCollisions(&errs)
	p.validateRecoveryService(&errs)
	p.validateGrants(&errs)
	p.validateAbsentListenerNotFailOpen(&errs)

	return errs.Err()
}

// validatePortOwnership enforces I7, once per backend.
//
// The rule is per (backend, proto, port) rather than per (proto, port), and
// the widening is deliberate. I7 exists because two nftables services on one
// port write two accept rules and two drop rules into the same hook, where
// one table's drop defeats the other's accept and a correctly signed packet
// silently accomplishes nothing. A script-backed service writes no nftables
// rule at all, so it cannot collide with an nftables service that way — and
// pairing the two on one port is the deployment the script backend is meant
// for: the kernel holds the local bolt while the script handles the
// perimeter in front of it.
//
// Uniqueness still holds within each backend. Two script services on one port
// do collide, for the ordinary reason: they drive the same perimeter, and one
// service's close withdraws the other's admission.
func (p *Policy) validatePortOwnership(errs *ErrorList) {
	type portKey struct {
		backend Backend
		proto   string
		port    uint16
	}
	owner := map[portKey]string{}
	// The SPA carriers own their ports, and a gate that claims one is refused
	// here rather than silently world-opened.
	//
	// The dead-man accept rules test membership in agent_up, and agent_up
	// holds the carrier ports as bare inet_service numbers: `udp dport
	// @agent_up accept` is always present, and `tcp dport @agent_up accept` is
	// present whenever the http carrier is on. So a gate sitting on a carrier's
	// number is matched by that accept, which precedes and shadows the gate's
	// own drop, leaving the gate open to every source while the agent is alive
	// even when its posture is fail-closed. The carrier's own drop below the
	// accept never fires either. This was found by audit; nothing but this
	// registration refuses it.
	//
	// Both protocols and both carrier ports, so a gate's safety never depends
	// on which carriers happen to be enabled: agent_up is one set consulted by
	// both accepts, so tcp/spa_port, udp/spa_port, and both protocols of
	// spa_http_port are all reachable through it depending on configuration,
	// and a gate on any of them is a footgun regardless. nftables only, for
	// the same reason as before: a script backend writes no rule in this hook
	// and so cannot be shadowed by it.
	for _, proto := range []string{"tcp", "udp"} {
		owner[portKey{backend: BackendNFTables, proto: proto, port: p.SPAPort}] = "the spa udp carrier"
		if p.SPAHTTPPort != 0 {
			owner[portKey{backend: BackendNFTables, proto: proto, port: p.SPAHTTPPort}] = "the spa http carrier"
		}
	}
	for _, svc := range p.Services {
		if svc.Kind != KindGate {
			continue
		}
		for _, port := range svc.Ports {
			key := portKey{backend: svc.Backend, proto: svc.Proto, port: port}
			if prev, taken := owner[key]; taken {
				errs.Addf("%s/%d is claimed on the %s backend by both %q and %q; a port must have exactly "+
					"one owner per backend, or one table's drop defeats the other's accept",
					svc.Proto, port, svc.Backend, prev, svc.Name)
				continue
			}
			owner[key] = svc.Name
		}
	}
}

// validateForwardTargetOwnership is I7 one hop further in: the internal end of
// a forwarded path has exactly one owner, the same way the external end does.
//
// validatePortOwnership sees only this host's own ports, so two forwards on
// different external ports pointing at one internal (proto, address, port) sail
// past it. They land on the same forward-chain rules, since the accept and the
// drop are both written against the internal target, which is what the packet
// carries once it has been translated, and one service's drop is terminal ahead
// of the other service's accept. A correctly signed knock for the second
// service opens its set and accomplishes nothing, which is exactly the failure
// I7 exists to keep out of the field.
func (p *Policy) validateForwardTargetOwnership(errs *ErrorList) {
	type targetKey struct {
		proto string
		to    netip.Addr
		port  uint16
	}
	owner := map[targetKey]string{}
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := p.Services[name]
		if svc.Kind != KindGate || svc.Forward == nil {
			continue
		}
		key := targetKey{proto: svc.Proto, to: svc.Forward.To, port: svc.Forward.Port}
		if prev, taken := owner[key]; taken {
			errs.Addf("forward target %s/%s is claimed by both %q and %q; the forward chain's accept "+
				"and drop are both written against the internal target, so one service's drop defeats "+
				"the other's accept", svc.Proto, netip.AddrPortFrom(svc.Forward.To, svc.Forward.Port), prev, svc.Name)
			continue
		}
		owner[key] = svc.Name
	}
}

// Warnings collects every service's load-time warnings, sorted by service
// name so two runs against one file report them in the same order.
//
// They are separate from Validate's errors because they are not refusals:
// each names a property an operator chose that is worse than the default and
// cannot be fixed by this package. A caller that loads a policy is expected
// to surface them — see cmd/postern's agent command, which logs them at WARN
// before anything is armed.
func (p *Policy) Warnings() []string {
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []string
	if p.ConsoleRecovery {
		out = append(out, "console_recovery is set: this host arms with no verified recovery path. "+
			"A fail-closed service is unreachable except via the console ("+p.Console+"); there is no liveness pong "+
			"and no remote status or probe. Recovery is the console plus disarm --local.")
	}
	for _, name := range names {
		out = append(out, p.Services[name].Warnings()...)
	}
	return out
}

func (p *Policy) validateServiceIDCollisions(errs *ErrorList) {
	seen := map[[ServiceIDSize]byte]string{}
	for _, svc := range p.Services {
		id := svc.ID()
		if prev, dup := seen[id]; dup {
			errs.Addf("services %q and %q have colliding service ids", prev, svc.Name)
			continue
		}
		seen[id] = svc.Name
	}
}

func (p *Policy) validateRecoveryService(errs *ErrorList) {
	if !p.HasFailClosed() {
		return
	}
	if p.RecoveryService == "" {
		errs.Addf("recovery_service is required when any service is fail-closed: " +
			"arm-time liveness must prove the port an operator would actually recover with")
		return
	}
	svc, ok := p.Services[p.RecoveryService]
	if !ok {
		errs.Addf("recovery_service %q is not a declared service", p.RecoveryService)
		return
	}
	if svc.Kind != KindGate {
		errs.Addf("recovery_service %q has kind %q; it must be a gate with a reachable port", p.RecoveryService, svc.Kind)
	}
}

func (p *Policy) validateGrants(errs *ErrorList) {
	// KeyID is derived from the signing key, and Policy.Grants stops at the
	// first operator whose KeyID matches an incoming packet's. Two operators
	// sharing a signing key therefore have the same KeyID, and the second
	// one's grants are silently unreachable — a correctly signed packet
	// that does nothing, the same failure family as I7's port collision.
	seenKeys := map[[identity.KeyIDSize]byte]string{}
	// A shared encryption key is the same failure one field over, and worse:
	// KeyID is the signing key, so two operators sharing an ENCRYPTION key
	// have different KeyIDs and pass the check above, but TrialOpen stops at
	// the first shared secret that decrypts and returns on a KeyID mismatch
	// rather than trying the rest. So whichever of the two sorts first here
	// wins every packet, and the other operator is silently unknockable on
	// every host forever. An ordinary key rotation that re-uses the
	// encryption key produces it, and public material is all an attacker
	// needs to enroll a collision deliberately. Refused here where the
	// signing collision already is.
	seenEnc := map[[32]byte]string{}
	for _, op := range p.Operators {
		if op.Identity.Alg != identity.AlgEd25519X25519 {
			errs.Addf("operator %q has unsupported alg %q", op.Identity.Name, op.Identity.Alg)
		}
		keyID := op.Identity.KeyID()
		if prev, dup := seenKeys[keyID]; dup {
			errs.Addf("operator %q shares a signing key with operator %q; the second operator's grants are unreachable",
				op.Identity.Name, prev)
		} else {
			seenKeys[keyID] = op.Identity.Name
		}
		if prev, dup := seenEnc[op.Identity.Encryption]; dup {
			errs.Addf("operator %q shares an encryption key with operator %q; the second operator's knocks "+
				"decrypt under the first's shared secret and are then refused, so it is silently unknockable",
				op.Identity.Name, prev)
		} else {
			seenEnc[op.Identity.Encryption] = op.Identity.Name
		}
		for _, g := range op.Grants {
			for _, name := range g.Services {
				if _, ok := p.Services[name]; !ok {
					errs.Addf("operator %q is granted %q, which is not a declared service", op.Identity.Name, name)
				}
			}
			if g.AllowSourceCIDR {
				if g.MinIPv4Prefix <= 0 || g.MinIPv4Prefix > 32 {
					errs.Addf("operator %q allows asserted CIDRs but min_ipv4_prefix is %d; "+
						"without a bound an authorised operator could assert 0.0.0.0/0",
						op.Identity.Name, g.MinIPv4Prefix)
				}
				if g.MinIPv6Prefix <= 0 || g.MinIPv6Prefix > 128 {
					errs.Addf("operator %q allows asserted CIDRs but min_ipv6_prefix is %d; "+
						"without a bound an authorised operator could assert ::/0",
						op.Identity.Name, g.MinIPv6Prefix)
				}
			}
			// Every design example supplies max_ttl on a grant, so it is
			// intended as required — validated the same way Service.MaxTTL
			// is (a positivity check and the MaxTTLSeconds wire cap), rather
			// than left to guesswork. Unvalidated, a zero max_ttl is the
			// same shape as the min_ipv6_prefix bug this branch already
			// fixed: Phase B has to guess what zero means, and the
			// permissive reading silently drops the grant's cap entirely.
			if g.MaxTTL <= 0 {
				errs.Addf("operator %q has a grant for %v with a non-positive max_ttl", op.Identity.Name, g.Services)
			}
			if g.MaxTTL > MaxTTLSeconds*time.Second {
				errs.Addf("operator %q has a grant for %v with max_ttl %s; the wire limit is %d seconds",
					op.Identity.Name, g.Services, g.MaxTTL, MaxTTLSeconds)
			}
		}
	}
}

// validateAbsentListenerNotFailOpen enforces, at the schema level rather than
// by name, the rule the design states for the canary: a gate whose
// listener_expectation is "absent" may not be fail_posture "open". If it
// were, a dead agent would leave the port unfiltered, the health probe would
// get a connection-refused instead of a timeout, and the system would report
// green at exactly the moment the agent is dead. This needs no "if name ==
// canary" — the design asks for canary to stay an ordinary service, and any
// gate declared this way carries the same failure.
func (p *Policy) validateAbsentListenerNotFailOpen(errs *ErrorList) {
	for _, svc := range p.Services {
		if svc.Kind == KindGate && svc.ListenerExpectation == ListenerAbsent && svc.FailPosture == PostureOpen {
			errs.Addf("service %q has listener_expectation \"absent\" and fail_posture \"open\": "+
				"a dead agent would leave the port unfiltered, and a health probe would see "+
				"connection-refused instead of the timeout it is meant to catch",
				svc.Name)
		}
	}
}

// EphemeralLo and EphemeralHi are the kernel's default ephemeral port range
// (net.ipv4.ip_local_port_range). The rotating band must sit clear of it so the
// agent's fixed binds never collide with a source port the kernel hands an
// outbound socket.
const (
	EphemeralLo uint16 = 32768
	EphemeralHi uint16 = 60999
)

// validatePortRotation checks the port_rotation block: a correctly-sized
// secret, a positive window, and a range that is neither inverted nor
// overlapping the kernel's ephemeral range, the http carrier port, or any
// gated service's port. A rotating band swallowing a fixed port an operator
// still relies on would silently take that port away on whichever rotation
// window happens to land on it.
func (p *Policy) validatePortRotation(errs *ErrorList) {
	r := p.PortRotation
	if len(r.Secret) != knockport.SecretSize {
		errs.Addf("port_rotation.secret must be %d bytes, is %d", knockport.SecretSize, len(r.Secret))
	}
	if r.Window <= 0 {
		errs.Addf("port_rotation.window must be positive")
	}
	if r.RangeLo == 0 || r.RangeHi == 0 || r.RangeLo > r.RangeHi {
		errs.Addf("port_rotation.range is invalid: lo=%d hi=%d; want 0 < lo <= hi", r.RangeLo, r.RangeHi)
		return // the overlap checks below are meaningless on an inverted band
	}
	overlaps := func(lo, hi uint16) bool { return r.RangeLo <= hi && lo <= r.RangeHi }
	if overlaps(EphemeralLo, EphemeralHi) {
		errs.Addf("port_rotation.range %d-%d overlaps the kernel ephemeral range %d-%d; a bound port could "+
			"collide with an outbound socket's source port", r.RangeLo, r.RangeHi, EphemeralLo, EphemeralHi)
	}
	if p.SPAHTTPPort != 0 && overlaps(p.SPAHTTPPort, p.SPAHTTPPort) {
		errs.Addf("port_rotation.range %d-%d covers the http carrier port %d", r.RangeLo, r.RangeHi, p.SPAHTTPPort)
	}
	for _, svc := range p.Services {
		if svc.Kind != KindGate {
			continue
		}
		for _, port := range svc.Ports {
			if overlaps(port, port) {
				errs.Addf("port_rotation.range %d-%d covers service %q port %d", r.RangeLo, r.RangeHi, svc.Name, port)
			}
		}
	}
}
