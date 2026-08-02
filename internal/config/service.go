package config

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// Kind distinguishes port-owning gates from authenticated commands.
type Kind string

const (
	// KindGate owns ports and produces firewall rules.
	KindGate Kind = "gate"
	// KindAction owns no ports; confirm, disarm, and liveness.
	KindAction Kind = "action"
)

// FailPosture is what happens to a gate's ports when the agent is not running.
type FailPosture string

const (
	PostureOpen   FailPosture = "open"
	PostureClosed FailPosture = "closed"
)

// Backend names which gate implementation admits a source for one service.
//
// It is per service, not per host, and it is deliberately not a replacement
// for the nftables backend. nftables always exists: it owns the agent_up
// dead-man element, the SPA port's concealment, boot.nft, and every
// fail-posture drop rule (design section 4, invariant 1). A service opting
// into another backend moves only its own admissions.
type Backend string

const (
	// BackendNFTables is the default: the local kernel firewall holds this
	// service's admissions, with per-element kernel-owned expiry.
	BackendNFTables Backend = "nftables"
	// BackendScript hands this service's admissions to an operator-supplied
	// executable — a cloud provider's firewall, a load balancer, an appliance.
	// It buys reach and gives up the kernel's expiry guarantee; see
	// Service.Warnings and internal/gate's package doc.
	BackendScript Backend = "script"
)

// DefaultScriptTimeout bounds one script invocation when a service does not
// name its own. It is short on purpose: every verb is a single API call
// against a provider, and a backend that waits minutes for one is a backend
// whose reaper cannot keep to a schedule.
const DefaultScriptTimeout = 15 * time.Second

// MaxScriptTimeout is the ceiling a service may raise ScriptTimeout to. The
// bound exists because the timeout is also the worst case for how long a
// hung script delays its own service's next admission and its own reaper
// sweep; an unbounded value would make "degrades its own service" mean
// "disables its own service indefinitely".
const MaxScriptTimeout = 2 * time.Minute

// Forward is the machine behind the postern box that a gate's external port
// lands on, for the bastion and router deployments where the host running the
// agent is not the host being reached.
//
// Both fields are host configuration and there is no other way to populate
// them. The SPA packet selects a forward the way it selects any other service,
// by the service id hashed from the service name, and carries nothing an
// address could be derived from: spa.GatePayload's only address-shaped field
// is an asserted *source* prefix, and agent.Decision hands the gate a
// gate.Source and a TTL. Gate.Open takes no destination. That is the shape the
// rule needs to have. An operator's key means "open the path this host
// declared", never "forward me to an address I choose", and a key that could
// name its own target would be a pivot into the internal network for whoever
// holds one or ever steals one.
//
// The target is resolved into the ruleset at arm time, not at knock time: the
// generated DNAT rule carries the address as a literal and matches on set
// membership, so a knock adds a source to a set and can do nothing else.
type Forward struct {
	// To is the internal address the external port lands on.
	To netip.Addr
	// Port is the port on To. It is deliberately separate from the service's
	// own Ports, which are the external ports on the postern box: a forward
	// whose two ends were one field could not express the ordinary case of
	// reaching ssh on an internal host from a non-22 port outside.
	Port uint16
}

// ListenerExpectation is what pre-arm expects to find behind a gate's ports.
// The canary depends on nothing listening, so this is declared rather than
// assumed (design section 4).
type ListenerExpectation string

const (
	ListenerPresent   ListenerExpectation = "present"
	ListenerAbsent    ListenerExpectation = "absent"
	ListenerUnchecked ListenerExpectation = "unchecked"
)

// Verification names how the probe confirms a gate opened. tcp_rst is the
// only value in v1: connect and expect a reset, because nothing is listening
// (design section 4). It is meaningful only on a gate whose
// ListenerExpectation is absent — on a port that does have a listener, a
// successful connection is not a reset, so the check would report failure
// forever.
type Verification string

const (
	VerificationTCPRST Verification = "tcp_rst"
)

// MaxTTLSeconds is the wire limit: ttl_seconds is uint16.
const MaxTTLSeconds = 65535

// ServiceIDSize is the on-the-wire length of a service identifier.
const ServiceIDSize = 16

// MaxServiceNameLen bounds a service name so the hash input is unambiguous.
const MaxServiceNameLen = 32

// ReservedActions are names bound to specific packet payload variants. They
// may only be declared as KindAction.
var ReservedActions = []string{"confirm", "disarm", "liveness"}

// Service is one gated port set or one authenticated command.
type Service struct {
	Name                string
	Kind                Kind
	Proto               string
	Ports               []uint16
	DefaultTTL          time.Duration
	MaxTTL              time.Duration
	FailPosture         FailPosture
	ListenerExpectation ListenerExpectation
	Verification        Verification

	// Backend names which gate implementation admits sources for this
	// service. Empty on a resolved gate is a resolver bug, the same way an
	// empty FailPosture is; Policy.Validate says so.
	Backend Backend
	// ScriptPath is the absolute path of the executable BackendScript
	// invokes. It is required for that backend and forbidden for any other.
	ScriptPath string
	// ScriptTimeout bounds one invocation. Zero selects
	// DefaultScriptTimeout at resolution time.
	ScriptTimeout time.Duration

	// Forward, when set, makes this gate a path through this host to another
	// one rather than a path to a port on this host. Nil is the ordinary local
	// gate. See Forward.
	Forward *Forward
}

// ID is the identifier carried in the SPA packet: the first 16 bytes of
// SHA-256 over the service name. Hash-derived rather than a padded string, so
// the record stays fixed-width and service names stay out of a captured packet.
func (s Service) ID() [ServiceIDSize]byte {
	sum := sha256.Sum256([]byte(s.Name))
	var id [ServiceIDSize]byte
	copy(id[:], sum[:ServiceIDSize])
	return id
}

// ValidateServiceName enforces the grammar the hash input depends on:
// ASCII lowercase, digits, and interior hyphens, 1 to 32 bytes.
func ValidateServiceName(name string) error {
	var errs ErrorList
	if name == "" {
		errs.Addf("service name is empty")
		return errs.Err()
	}
	if len(name) > MaxServiceNameLen {
		errs.Addf("service name %q is %d bytes, limit is %d", name, len(name), MaxServiceNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !valid {
			errs.Addf("service name %q contains %q; only lowercase ascii, digits, and hyphen are allowed", name, string(c))
			break
		}
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		errs.Addf("service name %q may not begin or end with a hyphen", name)
	}
	return errs.Err()
}

func isReservedAction(name string) bool {
	for _, r := range ReservedActions {
		if r == name {
			return true
		}
	}
	return false
}

// Validate checks a single service in isolation. Cross-service rules such as
// unique port ownership belong to Task 5's Policy, which sees every service
// at once; a single Service must remain validatable on its own.
func (s Service) Validate() error {
	var errs ErrorList

	errs.AddAll(ValidateServiceName(s.Name))

	switch s.Kind {
	case KindGate:
		s.validateGate(&errs)
	case KindAction:
		s.validateAction(&errs)
	default:
		errs.Addf("service %q has unknown kind %q, want %q or %q", s.Name, s.Kind, KindGate, KindAction)
	}

	return errs.Err()
}

func (s Service) validateGate(errs *ErrorList) {
	if isReservedAction(s.Name) {
		errs.Addf("service %q is a reserved action name and may not be declared as a gate", s.Name)
	}
	if s.Proto != "tcp" {
		// v1 gates TCP only: confirmation and the canary proof are both
		// TCP-shaped, so a UDP gate would gate something postern cannot verify.
		errs.Addf("service %q has proto %q; v1 gates only tcp", s.Name, s.Proto)
	}
	if len(s.Ports) == 0 {
		errs.Addf("service %q is a gate and needs at least one port", s.Name)
	}
	if s.MaxTTL <= 0 {
		errs.Addf("service %q needs a positive max_ttl", s.Name)
	}
	if s.MaxTTL > MaxTTLSeconds*time.Second {
		errs.Addf("service %q has max_ttl %s; the wire limit is %d seconds", s.Name, s.MaxTTL, MaxTTLSeconds)
	}
	if s.DefaultTTL <= 0 {
		errs.Addf("service %q needs a positive default_ttl", s.Name)
	}
	if s.MaxTTL > 0 && s.DefaultTTL > s.MaxTTL {
		errs.Addf("service %q has default_ttl %s above max_ttl %s", s.Name, s.DefaultTTL, s.MaxTTL)
	}
	switch s.ListenerExpectation {
	case ListenerPresent, ListenerAbsent, ListenerUnchecked:
	default:
		errs.Addf("service %q has listener_expectation %q, want present, absent, or unchecked", s.Name, s.ListenerExpectation)
	}
	switch s.FailPosture {
	case "", PostureOpen, PostureClosed:
	default:
		errs.Addf("service %q has fail_posture %q, want open or closed", s.Name, s.FailPosture)
	}
	switch s.Verification {
	case "", VerificationTCPRST:
	default:
		errs.Addf("service %q has verification %q, want %q or empty", s.Name, s.Verification, VerificationTCPRST)
	}
	s.validateBackend(errs)
	s.validateForward(errs)
	if s.Verification != "" && s.ListenerExpectation != ListenerAbsent {
		// tcp_rst verification connects and expects a reset because nothing
		// is listening. On a listener_expectation: present or unchecked
		// service, a successful connection is not a reset, so this would
		// report failure forever rather than confirming anything.
		errs.Addf("service %q declares verification %q but listener_expectation is %q; "+
			"tcp_rst is only meaningful when listener_expectation is absent",
			s.Name, s.Verification, s.ListenerExpectation)
	}
}

// validateBackend holds every rule that depends on which gate implementation
// a service names. It runs on gates only; an action owns no ports and
// therefore has nothing to admit a source into.
func (s Service) validateBackend(errs *ErrorList) {
	switch s.Backend {
	case "", BackendNFTables:
		// An unresolved backend is caught by Policy.Validate, which is where
		// the equivalent unresolved-fail_posture check already lives; a
		// single Service must stay validatable before resolution.
		if s.ScriptPath != "" {
			errs.Addf("service %q declares script_path but backend is %q; script_path is only meaningful with backend %q",
				s.Name, s.Backend, BackendScript)
		}
		if s.ScriptTimeout != 0 {
			errs.Addf("service %q declares script_timeout but backend is %q", s.Name, s.Backend)
		}
	case BackendScript:
		s.validateScriptBackend(errs)
	default:
		errs.Addf("service %q has backend %q, want %q or %q", s.Name, s.Backend, BackendNFTables, BackendScript)
	}
}

func (s Service) validateScriptBackend(errs *ErrorList) {
	switch {
	case s.ScriptPath == "":
		errs.Addf("service %q has backend %q but no script_path", s.Name, BackendScript)
	case !filepath.IsAbs(s.ScriptPath):
		// Relative resolves against the agent's working directory, which
		// under systemd is "/" and under a test is whatever the harness
		// happened to chdir to. A root daemon must never execute a path
		// whose meaning depends on where it was started.
		errs.Addf("service %q has script_path %q, which is not absolute; the agent runs as root and "+
			"must never resolve an executable against its working directory", s.Name, s.ScriptPath)
	case strings.ContainsAny(s.ScriptPath, "\x00\n"):
		errs.Addf("service %q has a script_path containing a NUL or newline", s.Name)
	}
	if s.ScriptTimeout < 0 {
		errs.Addf("service %q has a negative script_timeout %s", s.Name, s.ScriptTimeout)
	}
	if s.ScriptTimeout > MaxScriptTimeout {
		errs.Addf("service %q has script_timeout %s; the limit is %s, because that timeout is also how long "+
			"a hung script delays this service's next admission and its own reaper sweep",
			s.Name, s.ScriptTimeout, MaxScriptTimeout)
	}
	if s.FailPosture == PostureClosed {
		// Refused rather than warned about. fail_posture: closed is a promise
		// that the drop rule survives the agent, and it is kept by a file on
		// disk that the kernel loads at boot with no process involved
		// (design section 7). A script backend has no boot-time form: nothing
		// runs it before the agent starts, so there is no state in which its
		// service is shut and the agent is absent. Accepting the word while
		// delivering none of the mechanism is how a posture silently inverts,
		// which is the failure this project's whole fail-posture machinery
		// exists to prevent.
		errs.Addf("service %q is backend %q and fail_posture %q; that posture is enforced by boot.nft "+
			"loading a drop rule before the agent exists, and a script backend has no boot-time form, "+
			"so the guarantee cannot be delivered", s.Name, BackendScript, PostureClosed)
	}
}

// validateForward holds every rule that depends on a gate landing somewhere
// other than this host. It runs on gates only; an action owns no ports and is
// refused a forward outright by validateAction.
func (s Service) validateForward(errs *ErrorList) {
	if s.Forward == nil {
		return
	}
	f := *s.Forward
	s.validateForwardTarget(f, errs)
	if f.Port == 0 {
		errs.Addf("service %q declares a forward with no port; the internal port is the port on %s, "+
			"not the port an operator dials", s.Name, f.To)
	}
	if len(s.Ports) > 1 {
		// One external port per forward. The pair (external port, internal
		// target) is what port ownership, the generated DNAT rule, and the
		// audit trail all name, and several external ports onto one target are
		// several names for one path that buy an operator nothing.
		errs.Addf("service %q declares a forward and %d external ports; a forward has exactly one, "+
			"because the path it names has exactly one internal end", s.Name, len(s.Ports))
	}
	if s.FailPosture == PostureOpen {
		// Refused rather than warned about, for the reason the script backend's
		// fail_posture: closed is refused: the word names a mechanism this shape
		// of service has no way to provide. Everywhere else in postern, "open"
		// means the drop rule disappears and the port returns to being reachable
		// as it was before postern existed (invariant 6, postern is an additive
		// deny layer). A forwarded path is not additive. Postern creates it, and
		// the DNAT rule is the path. Put that rule in postern_open and a dead
		// agent takes the path away, which is not "open"; put it in postern_boot
		// ungated and a dead agent leaves an unauthenticated route into the
		// internal network standing, which is "open" honoured and the whole
		// reason this feature keeps its target out of the packet undone.
		errs.Addf("service %q declares a forward and fail_posture %q; a forwarded path exists only "+
			"because postern's own DNAT rule creates it, so there is no prior state for the agent's "+
			"death to return the port to. A forward is therefore fail-closed, the alternatives being "+
			"a path that vanishes, which is not what %q means, and one that survives ungated, which "+
			"leaves an unauthenticated route to %s standing", s.Name, PostureOpen, PostureOpen, f.To)
	}
	if s.Backend != "" && s.Backend != BackendNFTables {
		// A service on another backend gets no nftables sets and no nftables
		// rules at all, which for a forward means no DNAT rule, which means no
		// path. The service would be a forward in name with nothing generated
		// to make it one.
		errs.Addf("service %q declares a forward and backend %q; the forwarded path is an nftables "+
			"DNAT rule, and a service on another backend generates no nftables rules at all",
			s.Name, s.Backend)
	}
	if s.ListenerExpectation != ListenerUnchecked {
		// Pre-arm probes this host. Nothing listens on a forward's external
		// port here by design, because the kernel translates the packet before
		// it can reach a local socket, and what does listen is on a machine
		// pre-arm has no way to inspect. "present" would fail arming forever
		// and "absent" would pass while asserting nothing.
		errs.Addf("service %q declares a forward and listener_expectation %q; the listener is on %s, "+
			"which pre-arm cannot see, and nothing listens on this host's own external port, so only "+
			"%q is a claim this host can make", s.Name, s.ListenerExpectation, f.To, ListenerUnchecked)
	}
}

// validateForwardTarget rejects the target addresses whose DNAT rule would not
// mean what the rest of this design assumes it means.
func (s Service) validateForwardTarget(f Forward, errs *ErrorList) {
	switch {
	case !f.To.IsValid():
		errs.Addf("service %q declares a forward with no target address", s.Name)
	case f.To.Zone() != "":
		errs.Addf("service %q has a forward target %q carrying a zone; a DNAT rule holds an address, "+
			"not an address plus the interface it was written on", s.Name, f.To)
	case f.To.IsUnspecified():
		errs.Addf("service %q has forward target %s, the unspecified address", s.Name, f.To)
	case f.To.IsLoopback():
		// Not tidiness. A packet translated to a loopback address becomes
		// locally destined, so it never traverses the forward hook, and the
		// drop rule that carries this service's fail-closed posture lives in
		// that chain. The posture would be declared and not enforced, and the
		// packet would instead meet whatever local service already owns that
		// port under that service's posture and that service's grant.
		errs.Addf("service %q has forward target %s; a translated packet to a loopback address is "+
			"locally destined, so it never reaches the forward chain where this service's drop rule "+
			"lives, and it would arrive at a local port under some other service's posture", s.Name, f.To)
	case f.To.IsMulticast():
		errs.Addf("service %q has forward target %s, a multicast address", s.Name, f.To)
	case f.To.IsLinkLocalUnicast():
		errs.Addf("service %q has forward target %s; a link-local address names a different host on "+
			"every interface, so it cannot identify the machine this forward reaches", s.Name, f.To)
	}
}

// Warnings are load-time findings that are true, bad, and deliberately not
// errors. They exist so an operator meets them when the config is read rather
// than discovering them during an outage.
//
// The one warning today is the script backend's expiry gap: see
// internal/gate's package doc and the README's posture table for the whole
// statement.
func (s Service) Warnings() []string {
	if s.Kind != KindGate || s.Backend != BackendScript {
		return nil
	}
	return []string{fmt.Sprintf(
		"service %q uses the script backend, so its admissions have no kernel-owned expiry: "+
			"the agent's own reaper closes them, and if the agent dies without shutting down cleanly "+
			"the hole stays open until the agent restarts and catches up, or until something else "+
			"removes it. That is weaker than either documented fail posture", s.Name)}
}

func (s Service) validateAction(errs *ErrorList) {
	if s.Backend != "" {
		errs.Addf("action %q may not declare backend", s.Name)
	}
	if s.ScriptPath != "" {
		errs.Addf("action %q may not declare script_path", s.Name)
	}
	if s.ScriptTimeout != 0 {
		errs.Addf("action %q may not declare script_timeout", s.Name)
	}
	if !isReservedAction(s.Name) {
		errs.Addf("service %q has kind action but is not one of the reserved actions %v", s.Name, ReservedActions)
	}
	if s.Proto != "" {
		errs.Addf("action %q may not declare proto", s.Name)
	}
	if len(s.Ports) != 0 {
		errs.Addf("action %q may not declare ports", s.Name)
	}
	if s.DefaultTTL != 0 || s.MaxTTL != 0 {
		errs.Addf("action %q may not declare TTLs", s.Name)
	}
	if s.FailPosture != "" {
		errs.Addf("action %q may not declare fail_posture", s.Name)
	}
	if s.ListenerExpectation != "" {
		errs.Addf("action %q may not declare listener_expectation", s.Name)
	}
	if s.Verification != "" {
		errs.Addf("action %q may not declare verification", s.Name)
	}
	if s.Forward != nil {
		errs.Addf("action %q may not declare forward", s.Name)
	}
}
