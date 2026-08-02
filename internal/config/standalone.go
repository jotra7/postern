package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
)

type yamlService struct {
	Kind                string       `yaml:"kind"`
	Proto               string       `yaml:"proto"`
	Ports               []uint16     `yaml:"ports"`
	DefaultTTL          string       `yaml:"default_ttl"`
	MaxTTL              string       `yaml:"max_ttl"`
	FailPosture         string       `yaml:"fail_posture"`
	ListenerExpectation string       `yaml:"listener_expectation"`
	Verification        string       `yaml:"verification"`
	Backend             string       `yaml:"backend"`
	ScriptPath          string       `yaml:"script_path"`
	ScriptTimeout       string       `yaml:"script_timeout"`
	Forward             *yamlForward `yaml:"forward"`
}

// yamlForward mirrors a service's forward block. It is a pointer on
// yamlService so that "no forward block" and "a forward block with nothing in
// it" stay different inputs: the second is a declaration with no target, which
// Service.validateForward refuses by name rather than quietly reading as an
// ordinary local gate.
type yamlForward struct {
	To   string `yaml:"to"`
	Port uint16 `yaml:"port"`
}

// decodeService is the one place a yamlService becomes a Service, shared by
// the standalone parser and the fleet inventory parser. The two used to carry
// separate copies of this block, and a field added to one and not the other
// is a field that silently means nothing in fleet mode — the compiled bundle
// would parse, validate, and run with the operator's declaration dropped.
func decodeService(name string, ys yamlService, breakglass map[string]bool, errs *ErrorList) Service {
	svc := Service{
		Name:                name,
		Kind:                Kind(ys.Kind),
		Proto:               ys.Proto,
		Ports:               ys.Ports,
		FailPosture:         FailPosture(ys.FailPosture),
		ListenerExpectation: ListenerExpectation(ys.ListenerExpectation),
		Verification:        Verification(ys.Verification),
		Backend:             Backend(ys.Backend),
		ScriptPath:          ys.ScriptPath,
	}
	// Parsed unconditionally, regardless of Kind: proto, ports, fail_posture,
	// listener_expectation, and the backend fields are all copied through the
	// same way, and an action that declares a TTL needs Service.Validate's
	// "may not declare TTLs" check to actually see a nonzero value to reject —
	// parsing only for gates left that check permanently unreachable through
	// this constructor, and any malformed duration on an action produced no
	// error at all.
	svc.DefaultTTL = parseDuration(ys.DefaultTTL, 0, name+".default_ttl", errs)
	svc.MaxTTL = parseDuration(ys.MaxTTL, 0, name+".max_ttl", errs)
	svc.ScriptTimeout = parseDuration(ys.ScriptTimeout, 0, name+".script_timeout", errs)
	svc.Forward = decodeForward(name, ys.Forward, errs)
	if svc.Kind != KindGate {
		return svc
	}

	if svc.ListenerExpectation == "" {
		if svc.Forward != nil {
			// The listener is on another machine. Defaulting a forward to
			// "present" would default it into a refusal, and pre-arm would go
			// looking on this host for a socket the design says will not be
			// there.
			svc.ListenerExpectation = ListenerUnchecked
		} else {
			svc.ListenerExpectation = ListenerPresent
		}
	}
	if svc.Backend == "" {
		svc.Backend = BackendNFTables
	}
	if svc.Backend == BackendScript && svc.ScriptTimeout == 0 {
		svc.ScriptTimeout = DefaultScriptTimeout
	}
	if svc.FailPosture == "" {
		switch {
		case svc.Forward != nil:
			// Ahead of the breakglass case on purpose. A forward has exactly one
			// posture it can deliver (Service.validateForward says why), so
			// letting breakglass_services default one to "open" would resolve it
			// straight into a refusal, which is a resolver telling operators to
			// write a word that changes nothing.
			svc.FailPosture = PostureClosed
		case svc.Backend == BackendScript:
			// A script-backed service has no boot.nft form, so the local
			// kernel drops nothing for it when the agent is absent — which is
			// exactly what "open" describes. Resolving it to the ordinary
			// non-breakglass default of "closed" would name a posture whose
			// mechanism is not generated for this service, and validation
			// refuses that combination outright; defaulting into a refusal is
			// a resolver telling operators to write a word that changes
			// nothing.
			svc.FailPosture = PostureOpen
		case breakglass[name]:
			// Breakglass services default open; every other gate defaults
			// closed, because once the same mechanism hides a database,
			// fail-open on agent death publishes that database.
			svc.FailPosture = PostureOpen
		default:
			svc.FailPosture = PostureClosed
		}
	}
	return svc
}

// decodeForward turns a forward block into the resolved target. It parses an
// IP literal and nothing else: a hostname here would put DNS on the path
// between a knock and the address a packet is translated to, and would make
// the target a thing a resolver answers for rather than a thing the host's
// own configuration states.
func decodeForward(name string, yf *yamlForward, errs *ErrorList) *Forward {
	if yf == nil {
		return nil
	}
	f := &Forward{Port: yf.Port}
	// An absent "to" is left invalid rather than reported here.
	// Service.validateForward names the missing target alongside every other
	// forward rule, so an operator meets one account of what a forward needs
	// instead of two.
	if yf.To != "" {
		addr, err := netip.ParseAddr(yf.To)
		if err != nil {
			errs.Addf("service %q forward.to %q is not an IP literal", name, yf.To)
			return f
		}
		f.To = addr.Unmap()
	}
	return f
}

// yamlPortRotation mirrors the port_rotation block:
// `port_rotation: { secret: <base64>, window: 600s, range: 20000-30000 }`.
// It is shared between yamlStandalone and yamlInventoryDefaults, both of
// which decode it as an ordinary pointer field (present vs. absent stays
// distinguishable the same way yamlForward does for a service's forward
// block). InventoryHost's port_rotation key is the one place this shape is
// not the whole story: it accepts the bare scalar "disabled" as well, so it
// decodes through yamlHostPortRotation instead (see inventory.go).
type yamlPortRotation struct {
	Secret string `yaml:"secret"`
	Window string `yaml:"window"`
	Range  string `yaml:"range"`
}

// decodePortRotation turns a *yamlPortRotation into the resolved
// *PortRotation ParseStandalone and ParseInventory both hand to Policy. nil
// in, nil out: an absent port_rotation key means fixed-port mode, and that
// distinction must survive past this function for Policy.Validate to see it.
// field prefixes every problem this reports (e.g. "port_rotation" or
// "defaults.port_rotation"), matching the field-naming convention every other
// parse error in this package already follows.
func decodePortRotation(yr *yamlPortRotation, field string, errs *ErrorList) *PortRotation {
	if yr == nil {
		return nil
	}
	r := &PortRotation{}
	secret, err := base64.StdEncoding.DecodeString(yr.Secret)
	if err != nil {
		errs.Addf("%s.secret: not base64: %v", field, err)
	} else {
		r.Secret = secret
	}
	r.Window = parseDuration(yr.Window, knockport.DefaultWindow, field+".window", errs)
	r.RangeLo, r.RangeHi = parseRange(yr.Range, field+".range", errs)
	return r
}

// parseRange parses a port_rotation range's "lo-hi" form (e.g.
// "20000-30000"). An empty string falls back to knockport's own default
// band, the same fallback idiom parseDuration uses for an empty duration
// field. A malformed value is reported through errs rather than returned,
// so a caller accumulates it alongside everything else this file already
// accumulates that way.
func parseRange(s, field string, errs *ErrorList) (lo, hi uint16) {
	if s == "" {
		return knockport.DefaultRangeLo, knockport.DefaultRangeHi
	}
	before, after, ok := strings.Cut(s, "-")
	if !ok {
		errs.Addf(`%s: %q is not of the form "lo-hi"`, field, s)
		return 0, 0
	}
	loN, err := strconv.ParseUint(before, 10, 16)
	if err != nil {
		errs.Addf("%s: lo %q: %v", field, before, err)
		return 0, 0
	}
	hiN, err := strconv.ParseUint(after, 10, 16)
	if err != nil {
		errs.Addf("%s: hi %q: %v", field, after, err)
		return 0, 0
	}
	return uint16(loN), uint16(hiN)
}

type yamlGrant struct {
	Services        []string `yaml:"services"`
	MaxTTL          string   `yaml:"max_ttl"`
	AllowSourceCIDR bool     `yaml:"allow_source_cidr"`
	MinIPv4Prefix   int      `yaml:"min_ipv4_prefix"`
	MinIPv6Prefix   int      `yaml:"min_ipv6_prefix"`
}

type yamlOperator struct {
	Name       string      `yaml:"name"`
	Alg        string      `yaml:"alg"`
	Signing    string      `yaml:"signing"`
	Encryption string      `yaml:"encryption"`
	Grants     []yamlGrant `yaml:"grants"`
}

type yamlStandalone struct {
	FleetID            string                 `yaml:"fleet_id"`
	HostID             string                 `yaml:"host_id"`
	Revision           uint64                 `yaml:"revision"`
	SPAPort            uint16                 `yaml:"spa_port"`
	SPAHTTPPort        uint16                 `yaml:"spa_http_port"`
	AlwaysAllowIface   string                 `yaml:"always_allow_iface"`
	ConsoleRecovery    bool                   `yaml:"console_recovery,omitempty"`
	Console            string                 `yaml:"console,omitempty"`
	RecoveryService    string                 `yaml:"recovery_service"`
	BreakglassServices []string               `yaml:"breakglass_services"`
	FreshnessWindow    string                 `yaml:"freshness_window"`
	FreshnessWindowMax string                 `yaml:"freshness_window_max"`
	Services           map[string]yamlService `yaml:"services"`
	Operators          []yamlOperator         `yaml:"operators"`
	// HubURL, BundleSigners and EnrollmentFloor are M2's fleet-mode keys. See
	// Policy.HubURL/BundleSigners/EnrollmentFloor for why they live here
	// rather than inside a fetched bundle.
	HubURL          string   `yaml:"hub_url"`
	BundleSigners   []string `yaml:"bundle_signers"`
	EnrollmentFloor uint64   `yaml:"enrollment_floor"`
	// PortRotation is a pointer, same reason as yamlForward: "no port_rotation
	// key" and "an empty port_rotation block" must stay distinguishable, since
	// the first means fixed-port mode and the second is a declaration with
	// nothing in it.
	PortRotation *yamlPortRotation `yaml:"port_rotation"`
}

// ParseStandalone reads a root-owned standalone configuration file. Structural
// problems are returned here; semantic ones surface from Policy.Validate.
func ParseStandalone(data []byte) (*Policy, error) {
	var doc yamlStandalone
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// KnownFields rejects any key that doesn't map to a struct field, at
	// every nesting level. This is a root-owned file that decides whether a
	// host is reachable: a typo like "fail_postur" (missing 'e') would
	// otherwise be silently dropped, and the service would fall through to
	// its resolved default — which for a non-breakglass gate is fail-closed,
	// the opposite of what a typo'd "open" would have meant, but for a
	// breakglass gate silently keeps fail-open when the operator's typo was
	// trying to say something else entirely. Either way: a typo must be a
	// parse error, never a silent behavior change.
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			// yaml.Unmarshal on an empty or comment-only document used to
			// return no error at all, and every field-level check below
			// (fleet_id, host_id, spa_port, ...) would fire and describe
			// what was missing. Decoder.Decode instead returns bare io.EOF
			// for the same input, which is a poor thing to hand an operator
			// holding a truncated or empty file — name the actual problem
			// instead of surfacing the underlying sentinel.
			return nil, fmt.Errorf("parse standalone config: empty document")
		}
		return nil, fmt.Errorf("parse standalone config: %w", err)
	}

	p := &Policy{
		Revision:         doc.Revision,
		SPAPort:          doc.SPAPort,
		SPAHTTPPort:      doc.SPAHTTPPort,
		AlwaysAllowIface: doc.AlwaysAllowIface,
		ConsoleRecovery:  doc.ConsoleRecovery,
		Console:          doc.Console,
		RecoveryService:  doc.RecoveryService,
		Services:         make(map[string]Service, len(doc.Services)),
		MaxOperators:     DefaultMaxOperators,
		HubURL:           doc.HubURL,
		EnrollmentFloor:  doc.EnrollmentFloor,
	}

	var errs ErrorList
	p.PortRotation = decodePortRotation(doc.PortRotation, "port_rotation", &errs)
	if err := decodeID(doc.FleetID, &p.FleetID); err != nil {
		errs.Addf("fleet_id: %v", err)
	}
	if err := decodeID(doc.HostID, &p.HostID); err != nil {
		errs.Addf("host_id: %v", err)
	}
	p.FreshnessWindow = parseDuration(doc.FreshnessWindow, DefaultFreshnessWindow, "freshness_window", &errs)
	p.FreshnessWindowMax = parseDuration(doc.FreshnessWindowMax, DefaultFreshnessWindowMax, "freshness_window_max", &errs)

	breakglass := map[string]bool{}
	for _, n := range doc.BreakglassServices {
		breakglass[n] = true
	}
	// nil (the key was absent) gets the hidden ssh default; an explicit
	// empty list ("breakglass_services: []") is a deliberate declaration of
	// no breakglass services and must not be overridden — yaml.v3 decodes
	// these two cases into a nil slice and a non-nil, zero-length slice
	// respectively, so this distinguishes them (len() alone cannot: both
	// have length 0). Explicit emptiness wins because this default errs
	// toward exposure, and only an operator who never wrote the key should
	// get it silently.
	if doc.BreakglassServices == nil {
		breakglass["ssh"] = true
	}

	for name, ys := range doc.Services {
		p.Services[name] = decodeService(name, ys, breakglass, &errs)
	}

	for _, yo := range doc.Operators {
		op := Operator{}
		op.Identity.Name = yo.Name
		op.Identity.Alg = identity.Algorithm(yo.Alg)
		if err := decodeKey(yo.Signing, &op.Identity.Signing); err != nil {
			errs.Addf("operator %q signing key: %v", yo.Name, err)
		}
		if err := decodeKey(yo.Encryption, &op.Identity.Encryption); err != nil {
			errs.Addf("operator %q encryption key: %v", yo.Name, err)
		}
		for _, yg := range yo.Grants {
			op.Grants = append(op.Grants, Grant{
				Services:        yg.Services,
				MaxTTL:          parseDuration(yg.MaxTTL, 0, yo.Name+".max_ttl", &errs),
				AllowSourceCIDR: yg.AllowSourceCIDR,
				MinIPv4Prefix:   yg.MinIPv4Prefix,
				MinIPv6Prefix:   yg.MinIPv6Prefix,
			})
		}
		p.Operators = append(p.Operators, op)
	}

	for i, s := range doc.BundleSigners {
		key, err := decodeHexKey32(s)
		if err != nil {
			errs.Addf("bundle_signers[%d]: %v", i, err)
			continue
		}
		p.BundleSigners = append(p.BundleSigners, key)
	}

	if err := errs.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeID(s string, out *[16]byte) error {
	if s == "" {
		return fmt.Errorf("missing")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != 16 {
		return fmt.Errorf("is %d bytes, want 16", len(raw))
	}
	copy(out[:], raw)
	return nil
}

// decodeHexKey32 decodes a bundle_signers entry: hex, deliberately distinct
// from decodeKey's base64, since a bundle_signers value is a raw Ed25519
// public key rather than one of this file's operator identities.
func decodeHexKey32(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, fmt.Errorf("missing")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("is %d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func decodeKey(s string, out *[32]byte) error {
	if s == "" {
		return fmt.Errorf("missing")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("is %d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return nil
}

func parseDuration(s string, fallback time.Duration, field string, errs *ErrorList) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		errs.Addf("%s: %v", field, err)
		return fallback
	}
	return d
}
