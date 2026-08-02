package config

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	"github.com/jotra7/postern/internal/identity"
)

// Inventory is the fleet's hand-edited source of truth: a YAML file in git,
// reviewed in diffs, that never leaves the operator's machine or the
// repository (design section 6, "Fleet inventory"). `postern sign` compiles
// it into one signed, sealed bundle per host; this package only parses and
// validates it.
type Inventory struct {
	FleetID       [16]byte
	Version       uint64
	BundleSigners []string // operator names permitted to sign bundles
	Operators     []InventoryOperator
	Services      map[string]Service
	Defaults      InventoryDefaults
	Hosts         []InventoryHost
}

// InventoryOperator is a named identity plus the grants it holds across the
// fleet. Unlike config.Operator's grants (host-implicit, because a standalone
// file describes one host), each grant here names which hosts it applies to.
type InventoryOperator struct {
	Identity identity.PublicIdentity
	Grants   []InventoryGrant
}

// InventoryGrant is one operator's permission over a set of hosts and
// services.
type InventoryGrant struct {
	Hosts           []string // "*" or exact host names
	Services        []string
	MaxTTL          time.Duration
	AllowSourceCIDR bool
	// MinIPv4Prefix and MinIPv6Prefix are both carried through even though
	// only one applies to any given packet: config.Grant.AllowsSource checks
	// the field matching the packet's address family, so dropping either one
	// here would floor that family at zero while the compiled config still
	// claimed a minimum.
	MinIPv4Prefix int
	MinIPv6Prefix int
}

// InventorySSH is the SSH target for enrollment and deploys.
//
// It is declared here rather than reused from internal/client because
// internal/config must not import internal/client: the agent imports config,
// and nothing on a host should pull in the operator's client code. The two
// types are identical by coincidence of purpose, not by inheritance.
type InventorySSH struct {
	Host string
	User string
	Port uint16
}

// InventoryDefaults are the fleet-wide values a host uses unless its own
// entry overrides them.
type InventoryDefaults struct {
	SPAPort          uint16
	SPAHTTPPort      uint16
	AlwaysAllowIface string
	// ConsoleRecovery, when true, is the fleet-wide acknowledgement that
	// Console is each host's out-of-band recovery route, letting a host
	// with no always_allow_iface of its own still pass Policy.Validate. A
	// per-host console_recovery: true overrides this the same way any other
	// per-host field does.
	ConsoleRecovery    bool
	RecoveryService    string
	FreshnessWindow    time.Duration
	FreshnessWindowMax time.Duration
	// PortRotation is the fleet-wide rotating-port declaration every host
	// takes unless its own entry overrides it (a per-host block) or opts out
	// entirely (PortRotationDisabled on InventoryHost). Nil means fixed-port
	// mode fleet-wide.
	PortRotation *PortRotation
}

// InventoryHost is one host's entry: enough for `postern sign` to compile its
// resolved policy and for enrollment to record what it found.
type InventoryHost struct {
	Name         string
	HostID       [16]byte
	KnockAddr    netip.AddrPort
	SSH          InventorySSH
	HostIdentity identity.PublicIdentity
	Services     []string
	Groups       []string
	// ProviderFronted records whether knock_addr is a CDN/proxy origin
	// address rather than a directly-reachable host, mirroring the design's
	// `provider_fronted` field. It carries no other behaviour here.
	ProviderFronted bool
	Console         string
	// ConsoleRecovery declares Console as this host's acknowledged
	// out-of-band recovery route, letting it compile with no
	// always_allow_iface (design section on console-recovery mode). It is
	// ORed with the fleet default in Compile, so either can set it.
	ConsoleRecovery bool
	// Overrides, empty meaning "take the fleet default".
	SPAPort          uint16
	SPAHTTPPort      uint16
	AlwaysAllowIface string
	RecoveryService  string
	// PortRotation, when set, overrides the fleet's defaults.PortRotation
	// with this host's own block. Nil (and PortRotationDisabled false) means
	// "take the fleet default", the same override shape every other field
	// above uses.
	PortRotation *PortRotation
	// PortRotationDisabled records a per-host `port_rotation: disabled`: the
	// one way a host declines the fleet's defaults.PortRotation rather than
	// inheriting it. It is orthogonal to PortRotation being nil, which merely
	// means "no override of my own" and still inherits the fleet default.
	PortRotationDisabled bool
}

// yamlInventoryGrant mirrors one grant entry under an operator.
type yamlInventoryGrant struct {
	Hosts           []string `yaml:"hosts"`
	Services        []string `yaml:"services"`
	MaxTTL          string   `yaml:"max_ttl"`
	AllowSourceCIDR bool     `yaml:"allow_source_cidr"`
	MinIPv4Prefix   int      `yaml:"min_ipv4_prefix"`
	MinIPv6Prefix   int      `yaml:"min_ipv6_prefix"`
}

// yamlInventoryOperator mirrors one operator entry.
type yamlInventoryOperator struct {
	Name       string               `yaml:"name"`
	Alg        string               `yaml:"alg"`
	Signing    string               `yaml:"signing"`
	Encryption string               `yaml:"encryption"`
	Grants     []yamlInventoryGrant `yaml:"grants"`
}

// yamlInventorySSH mirrors InventorySSH.
type yamlInventorySSH struct {
	Host string `yaml:"host"`
	User string `yaml:"user"`
	Port uint16 `yaml:"port"`
}

// yamlInventoryHostIdentity mirrors a host's identity block. It uses the same
// alg/signing/encryption shape as an operator's identity (a single tagged key
// suite), not the design doc's illustrative signing_alg/encryption_alg split
// — the target type is identity.PublicIdentity, which has one Alg field
// covering both keys, so the operator encoding is the one that actually
// round-trips through decodeKey/decodeID.
type yamlInventoryHostIdentity struct {
	Alg        string `yaml:"alg"`
	Signing    string `yaml:"signing"`
	Encryption string `yaml:"encryption"`
}

// yamlInventoryHost mirrors one host entry.
type yamlInventoryHost struct {
	Name             string                    `yaml:"name"`
	HostID           string                    `yaml:"host_id"`
	KnockAddr        string                    `yaml:"knock_addr"`
	SSH              yamlInventorySSH          `yaml:"ssh"`
	HostIdentity     yamlInventoryHostIdentity `yaml:"host_identity"`
	Services         []string                  `yaml:"services"`
	Groups           []string                  `yaml:"groups"`
	ProviderFronted  bool                      `yaml:"provider_fronted"`
	Console          string                    `yaml:"console"`
	ConsoleRecovery  bool                      `yaml:"console_recovery"`
	SPAPort          uint16                    `yaml:"spa_port"`
	SPAHTTPPort      uint16                    `yaml:"spa_http_port"`
	AlwaysAllowIface string                    `yaml:"always_allow_iface"`
	RecoveryService  string                    `yaml:"recovery_service"`
	PortRotation     yamlHostPortRotation      `yaml:"port_rotation"`
}

// yamlHostPortRotation decodes a host's port_rotation key, which is
// polymorphic in a way no other field in this file is: it is either a
// mapping with the same shape as yamlPortRotation (a per-host override) or
// the bare scalar "disabled" (opting this host out of the fleet's
// defaults.port_rotation instead of inheriting it). A key that is simply
// absent leaves both fields at their zero value, which is "inherit the fleet
// default" — the ordinary override behaviour every other per-host field
// already has.
type yamlHostPortRotation struct {
	Block    *yamlPortRotation
	Disabled bool
}

// UnmarshalYAML implements yaml.Unmarshaler. It has to do its own
// known-fields check on the mapping branch: yaml.Node.Decode always starts a
// fresh decoder that does not inherit the parent Decoder.KnownFields(true)
// this package relies on everywhere else, so a typo'd key inside the block
// (e.g. "windo" for "window") would otherwise be silently dropped instead of
// rejected the way every other misspelled key in this host-adjacent,
// diff-reviewed file already is.
func (h *yamlHostPortRotation) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		if s != "disabled" {
			return fmt.Errorf(`port_rotation: %q is not "disabled"; a per-host override must be a mapping`, s)
		}
		h.Disabled = true
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf(`port_rotation: must be a mapping or the scalar "disabled"`)
	}
	block := &yamlPortRotation{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, val := node.Content[i], node.Content[i+1]
		var err error
		switch key.Value {
		case "secret":
			err = val.Decode(&block.Secret)
		case "window":
			err = val.Decode(&block.Window)
		case "range":
			err = val.Decode(&block.Range)
		default:
			return fmt.Errorf("field %s not found in type config.yamlPortRotation", key.Value)
		}
		if err != nil {
			return err
		}
	}
	h.Block = block
	return nil
}

// yamlInventoryDefaults mirrors the fleet-wide defaults block.
type yamlInventoryDefaults struct {
	SPAPort            uint16            `yaml:"spa_port"`
	SPAHTTPPort        uint16            `yaml:"spa_http_port"`
	AlwaysAllowIface   string            `yaml:"always_allow_iface"`
	ConsoleRecovery    bool              `yaml:"console_recovery"`
	RecoveryService    string            `yaml:"recovery_service"`
	FreshnessWindow    string            `yaml:"freshness_window"`
	FreshnessWindowMax string            `yaml:"freshness_window_max"`
	PortRotation       *yamlPortRotation `yaml:"port_rotation"`
}

// yamlInventory mirrors the whole document. breakglass_services is decoded
// here but has no field on Inventory: it only ever feeds the per-service
// FailPosture default computed below, the same way ParseStandalone uses it,
// and there is nothing for a later reader of *Inventory to do with the raw
// list once that resolution has happened.
type yamlInventory struct {
	FleetID            string                  `yaml:"fleet_id"`
	Version            uint64                  `yaml:"version"`
	BundleSigners      []string                `yaml:"bundle_signers"`
	Operators          []yamlInventoryOperator `yaml:"operators"`
	BreakglassServices []string                `yaml:"breakglass_services"`
	Services           map[string]yamlService  `yaml:"services"`
	Defaults           yamlInventoryDefaults   `yaml:"defaults"`
	Hosts              []yamlInventoryHost     `yaml:"hosts"`
}

// ParseInventory reads the fleet inventory. Structural problems (malformed
// hex, malformed keys, malformed durations, an unknown field) are returned
// here; cross-referencing problems (an unknown bundle signer, a duplicate
// host_id, ...) surface from Inventory.Validate.
func ParseInventory(data []byte) (*Inventory, error) {
	var doc yamlInventory
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// KnownFields(true), same as ParseStandalone and for the same reason:
	// this is host-adjacent configuration reviewed in diffs, where a
	// misspelled key can silently drop a grant or invert a fail posture. The
	// client's own host entry (internal/client/config.go) is the one place
	// that relaxed this, because there an unknown key only costs a feature,
	// never a posture — that reasoning does not apply here.
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse inventory: empty document")
		}
		return nil, fmt.Errorf("parse inventory: %w", err)
	}

	inv := &Inventory{
		Version:       doc.Version,
		BundleSigners: doc.BundleSigners,
		Services:      make(map[string]Service, len(doc.Services)),
	}

	var errs ErrorList
	if err := decodeID(doc.FleetID, &inv.FleetID); err != nil {
		errs.Addf("fleet_id: %v", err)
	}

	inv.Defaults.SPAPort = doc.Defaults.SPAPort
	inv.Defaults.SPAHTTPPort = doc.Defaults.SPAHTTPPort
	inv.Defaults.AlwaysAllowIface = doc.Defaults.AlwaysAllowIface
	inv.Defaults.ConsoleRecovery = doc.Defaults.ConsoleRecovery
	inv.Defaults.RecoveryService = doc.Defaults.RecoveryService
	inv.Defaults.FreshnessWindow = parseDuration(doc.Defaults.FreshnessWindow, DefaultFreshnessWindow, "defaults.freshness_window", &errs)
	inv.Defaults.FreshnessWindowMax = parseDuration(doc.Defaults.FreshnessWindowMax, DefaultFreshnessWindowMax, "defaults.freshness_window_max", &errs)
	inv.Defaults.PortRotation = decodePortRotation(doc.Defaults.PortRotation, "defaults.port_rotation", &errs)

	// Same nil-vs-empty-slice distinction ParseStandalone makes: absent
	// breakglass_services gets the hidden ssh default, an explicit empty list
	// is a deliberate declaration of none.
	breakglass := map[string]bool{}
	for _, n := range doc.BreakglassServices {
		breakglass[n] = true
	}
	if doc.BreakglassServices == nil {
		breakglass["ssh"] = true
	}

	for name, ys := range doc.Services {
		// Shared with ParseStandalone rather than duplicated: see
		// decodeService. A field resolved in one parser and not the other
		// means an operator's declaration silently disappears on whichever
		// side missed it, and the compiled bundle still parses and runs.
		inv.Services[name] = decodeService(name, ys, breakglass, &errs)
	}

	for _, yo := range doc.Operators {
		op := InventoryOperator{}
		op.Identity.Name = yo.Name
		op.Identity.Alg = identity.Algorithm(yo.Alg)
		if err := decodeKey(yo.Signing, &op.Identity.Signing); err != nil {
			errs.Addf("operator %q signing key: %v", yo.Name, err)
		}
		if err := decodeKey(yo.Encryption, &op.Identity.Encryption); err != nil {
			errs.Addf("operator %q encryption key: %v", yo.Name, err)
		}
		for _, yg := range yo.Grants {
			op.Grants = append(op.Grants, InventoryGrant{
				Hosts:           yg.Hosts,
				Services:        yg.Services,
				MaxTTL:          parseDuration(yg.MaxTTL, 0, yo.Name+".max_ttl", &errs),
				AllowSourceCIDR: yg.AllowSourceCIDR,
				MinIPv4Prefix:   yg.MinIPv4Prefix,
				MinIPv6Prefix:   yg.MinIPv6Prefix,
			})
		}
		inv.Operators = append(inv.Operators, op)
	}

	for _, yh := range doc.Hosts {
		host := InventoryHost{
			Name:                 yh.Name,
			SSH:                  InventorySSH{Host: yh.SSH.Host, User: yh.SSH.User, Port: yh.SSH.Port},
			Services:             yh.Services,
			Groups:               yh.Groups,
			ProviderFronted:      yh.ProviderFronted,
			Console:              yh.Console,
			ConsoleRecovery:      yh.ConsoleRecovery,
			SPAPort:              yh.SPAPort,
			SPAHTTPPort:          yh.SPAHTTPPort,
			AlwaysAllowIface:     yh.AlwaysAllowIface,
			RecoveryService:      yh.RecoveryService,
			PortRotationDisabled: yh.PortRotation.Disabled,
		}
		host.PortRotation = decodePortRotation(yh.PortRotation.Block, fmt.Sprintf("host %q port_rotation", yh.Name), &errs)
		if err := decodeID(yh.HostID, &host.HostID); err != nil {
			errs.Addf("host %q host_id: %v", yh.Name, err)
		}
		host.HostIdentity.Name = yh.Name
		host.HostIdentity.Alg = identity.Algorithm(yh.HostIdentity.Alg)
		if err := decodeKey(yh.HostIdentity.Signing, &host.HostIdentity.Signing); err != nil {
			errs.Addf("host %q host_identity signing key: %v", yh.Name, err)
		}
		if err := decodeKey(yh.HostIdentity.Encryption, &host.HostIdentity.Encryption); err != nil {
			errs.Addf("host %q host_identity encryption key: %v", yh.Name, err)
		}
		if yh.KnockAddr == "" {
			errs.Addf("host %q has no knock_addr", yh.Name)
		} else if addr, err := netip.ParseAddr(yh.KnockAddr); err != nil {
			// Named explicitly, same as the client's own knock_addr check:
			// this is the address an emergency open dials, and it must be an
			// IP literal so DNS never sits on that path.
			errs.Addf("host %q knock_addr %q is not an IP literal", yh.Name, yh.KnockAddr)
		} else {
			port := host.SPAPort
			if port == 0 {
				port = inv.Defaults.SPAPort
			}
			host.KnockAddr = netip.AddrPortFrom(addr.Unmap(), port)
		}
		inv.Hosts = append(inv.Hosts, host)
	}

	if err := errs.Err(); err != nil {
		return nil, err
	}
	return inv, nil
}

// Host resolves a host by name.
func (inv *Inventory) Host(name string) (*InventoryHost, error) {
	for i := range inv.Hosts {
		if inv.Hosts[i].Name == name {
			return &inv.Hosts[i], nil
		}
	}
	return nil, fmt.Errorf("no host named %q in the inventory", name)
}

// Validate applies the cross-referencing rules that need to see more than one
// declaration at once: every bundle_signers entry resolves to an operator,
// the set is non-empty, host_ids are unique, host names are unique, every
// grant's hosts entries resolve (with "*" always resolving), every host's
// services entries resolve, and every host's encryption key is a usable
// X25519 point. Each rule is its own method so a mutation in one cannot be
// masked by another firing on the same fixture.
func (inv *Inventory) Validate() error {
	var errs ErrorList

	for _, svc := range inv.Services {
		errs.AddAll(svc.Validate())
	}

	inv.validateBundleSignersNonEmpty(&errs)
	inv.validateBundleSignersResolve(&errs)
	inv.validateHostIDsUnique(&errs)
	inv.validateHostNamesUnique(&errs)
	inv.validateGrantHosts(&errs)
	inv.validateHostServices(&errs)
	inv.validateHostEncryptionKeys(&errs)

	return errs.Err()
}

// validateBundleSignersNonEmpty rejects an inventory that can never produce a
// bundle at all: bundle signing authority is transitively door-opening
// authority (design section 6), and a fleet with no signer cannot arm
// anything.
func (inv *Inventory) validateBundleSignersNonEmpty(errs *ErrorList) {
	if len(inv.BundleSigners) == 0 {
		errs.Addf("bundle_signers is empty; no signer means no bundle can ever be produced")
	}
}

// validateBundleSignersResolve rejects a bundle_signers entry naming no
// operator: such a signer's bundles would fail verification against every
// agent that trusts the operator set, discovered at rollout rather than at
// review time.
func (inv *Inventory) validateBundleSignersResolve(errs *ErrorList) {
	operators := map[string]bool{}
	for _, op := range inv.Operators {
		operators[op.Identity.Name] = true
	}
	for _, name := range inv.BundleSigners {
		if !operators[name] {
			errs.Addf("bundle_signers names %q, which is not a declared operator", name)
		}
	}
}

// validateHostIDsUnique rejects two hosts sharing a host_id: host_id is the
// bundle store key, so each would receive the other's bundle from the hub.
func (inv *Inventory) validateHostIDsUnique(errs *ErrorList) {
	seen := map[[16]byte]string{}
	for _, h := range inv.Hosts {
		if prev, dup := seen[h.HostID]; dup {
			errs.Addf("hosts %q and %q share host_id %x", prev, h.Name, h.HostID)
			continue
		}
		seen[h.HostID] = h.Name
	}
}

// validateHostNamesUnique rejects two hosts sharing a name: host names are
// how grants, groups, and the CLI address a host, so a duplicate makes that
// addressing ambiguous.
func (inv *Inventory) validateHostNamesUnique(errs *ErrorList) {
	seen := map[string]bool{}
	for _, h := range inv.Hosts {
		if seen[h.Name] {
			errs.Addf("host %q is defined twice", h.Name)
			continue
		}
		seen[h.Name] = true
	}
}

// validateGrantHosts rejects a grant naming a host that does not exist: a
// typo or a stale entry, and silently granting nothing is how an operator
// discovers at 3am that their key was never on the host. "*" always resolves.
func (inv *Inventory) validateGrantHosts(errs *ErrorList) {
	hostNames := map[string]bool{}
	for _, h := range inv.Hosts {
		hostNames[h.Name] = true
	}
	for _, op := range inv.Operators {
		for _, g := range op.Grants {
			for _, hn := range g.Hosts {
				if hn == "*" {
					continue
				}
				if !hostNames[hn] {
					errs.Addf("operator %q has a grant naming host %q, which is not a declared host", op.Identity.Name, hn)
				}
			}
		}
	}
}

// validateHostServices rejects a host naming a service the fleet does not
// define: it would resolve to a policy with a dangling name.
func (inv *Inventory) validateHostServices(errs *ErrorList) {
	for _, h := range inv.Hosts {
		for _, sn := range h.Services {
			if _, ok := inv.Services[sn]; !ok {
				errs.Addf("host %q names service %q, which is not a declared service", h.Name, sn)
			}
		}
	}
}

// validateHostEncryptionKeys rejects a host_identity.encryption key that is
// not a usable X25519 point. decodeKey above validates only base64 and
// length, so a low-order point — one of the small-order points of Curve25519
// — parses and validates cleanly otherwise, and it is exactly this field that
// bundle.Seal uses as the recipient key when it seals a host's bundle. Left
// unchecked here, the mistake surfaces from bundle.Seal's own defense in
// depth (it returns ErrRecipientKey) — but only per host, in the middle of a
// signing run, rather than once here on the inventory diff. Design section 6
// is explicit that fleet mistakes belong in the diff review, not at rollout.
//
// This runs the same curve25519.X25519 rejection identity.Signer.Precompute
// and bundle.Seal both use, against a random ephemeral scalar: Validate holds
// no private key of its own to reuse, and the scalar's value does not change
// the outcome — clamping makes every X25519 scalar a multiple of the
// cofactor, so the rejection depends on the peer point alone.
func (inv *Inventory) validateHostEncryptionKeys(errs *ErrorList) {
	for _, h := range inv.Hosts {
		var scalar [32]byte
		if _, err := rand.Read(scalar[:]); err != nil {
			errs.Addf("host %q host_identity encryption key: read scalar: %v", h.Name, err)
			continue
		}
		if _, err := curve25519.X25519(scalar[:], h.HostIdentity.Encryption[:]); err != nil {
			errs.Addf("host %q host_identity encryption key is not a usable X25519 point: %v", h.Name, err)
		}
	}
}
