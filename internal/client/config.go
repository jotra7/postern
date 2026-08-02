package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/knockport"
)

// DefaultSPAPort is the port design section 6's example configurations use.
// A host entry may override it; nothing here assumes a well-known port is
// discoverable.
const DefaultSPAPort uint16 = 62201

// DefaultConnectTimeout is how long the confirmation connect waits per
// attempt. Short on purpose: the operator is waiting, and a long timeout
// buys nothing a retry does not.
const DefaultConnectTimeout = 4 * time.Second

// DefaultConnectAttempts is the brief's "short timeout and one retry".
const DefaultConnectAttempts = 2

// SSHTarget is how an operator reaches the host once the gate is open. It is
// recorded so `open` can print the command to run next, and deliberately not
// used as a network address: see the package doc.
type SSHTarget struct {
	Host string `yaml:"host"`
	User string `yaml:"user"`
	Port uint16 `yaml:"port"`
}

// HostService is one gated service as the client knows it: the name that
// hashes to the packet's service_id, and the TCP port the confirmation
// connect targets.
type HostService struct {
	Port uint16        `yaml:"port"`
	TTL  time.Duration `yaml:"-"`
	// RawTTL is the YAML form ("120s"). Parsed into TTL by Load.
	RawTTL string `yaml:"ttl"`
}

// Host is everything the client needs to knock one host without consulting
// anything else — no hub, no resolver, no inventory fetch.
type Host struct {
	Name string `yaml:"name"`
	// RawHostID is 32 hex characters, the same 16 bytes the packet carries.
	RawHostID string `yaml:"host_id"`
	// RawKnockAddr must be an IP literal. See the package doc.
	RawKnockAddr string `yaml:"knock_addr"`
	KnockPort    uint16 `yaml:"knock_port"`
	// RawAlwaysAllowAddr is the host's own address on its always-allow
	// interface, as init-standalone found it there. An IP literal, for the
	// same reason knock_addr is one.
	//
	// knock_addr cannot serve both commands. `open` has to knock the public
	// address, because the gate opens for the source the knock arrived from
	// and an operator who is locked out is on the public path; `status` has to
	// reach the always-allow address, because the agent emits a liveness pong
	// only for a ping that arrived on the always-allow interface and refuses
	// one that did not in silence (design section 7). On a host where those
	// are two addresses, a single field gave an operator a working `open` or a
	// working `status` and never both, which is how this was found on live
	// hardware rather than here.
	//
	// Empty is not an error. It is what every entry written before this field
	// existed says, and what init-standalone writes when it cannot see the
	// interface's addresses; StatusAddr falls back to knock_addr there, which
	// is what standalone and loopback deployments want anyway.
	RawAlwaysAllowAddr string `yaml:"always_allow_addr,omitempty"`
	// KnockHTTPPort is the host's spa_http_port, when it runs the HTTP
	// carrier. Zero means the host entry does not claim one, and
	// `open --carrier http` against it is refused rather than guessed at:
	// there is no well-known port to fall back to, and a knock sent to a
	// guessed port is silence indistinguishable from every other kind.
	KnockHTTPPort uint16 `yaml:"knock_http_port"`
	// RawHostEncryption is the host's X25519 public key, base64. The SPA
	// datagram is sealed to it.
	RawHostEncryption string `yaml:"host_encryption"`
	// RawHostSigning is the host's Ed25519 public key, base64. It verifies
	// the liveness pong, which is the one thing the host ever sends back.
	RawHostSigning  string                 `yaml:"host_signing"`
	RecoveryService string                 `yaml:"recovery_service"`
	SSH             SSHTarget              `yaml:"ssh"`
	Services        map[string]HostService `yaml:"services"`

	// AllowSourceCIDR records what this host's enrollment said about whether
	// the operator holding this entry may assert a source prefix
	// (`open --source-cidr`). The grant itself lives on the host and is not
	// observable from here; this is only what enrollment wrote down.
	//
	// A pointer, because "the entry does not say" is a third state and has to
	// stay distinguishable from an explicit false. It is what a hand-written
	// entry produces, and what init-standalone prints when one host entry is
	// handed to several operators whose grants differ — one document cannot
	// answer for all of them. Advice treats silence as silence rather than as
	// a refusal.
	AllowSourceCIDR *bool `yaml:"allow_source_cidr,omitempty"`

	// RawPortRotation is the rotating-port block, present only on rotation hosts.
	RawPortRotation *rawPortRotation  `yaml:"port_rotation,omitempty"`
	PortRotation    *HostPortRotation `yaml:"-"`

	HostID          [16]byte   `yaml:"-"`
	KnockAddr       netip.Addr `yaml:"-"`
	AlwaysAllowAddr netip.Addr `yaml:"-"`
	HostEncrypt     [32]byte   `yaml:"-"`
	HostSign        [32]byte   `yaml:"-"`
}

// rawPortRotation is port_rotation as it appears in YAML: `port_rotation:
// { secret: <base64>, window: 10m, range: 20000-30000 }`.
type rawPortRotation struct {
	Secret string `yaml:"secret"`
	Window string `yaml:"window"`
	Range  string `yaml:"range"`
}

// HostPortRotation is the resolved form of rawPortRotation: the key and
// parameters CurrentKnockPort needs to compute knockport.Port. Present only
// when the host entry carries a port_rotation block.
type HostPortRotation struct {
	Secret           []byte
	Window           time.Duration
	RangeLo, RangeHi uint16
}

// Config is the operator's local cache: their own identity and every host
// they can knock.
type Config struct {
	Operator string `yaml:"operator"`
	// KeyFile holds the operator's signing and encryption keys. Relative
	// paths resolve against the config file's own directory, so a whole
	// postern directory can be moved or synced as a unit.
	KeyFile string `yaml:"key_file"`
	Hosts   []Host `yaml:"hosts"`

	// CounterFile persists the monotonic SPA counter. Relative paths resolve
	// the same way KeyFile's do. Empty selects "counter.json" beside the
	// config.
	CounterFile string `yaml:"counter_file"`

	dir string
}

// SPAPort is the UDP port the agent binds on this host.
func (h *Host) SPAPort() uint16 {
	if h.KnockPort == 0 {
		return DefaultSPAPort
	}
	return h.KnockPort
}

// KnockAddrPort is where the datagram goes.
func (h *Host) KnockAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(h.KnockAddr, h.SPAPort())
}

// CurrentKnockPort is the single port the client knocks right now: the current
// window's port(w). The client sends one datagram here and does not also knock
// the neighbor windows: the agent holds w and both neighbors live, so this lands
// whenever the two clocks are within about one window, and one packet rather than
// three avoids a burst fingerprint. It reports false on a fixed-port host, whose
// caller uses KnockAddrPort instead.
func (h *Host) CurrentKnockPort(nowUnix int64) (uint16, bool) {
	if h.PortRotation == nil {
		return 0, false
	}
	r := h.PortRotation
	w := knockport.Window(nowUnix, r.Window)
	return knockport.Port(r.Secret, w, r.RangeLo, r.RangeHi), true
}

// StatusAddr is the address `postern status` reaches this host at: the
// always-allow address when the entry records one, and knock_addr when it
// does not.
//
// The fallback is what keeps standalone, loopback and the single-machine e2e
// working, where the two addresses are the same address anyway, and what keeps
// an entry written before always_allow_addr existed usable rather than newly
// broken.
func (h *Host) StatusAddr() netip.Addr {
	if h.AlwaysAllowAddr.IsValid() {
		return h.AlwaysAllowAddr
	}
	return h.KnockAddr
}

// CarrierAddrPort is where the datagram goes for a given carrier.
//
// It refuses rather than defaults when the HTTP carrier is asked for and the
// host entry names no port for it. A default would have to be invented here,
// and an invented port produces a knock that lands nowhere — which on the SPA
// path is indistinguishable from a knock that landed and was rejected, from a
// dead agent, and from a blocked network. An operator during an outage is
// owed the difference.
func (h *Host) CarrierAddrPort(c Carrier) (netip.AddrPort, error) {
	if c != CarrierHTTP {
		return h.KnockAddrPort(), nil
	}
	if h.KnockHTTPPort == 0 {
		return netip.AddrPort{}, fmt.Errorf(
			"host %q has no knock_http_port, so there is no http carrier to knock; "+
				"the host must set spa_http_port and this entry must record it", h.Name)
	}
	return netip.AddrPortFrom(h.KnockAddr, h.KnockHTTPPort), nil
}

// Service resolves a service name to its client-side definition.
func (h *Host) Service(name string) (HostService, error) {
	svc, ok := h.Services[name]
	if !ok {
		return HostService{}, fmt.Errorf("host %q has no service %q configured", h.Name, name)
	}
	return svc, nil
}

// AssertedSourceGrant reports what this entry records about whether the host
// will accept a source prefix asserted by the operator holding it.
func (h *Host) AssertedSourceGrant() AssertedSourceGrant {
	if h == nil || h.AllowSourceCIDR == nil {
		return AssertedSourceUnknown
	}
	if *h.AllowSourceCIDR {
		return AssertedSourceGranted
	}
	return AssertedSourceNotGranted
}

// ConnectAddr is what the confirmation connect dials: knock_addr and the
// service's own port.
//
// Deliberately not the SSH hostname. On a CDN-fronted host that name
// resolves to an edge, so a connect there would report a proxy's behaviour
// rather than the gate's; and resolving any name at all would put DNS on the
// critical path of an emergency open (design section 6).
func (h *Host) ConnectAddr(svc HostService) netip.AddrPort {
	return netip.AddrPortFrom(h.KnockAddr, svc.Port)
}

// ServiceID is the identifier the packet carries for a named service.
func ServiceID(name string) [config.ServiceIDSize]byte {
	return config.Service{Name: name}.ID()
}

// LoadConfig reads and validates an operator config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // reading the operator's own config path is this function's purpose
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve client config path: %w", err)
	}
	cfg.dir = filepath.Dir(abs)
	return cfg, nil
}

// ParseConfig decodes and validates the config bytes. Paths inside it stay
// relative until LoadConfig anchors them.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Deliberately NOT dec.KnownFields(true), and the asymmetry with
	// config.ParseStandalone is the point.
	//
	// This file is derived data: it is copied out of the host's entry.yaml or
	// the fleet inventory, and every field in it describes a capability the
	// host has. An unknown key therefore means "the host that enrolled you is
	// newer than you are" — and refusing to parse turns that into a laptop
	// that cannot knock, during the outage it was kept for.
	//
	// The host's own config keeps KnownFields(true), where a misspelled key
	// does not cost a feature but silently inverts a fail posture.
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("parse client config: empty document")
		}
		return nil, fmt.Errorf("parse client config: %w", err)
	}

	var errs config.ErrorList
	if cfg.Operator == "" {
		errs.Addf("operator is required; it names which identity signs these packets")
	}
	if len(cfg.Hosts) == 0 {
		errs.Addf("no hosts are configured; there is nothing to knock")
	}
	seen := map[string]bool{}
	for i := range cfg.Hosts {
		h := &cfg.Hosts[i]
		if h.Name == "" {
			errs.Addf("hosts[%d] has no name", i)
		}
		if seen[h.Name] {
			errs.Addf("host %q is defined twice", h.Name)
		}
		seen[h.Name] = true
		validateHost(h, &errs)
	}
	if err := errs.Err(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateHost(h *Host, errs *config.ErrorList) {
	if err := decodeHex16(h.RawHostID, &h.HostID); err != nil {
		errs.Addf("host %q host_id: %v", h.Name, err)
	}
	if err := decodeBase64Key(h.RawHostEncryption, &h.HostEncrypt); err != nil {
		errs.Addf("host %q host_encryption: %v", h.Name, err)
	}
	// host_signing is optional: it is only needed to verify a liveness pong,
	// and a host an operator never runs `status` against does not need one.
	// An empty value stays the zero key, and Status's pingOnce refuses to use it.
	if h.RawHostSigning != "" {
		if err := decodeBase64Key(h.RawHostSigning, &h.HostSign); err != nil {
			errs.Addf("host %q host_signing: %v", h.Name, err)
		}
	}

	if h.RawKnockAddr == "" {
		errs.Addf("host %q has no knock_addr", h.Name)
	} else {
		addr, err := netip.ParseAddr(h.RawKnockAddr)
		if err != nil {
			// Named explicitly rather than folded into a parse error, because
			// the reason is the whole point: this runs when the operator is
			// locked out, and a resolver is one of the things that may be
			// down with everything else.
			errs.Addf("host %q knock_addr %q is not an IP literal; postern resolves no names during an "+
				"open, because DNS is on the critical path of nothing that has to work when the mesh is down "+
				"— and on a CDN-fronted host the name resolves to an edge rather than the origin the gate protects",
				h.Name, h.RawKnockAddr)
		} else {
			h.KnockAddr = addr.Unmap()
		}
	}

	// Absence is the documented third state, so only a value that is present
	// and wrong is refused. A name here would be refused for the reason
	// knock_addr's is, with one more on top: `status` is how an operator finds
	// out whether the always-allow path still carries them, and a resolver
	// that answered with yesterday's address would make that check report on
	// an address the host no longer has.
	if h.RawAlwaysAllowAddr != "" {
		addr, err := netip.ParseAddr(h.RawAlwaysAllowAddr)
		if err != nil {
			errs.Addf("host %q always_allow_addr %q is not an IP literal; it is the host's own address on "+
				"its always-allow interface, and postern resolves no names on the path it checks when "+
				"everything else is down", h.Name, h.RawAlwaysAllowAddr)
		} else {
			h.AlwaysAllowAddr = addr.Unmap()
		}
	}

	if len(h.Services) == 0 {
		errs.Addf("host %q has no services; there is nothing to open", h.Name)
	}
	for name, svc := range h.Services {
		if err := config.ValidateServiceName(name); err != nil {
			errs.Addf("host %q service %q: %v", h.Name, name, err)
		}
		if svc.Port == 0 {
			errs.Addf("host %q service %q has no port; the confirmation connect would have nothing to dial", h.Name, name)
		}
		if svc.RawTTL != "" {
			d, err := time.ParseDuration(svc.RawTTL)
			if err != nil {
				errs.Addf("host %q service %q ttl: %v", h.Name, name, err)
			} else {
				svc.TTL = d
			}
		}
		h.Services[name] = svc
	}

	if h.RawPortRotation != nil {
		raw := h.RawPortRotation
		r := &HostPortRotation{}
		secret, err := base64.StdEncoding.DecodeString(raw.Secret)
		if err != nil {
			errs.Addf("host %q port_rotation secret: not base64: %v", h.Name, err)
		} else if len(secret) != knockport.SecretSize {
			errs.Addf("host %q port_rotation secret is %d bytes, want %d", h.Name, len(secret), knockport.SecretSize)
		} else {
			r.Secret = secret
		}
		if raw.Window != "" {
			d, err := time.ParseDuration(raw.Window)
			if err != nil {
				errs.Addf("host %q port_rotation window: %v", h.Name, err)
			} else {
				r.Window = d
			}
		} else {
			r.Window = knockport.DefaultWindow
		}
		if raw.Range != "" {
			before, after, ok := strings.Cut(raw.Range, "-")
			if !ok {
				errs.Addf("host %q port_rotation range %q is not of the form \"lo-hi\"", h.Name, raw.Range)
			} else {
				loN, errLo := strconv.ParseUint(before, 10, 16)
				hiN, errHi := strconv.ParseUint(after, 10, 16)
				if errLo != nil {
					errs.Addf("host %q port_rotation range lo %q: %v", h.Name, before, errLo)
				} else if errHi != nil {
					errs.Addf("host %q port_rotation range hi %q: %v", h.Name, after, errHi)
				} else {
					r.RangeLo, r.RangeHi = uint16(loN), uint16(hiN)
				}
			}
		} else {
			r.RangeLo, r.RangeHi = knockport.DefaultRangeLo, knockport.DefaultRangeHi
		}
		h.PortRotation = r
	}
}

// Host resolves a host by name.
func (c *Config) Host(name string) (*Host, error) {
	for i := range c.Hosts {
		if c.Hosts[i].Name == name {
			return &c.Hosts[i], nil
		}
	}
	return nil, fmt.Errorf("no host named %q in the client config", name)
}

// KeyFilePath is the operator key file, anchored against the config's own
// directory when the configured value is relative.
func (c *Config) KeyFilePath() string {
	return c.anchor(c.KeyFile, "identity.json")
}

// CounterFilePath is the persisted SPA counter, anchored the same way.
func (c *Config) CounterFilePath() string {
	return c.anchor(c.CounterFile, "counter.json")
}

func (c *Config) anchor(p, fallback string) string {
	if p == "" {
		p = fallback
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// SetDir anchors relative paths for a Config that did not come from a file.
func (c *Config) SetDir(dir string) { c.dir = dir }

func decodeHex16(s string, out *[16]byte) error {
	if s == "" {
		return errors.New("missing")
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

func decodeBase64Key(s string, out *[32]byte) error {
	if s == "" {
		return errors.New("missing")
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
