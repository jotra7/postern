package config_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// forwardGate is a valid forwarded path, which each test below then breaks in
// exactly one way, so a refusal is attributable to the rule under test rather
// than to some other field the fixture happened to leave wrong.
//
// The external port (2222) and the internal one (22) differ, and so do the
// postern box's role and the target's: nothing in this fixture would still
// read correctly if the two ends of the path were transposed.
func forwardGate() config.Service {
	return config.Service{
		Name:                "dbhost",
		Kind:                config.KindGate,
		Proto:               "tcp",
		Ports:               []uint16{2222},
		DefaultTTL:          120 * time.Second,
		MaxTTL:              300 * time.Second,
		FailPosture:         config.PostureClosed,
		ListenerExpectation: config.ListenerUnchecked,
		Backend:             config.BackendNFTables,
		Forward:             &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 22},
	}
}

func TestConfig_ServiceValidate_AcceptsAForwardedGate(t *testing.T) {
	if err := forwardGate().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// The posture refusal, which is the one this feature turns on. A forwarded path
// exists only because postern's own DNAT rule creates it, so the agent's death
// either takes the path away, which is not what "open" means anywhere else in
// postern, or leaves an unauthenticated route to the internal machine standing.
func TestConfig_ServiceValidate_RejectsAForwardDeclaredFailOpen(t *testing.T) {
	svc := forwardGate()
	svc.FailPosture = config.PostureOpen

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a fail-open forward")
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Errorf("refusal does not say which posture a forward has: %v", err)
	}
	if !strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("refusal does not name what would be left exposed: %v", err)
	}
}

// Pre-arm probes this host. Nothing listens on a forward's external port here
// by design, and what does listen is on a machine pre-arm cannot see, so
// "present" would block arming forever and "absent" would pass while asserting
// nothing about the path.
func TestConfig_ServiceValidate_RejectsAForwardDeclaringALocalListener(t *testing.T) {
	for _, expectation := range []config.ListenerExpectation{config.ListenerPresent, config.ListenerAbsent} {
		t.Run(string(expectation), func(t *testing.T) {
			svc := forwardGate()
			svc.ListenerExpectation = expectation
			// verification stays empty. A tcp_rst declaration would be refused
			// by the existing verification/listener_expectation rule as well,
			// and a refusal two rules agree on cannot show that this one works.

			err := svc.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a forward with listener_expectation %q", expectation)
			}
			if !strings.Contains(err.Error(), "listener_expectation") {
				t.Errorf("refusal does not name the field: %v", err)
			}
			if !strings.Contains(err.Error(), "10.0.0.5") {
				t.Errorf("refusal does not say where the listener actually is: %v", err)
			}
		})
	}
}

// A service on another backend generates no nftables rules at all, so it would
// generate no DNAT rule: a forward in name with nothing to make it one. This is
// also refused by the script backend's own fail_posture rule, since a forward
// resolves closed, so the assertion is on this refusal's own wording rather
// than on there being an error.
func TestConfig_ServiceValidate_RejectsAForwardOnAnotherBackend(t *testing.T) {
	svc := forwardGate()
	svc.Backend = config.BackendScript
	svc.ScriptPath = "/opt/postern/perimeter.sh"
	svc.ScriptTimeout = 15 * time.Second

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a forward on the script backend")
	}
	if !strings.Contains(err.Error(), "DNAT") {
		t.Errorf("refusal does not name the mechanism a forward needs and this backend does not build: %v", err)
	}
}

// Each target refusal has its own reason, and the loopback one is not tidiness:
// a packet translated to a loopback address becomes locally destined, so it
// never traverses the forward hook where this service's drop rule lives, and it
// arrives instead at a local port under some other service's posture and grant.
func TestConfig_ServiceValidate_RejectsUnroutableForwardTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		to   netip.Addr
		want string
	}{
		{"missing", netip.Addr{}, "no target address"},
		// Unique-local rather than link-local on purpose. A zoned link-local
		// address is refused by two rules, and a refusal two rules agree on
		// cannot show that the zone rule works.
		{"zoned", netip.MustParseAddr("fd00::5%eth0"), "zone"},
		{"unspecified v4", netip.MustParseAddr("0.0.0.0"), "unspecified"},
		{"unspecified v6", netip.MustParseAddr("::"), "unspecified"},
		{"loopback v4", netip.MustParseAddr("127.0.0.1"), "locally destined"},
		{"loopback v6", netip.MustParseAddr("::1"), "locally destined"},
		{"multicast", netip.MustParseAddr("239.1.2.3"), "multicast"},
		{"link local v4", netip.MustParseAddr("169.254.1.2"), "link-local"},
		{"link local v6", netip.MustParseAddr("fe80::1"), "link-local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := forwardGate()
			svc.Forward = &config.Forward{To: tc.to, Port: 22}

			err := svc.Validate()
			if err == nil {
				t.Fatalf("Validate accepted forward target %v", tc.to)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal for %v does not say %q: %v", tc.to, tc.want, err)
			}
		})
	}
}

func TestConfig_ServiceValidate_RejectsAForwardWithNoTargetPort(t *testing.T) {
	svc := forwardGate()
	svc.Forward = &config.Forward{To: netip.MustParseAddr("10.0.0.5")}

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a forward with no target port")
	}
	if !strings.Contains(err.Error(), "no port") {
		t.Errorf("refusal does not name the missing port: %v", err)
	}
}

func TestConfig_ServiceValidate_RejectsAForwardWithSeveralExternalPorts(t *testing.T) {
	svc := forwardGate()
	svc.Ports = []uint16{2222, 2223}

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a forward with two external ports")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("refusal does not say how many a forward has: %v", err)
	}
}

func TestConfig_ServiceValidate_RejectsAnActionDeclaringAForward(t *testing.T) {
	svc := config.Service{
		Name:    "confirm",
		Kind:    config.KindAction,
		Forward: &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 22},
	}

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted an action declaring a forward")
	}
	if !strings.Contains(err.Error(), "may not declare forward") {
		t.Errorf("refusal does not name the field: %v", err)
	}
}

// I7 one hop further in. Two forwards on different external ports pointing at
// one internal target write identical accept and drop rules into the forward
// chain, because both are written against the target the packet carries after
// translation, and one service's drop is terminal ahead of the other's accept.
func TestConfig_PolicyValidate_RejectsTwoForwardsOnOneInternalTarget(t *testing.T) {
	p := forwardPolicy(t)
	second := forwardGate()
	second.Name = "dbhost-alt"
	second.Ports = []uint16{2223}
	second.Forward = &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 22}
	p.Services["dbhost-alt"] = second

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted two forwards onto one internal target")
	}
	if !strings.Contains(err.Error(), "10.0.0.5:22") {
		t.Errorf("refusal does not name the contested target: %v", err)
	}

	// A second forward to a DIFFERENT internal target on the same machine is
	// fine, so the rule is about the target and not about having two forwards.
	second.Forward = &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 5432}
	p.Services["dbhost-alt"] = second
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate refused two forwards onto distinct targets: %v", err)
	}
}

// A forward's external port is a port on this host like any other, so it joins
// the one-owner-per-(backend, proto, port) rule rather than sitting outside it.
func TestConfig_PolicyValidate_RejectsALocalGateClaimingAForwardsExternalPort(t *testing.T) {
	p := forwardPolicy(t)
	p.Services["admin"] = config.Service{
		Name: "admin", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{2222},
		DefaultTTL: 10 * time.Second, MaxTTL: 20 * time.Second,
		FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
		Backend: config.BackendNFTables,
	}

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted a local gate on a forward's external port")
	}
	if !strings.Contains(err.Error(), "tcp/2222") {
		t.Errorf("refusal does not name the contested port: %v", err)
	}
}

// forwardPolicy is a minimal valid policy carrying one forwarded path. A
// forward is fail-closed, so recovery_service is required and names an
// ordinary local gate.
func forwardPolicy(t *testing.T) *config.Policy {
	t.Helper()
	return &config.Policy{
		SPAPort:            62201,
		AlwaysAllowIface:   "tailscale0",
		RecoveryService:    "ssh",
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 24 * time.Hour,
		MaxOperators:       config.DefaultMaxOperators,
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
				Backend: config.BackendNFTables,
			},
			"dbhost": forwardGate(),
		},
	}
}

// forwardYAML declares one forwarded path and one ordinary local gate, with
// dbhost named in breakglass_services on purpose: that list is what would
// otherwise resolve this service to fail_posture: open, straight into the
// refusal above.
const forwardYAML = `
fleet_id: 000102030405060708090a0b0c0d0e0f
host_id: 100102030405060708090a0b0c0d0e0f
spa_port: 62201
always_allow_iface: tailscale0
recovery_service: ssh
breakglass_services: [ssh, dbhost]
services:
  ssh:
    kind: gate
    proto: tcp
    ports: [22]
    default_ttl: 120s
    max_ttl: 300s
  dbhost:
    kind: gate
    proto: tcp
    ports: [2222]
    default_ttl: 120s
    max_ttl: 300s
    forward:
      to: 10.0.0.5
      port: 22
operators:
  - name: laptop
    alg: ed25519+x25519
    signing: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
    encryption: ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
    grants:
      - services: [ssh, dbhost]
        max_ttl: 300s
`

// The whole configuration shape in one assertion: an operator writes an
// internal target in the host's own file, and it arrives on the resolved
// service. The packet never sees it, and there is nothing on the wire it
// could arrive from.
func TestConfig_ParseStandalone_ReadsAForwardsTargetFromTheHostFile(t *testing.T) {
	p, err := config.ParseStandalone([]byte(forwardYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	fwd := p.Services["dbhost"].Forward
	if fwd == nil {
		t.Fatal("dbhost resolved with no forward")
	}
	if fwd.To.String() != "10.0.0.5" {
		t.Errorf("forward target = %s, want 10.0.0.5", fwd.To)
	}
	if fwd.Port != 22 {
		t.Errorf("forward target port = %d, want 22", fwd.Port)
	}
	if got := p.Services["dbhost"].Ports; len(got) != 1 || got[0] != 2222 {
		t.Errorf("external ports = %v, want [2222]; the external port is this host's, not the target's", got)
	}
	if p.Services["ssh"].Forward != nil {
		t.Errorf("a service that declared no forward resolved with one: %+v", p.Services["ssh"].Forward)
	}
}

// breakglass_services names dbhost, and a forward still resolves closed.
// Resolving it open would default it straight into the refusal above, which is
// a resolver telling operators to write a word that changes nothing.
func TestConfig_ParseStandalone_ResolvesAForwardClosedDespiteBreakglass(t *testing.T) {
	p, err := config.ParseStandalone([]byte(forwardYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if got := p.Services["dbhost"].FailPosture; got != config.PostureClosed {
		t.Errorf("forward fail_posture = %q, want %q", got, config.PostureClosed)
	}
	// The same breakglass list still resolves an ordinary gate to open, so the
	// override is the forward's and not breakglass having stopped working.
	if got := p.Services["ssh"].FailPosture; got != config.PostureOpen {
		t.Errorf("breakglass ssh fail_posture = %q, want %q", got, config.PostureOpen)
	}
}

// A gate defaults to listener_expectation: present, and a forward must not,
// because pre-arm would then go looking on this host for a socket the design
// says will not be there.
func TestConfig_ParseStandalone_ResolvesAForwardToAnUncheckedListener(t *testing.T) {
	p, err := config.ParseStandalone([]byte(forwardYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if got := p.Services["dbhost"].ListenerExpectation; got != config.ListenerUnchecked {
		t.Errorf("forward listener_expectation = %q, want %q", got, config.ListenerUnchecked)
	}
	if got := p.Services["ssh"].ListenerExpectation; got != config.ListenerPresent {
		t.Errorf("local gate listener_expectation = %q, want %q", got, config.ListenerPresent)
	}
}

// The whole document a forward appears in must validate, or the shape is
// declarable and unusable.
func TestConfig_ParseStandalone_AForwardedHostValidates(t *testing.T) {
	p, err := config.ParseStandalone([]byte(forwardYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// A hostname here would put DNS between a knock and the address a packet is
// translated to, and would make the target something a resolver answers for
// rather than something this host's configuration states.
func TestConfig_ParseStandalone_RejectsAForwardTargetThatIsNotAnIPLiteral(t *testing.T) {
	bad := strings.Replace(forwardYAML, "to: 10.0.0.5", "to: db.internal.example.com", 1)

	_, err := config.ParseStandalone([]byte(bad))
	if err == nil {
		t.Fatal("ParseStandalone accepted a hostname as a forward target")
	}
	if !strings.Contains(err.Error(), "IP literal") {
		t.Errorf("refusal does not say what a target must be: %v", err)
	}
}

// Host config parsing is strict, and a misspelled key inside a forward block
// would drop the target and leave a service that opens this host's own port
// instead of the path an operator wrote.
func TestConfig_ParseStandalone_RejectsAMisspelledForwardKey(t *testing.T) {
	bad := strings.Replace(forwardYAML, "      port: 22", "      prot: 22", 1)

	_, err := config.ParseStandalone([]byte(bad))
	if err == nil {
		t.Fatal("ParseStandalone accepted an unknown key inside a forward block")
	}
}

// The fleet parser and the standalone parser share decodeService, and this
// holds them to it. A forward that resolved in one and not the other would be
// an operator's declaration silently dropped on the fleet path: the compiled
// bundle would still parse, validate, and run, with the host opening its own
// external port instead of the path the inventory diff was reviewed for.
func TestConfig_ParseInventory_ReadsAForwardsTarget(t *testing.T) {
	inv, err := config.ParseInventory([]byte(strings.Replace(validInventory,
		"  mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }",
		"  mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }\n"+
			"  dbhost:   { kind: gate, proto: tcp, ports: [2222], default_ttl: 120s, max_ttl: 300s, forward: { to: 10.0.0.5, port: 22 } }",
		1)))
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}
	svc := inv.Services["dbhost"]
	if svc.Forward == nil {
		t.Fatal("the fleet parser dropped the forward block")
	}
	if svc.Forward.To.String() != "10.0.0.5" || svc.Forward.Port != 22 {
		t.Fatalf("fleet-parsed forward target is %s:%d, want 10.0.0.5:22", svc.Forward.To, svc.Forward.Port)
	}
	if svc.FailPosture != config.PostureClosed {
		t.Errorf("fleet-parsed forward fail_posture = %q, want %q", svc.FailPosture, config.PostureClosed)
	}
	if svc.ListenerExpectation != config.ListenerUnchecked {
		t.Errorf("fleet-parsed forward listener_expectation = %q, want %q", svc.ListenerExpectation, config.ListenerUnchecked)
	}
}
