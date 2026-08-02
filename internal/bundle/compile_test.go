package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

// baseInventory is a fleet inventory built directly (not through
// ParseInventory) with two hosts:
//
//   - web-01: no per-host overrides, services [ssh] only — this is the host
//     that proves the fleet's admin gate and its own action services are
//     handled correctly, since it names neither.
//   - db-01: overrides every one of the three overridable defaults
//     (spa_port, always_allow_iface, recovery_service) and carries the
//     fleet's fail-closed admin gate.
//
// freshness_window/freshness_window_max are set away from
// config.DefaultFreshnessWindow/DefaultFreshnessWindowMax on purpose, so a
// test that reads back the resolved default is distinguishable from one that
// silently substituted the package fallback.
func baseInventory() *config.Inventory {
	return &config.Inventory{
		FleetID: [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00},
		Version: 1,
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
				Backend: config.BackendNFTables,
			},
			"admin": {
				Name: "admin", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8443},
				DefaultTTL: 600 * time.Second, MaxTTL: 1800 * time.Second,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
				Backend: config.BackendNFTables,
			},
			"confirm":  {Name: "confirm", Kind: config.KindAction},
			"disarm":   {Name: "disarm", Kind: config.KindAction},
			"liveness": {Name: "liveness", Kind: config.KindAction},
		},
		Defaults: config.InventoryDefaults{
			SPAPort:            62201,
			AlwaysAllowIface:   "tailscale0",
			RecoveryService:    "ssh",
			FreshnessWindow:    45 * time.Second,
			FreshnessWindowMax: 12 * time.Hour,
		},
		Hosts: []config.InventoryHost{
			{
				Name:     "web-01",
				HostID:   [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				Services: []string{"ssh"},
			},
			{
				Name:             "db-01",
				HostID:           [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
				Services:         []string{"ssh", "admin"},
				SPAPort:          62299,
				AlwaysAllowIface: "eth1",
				RecoveryService:  "admin",
			},
		},
	}
}

// inventoryWith builds a fresh baseInventory and applies opts, each of which
// (in this file, only grant) mutates it before it is handed to Compile.
func inventoryWith(t *testing.T, opts ...func(*config.Inventory)) *config.Inventory {
	t.Helper()
	inv := baseInventory()
	for _, opt := range opts {
		opt(inv)
	}
	return inv
}

// identityFor derives a deterministic, distinct PublicIdentity per operator
// name so that two operators in the same test never accidentally collide on
// a signing key — Policy.Validate rejects that collision, which would make
// every multi-operator test in this file fail for the wrong reason.
func identityFor(name string) identity.PublicIdentity {
	var signing, encryption [32]byte
	sigSum := sha256.Sum256([]byte("signing:" + name))
	encSum := sha256.Sum256([]byte("encryption:" + name))
	copy(signing[:], sigSum[:])
	copy(encryption[:], encSum[:])
	return identity.PublicIdentity{
		Name:       name,
		Alg:        identity.AlgEd25519X25519,
		Signing:    signing,
		Encryption: encryption,
	}
}

// grant appends one operator, granted the given services on the given
// hosts, with a permissive-but-valid asserted-source configuration so the
// resulting Policy passes Policy.Validate without every test having to
// restate that boilerplate.
func grant(name string, hostNames, svcNames []string) func(*config.Inventory) {
	return func(inv *config.Inventory) {
		inv.Operators = append(inv.Operators, config.InventoryOperator{
			Identity: identityFor(name),
			Grants: []config.InventoryGrant{
				{
					Hosts:           hostNames,
					Services:        svcNames,
					MaxTTL:          300 * time.Second,
					AllowSourceCIDR: true,
					MinIPv4Prefix:   24,
					MinIPv6Prefix:   64,
				},
			},
		})
	}
}

func hosts(names ...string) []string    { return names }
func services(names ...string) []string { return names }

func assertHasOperator(t *testing.T, p *config.Policy, name string) {
	t.Helper()
	for _, op := range p.Operators {
		if op.Identity.Name == name {
			return
		}
	}
	t.Errorf("compiled policy has no operator %q; want it present", name)
}

func assertNotHasOperator(t *testing.T, p *config.Policy, name string) {
	t.Helper()
	for _, op := range p.Operators {
		if op.Identity.Name == name {
			t.Errorf("compiled policy has operator %q; want it absent", name)
			return
		}
	}
}

// firstGrant returns the first grant of the named operator, failing the test
// if that operator or a grant of theirs is missing.
func firstGrant(t *testing.T, p *config.Policy, opName string) config.Grant {
	t.Helper()
	for _, op := range p.Operators {
		if op.Identity.Name == opName {
			if len(op.Grants) == 0 {
				t.Fatalf("operator %q has no grants", opName)
			}
			return op.Grants[0]
		}
	}
	t.Fatalf("no operator named %q in compiled policy", opName)
	return config.Grant{}
}

// The central property: a host receives exactly the operators granted to
// it, and no others. A grant leaking across hosts is a key on a machine the
// operator never authorised, which no amount of downstream checking
// recovers from — the agent believes its own policy.
func TestBundle_Compile_GivesAHostOnlyItsOwnGrants(t *testing.T) {
	inv := inventoryWith(t,
		grant("laptop", hosts("*"), services("ssh")),
		grant("contractor", hosts("web-01"), services("ssh")),
	)
	web, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile web-01: %v", err)
	}
	db, err := bundle.Compile(inv, "db-01")
	if err != nil {
		t.Fatalf("compile db-01: %v", err)
	}
	assertHasOperator(t, web, "laptop")
	assertHasOperator(t, web, "contractor")
	assertHasOperator(t, db, "laptop")
	assertNotHasOperator(t, db, "contractor") // the whole test
}

// A host's policy carries only the services that host lists, not the whole
// fleet's catalogue. Otherwise every host arms a drop rule for every port
// any host in the fleet gates, and a fail-closed admin service defined for
// one host silently blackholes 8443 on all of them.
func TestBundle_Compile_CarriesOnlyTheHostsOwnServices(t *testing.T) {
	inv := inventoryWith(t)
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, ok := p.Services["admin"]; ok {
		t.Error(`Services["admin"] present; web-01 does not list admin`)
	}
	got, ok := p.Services["ssh"]
	if !ok {
		t.Fatal(`Services["ssh"] missing; web-01 does list ssh`)
	}
	if diff := cmp.Diff(inv.Services["ssh"], got); diff != "" {
		t.Errorf("Services[ssh] copied with changed fields (-want +got):\n%s", diff)
	}
}

// Action services (confirm, disarm, liveness) are fleet-wide: they have no
// ports to own, and a host that cannot be confirmed can never complete an
// arm. web-01's own services list names none of them, so this is the one
// test that would fail if the fleet-wide action loop were deleted — a
// fixture that already listed them on every host could not tell the
// difference.
func TestBundle_Compile_CarriesFleetWideActionServicesRegardlessOfHostList(t *testing.T) {
	inv := inventoryWith(t)
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, name := range []string{"confirm", "disarm", "liveness"} {
		if _, ok := p.Services[name]; !ok {
			t.Errorf("Services[%q] missing; action services are fleet-wide regardless of the host's own list", name)
		}
	}
}

// Per-host overrides beat fleet defaults; absent overrides inherit. Checked
// both ways: web-01 declares no overrides and must land on the fleet
// defaults, db-01 overrides all three overridable fields and must land on
// its own values instead.
func TestBundle_Compile_HostOverridesBeatDefaults(t *testing.T) {
	inv := inventoryWith(t)

	web, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile web-01: %v", err)
	}
	if web.SPAPort != inv.Defaults.SPAPort {
		t.Errorf("web-01 SPAPort = %d, want the fleet default %d", web.SPAPort, inv.Defaults.SPAPort)
	}
	if web.AlwaysAllowIface != inv.Defaults.AlwaysAllowIface {
		t.Errorf("web-01 AlwaysAllowIface = %q, want the fleet default %q", web.AlwaysAllowIface, inv.Defaults.AlwaysAllowIface)
	}
	if web.RecoveryService != inv.Defaults.RecoveryService {
		t.Errorf("web-01 RecoveryService = %q, want the fleet default %q", web.RecoveryService, inv.Defaults.RecoveryService)
	}

	db, err := bundle.Compile(inv, "db-01")
	if err != nil {
		t.Fatalf("compile db-01: %v", err)
	}
	if db.SPAPort != 62299 {
		t.Errorf("db-01 SPAPort = %d, want its own override 62299", db.SPAPort)
	}
	if db.AlwaysAllowIface != "eth1" {
		t.Errorf("db-01 AlwaysAllowIface = %q, want its own override eth1", db.AlwaysAllowIface)
	}
	if db.RecoveryService != "admin" {
		t.Errorf("db-01 RecoveryService = %q, want its own override admin", db.RecoveryService)
	}
}

// #49. A host running the HTTP carrier sets spa_http_port, and Compile must
// carry it into the bundle. A compiled policy with spa_http_port 0 for a host
// whose running config has it non-zero is refused by the agent's
// carrier-port-unchanged guard on every pull (checkCarrierPortsUnchanged),
// permanently killing that host's bundle plane. The default and the per-host
// override both have to reach the compiled policy.
func TestBundle_Compile_CarriesTheHTTPCarrierPort(t *testing.T) {
	inv := baseInventory()
	inv.Defaults.SPAHTTPPort = 62443
	inv.Hosts[1].SPAHTTPPort = 62444 // db-01 overrides the fleet default

	web, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile web-01: %v", err)
	}
	if web.SPAHTTPPort != 62443 {
		t.Fatalf("web-01 SPAHTTPPort = %d, want the fleet default 62443; a bundle that carries 0 is "+
			"refused by the carrier-port guard on a host that runs the HTTP carrier", web.SPAHTTPPort)
	}

	db, err := bundle.Compile(inv, "db-01")
	if err != nil {
		t.Fatalf("compile db-01: %v", err)
	}
	if db.SPAHTTPPort != 62444 {
		t.Fatalf("db-01 SPAHTTPPort = %d, want its own override 62444", db.SPAHTTPPort)
	}
}

// FleetID, HostID, and the freshness window pair have no per-host override in
// the inventory schema: they are copied straight through from the inventory
// and the host record. Distinct, non-default values in the fixture (neither
// config.DefaultFreshnessWindow nor DefaultFreshnessWindowMax) make this
// test fail if Compile ever forgot to set one of them — a round trip through
// MarshalStandalone/ParseStandalone alone would not catch that, since an
// un-set zero value marshals and parses back just as consistently as a real
// one.
func TestBundle_Compile_MapsScalarFleetFields(t *testing.T) {
	inv := inventoryWith(t)
	host, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if p.FleetID != inv.FleetID {
		t.Errorf("FleetID = %x, want the inventory's %x", p.FleetID, inv.FleetID)
	}
	if p.HostID != host.HostID {
		t.Errorf("HostID = %x, want the host's own %x", p.HostID, host.HostID)
	}
	if p.FreshnessWindow != inv.Defaults.FreshnessWindow {
		t.Errorf("FreshnessWindow = %s, want the fleet default %s", p.FreshnessWindow, inv.Defaults.FreshnessWindow)
	}
	if p.FreshnessWindowMax != inv.Defaults.FreshnessWindowMax {
		t.Errorf("FreshnessWindowMax = %s, want the fleet default %s", p.FreshnessWindowMax, inv.Defaults.FreshnessWindowMax)
	}
}

// Revision is the bundle version. Design section 5 makes the confirm
// packet's pending_revision mode-independent, and in fleet mode it is the
// inventory's version — so a compiled policy that dropped it would make
// every fleet confirm name revision 0.
func TestBundle_Compile_RevisionIsTheInventoryVersion(t *testing.T) {
	inv := inventoryWith(t)
	inv.Version = 47
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if p.Revision != 47 {
		t.Errorf("Revision = %d, want the inventory version 47", p.Revision)
	}
}

// A grant naming a service the host does not carry must be narrowed down to
// the services the host actually has, not carried inert — otherwise
// `postern status` would show an operator holding access that resolves to
// nothing on this host.
func TestBundle_Compile_NarrowsGrantServicesToWhatHostCarries(t *testing.T) {
	inv := inventoryWith(t, grant("laptop", hosts("*"), services("ssh", "admin")))
	p, err := bundle.Compile(inv, "web-01") // web-01 lists ssh only, not admin
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	g := firstGrant(t, p, "laptop")
	want := []string{"ssh"}
	if !slices.Equal(g.Services, want) {
		t.Errorf("Grant.Services = %v, want %v (admin narrowed away; web-01 does not carry it)", g.Services, want)
	}
}

// A grant left with no surviving services after narrowing must be dropped
// entirely, not carried as an empty-but-present grant: an operator whose
// only granted service the host doesn't have is not authorised for anything
// here.
func TestBundle_Compile_DropsGrantEntirelyWhenNoServicesSurviveNarrowing(t *testing.T) {
	inv := inventoryWith(t, grant("admin-only", hosts("*"), services("admin")))
	p, err := bundle.Compile(inv, "web-01") // web-01 does not carry admin at all
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	assertNotHasOperator(t, p, "admin-only")
}

// A surviving grant's other fields (MaxTTL, AllowSourceCIDR, and critically
// both address-family prefix minimums independently) must pass through
// unchanged. config.Grant.AllowsSource checks whichever prefix field matches
// a packet's address family, so a fixture that only ever set one of the two
// to a nonzero value could not tell the difference if the other were
// silently dropped to zero.
func TestBundle_Compile_PreservesGrantFieldsVerbatim(t *testing.T) {
	inv := inventoryWith(t, grant("laptop", hosts("*"), services("ssh")))
	inv.Operators[0].Grants[0].MaxTTL = 123 * time.Second
	inv.Operators[0].Grants[0].AllowSourceCIDR = true
	inv.Operators[0].Grants[0].MinIPv4Prefix = 20
	inv.Operators[0].Grants[0].MinIPv6Prefix = 100

	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	g := firstGrant(t, p, "laptop")
	if g.MaxTTL != 123*time.Second {
		t.Errorf("MaxTTL = %s, want 123s", g.MaxTTL)
	}
	if !g.AllowSourceCIDR {
		t.Error("AllowSourceCIDR = false, want true")
	}
	if g.MinIPv4Prefix != 20 {
		t.Errorf("MinIPv4Prefix = %d, want 20", g.MinIPv4Prefix)
	}
	if g.MinIPv6Prefix != 100 {
		t.Errorf("MinIPv6Prefix = %d, want 100 (must survive independently of MinIPv4Prefix)", g.MinIPv6Prefix)
	}
}

// Operators come out sorted by name. A fixture whose grants happen to be
// declared in alphabetical order could never tell a real sort from a missing
// one, so this test declares them out of order on purpose.
func TestBundle_Compile_SortsOperatorsAlphabetically(t *testing.T) {
	inv := inventoryWith(t,
		grant("zzz-last", hosts("*"), services("ssh")),
		grant("aaa-first", hosts("*"), services("ssh")),
		grant("mmm-middle", hosts("*"), services("ssh")),
	)
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var names []string
	for _, op := range p.Operators {
		names = append(names, op.Identity.Name)
	}
	want := []string{"aaa-first", "mmm-middle", "zzz-last"}
	if !slices.Equal(names, want) {
		t.Errorf("Operators in order %v, want alphabetical %v", names, want)
	}
}

// Host matching is "*" or an exact name — no globbing, no regex. A grant
// naming "web-*" must not match "web-01": a pattern language here is a way
// to grant an operator's key to a host nobody meant to name, in a file whose
// whole review model is humans reading diffs.
func TestBundle_Compile_HostMatchDoesNotGlob(t *testing.T) {
	inv := inventoryWith(t, grant("wildcard-attempt", hosts("web-*"), services("ssh")))
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	assertNotHasOperator(t, p, "wildcard-attempt")
}

// Compiling a host that is not in the inventory is an operator typo, and it
// must not produce an empty-but-valid policy — a host armed with no
// operators is a host nobody can knock.
func TestBundle_Compile_RejectsAnUnknownHost(t *testing.T) {
	_, err := bundle.Compile(inventoryWith(t), "no-such-host")
	if err == nil {
		t.Fatal("Compile(no-such-host) = nil error, want a not-found error")
	}
}

// A host naming a service the fleet does not define must be rejected by
// Compile itself, not just by Inventory.Validate: Compile is handed a
// *config.Inventory directly and cannot assume Validate ever ran on it.
//
// This checks the specific "is not defined" message Compile's own guard
// produces, not merely that some error came back: a zero-value config.Service
// stored under the dangling name would still eventually trip
// Policy.Validate's unrelated map-key/kind checks and return a non-nil error
// of its own, which would let this test pass even if Compile's own guard
// were deleted — asserting the message is what actually exercises that line.
func TestBundle_Compile_RejectsHostNamingAnUndeclaredService(t *testing.T) {
	inv := inventoryWith(t)
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	h.Services = append(h.Services, "no-such-service")
	_, err = bundle.Compile(inv, "web-01")
	if err == nil {
		t.Fatal("Compile accepted a host naming a service the fleet does not define")
	}
	if !strings.Contains(err.Error(), `"no-such-service" is not defined`) {
		t.Fatalf("Compile() err = %v, want it to name the undefined service", err)
	}
}

// Compiling is a way to produce configuration, not a way around the rules
// that make configuration safe: a resolved policy whose fail-closed gate has
// no resolvable recovery_service must be rejected here exactly as
// Policy.Validate would reject it directly.
func TestBundle_Compile_RejectsWhenResolvedPolicyFailsValidate(t *testing.T) {
	inv := inventoryWith(t)
	inv.Defaults.RecoveryService = ""
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	h.Services = append(h.Services, "admin") // now web-01 carries a fail-closed gate
	_, err = bundle.Compile(inv, "web-01")
	if err == nil {
		t.Fatal("Compile accepted a fail-closed gate with no resolvable recovery_service")
	}
}

// A host that has declared console_recovery and a console route compiles to
// a Policy with no always_allow_iface at all — the one case
// Policy.Validate accepts an empty iface, because the operator has
// acknowledged the out-of-band console as the last resort. Compile must
// carry ConsoleRecovery and Console through and must not refuse the missing
// iface itself; that call belongs to Policy.Validate alone.
func TestBundle_Compile_ConsoleRecoveryHostNeedsNoAlwaysAllowIface(t *testing.T) {
	inv := inventoryWith(t)
	inv.Defaults.AlwaysAllowIface = "" // no fleet-wide fallback either
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	h.ConsoleRecovery = true
	h.Console = "https://provider.example/instances/web-01/console"

	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !p.ConsoleRecovery {
		t.Error("ConsoleRecovery = false, want true")
	}
	if p.Console != "https://provider.example/instances/web-01/console" {
		t.Errorf("Console = %q, want the host's console URL", p.Console)
	}
	if p.AlwaysAllowIface != "" {
		t.Errorf("AlwaysAllowIface = %q, want empty (console-recovery is the acknowledged path)", p.AlwaysAllowIface)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("compiled console-recovery policy fails Policy.Validate: %v", err)
	}
}

// A host with neither an always_allow_iface (from itself or the fleet
// default) nor console_recovery must still be refused at compile time: the
// two are the only routes Policy.Validate accepts, and dropping both leaves
// a host with no way in once fail-closed rules land.
func TestBundle_Compile_RejectsNoIfaceAndNoConsoleRecovery(t *testing.T) {
	inv := inventoryWith(t)
	inv.Defaults.AlwaysAllowIface = ""
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	h.ConsoleRecovery = false
	h.Console = ""

	_, err = bundle.Compile(inv, "web-01")
	if err == nil {
		t.Fatal("Compile accepted a host with no always_allow_iface and no console_recovery")
	}
}

// A host with no per-host port_rotation block inherits the fleet's
// defaults.port_rotation verbatim.
func TestBundle_Compile_InheritsDefaultsPortRotationWhenHostHasNoOverride(t *testing.T) {
	inv := inventoryWith(t)
	inv.Defaults.PortRotation = &config.PortRotation{
		Secret:  bytes.Repeat([]byte{0xab}, 32),
		Window:  10 * time.Minute,
		RangeLo: 20000,
		RangeHi: 30000,
	}
	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if diff := cmp.Diff(inv.Defaults.PortRotation, p.PortRotation); diff != "" {
		t.Errorf("PortRotation not inherited from defaults (-want +got):\n%s", diff)
	}
}

// A host declaring port_rotation: disabled opts out of the fleet default
// entirely: the compiled policy carries no rotation at all, falling back to
// the host's ordinary fixed spa_port, which Compile must still carry through
// untouched.
func TestBundle_Compile_HostPortRotationDisabledOverridesFleetDefault(t *testing.T) {
	inv := inventoryWith(t)
	inv.Defaults.PortRotation = &config.PortRotation{
		Secret:  bytes.Repeat([]byte{0xab}, 32),
		Window:  10 * time.Minute,
		RangeLo: 20000,
		RangeHi: 30000,
	}
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	h.PortRotationDisabled = true

	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if p.PortRotation != nil {
		t.Errorf("PortRotation = %+v, want nil: the host disabled fleet rotation", p.PortRotation)
	}
	if p.SPAPort != inv.Defaults.SPAPort {
		t.Errorf("SPAPort = %d, want the fleet default %d intact", p.SPAPort, inv.Defaults.SPAPort)
	}
}

// The third branch resolvePortRotation has to choose between: a host with
// its own port_rotation block gets that block, not the fleet default, even
// though the fleet default is also set and would otherwise be a valid
// choice. TestBundle_Compile_InheritsDefaultsPortRotationWhenHostHasNoOverride
// covers "no override" and TestBundle_Compile_HostPortRotationDisabledOverridesFleetDefault
// covers "opted out"; this is the third state neither of those exercises.
func TestBundle_Compile_HostPortRotationOverridesFleetDefault(t *testing.T) {
	inv := inventoryWith(t)
	inv.Defaults.PortRotation = &config.PortRotation{
		Secret:  bytes.Repeat([]byte{0xab}, 32),
		Window:  10 * time.Minute,
		RangeLo: 20000,
		RangeHi: 30000,
	}
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	h.PortRotation = &config.PortRotation{
		Secret:  bytes.Repeat([]byte{0xcd}, 32),
		Window:  5 * time.Minute,
		RangeLo: 21000,
		RangeHi: 22000,
	}

	p, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if diff := cmp.Diff(h.PortRotation, p.PortRotation); diff != "" {
		t.Errorf("PortRotation did not take the host's own block (-want +got):\n%s", diff)
	}
	if cmp.Diff(inv.Defaults.PortRotation, p.PortRotation) == "" {
		t.Fatal("compiled PortRotation equals the fleet default; this fixture does not actually " +
			"exercise the host's own override winning")
	}
}

// The compiled policy must survive the same validation a standalone policy
// does. Compiling is a way to produce configuration, not a way around the
// rules that make configuration safe — most sharply, that a fail-closed
// service cannot be armed with no recovery_service set.
func TestBundle_Compile_OutputPassesPolicyValidate(t *testing.T) {
	p, err := bundle.Compile(inventoryWith(t), "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("compiled policy fails Policy.Validate: %v", err)
	}
}

// And it must survive the marshal/parse round trip, since that is how it
// actually reaches the agent. This is the test that catches a field Compile
// sets and MarshalStandalone forgets.
//
// cmpopts.EquateEmpty is required here for a reason that has nothing to do
// with Compile: action services (confirm/disarm/liveness) legitimately have
// a nil Ports slice (Service.Validate rejects a nonzero one for an action),
// and yaml.v3 marshals a nil []uint16 the same way it marshals an empty one
// ("[]"), then unmarshals that back as a non-nil, zero-length slice. Compile
// cannot avoid this — it copies the service through unchanged — and a
// zero-length slice means exactly the same thing operationally as a nil one
// (no ports), so equating them here asserts what actually matters instead of
// an accident of the YAML library's round trip.
func TestBundle_Compile_SurvivesTheTripThroughYAML(t *testing.T) {
	want, err := bundle.Compile(inventoryWith(t), "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	data, err := config.MarshalStandalone(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := config.ParseStandalone(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("(-compiled +round-tripped):\n%s", diff)
	}
}

// The same round trip, but with operators and grants actually populated —
// the empty-operators case above cannot exercise operator/grant field
// mapping (Signing/Encryption keys, both prefix minimums, MaxTTL) at all,
// since there is nothing there to lose.
func TestBundle_Compile_SurvivesTheTripThroughYAMLWithGrants(t *testing.T) {
	inv := inventoryWith(t,
		grant("laptop", hosts("*"), services("ssh")),
		grant("contractor", hosts("web-01"), services("ssh")),
	)
	want, err := bundle.Compile(inv, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	data, err := config.MarshalStandalone(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := config.ParseStandalone(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("(-compiled +round-tripped):\n%s", diff)
	}
}

// Two `postern sign` runs over an unchanged inventory must produce
// byte-identical policy bytes, whatever order the inventory happened to
// declare things in — and however Go's map iteration comes out on the day.
//
// This is not tidiness. config_hash in every heartbeat is a sha256 of exactly
// these bytes (see agent.Daemon.configHash), so a compile that is stable only
// by luck makes a fleet look like it is drifting every time a host restarts,
// which is the one signal an operator would use to find real drift.
//
// The declared order is reversed between the two inventories, because that is
// the input the sorting exists for and the round-trip tests above never
// varied. Repeating the marshal is the other half, and it is a different
// question: Compile writes into maps, so the same *Policy must still produce
// the same bytes however those maps are walked.
//
// Two independent controls hold the first half up — Compile sorts p.Operators
// and config.MarshalStandalone sorts them again — so this asserts the
// property rather than either control, and removing either one alone leaves
// it passing. That redundancy is deliberate and worth keeping; what is not
// acceptable is nothing checking the property they exist for.
// TestBundle_Compile_SortsOperatorsAlphabetically is what isolates Compile's
// own sort.
//
// Mutation verified: removing BOTH sorts fails this on the reversed-inventory
// half, with the two policies differing in operator order.
func TestBundle_Compile_ProducesByteIdenticalPolicyBytesWhateverTheDeclaredOrder(t *testing.T) {
	forward := inventoryWith(t,
		grant("aaa-first", hosts("*"), services("ssh")),
		grant("mmm-middle", hosts("*"), services("ssh")),
		grant("zzz-last", hosts("*"), services("ssh")),
	)
	reversed := inventoryWith(t,
		grant("zzz-last", hosts("*"), services("ssh")),
		grant("mmm-middle", hosts("*"), services("ssh")),
		grant("aaa-first", hosts("*"), services("ssh")),
	)
	if forward.Operators[0].Identity.Name == reversed.Operators[0].Identity.Name {
		t.Fatal("the two fixtures declare operators in the same order; this test asserts nothing")
	}

	compileAndMarshal := func(inv *config.Inventory) []byte {
		t.Helper()
		p, err := bundle.Compile(inv, "web-01")
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		data, err := config.MarshalStandalone(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return data
	}

	a := compileAndMarshal(forward)
	b := compileAndMarshal(reversed)
	if !bytes.Equal(a, b) {
		t.Fatalf("two inventories differing only in declaration order compiled to different bytes; "+
			"config_hash would report drift on every re-sign\n--- forward ---\n%s\n--- reversed ---\n%s", a, b)
	}

	// And the same *Policy marshals the same way every time, which the pair
	// above cannot show: both halves of it could walk one map identically by
	// coincidence within a single process.
	p, err := bundle.Compile(forward, "web-01")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	first, err := config.MarshalStandalone(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 32; i++ {
		again, err := config.MarshalStandalone(p)
		if err != nil {
			t.Fatalf("marshal #%d: %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("marshal #%d of the same compiled policy differs from the first; config_hash is "+
				"then a fact about map iteration rather than about this host's configuration", i)
		}
	}
}
