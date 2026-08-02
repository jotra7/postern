package config_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// validInventory is a fleet inventory that parses and validates cleanly,
// built to exercise every field ParseInventory maps and every rule
// Inventory.Validate checks: two hosts (one taking the fleet's default
// spa_port, one overriding it and every other per-host default), an operator
// granted by exact host name rather than "*", and a gate service
// (mgmt) that leaves listener_expectation and fail_posture to be resolved
// rather than declaring them, exercising the gate-defaulting branch neither
// ssh, canary, nor admin exercise (each of those declares its own).
//
// freshness_window/freshness_window_max are set away from
// DefaultFreshnessWindow/DefaultFreshnessWindowMax on purpose, so a test
// substituting them away and one asserting the explicit value are actually
// distinguishable from the parser's fallback.
const validInventory = `
fleet_id: "0102030405060708090a0b0c0d0e0f10"
version: 47

bundle_signers: [laptop-primary]

operators:
  - name: laptop-primary
    alg: ed25519+x25519
    signing:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    encryption: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    grants:
      - hosts: ["*"]
        services: ["ssh", "confirm", "disarm", "liveness"]
        max_ttl: 300s
        allow_source_cidr: true
        min_ipv4_prefix: 24
        min_ipv6_prefix: 64
  - name: probe-01
    alg: ed25519+x25519
    signing:    "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    encryption: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
    grants: [{ hosts: ["*"], services: ["canary"], max_ttl: 30s }]
  - name: liveness-peer-01
    alg: ed25519+x25519
    signing:    "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
    encryption: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="
    grants: [{ hosts: ["*"], services: ["liveness"], max_ttl: 30s }]
  - name: admin-op
    alg: ed25519+x25519
    signing:    "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY="
    encryption: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    grants: [{ hosts: ["web-02"], services: ["admin"], max_ttl: 600s }]

breakglass_services: [ssh]

services:
  ssh:      { kind: gate, proto: tcp, ports: [22],    default_ttl: 120s, max_ttl: 300s,  listener_expectation: present }
  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s,  max_ttl: 60s,   listener_expectation: absent, verification: tcp_rst }
  admin:    { kind: gate, proto: tcp, ports: [8443],  default_ttl: 600s, max_ttl: 1800s, listener_expectation: unchecked, fail_posture: open }
  mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }
  confirm:  { kind: action }
  disarm:   { kind: action }
  liveness: { kind: action }

defaults:
  spa_port: 62201
  spa_http_port: 62443
  always_allow_iface: tailscale0
  recovery_service: ssh
  freshness_window: 45s
  freshness_window_max: 12h

hosts:
  - name: web-01
    host_id: "1112131415161718191a1b1c1d1e1f20"
    knock_addr: 203.0.113.9
    ssh: { host: web-01.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="
      encryption: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="
    services: [ssh, canary]
    groups: [prod, cdn-fronted]
    provider_fronted: true
    console: "https://provider.example/instances/web-01/console"
  - name: web-02
    host_id: "2122232425262728292a2b2c2d2e2f30"
    knock_addr: 203.0.113.10
    spa_port: 62299
    spa_http_port: 62444
    always_allow_iface: eth1
    recovery_service: admin
    ssh: { host: web-02.example.com, user: ops, port: 2222 }
    host_identity:
      alg: ed25519+x25519
      signing:    "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo="
      encryption: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws="
    services: [ssh, admin]
    groups: [prod]
    provider_fronted: false
    console: "https://provider.example/instances/web-02/console"
`

func mustParseInventory(t *testing.T, data []byte) *config.Inventory {
	t.Helper()
	inv, err := config.ParseInventory(data)
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}
	return inv
}

// inventoryFixture derives a variant of validInventory by replacing one
// occurrence of `from` with `to`, the same strings.Replace idiom
// resolve_test.go's validStandalone-derived fixtures use.
func inventoryFixture(t *testing.T, from, to string) []byte {
	t.Helper()
	if !strings.Contains(validInventory, from) {
		t.Fatalf("inventoryFixture: %q not found in validInventory", from)
	}
	return []byte(strings.Replace(validInventory, from, to, 1))
}

func exampleInventory(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../examples/inventory.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	return data
}

// assertSomeOperatorIsGranted fails unless some operator holds a grant
// naming service.
func assertSomeOperatorIsGranted(t *testing.T, inv *config.Inventory, service string) {
	t.Helper()
	for _, op := range inv.Operators {
		for _, g := range op.Grants {
			for _, s := range g.Services {
				if s == service {
					return
				}
			}
		}
	}
	t.Fatalf("no operator is granted %q; the shipped example cannot exercise it", service)
}

// The shipped example is the thing most operators will copy. Section 6 of the
// design calls out that an example missing the probe operator or the liveness
// grant ships a fleet that cannot verify itself and cannot arm a fail-closed
// service — the exact failure the project exists to prevent, arriving through
// the examples rather than the code.
func TestConfig_ParseInventory_ShippedExampleIsUsable(t *testing.T) {
	data, err := os.ReadFile("../../examples/inventory.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	inv, err := config.ParseInventory(data)
	if err != nil {
		t.Fatalf("the shipped example does not parse: %v", err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("the shipped example does not validate: %v", err)
	}
	assertSomeOperatorIsGranted(t, inv, "canary")
	assertSomeOperatorIsGranted(t, inv, "liveness")
}

// A bundle signer that is not an operator has no key to verify against, so
// the agent would reject every bundle it signed — a fleet that cannot be
// deployed to, discovered at rollout rather than at review time.
func TestConfig_ParseInventory_RejectsAnUnknownBundleSigner(t *testing.T) {
	data := inventoryFixture(t, "bundle_signers: [laptop-primary]",
		"bundle_signers: [laptop-primary, nobody-by-that-name]")
	inv := mustParseInventory(t, data)
	if err := inv.Validate(); err == nil {
		t.Fatal("accepted a bundle_signer naming no operator")
	}
}

// Section 6: bundle signing authority is transitively door-opening authority.
// An inventory with no signer at all cannot produce a bundle, and saying so
// at parse time beats a confusing failure inside `postern sign`.
func TestConfig_ParseInventory_RejectsAnEmptySignerSet(t *testing.T) {
	data := inventoryFixture(t, "bundle_signers: [laptop-primary]", "bundle_signers: []")
	inv := mustParseInventory(t, data)
	if err := inv.Validate(); err == nil {
		t.Fatal("accepted an inventory with no bundle signers")
	}
}

// Two hosts sharing a host_id would each receive the other's bundle from the
// hub, since host_id is the store key.
func TestConfig_ParseInventory_RejectsDuplicateHostIDs(t *testing.T) {
	data := inventoryFixture(t,
		`host_id: "2122232425262728292a2b2c2d2e2f30"`,
		`host_id: "1112131415161718191a1b1c1d1e1f20"`)
	inv := mustParseInventory(t, data)
	err := inv.Validate()
	if err == nil {
		t.Fatal("accepted two hosts sharing a host_id")
	}
	if !strings.Contains(err.Error(), "share host_id") {
		t.Fatalf("Validate() = %v, want it to name the shared host_id", err)
	}
}

// Grants name hosts. A grant naming a host that does not exist is either a
// typo or a stale entry, and silently granting nothing is how an operator
// discovers at 3am that their key was never on the host.
func TestConfig_ParseInventory_RejectsAGrantNamingAnUnknownHost(t *testing.T) {
	data := inventoryFixture(t, `grants: [{ hosts: ["web-02"], services: ["admin"], max_ttl: 600s }]`,
		`grants: [{ hosts: ["web-99"], services: ["admin"], max_ttl: 600s }]`)
	inv := mustParseInventory(t, data)
	err := inv.Validate()
	if err == nil {
		t.Fatal("accepted a grant naming a host that does not exist")
	}
	if !strings.Contains(err.Error(), `"web-99"`) {
		t.Fatalf("Validate() = %v, want it to name the unknown host", err)
	}
}

// A host listing a service the fleet does not define resolves to a policy
// with a dangling name.
func TestConfig_ParseInventory_RejectsAHostNamingAnUnknownService(t *testing.T) {
	data := inventoryFixture(t, "services: [ssh, admin]", "services: [ssh, no-such-service]")
	inv := mustParseInventory(t, data)
	err := inv.Validate()
	if err == nil {
		t.Fatal("accepted a host naming a service that does not exist")
	}
	if !strings.Contains(err.Error(), `"no-such-service"`) {
		t.Fatalf("Validate() = %v, want it to name the unknown service", err)
	}
}

// Host names address a host from grants, groups, and the CLI; a duplicate
// makes that addressing ambiguous, the same failure family as duplicate
// host_ids but keyed on the human name instead of the store key.
func TestConfig_ParseInventory_RejectsDuplicateHostNames(t *testing.T) {
	data := inventoryFixture(t, "name: web-02", "name: web-01")
	inv := mustParseInventory(t, data)
	err := inv.Validate()
	if err == nil {
		t.Fatal("accepted two hosts sharing a name")
	}
	if !strings.Contains(err.Error(), `"web-01" is defined twice`) {
		t.Fatalf("Validate() = %v, want it to report web-01 defined twice", err)
	}
}

// Service.Name is load-bearing, not decorative: Service.ID() is
// sha256(Name)[:16], and that ID is what a packet's service_id names. The
// services block is a YAML map, so the name lives in the key and nothing
// fills the struct field automatically — leave it unset and every service in
// the fleet hashes to the same ID.
func TestConfig_ParseInventory_SetsServiceNameFromTheMapKey(t *testing.T) {
	inv := mustParseInventory(t, exampleInventory(t))
	for key, svc := range inv.Services {
		if svc.Name != key {
			t.Errorf("services[%q].Name = %q; service_id would be sha256(%q)", key, svc.Name, svc.Name)
		}
	}
}

// The baseline fixture is otherwise-valid on purpose: it is the positive
// control every rejection test above mutates away from, and it alone
// exercises two behaviours no rejection test can: that "*" actually resolves
// as a wildcard (three operators here grant on "*", and no host is literally
// named "*"), and that a grant naming a real, declared host validates clean
// (admin-op names "web-02" exactly).
func TestConfig_ParseInventory_ValidFixtureParsesAndValidates(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	if err := inv.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestConfig_ParseInventory_MapsTopLevelFields(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	want := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	if inv.FleetID != want {
		t.Errorf("FleetID = %x, want %x", inv.FleetID, want)
	}
	if inv.Version != 47 {
		t.Errorf("Version = %d, want 47", inv.Version)
	}
	if len(inv.BundleSigners) != 1 || inv.BundleSigners[0] != "laptop-primary" {
		t.Errorf("BundleSigners = %v, want [laptop-primary]", inv.BundleSigners)
	}
}

func TestConfig_ParseInventory_MapsDefaultsFields(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	d := inv.Defaults
	if d.SPAPort != 62201 {
		t.Errorf("Defaults.SPAPort = %d, want 62201", d.SPAPort)
	}
	if d.SPAHTTPPort != 62443 {
		t.Errorf("Defaults.SPAHTTPPort = %d, want 62443; without it a fleet host running the HTTP "+
			"carrier gets bundles carrying 0 and refuses them all", d.SPAHTTPPort)
	}
	if d.AlwaysAllowIface != "tailscale0" {
		t.Errorf("Defaults.AlwaysAllowIface = %q, want tailscale0", d.AlwaysAllowIface)
	}
	if d.RecoveryService != "ssh" {
		t.Errorf("Defaults.RecoveryService = %q, want ssh", d.RecoveryService)
	}
	// 45s/12h, not DefaultFreshnessWindow/DefaultFreshnessWindowMax (60s/24h):
	// pins that the explicit value is actually carried through rather than
	// the fallback silently winning.
	if d.FreshnessWindow != 45*time.Second {
		t.Errorf("Defaults.FreshnessWindow = %s, want 45s", d.FreshnessWindow)
	}
	if d.FreshnessWindowMax != 12*time.Hour {
		t.Errorf("Defaults.FreshnessWindowMax = %s, want 12h", d.FreshnessWindowMax)
	}
}

func TestConfig_ParseInventory_DefaultsFreshnessFallsBackWhenEmpty(t *testing.T) {
	data := inventoryFixture(t, "  freshness_window: 45s\n", "")
	inv := mustParseInventory(t, data)
	if inv.Defaults.FreshnessWindow != config.DefaultFreshnessWindow {
		t.Errorf("Defaults.FreshnessWindow = %s, want the default %s", inv.Defaults.FreshnessWindow, config.DefaultFreshnessWindow)
	}
}

func TestConfig_ParseInventory_RejectsMalformedDefaultsFreshnessWindow(t *testing.T) {
	data := inventoryFixture(t, "freshness_window: 45s", "freshness_window: not-a-duration")
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "defaults.freshness_window") {
		t.Fatalf("ParseInventory() = %v, want it to name defaults.freshness_window", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedDefaultsFreshnessWindowMax(t *testing.T) {
	data := inventoryFixture(t, "freshness_window_max: 12h", "freshness_window_max: not-a-duration")
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "defaults.freshness_window_max") {
		t.Fatalf("ParseInventory() = %v, want it to name defaults.freshness_window_max", err)
	}
}

func TestConfig_ParseInventory_MapsServiceFields(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))

	ssh := inv.Services["ssh"]
	if ssh.Kind != config.KindGate {
		t.Errorf("ssh.Kind = %q, want gate", ssh.Kind)
	}
	if ssh.Proto != "tcp" {
		t.Errorf("ssh.Proto = %q, want tcp", ssh.Proto)
	}
	if len(ssh.Ports) != 1 || ssh.Ports[0] != 22 {
		t.Errorf("ssh.Ports = %v, want [22]", ssh.Ports)
	}
	if ssh.DefaultTTL != 120*time.Second {
		t.Errorf("ssh.DefaultTTL = %s, want 120s", ssh.DefaultTTL)
	}
	if ssh.MaxTTL != 300*time.Second {
		t.Errorf("ssh.MaxTTL = %s, want 300s", ssh.MaxTTL)
	}
	if ssh.ListenerExpectation != config.ListenerPresent {
		t.Errorf("ssh.ListenerExpectation = %q, want present", ssh.ListenerExpectation)
	}
	// ssh is in breakglass_services: fail_posture defaults open.
	if ssh.FailPosture != config.PostureOpen {
		t.Errorf("ssh.FailPosture = %q, want open", ssh.FailPosture)
	}

	canary := inv.Services["canary"]
	if canary.ListenerExpectation != config.ListenerAbsent {
		t.Errorf("canary.ListenerExpectation = %q, want absent", canary.ListenerExpectation)
	}
	if canary.Verification != config.VerificationTCPRST {
		t.Errorf("canary.Verification = %q, want tcp_rst", canary.Verification)
	}
	// canary is not in breakglass_services: fail_posture defaults closed.
	if canary.FailPosture != config.PostureClosed {
		t.Errorf("canary.FailPosture = %q, want closed", canary.FailPosture)
	}

	// admin explicitly declares fail_posture: open even though it is not in
	// breakglass_services, so the resolved default (closed, same as mgmt
	// below) would be wrong here: this is what pins that an explicit
	// fail_posture is carried through as-is rather than always being
	// overwritten by the gate-defaulting branch.
	admin := inv.Services["admin"]
	if admin.FailPosture != config.PostureOpen {
		t.Errorf("admin.FailPosture = %q, want the explicitly declared open", admin.FailPosture)
	}

	// mgmt declares neither listener_expectation nor fail_posture: this is
	// the one service in the fixture that exercises the gate-defaulting
	// branch (present / closed) rather than an explicit value.
	mgmt := inv.Services["mgmt"]
	if mgmt.ListenerExpectation != config.ListenerPresent {
		t.Errorf("mgmt.ListenerExpectation = %q, want the resolved default present", mgmt.ListenerExpectation)
	}
	if mgmt.FailPosture != config.PostureClosed {
		t.Errorf("mgmt.FailPosture = %q, want the resolved default closed", mgmt.FailPosture)
	}

	confirm := inv.Services["confirm"]
	if confirm.Kind != config.KindAction {
		t.Errorf("confirm.Kind = %q, want action", confirm.Kind)
	}
	// Actions never go through the gate-defaulting branch: nothing should
	// have filled these in.
	if confirm.FailPosture != "" {
		t.Errorf("confirm.FailPosture = %q, want empty (actions are not defaulted)", confirm.FailPosture)
	}
	if confirm.ListenerExpectation != "" {
		t.Errorf("confirm.ListenerExpectation = %q, want empty (actions are not defaulted)", confirm.ListenerExpectation)
	}
}

// Companion to the explicit-empty-list test below: when breakglass_services
// is absent from the document entirely (not merely an empty list), ssh gets
// the hidden default of fail_posture open. A fixture that always writes
// breakglass_services (even as "[]") can never distinguish "absent" from
// "explicitly empty", since yaml.v3 decodes those to a nil slice and a
// non-nil zero-length slice respectively — this is the one test that removes
// the key altogether.
func TestConfig_ParseInventory_AbsentBreakglassServicesDefaultsSSHOpen(t *testing.T) {
	data := inventoryFixture(t, "breakglass_services: [ssh]\n\n", "")
	inv := mustParseInventory(t, data)
	if got := inv.Services["ssh"].FailPosture; got != config.PostureOpen {
		t.Fatalf("ssh.FailPosture = %q, want open: an absent breakglass_services key gets the hidden ssh default", got)
	}
}

func TestConfig_ParseInventory_ExplicitEmptyBreakglassOverridesHiddenDefault(t *testing.T) {
	data := inventoryFixture(t, "breakglass_services: [ssh]", "breakglass_services: []")
	inv := mustParseInventory(t, data)
	if got := inv.Services["ssh"].FailPosture; got != config.PostureClosed {
		t.Fatalf("ssh.FailPosture = %q, want closed: breakglass_services: [] explicitly declares no breakglass services", got)
	}
}

func TestConfig_ParseInventory_RejectsMalformedServiceDefaultTTL(t *testing.T) {
	data := inventoryFixture(t,
		"mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }",
		"mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: not-a-duration,  max_ttl: 120s }")
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "mgmt.default_ttl") {
		t.Fatalf("ParseInventory() = %v, want it to name mgmt.default_ttl", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedServiceMaxTTL(t *testing.T) {
	data := inventoryFixture(t,
		"mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }",
		"mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: not-a-duration }")
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "mgmt.max_ttl") {
		t.Fatalf("ParseInventory() = %v, want it to name mgmt.max_ttl", err)
	}
}

func TestConfig_ParseInventory_MapsOperatorIdentityFields(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	var laptop *config.InventoryOperator
	for i := range inv.Operators {
		if inv.Operators[i].Identity.Name == "laptop-primary" {
			laptop = &inv.Operators[i]
		}
	}
	if laptop == nil {
		t.Fatal("no operator named laptop-primary")
	}
	if laptop.Identity.Alg != "ed25519+x25519" {
		t.Errorf("Identity.Alg = %q, want ed25519+x25519", laptop.Identity.Alg)
	}
	wantSigning := [32]byte{}
	wantEncryption := [32]byte{}
	for i := range wantEncryption {
		wantEncryption[i] = 0x01
	}
	if laptop.Identity.Signing != wantSigning {
		t.Errorf("Identity.Signing = %x, want all-zero", laptop.Identity.Signing)
	}
	if laptop.Identity.Encryption != wantEncryption {
		t.Errorf("Identity.Encryption = %x, want all-0x01", laptop.Identity.Encryption)
	}
}

func TestConfig_ParseInventory_RejectsMalformedOperatorSigningKey(t *testing.T) {
	data := inventoryFixture(t,
		`signing:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`,
		`signing:    "not-base64!!"`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "laptop-primary") {
		t.Fatalf("ParseInventory() = %v, want it to name the operator with the bad signing key", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedOperatorEncryptionKey(t *testing.T) {
	data := inventoryFixture(t,
		`encryption: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="`,
		`encryption: "not-base64!!"`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "laptop-primary") {
		t.Fatalf("ParseInventory() = %v, want it to name the operator with the bad encryption key", err)
	}
}

// This is the grant the coordinator specifically flagged: min_ipv6_prefix
// must survive independently of min_ipv4_prefix. config.Grant.AllowsSource
// checks whichever field matches a packet's address family, so a test that
// only ever reads MinIPv4Prefix would not notice MinIPv6Prefix silently
// dropping to zero.
func TestConfig_ParseInventory_MapsGrantFields(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	var laptop *config.InventoryOperator
	for i := range inv.Operators {
		if inv.Operators[i].Identity.Name == "laptop-primary" {
			laptop = &inv.Operators[i]
		}
	}
	if laptop == nil || len(laptop.Grants) != 1 {
		t.Fatalf("fixture precondition failed: laptop-primary grants = %+v", laptop)
	}
	g := laptop.Grants[0]
	if len(g.Hosts) != 1 || g.Hosts[0] != "*" {
		t.Errorf("Grant.Hosts = %v, want [*]", g.Hosts)
	}
	wantServices := []string{"ssh", "confirm", "disarm", "liveness"}
	if !slices.Equal(g.Services, wantServices) {
		t.Errorf("Grant.Services = %v, want %v", g.Services, wantServices)
	}
	if g.MaxTTL != 300*time.Second {
		t.Errorf("Grant.MaxTTL = %s, want 300s", g.MaxTTL)
	}
	if !g.AllowSourceCIDR {
		t.Error("Grant.AllowSourceCIDR = false, want true")
	}
	if g.MinIPv4Prefix != 24 {
		t.Errorf("Grant.MinIPv4Prefix = %d, want 24", g.MinIPv4Prefix)
	}
	if g.MinIPv6Prefix != 64 {
		t.Errorf("Grant.MinIPv6Prefix = %d, want 64", g.MinIPv6Prefix)
	}
}

func TestConfig_ParseInventory_RejectsMalformedGrantMaxTTL(t *testing.T) {
	data := inventoryFixture(t, "max_ttl: 600s", "max_ttl: not-a-duration")
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "admin-op.max_ttl") {
		t.Fatalf("ParseInventory() = %v, want it to name admin-op.max_ttl", err)
	}
}

func TestConfig_ParseInventory_MapsHostFields(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	h, err := inv.Host("web-02")
	if err != nil {
		t.Fatalf("Host(web-02): %v", err)
	}
	if h.Name != "web-02" {
		t.Errorf("Name = %q, want web-02", h.Name)
	}
	wantHostID := [16]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30}
	if h.HostID != wantHostID {
		t.Errorf("HostID = %x, want %x", h.HostID, wantHostID)
	}
	if h.SSH.Host != "web-02.example.com" {
		t.Errorf("SSH.Host = %q, want web-02.example.com", h.SSH.Host)
	}
	if h.SSH.User != "ops" {
		t.Errorf("SSH.User = %q, want ops", h.SSH.User)
	}
	if h.SSH.Port != 2222 {
		t.Errorf("SSH.Port = %d, want 2222", h.SSH.Port)
	}
	if h.HostIdentity.Name != "web-02" {
		t.Errorf("HostIdentity.Name = %q, want web-02 (the host's own name)", h.HostIdentity.Name)
	}
	if h.HostIdentity.Alg != "ed25519+x25519" {
		t.Errorf("HostIdentity.Alg = %q, want ed25519+x25519", h.HostIdentity.Alg)
	}
	wantSigning := [32]byte{}
	wantEncryption := [32]byte{}
	for i := range wantSigning {
		wantSigning[i] = 0x0a
		wantEncryption[i] = 0x0b
	}
	if h.HostIdentity.Signing != wantSigning {
		t.Errorf("HostIdentity.Signing = %x, want %x", h.HostIdentity.Signing, wantSigning)
	}
	if h.HostIdentity.Encryption != wantEncryption {
		t.Errorf("HostIdentity.Encryption = %x, want %x", h.HostIdentity.Encryption, wantEncryption)
	}
	wantServices := []string{"ssh", "admin"}
	if !slices.Equal(h.Services, wantServices) {
		t.Errorf("Services = %v, want %v", h.Services, wantServices)
	}
	wantGroups := []string{"prod"}
	if !slices.Equal(h.Groups, wantGroups) {
		t.Errorf("Groups = %v, want %v", h.Groups, wantGroups)
	}
	if h.ProviderFronted {
		t.Error("ProviderFronted = true, want false")
	}
	if h.Console != "https://provider.example/instances/web-02/console" {
		t.Errorf("Console = %q", h.Console)
	}
	if h.SPAPort != 62299 {
		t.Errorf("SPAPort override = %d, want 62299", h.SPAPort)
	}
	if h.SPAHTTPPort != 62444 {
		t.Errorf("SPAHTTPPort override = %d, want 62444", h.SPAHTTPPort)
	}
	if h.AlwaysAllowIface != "eth1" {
		t.Errorf("AlwaysAllowIface override = %q, want eth1", h.AlwaysAllowIface)
	}
	if h.RecoveryService != "admin" {
		t.Errorf("RecoveryService override = %q, want admin", h.RecoveryService)
	}

	// web-01 carries provider_fronted: true, the opposite of web-02, so this
	// field's mapping is checked both ways.
	h1, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	if !h1.ProviderFronted {
		t.Error("web-01 ProviderFronted = false, want true")
	}
	// web-01 declares none of the three per-host overrides: they must stay
	// at the zero value, "take the fleet default".
	if h1.SPAPort != 0 || h1.SPAHTTPPort != 0 || h1.AlwaysAllowIface != "" || h1.RecoveryService != "" {
		t.Errorf("web-01 overrides = %+v, want all zero (no overrides declared)", h1)
	}
}

func TestConfig_ParseInventory_RejectsMalformedHostID(t *testing.T) {
	data := inventoryFixture(t, `host_id: "2122232425262728292a2b2c2d2e2f30"`, `host_id: "not-hex"`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "web-02") {
		t.Fatalf("ParseInventory() = %v, want it to name web-02", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedHostIdentitySigningKey(t *testing.T) {
	data := inventoryFixture(t,
		`signing:    "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo="`,
		`signing:    "not-base64!!"`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "web-02") {
		t.Fatalf("ParseInventory() = %v, want it to name web-02", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedHostIdentityEncryptionKey(t *testing.T) {
	data := inventoryFixture(t,
		`encryption: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws="`,
		`encryption: "not-base64!!"`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "web-02") {
		t.Fatalf("ParseInventory() = %v, want it to name web-02", err)
	}
}

func TestConfig_ParseInventory_ResolvesKnockAddrPortFromHostOverride(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	h, err := inv.Host("web-02")
	if err != nil {
		t.Fatalf("Host(web-02): %v", err)
	}
	if h.KnockAddr.Port() != 62299 {
		t.Errorf("web-02 KnockAddr port = %d, want the host's own spa_port override 62299", h.KnockAddr.Port())
	}
	if h.KnockAddr.Addr().String() != "203.0.113.10" {
		t.Errorf("web-02 KnockAddr addr = %s, want 203.0.113.10", h.KnockAddr.Addr())
	}
}

func TestConfig_ParseInventory_ResolvesKnockAddrPortFromFleetDefault(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	// web-01 declares no spa_port override, so its knock port must come from
	// defaults.spa_port (62201), not from web-02's 62299 or a zero value.
	if h.KnockAddr.Port() != inv.Defaults.SPAPort {
		t.Errorf("web-01 KnockAddr port = %d, want the fleet default %d", h.KnockAddr.Port(), inv.Defaults.SPAPort)
	}
}

// The parser unmaps an IPv4-mapped IPv6 literal, the same way
// internal/client's own knock_addr handling does: without it, an operator
// who wrote "::ffff:203.0.113.9" instead of the plain v4 form would silently
// get a different (if numerically equivalent) address in KnockAddr.
func TestConfig_ParseInventory_UnmapsIPv4MappedKnockAddr(t *testing.T) {
	data := inventoryFixture(t, "knock_addr: 203.0.113.9", "knock_addr: ::ffff:203.0.113.9")
	inv := mustParseInventory(t, data)
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	if h.KnockAddr.Addr().String() != "203.0.113.9" {
		t.Errorf("KnockAddr address = %s, want the unmapped 203.0.113.9", h.KnockAddr.Addr())
	}
	if h.KnockAddr.Addr().Is4In6() {
		t.Error("KnockAddr address is still 4-in-6 form; Unmap did not run")
	}
}

func TestConfig_ParseInventory_RejectsMissingKnockAddr(t *testing.T) {
	data := inventoryFixture(t, `knock_addr: 203.0.113.9`, `knock_addr: ""`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "no knock_addr") {
		t.Fatalf("ParseInventory() = %v, want an error naming the missing knock_addr", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedKnockAddr(t *testing.T) {
	data := inventoryFixture(t, "knock_addr: 203.0.113.9", "knock_addr: not-an-ip")
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "not an IP literal") {
		t.Fatalf("ParseInventory() = %v, want an error naming the malformed knock_addr", err)
	}
}

func TestConfig_ParseInventory_RejectsMalformedFleetID(t *testing.T) {
	data := inventoryFixture(t, `fleet_id: "0102030405060708090a0b0c0d0e0f10"`, `fleet_id: "not-hex"`)
	_, err := config.ParseInventory(data)
	if err == nil || !strings.Contains(err.Error(), "fleet_id") {
		t.Fatalf("ParseInventory() = %v, want an error naming fleet_id", err)
	}
}

func TestConfig_ParseInventory_RejectsEmptyDocument(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"empty", ""},
		{"comment only", "# just a comment\n"},
		{"whitespace only", "   \n\n  \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.ParseInventory([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), "empty document") {
				t.Fatalf("ParseInventory(%q) = %v, want an error naming an empty document", tc.yaml, err)
			}
		})
	}
}

// This is host-adjacent configuration reviewed in diffs (not the client's
// derived cache), so it keeps KnownFields(true): a misspelled key here can
// silently drop a grant or invert a posture, and must be a parse error rather
// than a silently-ignored key.
func TestConfig_ParseInventory_RejectsUnknownFieldTypo(t *testing.T) {
	data := inventoryFixture(t, "knock_addr: 203.0.113.9", "knock_adrr: 203.0.113.9")
	_, err := config.ParseInventory(data)
	if err == nil {
		t.Fatal("ParseInventory() = nil error, want a rejection of the unknown field")
	}
	if !strings.Contains(err.Error(), "field knock_adrr not found") {
		t.Fatalf("ParseInventory() = %v, want it to name the unknown field", err)
	}
}

// defaults.port_rotation is an ordinary *yamlPortRotation pointer field, the
// same non-polymorphic shape yamlStandalone's port_rotation has (see
// TestConfig_ParseStandalone_RejectsUnknownPortRotationFieldTypo): it needs
// no custom UnmarshalYAML, so it inherits Decoder.KnownFields(true) through
// the normal recursive-struct decode path. A typo'd key inside the block
// must still be a parse error.
func TestConfig_ParseInventory_RejectsUnknownDefaultsPortRotationFieldTypo(t *testing.T) {
	data := inventoryFixture(t, "  freshness_window_max: 12h\n",
		"  freshness_window_max: 12h\n"+
			"  port_rotation: { secret: \"3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0=\", window: 45s, rnge: 20000-30000 }\n")
	_, err := config.ParseInventory(data)
	if err == nil {
		t.Fatal("ParseInventory() = nil error, want a rejection of the unknown field")
	}
	if !strings.Contains(err.Error(), "field rnge not found") {
		t.Fatalf("ParseInventory() = %v, want it to name the unknown field", err)
	}
}

func TestConfig_InventoryHost_ResolvesByName(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	if h.Name != "web-01" {
		t.Errorf("Host(web-01).Name = %q, want web-01", h.Name)
	}
}

func TestConfig_InventoryHost_RejectsUnknownName(t *testing.T) {
	inv := mustParseInventory(t, []byte(validInventory))
	if _, err := inv.Host("no-such-host"); err == nil {
		t.Fatal("Host(no-such-host) = nil error, want a not-found error")
	}
}

// Wires the per-service Service.Validate() dispatch inside Inventory.Validate:
// a service that would fail on its own (v1 gates are tcp-only) must still
// fail when reached through the fleet inventory, not just through
// Service.Validate called directly.
func TestConfig_Validate_RejectsAServiceFailingItsOwnValidation(t *testing.T) {
	data := inventoryFixture(t,
		"mgmt:     { kind: gate, proto: tcp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }",
		"mgmt:     { kind: gate, proto: udp, ports: [9000],  default_ttl: 60s,  max_ttl: 120s }")
	inv := mustParseInventory(t, data)
	err := inv.Validate()
	if err == nil || !strings.Contains(err.Error(), "only tcp") {
		t.Fatalf("Validate() = %v, want an error from Service.Validate rejecting proto udp", err)
	}
}

// A low-order Curve25519 point in host_identity.encryption drives
// bundle.Seal's X25519 exchange to a fixed, publicly computable shared
// secret (bundle.Seal's own checkRecipient documents the same set), so the
// "sealed" bundle would be readable by anyone who fetched it from the hub.
// decodeKey validates only base64 and length, so a hand-edited inventory
// carrying one of these parses cleanly; Validate is where design section 6
// says this belongs — caught on the diff, at review time, rather than per
// host in the middle of a `postern sign` run.
func TestConfig_Validate_RejectsALowOrderHostEncryptionKey(t *testing.T) {
	// The same small-order points bundle_test.go's
	// TestBundle_Seal_RejectsALowOrderRecipientKey screens for.
	for _, hexKey := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		t.Run(hexKey[:8], func(t *testing.T) {
			raw, err := hex.DecodeString(hexKey)
			if err != nil {
				t.Fatalf("DecodeString: %v", err)
			}
			key := base64.StdEncoding.EncodeToString(raw)
			data := inventoryFixture(t,
				`encryption: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="`,
				`encryption: "`+key+`"`)
			inv := mustParseInventory(t, data)
			err = inv.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want a rejection of the low-order host_identity encryption key")
			}
			if !strings.Contains(err.Error(), "web-01") {
				t.Fatalf("Validate() = %v, want it to name web-01", err)
			}
			if !strings.Contains(err.Error(), "not a usable X25519 point") {
				t.Fatalf("Validate() = %v, want it to say the key is not a usable X25519 point", err)
			}
		})
	}
}

// A host's port_rotation key is polymorphic: the bare scalar "disabled" opts
// the host out of the fleet's defaults.port_rotation instead of inheriting
// it, and carries no block of its own.
func TestConfig_ParseInventory_HostPortRotationDisabledParsesWithNoBlock(t *testing.T) {
	data := inventoryFixture(t,
		`console: "https://provider.example/instances/web-01/console"`,
		"console: \"https://provider.example/instances/web-01/console\"\n    port_rotation: disabled")
	inv := mustParseInventory(t, data)
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	if !h.PortRotationDisabled {
		t.Error("PortRotationDisabled = false, want true")
	}
	if h.PortRotation != nil {
		t.Errorf("PortRotation = %+v, want nil: \"disabled\" carries no block", h.PortRotation)
	}
}

// The other branch of the same polymorphic key: a host declaring its own
// mapping block gets that block, distinct from the fleet's
// defaults.port_rotation, and PortRotationDisabled stays false (only the
// bare "disabled" scalar sets it, never a mapping). Together with
// TestConfig_ParseInventory_HostPortRotationDisabledParsesWithNoBlock above,
// this pins down both arms of yamlHostPortRotation.UnmarshalYAML: this is
// the riskiest of the two, since it is the one path Compile actually reads a
// value out of (resolvePortRotation's host.PortRotation != nil branch, see
// bundle.TestBundle_Compile_HostPortRotationOverridesFleetDefault).
func TestConfig_ParseInventory_HostPortRotationBlockParsesDistinctFromFleetDefault(t *testing.T) {
	data := strings.Replace(validInventory,
		"  freshness_window_max: 12h\n",
		"  freshness_window_max: 12h\n"+
			`  port_rotation: { secret: "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0=", window: 45s, range: 20000-30000 }`+"\n",
		1)
	data = strings.Replace(data,
		`console: "https://provider.example/instances/web-01/console"`,
		"console: \"https://provider.example/instances/web-01/console\"\n"+
			`    port_rotation: { secret: "7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u4=", window: 900s, range: 21000-31000 }`,
		1)
	inv := mustParseInventory(t, []byte(data))

	if inv.Defaults.PortRotation == nil {
		t.Fatal("Defaults.PortRotation = nil, want the fleet-wide block the fixture declares")
	}
	wantDefaultSecret := bytes.Repeat([]byte{0xdd}, 32)
	if !bytes.Equal(inv.Defaults.PortRotation.Secret, wantDefaultSecret) {
		t.Errorf("Defaults.PortRotation.Secret = %x, want %x", inv.Defaults.PortRotation.Secret, wantDefaultSecret)
	}
	if inv.Defaults.PortRotation.RangeLo != 20000 || inv.Defaults.PortRotation.RangeHi != 30000 {
		t.Errorf("Defaults.PortRotation range = %d-%d, want 20000-30000",
			inv.Defaults.PortRotation.RangeLo, inv.Defaults.PortRotation.RangeHi)
	}

	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	if h.PortRotationDisabled {
		t.Error("PortRotationDisabled = true, want false: this host declares its own block, not \"disabled\"")
	}
	if h.PortRotation == nil {
		t.Fatal("web-01 PortRotation = nil, want its own block")
	}
	wantHostSecret := bytes.Repeat([]byte{0xee}, 32)
	if !bytes.Equal(h.PortRotation.Secret, wantHostSecret) {
		t.Errorf("web-01 PortRotation.Secret = %x, want %x", h.PortRotation.Secret, wantHostSecret)
	}
	if h.PortRotation.Window != 900*time.Second {
		t.Errorf("web-01 PortRotation.Window = %s, want 900s", h.PortRotation.Window)
	}
	if h.PortRotation.RangeLo != 21000 || h.PortRotation.RangeHi != 31000 {
		t.Errorf("web-01 PortRotation range = %d-%d, want 21000-31000", h.PortRotation.RangeLo, h.PortRotation.RangeHi)
	}
	if bytes.Equal(h.PortRotation.Secret, inv.Defaults.PortRotation.Secret) {
		t.Fatal("web-01's own port_rotation secret equals the fleet default's; this fixture does not actually " +
			"exercise a distinct per-host block")
	}
}

// yamlHostPortRotation.UnmarshalYAML hand-rolls its own known-fields check on
// the mapping branch, because yaml.Node.Decode always starts a fresh decoder
// that does not inherit the parent Decoder.KnownFields(true) this package
// relies on everywhere else (see the doc comment on
// yamlHostPortRotation.UnmarshalYAML in inventory.go). Nothing but this test
// exercises that hand-rolled check; without it, a typo'd key inside a
// per-host port_rotation block would silently parse clean.
func TestConfig_ParseInventory_RejectsUnknownHostPortRotationFieldTypo(t *testing.T) {
	data := strings.Replace(validInventory,
		`console: "https://provider.example/instances/web-01/console"`,
		"console: \"https://provider.example/instances/web-01/console\"\n"+
			`    port_rotation: { secret: "7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u4=", window: 900s, rnge: 21000-31000 }`,
		1)
	_, err := config.ParseInventory([]byte(data))
	if err == nil {
		t.Fatal("ParseInventory() = nil error, want a rejection of the unknown field inside the host's port_rotation block")
	}
}

func TestConfig_ParseInventory_ExampleAndFixtureAreParseable(t *testing.T) {
	// Sanity: the two YAML documents this file relies on are each valid on
	// their own, independent of any specific test above.
	if _, err := config.ParseInventory(exampleInventory(t)); err != nil {
		t.Fatalf("examples/inventory.yaml: %v", err)
	}
	if _, err := config.ParseInventory(bytes.TrimSpace([]byte(validInventory))); err != nil {
		t.Fatalf("validInventory: %v", err)
	}
}
