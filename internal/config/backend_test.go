package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// scriptGate is a valid script-backed gate, which each test below then breaks
// in exactly one way, so a refusal is attributable to the rule under test
// rather than to some other field the fixture happened to leave wrong.
func scriptGate() config.Service {
	return config.Service{
		Name:                "perimeter",
		Kind:                config.KindGate,
		Proto:               "tcp",
		Ports:               []uint16{22},
		DefaultTTL:          120 * time.Second,
		MaxTTL:              300 * time.Second,
		FailPosture:         config.PostureOpen,
		ListenerExpectation: config.ListenerUnchecked,
		Backend:             config.BackendScript,
		ScriptPath:          "/opt/postern/perimeter.sh",
		ScriptTimeout:       15 * time.Second,
	}
}

func TestConfig_ServiceValidate_AcceptsAScriptBackedGate(t *testing.T) {
	if err := scriptGate().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestConfig_ServiceValidate_RejectsAnUnknownBackend(t *testing.T) {
	svc := scriptGate()
	svc.Backend = "iptables"
	svc.ScriptPath = ""
	svc.ScriptTimeout = 0

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted an unknown backend")
	}
	if !strings.Contains(err.Error(), "backend \"iptables\"") {
		t.Errorf("error does not name the backend: %v", err)
	}
}

func TestConfig_ServiceValidate_RejectsAScriptBackendWithNoPath(t *testing.T) {
	svc := scriptGate()
	svc.ScriptPath = ""

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a script backend with no script_path")
	}
	if !strings.Contains(err.Error(), "no script_path") {
		t.Errorf("error does not name the missing path: %v", err)
	}
}

// A relative path resolves against the agent's working directory, which under
// systemd is "/" and under a test is wherever the harness chdir'd. A root
// daemon must never execute a path whose meaning depends on that.
func TestConfig_ServiceValidate_RejectsARelativeScriptPath(t *testing.T) {
	svc := scriptGate()
	svc.ScriptPath = "scripts/perimeter.sh"

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a relative script_path")
	}
	if !strings.Contains(err.Error(), "not absolute") {
		t.Errorf("error does not name the relative path: %v", err)
	}
}

// The mechanism fail_posture: closed rests on is boot.nft loading a drop rule
// before the agent exists. A script backend has no boot-time form, so there
// is no state in which its service is shut and the agent is absent. Accepting
// the word while delivering none of the mechanism is how a posture silently
// inverts.
func TestConfig_ServiceValidate_RejectsFailClosedOnAScriptBackend(t *testing.T) {
	svc := scriptGate()
	svc.FailPosture = config.PostureClosed

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted fail_posture: closed on a script backend")
	}
	if !strings.Contains(err.Error(), "boot.nft") {
		t.Errorf("error does not explain which mechanism is missing: %v", err)
	}
}

// The same field on the wrong backend is a declaration that does nothing, and
// a declaration that does nothing on a firewall config is one an operator
// believes.
func TestConfig_ServiceValidate_RejectsScriptFieldsOnTheNFTablesBackend(t *testing.T) {
	svc := scriptGate()
	svc.Backend = config.BackendNFTables

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted script_path on the nftables backend")
	}
	for _, want := range []string{"script_path", "script_timeout"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// The timeout is also how long a hung script delays its own service's next
// admission and its own reaper sweep, so an unbounded value would make
// "degrades its own service" mean "disables it indefinitely".
func TestConfig_ServiceValidate_RejectsAnOversizedScriptTimeout(t *testing.T) {
	svc := scriptGate()
	svc.ScriptTimeout = config.MaxScriptTimeout + time.Second

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted a script_timeout above the limit")
	}
	if !strings.Contains(err.Error(), "script_timeout") {
		t.Errorf("error does not name the field: %v", err)
	}
}

func TestConfig_ServiceValidate_RejectsBackendFieldsOnAnAction(t *testing.T) {
	svc := config.Service{
		Name:          "confirm",
		Kind:          config.KindAction,
		Backend:       config.BackendScript,
		ScriptPath:    "/opt/postern/confirm.sh",
		ScriptTimeout: time.Second,
	}

	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate accepted backend fields on an action")
	}
	for _, want := range []string{"may not declare backend", "may not declare script_path", "may not declare script_timeout"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q: %v", want, err)
		}
	}
}

const scriptBackendYAML = `
fleet_id: 000102030405060708090a0b0c0d0e0f
host_id: 100102030405060708090a0b0c0d0e0f
spa_port: 62201
always_allow_iface: tailscale0
services:
  ssh:
    kind: gate
    proto: tcp
    ports: [22]
    default_ttl: 120s
    max_ttl: 300s
  perimeter:
    kind: gate
    proto: tcp
    ports: [22]
    default_ttl: 120s
    max_ttl: 300s
    listener_expectation: unchecked
    backend: script
    script_path: /opt/postern/perimeter.sh
operators:
  - name: laptop
    alg: ed25519+x25519
    signing: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
    encryption: ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
    grants:
      - services: [ssh, perimeter]
        max_ttl: 300s
`

// A service that says nothing about a backend must resolve to nftables, which
// is what makes every config written before this field existed behave exactly
// as it did.
func TestConfig_ParseStandalone_DefaultsTheBackendToNFTables(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if got := p.Services["ssh"].Backend; got != config.BackendNFTables {
		t.Errorf("ssh backend = %q, want %q", got, config.BackendNFTables)
	}
}

// A script-backed gate resolves to fail_posture: open because the local
// kernel drops nothing for it when the agent is absent — which is exactly
// what "open" describes. Resolving it to the ordinary non-breakglass default
// of "closed" would default straight into a refusal.
func TestConfig_ParseStandalone_ResolvesAScriptGateToFailOpen(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	svc := p.Services["perimeter"]
	if svc.Backend != config.BackendScript {
		t.Fatalf("perimeter backend = %q, want %q", svc.Backend, config.BackendScript)
	}
	if svc.FailPosture != config.PostureOpen {
		t.Errorf("perimeter fail_posture = %q, want %q", svc.FailPosture, config.PostureOpen)
	}
	if svc.ScriptTimeout != config.DefaultScriptTimeout {
		t.Errorf("perimeter script_timeout = %s, want the default %s", svc.ScriptTimeout, config.DefaultScriptTimeout)
	}
}

// Pairing a local nftables gate with a script-backed one on the same port is
// the deployment the script backend is meant for: the kernel holds the local
// bolt while the script handles the perimeter. I7's reason — one table's drop
// defeating the other's accept — does not apply to a service that writes no
// table rule.
func TestConfig_PolicyValidate_AllowsOnePortOnTwoDifferentBackends(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// Uniqueness still holds within a backend: two script services on one port
// drive the same perimeter, and one's close withdraws the other's admission.
func TestConfig_PolicyValidate_RejectsTwoScriptServicesOnOnePort(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	second := p.Services["perimeter"]
	second.Name = "perimeter-two"
	p.Services["perimeter-two"] = second

	err = p.Validate()
	if err == nil {
		t.Fatal("Validate accepted two script-backed services on one port")
	}
	if !strings.Contains(err.Error(), "one owner per backend") {
		t.Errorf("error does not explain the per-backend ownership rule: %v", err)
	}
}

func TestConfig_PolicyValidate_RejectsTwoNFTablesServicesOnOnePort(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	second := p.Services["ssh"]
	second.Name = "ssh-two"
	p.Services["ssh-two"] = second

	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted two nftables-backed services on one port")
	}
}

// A hand-built or half-resolved policy must not read as nftables downstream,
// where the ruleset planner would generate a drop rule for a port whose
// admissions a script was supposed to own.
func TestConfig_PolicyValidate_RejectsAnUnresolvedBackend(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	svc := p.Services["ssh"]
	svc.Backend = ""
	p.Services["ssh"] = svc

	err = p.Validate()
	if err == nil {
		t.Fatal("Validate accepted an unresolved backend")
	}
	if !strings.Contains(err.Error(), "no resolved backend") {
		t.Errorf("error does not name the unresolved backend: %v", err)
	}
}

// The expiry gap is a warning rather than a refusal, and a warning nobody is
// shown is the same as no warning — so it has to be reachable through the
// policy an operator loaded, not buried in a doc comment.
func TestConfig_PolicyWarnings_NamesTheScriptBackendsMissingExpiryGuarantee(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}

	warnings := p.Warnings()
	if len(warnings) != 1 {
		t.Fatalf("warnings = %d, want 1: %v", len(warnings), warnings)
	}
	for _, want := range []string{"perimeter", "no kernel-owned expiry", "if the agent dies"} {
		if !strings.Contains(warnings[0], want) {
			t.Errorf("warning does not mention %q: %q", want, warnings[0])
		}
	}
}

func TestConfig_PolicyHasScriptBackend_IsFalseWithoutOne(t *testing.T) {
	p, err := config.ParseStandalone([]byte(scriptBackendYAML))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if !p.HasScriptBackend() {
		t.Error("HasScriptBackend = false on a policy that declares one")
	}
	delete(p.Services, "perimeter")
	if p.HasScriptBackend() {
		t.Error("HasScriptBackend = true on a policy with no script-backed service")
	}
}

// The two parsers share decodeService, and this is what holds them to it: a
// field resolved in one and not the other means an operator's declaration
// silently disappears on whichever side missed it, and the compiled bundle
// still parses and runs.
func TestConfig_ParseInventory_ResolvesTheBackendTheSameWayAsStandalone(t *testing.T) {
	const inv = `
fleet_id: 000102030405060708090a0b0c0d0e0f
version: 1
defaults:
  spa_port: 62201
  always_allow_iface: tailscale0
services:
  ssh:
    kind: gate
    proto: tcp
    ports: [22]
    default_ttl: 120s
    max_ttl: 300s
  perimeter:
    kind: gate
    proto: tcp
    ports: [8443]
    default_ttl: 120s
    max_ttl: 300s
    listener_expectation: unchecked
    backend: script
    script_path: /opt/postern/perimeter.sh
hosts:
  - name: web-01
    host_id: "100102030405060708090a0b0c0d0e0f"
    knock_addr: 203.0.113.9
    host_identity:
      alg: ed25519+x25519
      signing:    "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="
      encryption: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="
    services: [ssh, perimeter]
`
	got, err := config.ParseInventory([]byte(inv))
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}
	if b := got.Services["ssh"].Backend; b != config.BackendNFTables {
		t.Errorf("ssh backend = %q, want %q", b, config.BackendNFTables)
	}
	svc := got.Services["perimeter"]
	if svc.Backend != config.BackendScript {
		t.Errorf("perimeter backend = %q, want %q", svc.Backend, config.BackendScript)
	}
	if svc.ScriptPath != "/opt/postern/perimeter.sh" {
		t.Errorf("perimeter script_path = %q", svc.ScriptPath)
	}
	if svc.ScriptTimeout != config.DefaultScriptTimeout {
		t.Errorf("perimeter script_timeout = %s, want the default %s", svc.ScriptTimeout, config.DefaultScriptTimeout)
	}
	if svc.FailPosture != config.PostureOpen {
		t.Errorf("perimeter fail_posture = %q, want %q", svc.FailPosture, config.PostureOpen)
	}
}
