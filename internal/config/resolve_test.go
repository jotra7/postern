package config_test

import (
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/knockport"
)

// validStandalone must match docs/superpowers/specs/2026-07-27-postern-design.md,
// section 6 "Standalone config" (the ```yaml fenced block under that
// heading), field for field and value for value, with two narrow exceptions:
//
//   - fleet_id, host_id, and every operator's signing/encryption key are
//     "..." placeholders in the spec (illustrative, not parseable data);
//     this fixture substitutes concrete, valid test values in their place
//     so ParseStandalone and Validate can actually run against it.
//   - freshness_window and freshness_window_max do not appear in that spec
//     block at all — it relies on ParseStandalone's defaults (60s and 24h);
//     this fixture sets them explicitly to those same default values, so
//     the fixture's *behavior*, not its literal bytes, matches the spec.
//
// This fixture exists to catch drift between the design and the parser — a
// field the design ships that the parser rejects, or vice versa. It
// previously omitted "verification: tcp_rst" on canary, which every one of
// the design's config examples includes; ParseStandalone then rejected it
// once KnownFields(true) landed, and this fixture could not have caught
// that, because it never contained the field in the first place. If
// section 6 changes, update this fixture (and the field-by-field assertions
// in TestConfig_ParseStandalone_ShippedExampleIsValid below) in the same
// change — a fixture that quietly stops matching what an operator actually
// copy-pastes defeats the reason it exists.
const validStandalone = `
fleet_id: "0102030405060708090a0b0c0d0e0f10"
host_id:  "1112131415161718191a1b1c1d1e1f20"
spa_port: 62201
always_allow_iface: tailscale0
recovery_service: ssh
breakglass_services: [ssh]
freshness_window: 60s
freshness_window_max: 24h

services:
  ssh:      { kind: gate, proto: tcp, ports: [22],    default_ttl: 120s, max_ttl: 300s, listener_expectation: present }
  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s,  max_ttl: 60s,  listener_expectation: absent, verification: tcp_rst }
  confirm:  { kind: action }
  disarm:   { kind: action }
  liveness: { kind: action }

operators:
  - name: laptop-primary
    alg: ed25519+x25519
    signing:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    encryption: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    grants:
      - services: ["ssh", "confirm", "disarm", "liveness"]
        max_ttl: 300s
  - name: probe-local
    alg: ed25519+x25519
    signing:    "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    encryption: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
    grants:
      - services: ["canary"]
        max_ttl: 30s
`

func parseOrFail(t *testing.T, yaml string) *config.Policy {
	t.Helper()
	p, err := config.ParseStandalone([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	return p
}

func TestConfig_ParseStandalone_ShippedExampleIsValid(t *testing.T) {
	// The shipped example must arm. An example that cannot is the failure the
	// design exists to prevent, arriving through documentation.
	//
	// This test's name previously claimed more than it checked: the fixture
	// it validated never contained "verification: tcp_rst", so this test
	// could not have caught the field's absence causing the shipped example
	// to be rejected once KnownFields(true) landed. The assertions below
	// cover every field the spec's "Standalone config" example (section 6)
	// declares, not just RecoveryService and operator count — see the
	// contract comment on validStandalone above.
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if p.RecoveryService != "ssh" {
		t.Fatalf("RecoveryService = %q, want ssh", p.RecoveryService)
	}
	if len(p.Operators) != 2 {
		t.Fatalf("len(Operators) = %d, want 2", len(p.Operators))
	}
	for _, name := range []string{"ssh", "canary", "confirm", "disarm", "liveness"} {
		if _, ok := p.Services[name]; !ok {
			t.Errorf("Services[%q] missing; the spec's standalone example declares it", name)
		}
	}
	ssh := p.Services["ssh"]
	if ssh.FailPosture != config.PostureOpen {
		t.Errorf("ssh.FailPosture = %q, want open (ssh is in breakglass_services)", ssh.FailPosture)
	}
	canary := p.Services["canary"]
	if canary.ListenerExpectation != config.ListenerAbsent {
		t.Errorf("canary.ListenerExpectation = %q, want absent", canary.ListenerExpectation)
	}
	if canary.Verification != config.VerificationTCPRST {
		t.Errorf("canary.Verification = %q, want %q; every one of the design's config examples declares it on canary",
			canary.Verification, config.VerificationTCPRST)
	}
	if canary.FailPosture != config.PostureClosed {
		t.Errorf("canary.FailPosture = %q, want closed", canary.FailPosture)
	}
}

func TestConfig_ParseStandalone_RejectsEmptyDocument(t *testing.T) {
	// MINOR: yaml.Unmarshal on an empty/comment-only document used to
	// return no error at all, letting the field-level checks (fleet_id,
	// host_id, spa_port, ...) enumerate what was missing. Decoder.Decode
	// instead returns bare io.EOF for the same input — a poor diagnostic to
	// hand an operator holding a truncated file — so it must be translated
	// into something that names the actual problem.
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"empty", ""},
		{"comment only", "# just a comment\n"},
		{"whitespace only", "   \n\n  \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.ParseStandalone([]byte(tc.yaml))
			// "empty document" (not bare "empty"): service.go's name-empty
			// and verification messages both contain the word "empty" on
			// their own.
			if err == nil || !strings.Contains(err.Error(), "empty document") {
				t.Fatalf("ParseStandalone(%q) = %v, want an error naming an empty document", tc.yaml, err)
			}
		})
	}
}

func TestConfig_ParseStandalone_RejectsUnknownServiceFieldTypo(t *testing.T) {
	// I-1: a root-owned file that decides host reachability must not
	// silently drop a typo'd key. "fail_postur" (missing 'e') on ssh would
	// otherwise validate clean and resolve to fail_posture "open" via the
	// breakglass default — the opposite of whatever the operator's typo
	// was reaching for, with no diagnostic anywhere.
	bad := strings.Replace(validStandalone,
		`  ssh:      { kind: gate, proto: tcp, ports: [22],    default_ttl: 120s, max_ttl: 300s, listener_expectation: present }`,
		`  ssh:      { kind: gate, proto: tcp, ports: [22],    default_ttl: 120s, max_ttl: 300s, listener_expectation: present, fail_postur: closed }`, 1)
	_, err := config.ParseStandalone([]byte(bad))
	if err == nil {
		t.Fatal("ParseStandalone() = nil error, want a rejection of the unknown field")
	}
	// "field fail_postur not found" (not bare "fail_postur"): "fail_postur"
	// is an 11-of-12-character prefix of "fail_posture", so a bare-substring
	// anchor is only safe as long as no parse-level message anywhere in this
	// package happens to mention "fail_posture" — true today, but the exact
	// phrase yaml.v3's KnownFields emits is what actually pins this to the
	// unknown-field rejection, the same anchoring style the sibling test
	// below uses for "field service not found".
	if !strings.Contains(err.Error(), "field fail_postur not found") {
		t.Fatalf("ParseStandalone() = %v, want it to name the unknown field", err)
	}
}

func TestConfig_ParseStandalone_RejectsUnknownGrantFieldTypo(t *testing.T) {
	// I-1, nested case: "service" instead of "services" inside a grant
	// produces an operator granted nothing, and previously validated green
	// — on a fail-closed host that is exactly the lockout this layer
	// exists to prevent.
	bad := strings.Replace(validStandalone,
		`      - services: ["canary"]`,
		`      - service: ["canary"]`, 1)
	_, err := config.ParseStandalone([]byte(bad))
	if err == nil {
		t.Fatal("ParseStandalone() = nil error, want a rejection of the unknown field")
	}
	// Bare "service" is satisfied by nearly every error this package can
	// emit ("recovery_service ...", "is not a declared service", even the
	// type name "config.yamlService" inside an unrelated KnownFields
	// error). "field service not found" is the exact phrase yaml.v3's
	// KnownFields emits and names the specific rejected key, matching how
	// the sibling test above anchors on "fail_postur" rather than a bare
	// word.
	if !strings.Contains(err.Error(), "field service not found") {
		t.Fatalf("ParseStandalone() = %v, want it to name the unknown field", err)
	}
}

// port_rotation is decoded as an ordinary pointer struct field (unlike the
// per-host inventory form, it has no polymorphic scalar-or-mapping shape and
// so needs no custom UnmarshalYAML), which means it inherits
// Decoder.KnownFields(true) through the normal recursive-struct decode path
// exactly the way every other nested block in this file already does. This
// pins that inheritance in place: a typo'd key inside the block must be a
// parse error, not a silently-dropped field.
func TestConfig_ParseStandalone_RejectsUnknownPortRotationFieldTypo(t *testing.T) {
	bad := validStandalone +
		"port_rotation: { secret: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\", window: 600s, rnge: 20000-30000 }\n"
	_, err := config.ParseStandalone([]byte(bad))
	if err == nil {
		t.Fatal("ParseStandalone() = nil error, want a rejection of the unknown field")
	}
	if !strings.Contains(err.Error(), "field rnge not found") {
		t.Fatalf("ParseStandalone() = %v, want it to name the unknown field", err)
	}
}

// Companion to client.ParseConfig's TestClient_ParseConfig_IgnoresUnknownHostFields:
// the client dropped strict decoding for its host entries because an unknown
// key there costs a feature, never a posture. This test pins the other half
// of that asymmetry in place. ParseStandalone must keep KnownFields(true),
// because here a misspelled key does not lose a feature, it inverts one:
// "fail_postur" (missing the trailing 'e') resolves to the fail_posture zero
// value, and the service comes up OPEN on a host the operator configured
// shut. Later fields added to this config (hub_url, bundle_signers,
// enrollment_floor) must not be the excuse to relax this.
func TestConfig_ParseStandalone_StillRejectsAMisspelledFailPosture(t *testing.T) {
	bad := strings.Replace(validStandalone,
		`  ssh:      { kind: gate, proto: tcp, ports: [22],    default_ttl: 120s, max_ttl: 300s, listener_expectation: present }`,
		`  ssh:      { kind: gate, proto: tcp, ports: [22],    default_ttl: 120s, max_ttl: 300s, listener_expectation: present, fail_postur: closed }`, 1)
	if _, err := config.ParseStandalone([]byte(bad)); err == nil {
		t.Fatal("ParseStandalone accepted a misspelled fail_posture; " +
			"the service would have come up open on a host configured closed")
	}
}

func TestConfig_Validate_BreakglassDefaultsOpenOthersClosed(t *testing.T) {
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := p.Services["ssh"].FailPosture; got != config.PostureOpen {
		t.Errorf("ssh fail_posture = %q, want open (it is in breakglass_services)", got)
	}
	if got := p.Services["canary"].FailPosture; got != config.PostureClosed {
		t.Errorf("canary fail_posture = %q, want closed; a fail-open canary reports green when the agent is dead", got)
	}
}

func TestConfig_Validate_RejectsActionWithTTL(t *testing.T) {
	// I-3: default_ttl/max_ttl on an action must not be silently dropped
	// during parsing — Service.Validate's "may not declare TTLs" check
	// (Task 4) needs to actually see the nonzero value to reject it, or it
	// is unreachable through this constructor.
	yaml := strings.Replace(validStandalone,
		`  confirm:  { kind: action }`,
		`  confirm:  { kind: action, default_ttl: 300s }`, 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "may not declare TTLs") {
		t.Fatalf("Validate() = %v, want an error naming that actions may not declare TTLs", err)
	}
}

func TestConfig_ParseStandalone_RejectsMalformedActionTTL(t *testing.T) {
	// I-3, second half: a malformed duration on an action produced no
	// error at all when TTL fields were only parsed for gates.
	yaml := strings.Replace(validStandalone,
		`  confirm:  { kind: action }`,
		`  confirm:  { kind: action, default_ttl: not-a-duration }`, 1)
	_, err := config.ParseStandalone([]byte(yaml))
	if err == nil {
		t.Fatal("ParseStandalone() = nil error, want a malformed-duration error")
	}
	if !strings.Contains(err.Error(), "confirm.default_ttl") {
		t.Fatalf("ParseStandalone() = %v, want it to name confirm.default_ttl", err)
	}
}

func TestConfig_Validate_ExplicitEmptyBreakglassOverridesHiddenDefault(t *testing.T) {
	// I-2: "breakglass_services: []" is a deliberate declaration of no
	// breakglass services and must not be treated the same as the key
	// being entirely absent, which gets a hidden ssh default. An operator
	// who explicitly opts out of breakglass must get what they asked for
	// (ssh fail-closed like everything else), not a silently-reinstated
	// fail-open ssh gate.
	yaml := strings.Replace(validStandalone, "breakglass_services: [ssh]", "breakglass_services: []", 1)
	p := parseOrFail(t, yaml)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := p.Services["ssh"].FailPosture; got != config.PostureClosed {
		t.Fatalf("ssh fail_posture = %q, want closed: breakglass_services: [] explicitly declares no breakglass services", got)
	}
}

func TestConfig_Validate_RejectsOverlappingPorts(t *testing.T) {
	// I7: two services on one port land in different tables under different
	// postures and one drop defeats the other accept, producing a correctly
	// signed packet that silently does nothing.
	yaml := strings.Replace(validStandalone,
		`  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s,  max_ttl: 60s,  listener_expectation: absent, verification: tcp_rst }`,
		`  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s,  max_ttl: 60s,  listener_expectation: absent, verification: tcp_rst }
  shell2:   { kind: gate, proto: tcp, ports: [22],    default_ttl: 30s,  max_ttl: 60s,  listener_expectation: present }`, 1)

	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an overlapping-port error")
	}
	// "tcp/22" is the exact key format the port-ownership check emits
	// (fmt.Sprintf("%s/%d", proto, port)); it does not appear anywhere else
	// in this YAML (proto and port number are on separate, unjoined lines),
	// so this can only be satisfied by that specific check firing.
	if !strings.Contains(err.Error(), "tcp/22") {
		t.Fatalf("error %q does not name the conflicting port", err)
	}
}

func TestConfig_Validate_RejectsMissingRecoveryServiceWhenFailClosedExists(t *testing.T) {
	// There is no defensible default for "how would you fix this host", and
	// guessing ssh on a host that does not run sshd rebuilds the false green.
	yaml := strings.Replace(validStandalone, "recovery_service: ssh\n", "", 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want a recovery_service error")
	}
	// The literal text "recovery_service:" only appeared once in the source
	// YAML, on the line just deleted, so an error that merely echoed the
	// input back could not produce this match; it has to come from the
	// missing-recovery-service check itself. Anchor further on the
	// "is required" phrase specific to that check, since other
	// recovery_service errors (wrong kind, unknown service) also mention the
	// field name but say something else.
	if !strings.Contains(err.Error(), "recovery_service is required") {
		t.Fatalf("error %q does not report that recovery_service is required", err)
	}
}

func TestConfig_Validate_RejectsRecoveryServiceThatIsNotAGate(t *testing.T) {
	yaml := strings.Replace(validStandalone, "recovery_service: ssh", "recovery_service: confirm", 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), `recovery_service "confirm" has kind "action"`) {
		t.Fatalf("Validate() = %v, want an error naming recovery_service and its non-gate kind", err)
	}
}

func TestConfig_Validate_RejectsGrantForUnknownService(t *testing.T) {
	yaml := strings.Replace(validStandalone, `["ssh", "confirm", "disarm", "liveness"]`, `["ssh", "nonexistent"]`, 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("Validate() = %v, want an error naming the unknown service", err)
	}
}

func TestConfig_Validate_RejectsDuplicateOperatorSigningKeys(t *testing.T) {
	// I-4: KeyID is derived from the signing key, and Policy.Grants stops
	// at the first operator whose KeyID matches. Two operators sharing a
	// signing key therefore validate clean today and silently void the
	// second operator's grants — a correctly signed packet that does
	// nothing.
	p := parseOrFail(t, validStandalone)
	dup := p.Operators[0]
	dup.Identity.Name = "laptop-secondary"
	p.Operators = append(p.Operators, dup)

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want a duplicate-signing-key error")
	}
	// "shares a signing key" is the phrase this check alone emits; unlike
	// bare "operator", nothing else in this package's messages produces it.
	if !strings.Contains(err.Error(), "shares a signing key") {
		t.Fatalf("Validate() = %v, want it to report a shared signing key", err)
	}
	if !strings.Contains(err.Error(), "laptop-secondary") || !strings.Contains(err.Error(), "laptop-primary") {
		t.Fatalf("Validate() = %v, want it to name both operators", err)
	}
}

func TestConfig_Validate_RejectsAssertedCIDRPolicyWithoutMinimumPrefix(t *testing.T) {
	// Without a minimum prefix an authorised operator could assert 0.0.0.0/0.
	yaml := strings.Replace(validStandalone,
		`        max_ttl: 300s`,
		"        max_ttl: 300s\n        allow_source_cidr: true", 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "min_ipv4_prefix") {
		t.Fatalf("Validate() = %v, want an error naming min_ipv4_prefix", err)
	}
}

func TestConfig_Validate_RejectsAssertedCIDRPolicyWithoutMinimumIPv6Prefix(t *testing.T) {
	// C-1: ::/0 is the same failure as 0.0.0.0/0. min_ipv4_prefix alone is
	// not enough — a grant that sets it but leaves min_ipv6_prefix at its
	// zero value must still fail, not validate clean.
	yaml := strings.Replace(validStandalone,
		`        max_ttl: 300s`,
		"        max_ttl: 300s\n        allow_source_cidr: true\n        min_ipv4_prefix: 24", 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "min_ipv6_prefix") {
		t.Fatalf("Validate() = %v, want an error naming min_ipv6_prefix", err)
	}
}

func TestConfig_Validate_RejectsGrantWithNonPositiveMaxTTL(t *testing.T) {
	// Grant.MaxTTL was parsed with a zero fallback and never checked, while
	// Service.MaxTTL gets both a positivity check and a MaxTTLSeconds cap.
	// Every design example supplies max_ttl on a grant, so it is intended as
	// required; the same shape as the min_ipv6_prefix bug this branch
	// already fixed — left unvalidated, a zero max_ttl silently drops the
	// grant's cap rather than being caught at config-load time.
	yaml := strings.Replace(validStandalone, "        max_ttl: 300s\n", "", 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "non-positive max_ttl") {
		t.Fatalf("Validate() = %v, want an error naming a non-positive max_ttl", err)
	}
}

func TestConfig_Validate_RejectsGrantWithMaxTTLAboveWireLimit(t *testing.T) {
	// ttl_seconds is uint16 on the wire (MaxTTLSeconds = 65535); a grant
	// promising more than the wire can carry is unrepresentable.
	yaml := strings.Replace(validStandalone, "        max_ttl: 300s", "        max_ttl: 70000s", 1)
	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "wire limit is 65535 seconds") {
		t.Fatalf("Validate() = %v, want an error naming the wire limit", err)
	}
}

func TestConfig_Validate_AcceptsGrantMaxTTLAtWireLimit(t *testing.T) {
	// The wire limit is a floor-style boundary here too: exactly 65535s
	// (uint16 max) must validate, not merely anything strictly below it.
	yaml := strings.Replace(validStandalone, "        max_ttl: 300s", "        max_ttl: 65535s", 1)
	p := parseOrFail(t, yaml)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil: max_ttl at the exact wire limit", err)
	}
}

func TestConfig_Validate_RejectsGateWithUnresolvedFailPosture(t *testing.T) {
	// I-5: Service.Validate() (Task 4) deliberately allows an empty
	// FailPosture on a gate, because ParseStandalone is meant to resolve
	// it. A hand-built Policy that skips resolution must not validate
	// clean — HasFailClosed would treat the unresolved gate as not
	// fail-closed, and the recovery_service requirement would go
	// unenforced.
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate (before mutation): %v", err)
	}
	svc := p.Services["ssh"]
	svc.FailPosture = ""
	p.Services["ssh"] = svc

	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), `service "ssh" has no resolved fail_posture`) {
		t.Fatalf("Validate() = %v, want an error naming ssh's unresolved fail_posture", err)
	}
}

func TestConfig_Validate_RejectsAbsentListenerWithFailOpen(t *testing.T) {
	// MINOR (schema-level canary rule): a gate whose listener_expectation
	// is "absent" may not be fail_posture "open". Fail-open there leaves a
	// dead agent's port unfiltered, turning a health-probe timeout into a
	// connection-refused — the system reports green exactly when the agent
	// is dead. No "if name == canary": this is checked for any gate shaped
	// this way.
	p := parseOrFail(t, validStandalone)
	svc := p.Services["canary"]
	if svc.ListenerExpectation != config.ListenerAbsent {
		t.Fatalf("fixture precondition failed: canary listener_expectation = %q, want absent", svc.ListenerExpectation)
	}
	svc.FailPosture = config.PostureOpen
	p.Services["canary"] = svc

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error rejecting a fail-open absent-listener gate")
	}
	if !strings.Contains(err.Error(), `"absent"`) || !strings.Contains(err.Error(), `"open"`) {
		t.Fatalf("Validate() = %v, want it to name both listener_expectation \"absent\" and fail_posture \"open\"", err)
	}
}

func TestConfig_GrantAllows_MatchesOnlyListedServices(t *testing.T) {
	g := config.Grant{Services: []string{"ssh", "confirm"}}
	if !g.Allows("ssh") {
		t.Error(`Allows("ssh") = false, want true`)
	}
	if !g.Allows("confirm") {
		t.Error(`Allows("confirm") = false, want true`)
	}
	if g.Allows("canary") {
		t.Error(`Allows("canary") = true, want false`)
	}
	if g.Allows("") {
		t.Error(`Allows("") = true, want false`)
	}
}

func TestConfig_PolicyGrants_ResolvesGrantedService(t *testing.T) {
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	laptop := p.Operators[0]
	if laptop.Identity.Name != "laptop-primary" {
		t.Fatalf("fixture precondition failed: Operators[0] = %q, want laptop-primary", laptop.Identity.Name)
	}

	g, ok := p.Grants(laptop.Identity.KeyID(), "ssh")
	if !ok {
		t.Fatal("Grants(laptop-primary, ssh) ok = false, want true")
	}
	if !g.Allows("ssh") {
		t.Fatalf("Grants returned a grant that does not itself allow ssh: %+v", g)
	}
}

func TestConfig_PolicyGrants_RejectsUngrantedService(t *testing.T) {
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	probe := p.Operators[1]
	if probe.Identity.Name != "probe-local" {
		t.Fatalf("fixture precondition failed: Operators[1] = %q, want probe-local", probe.Identity.Name)
	}

	// probe-local is only granted canary, not ssh.
	if _, ok := p.Grants(probe.Identity.KeyID(), "ssh"); ok {
		t.Fatal("Grants(probe-local, ssh) ok = true, want false: probe-local has no grant covering ssh")
	}
}

func TestConfig_PolicyGrants_RejectsUnknownKeyID(t *testing.T) {
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var unknownKeyID [16]byte
	for i := range unknownKeyID {
		unknownKeyID[i] = 0xff
	}
	if _, ok := p.Grants(unknownKeyID, "ssh"); ok {
		t.Fatal("Grants(unknown key_id, ssh) ok = true, want false")
	}
}

func TestConfig_PolicyGrants_DuplicateSigningKeyStillResolvesFirstOperator(t *testing.T) {
	// I-4/I-6: this fixture is rejected by Validate (see
	// TestConfig_Validate_RejectsDuplicateOperatorSigningKeys), so this test
	// documents Grants' actual current behavior on an unvalidated Policy —
	// first-match-wins — rather than asserting Validate would allow it.
	p := parseOrFail(t, validStandalone)
	dup := p.Operators[0] // laptop-primary, granted ssh/confirm/disarm/liveness
	dup.Identity.Name = "laptop-secondary"
	dup.Grants = []config.Grant{{Services: []string{"canary"}}} // a grant the first operator does NOT have
	p.Operators = append(p.Operators, dup)

	// The shared KeyID resolves to the first operator in the slice, so a
	// grant that only the second (shadowed) operator declared is
	// unreachable — this is exactly the silent-void failure I-4 rejects at
	// Validate time.
	if _, ok := p.Grants(dup.Identity.KeyID(), "canary"); ok {
		t.Fatal("Grants(shared key_id, canary) ok = true, want false: the second operator's grant is unreachable behind the first's KeyID match")
	}
	if _, ok := p.Grants(dup.Identity.KeyID(), "ssh"); !ok {
		t.Fatal("Grants(shared key_id, ssh) ok = false, want true: the first operator (laptop-primary) still resolves")
	}
}

func TestConfig_ParseStandalone_RejectsMalformedFleetID(t *testing.T) {
	// I-6: at least one direct ParseStandalone failure-path test, not only
	// ones that happen to exercise it as a side effect.
	yaml := strings.Replace(validStandalone, `fleet_id: "0102030405060708090a0b0c0d0e0f10"`, `fleet_id: "not-hex"`, 1)
	_, err := config.ParseStandalone([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "fleet_id") {
		t.Fatalf("ParseStandalone() = %v, want an error naming fleet_id", err)
	}
}

func TestConfig_ServiceByID_ResolvesHashToService(t *testing.T) {
	p := parseOrFail(t, validStandalone)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	want := p.Services["ssh"]
	got, ok := p.ServiceByID(want.ID())
	if !ok {
		t.Fatal("ServiceByID did not resolve a known service id")
	}
	if got.Name != "ssh" {
		t.Fatalf("ServiceByID resolved to %q, want ssh", got.Name)
	}
}

func TestConfig_Validate_RejectsTooManyOperators(t *testing.T) {
	// Trial-decrypt cost is linear in the operator count (design section 5).
	p := parseOrFail(t, validStandalone)
	base := p.Operators[0]
	for i := 0; i < 40; i++ {
		op := base
		op.Identity.Name = "filler"
		p.Operators = append(p.Operators, op)
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an operator-count error")
	}
	// Bare "operator" is satisfied by several unrelated messages this
	// package can emit (unsupported alg, grant for an unknown service, an
	// operator name in a recovery_service-is-not-a-gate message, ...); none
	// of those apply here since every filler op is a byte-for-byte copy of a
	// valid operator, but a future duplicate-signing-key rule would also
	// fire on this fixture (all fillers share one key) and would also
	// mention "operator", passing this assertion for the wrong reason. Pin
	// to the phrase the count check itself emits, including both the actual
	// count (42 = 2 original + 40 filler) and the configured limit, which no
	// other check in this package produces.
	//
	// Left-anchored with "- " (the bullet prefix joinedError.Error() puts in
	// front of every item): a bare Contains on "42 operators configured,
	// limit is 32" would also be satisfied by a hypothetical "142 operators
	// configured, limit is 32" message, since the digit run "42" is a
	// substring of "142". Requiring the bullet dash immediately before "42"
	// rules that out, the same digit-prefix hazard the count-flattening
	// tests elsewhere in this file already guard against with HasPrefix.
	wantPhrase := "- 42 operators configured, limit is 32"
	if !strings.Contains(err.Error(), wantPhrase) {
		t.Fatalf("Validate() = %v, want it to contain %q", err, wantPhrase)
	}
}

func TestConfig_ErrorList_FlattensPolicyAndServiceErrorsWithAccurateCount(t *testing.T) {
	// Regression for the known ErrorList defect: Policy.Validate() must not
	// wrap a per-service Validate() error as a single nested item. This
	// service alone has three independent problems (name too long, name
	// begins with a hyphen, proto not tcp); the flattened top-level count
	// must include all three as distinct bullets, not one bullet containing
	// its own nested "N validation error(s):" block.
	badName := "-" + strings.Repeat("a", 32) // 33 bytes: too long AND leading hyphen
	yaml := strings.Replace(validStandalone,
		`  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s,  max_ttl: 60s,  listener_expectation: absent, verification: tcp_rst }`,
		`  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s,  max_ttl: 60s,  listener_expectation: absent, verification: tcp_rst }
  `+badName+`: { kind: gate, proto: udp, ports: [9999], default_ttl: 30s,  max_ttl: 60s,  listener_expectation: present }`, 1)

	p := parseOrFail(t, yaml)
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want errors")
	}
	msg := err.Error()

	if strings.Count(msg, "validation error(s):") != 1 {
		t.Fatalf("error is nested rather than flat (found more than one \"validation error(s):\" header): %q", msg)
	}
	// HasPrefix, not Contains: "13 validation error(s):" also contains the
	// substring "3 validation error(s):", so Contains would pass on a
	// double-digit miscount. The count is always the very first thing
	// joinedError.Error() renders, so an exact prefix is the right anchor.
	if !strings.HasPrefix(msg, "3 validation error(s):") {
		t.Fatalf("error %q does not report a flat top-level count of 3", msg)
	}
	// "is 33 bytes, limit is 32" (not bare "limit is 32"): MaxServiceNameLen
	// and DefaultMaxOperators are both 32, so a bare "limit is 32" would
	// also match an unrelated too-many-operators message elsewhere in this
	// package. The byte count anchors it to this specific name-length check.
	for _, want := range []string{"is 33 bytes, limit is 32", "may not begin or end with a hyphen", "only tcp"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing mention of %q", msg, want)
		}
	}
}

// M2's three fleet-mode keys are optional: a standalone document omitting
// them (as validStandalone does) must still parse, with the zero values that
// mean "standalone, no pull loop" — HubURL empty, BundleSigners nil,
// EnrollmentFloor zero.
func TestConfig_ParseStandalone_OmittedFleetKeysAreZero(t *testing.T) {
	p := parseOrFail(t, validStandalone)
	if p.HubURL != "" {
		t.Errorf("HubURL = %q, want empty when hub_url is absent", p.HubURL)
	}
	if p.BundleSigners != nil {
		t.Errorf("BundleSigners = %v, want nil when bundle_signers is absent", p.BundleSigners)
	}
	if p.EnrollmentFloor != 0 {
		t.Errorf("EnrollmentFloor = %d, want 0 when enrollment_floor is absent", p.EnrollmentFloor)
	}
}

// The positive counterpart: all three keys, present, land on Policy exactly.
func TestConfig_ParseStandalone_ParsesFleetKeys(t *testing.T) {
	yaml := validStandalone + `
hub_url: "https://hub.example.com"
bundle_signers: ["0101010101010101010101010101010101010101010101010101010101010101"]
enrollment_floor: 47
`
	p := parseOrFail(t, yaml)
	if p.HubURL != "https://hub.example.com" {
		t.Errorf("HubURL = %q, want https://hub.example.com", p.HubURL)
	}
	if p.EnrollmentFloor != 47 {
		t.Errorf("EnrollmentFloor = %d, want 47", p.EnrollmentFloor)
	}
	want := [32]byte{}
	for i := range want {
		want[i] = 0x01
	}
	if len(p.BundleSigners) != 1 || p.BundleSigners[0] != want {
		t.Fatalf("BundleSigners = %x, want [%x]", p.BundleSigners, want)
	}
}

// I-6, applied to bundle_signers: a direct ParseStandalone failure-path test
// for the new key, not only one that exercises it as a side effect.
func TestConfig_ParseStandalone_RejectsMalformedBundleSigner(t *testing.T) {
	yaml := validStandalone + `
bundle_signers: ["not-hex"]
`
	_, err := config.ParseStandalone([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "bundle_signers") {
		t.Fatalf("ParseStandalone() = %v, want an error naming bundle_signers", err)
	}
}

// A bundle_signers entry that is valid hex but the wrong length must also be
// rejected — the length check is a distinct control from the hex-validity
// one, and a mutation deleting only the length check must not pass this
// same test the hex-validity one already exercises.
func TestConfig_ParseStandalone_RejectsWrongLengthBundleSigner(t *testing.T) {
	yaml := validStandalone + `
bundle_signers: ["01020304"]
`
	_, err := config.ParseStandalone([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "bundle_signers") {
		t.Fatalf("ParseStandalone() = %v, want an error naming bundle_signers", err)
	}
}

func TestConfig_Validate_RejectsDuplicateOperatorEncryptionKeys(t *testing.T) {
	// The same failure one field over, and worse. KeyID is the signing key,
	// so two operators sharing an ENCRYPTION key have distinct KeyIDs and
	// pass the signing-key check. But TrialOpen stops at the first shared
	// secret that decrypts and returns on a KeyID mismatch, so the operator
	// that sorts second here is silently unknockable on every host forever.
	//
	// The dup shares only the encryption key: its signing key is changed, so
	// the signing-key check cannot fire and only the new encryption-key check
	// can refuse this. A dup that shared both keys would be rejected by the
	// older check and prove nothing about this one.
	p := parseOrFail(t, validStandalone)
	dup := p.Operators[0]
	dup.Identity.Name = "laptop-secondary"
	dup.Identity.Signing[0] ^= 0xFF // a distinct signing key, so a distinct KeyID

	if dup.Identity.KeyID() == p.Operators[0].Identity.KeyID() {
		t.Fatal("precondition: the two operators must have distinct KeyIDs, or the signing-key check " +
			"would be the thing refusing and this test would not exercise the encryption-key check")
	}
	p.Operators = append(p.Operators, dup)

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want a duplicate-encryption-key error")
	}
	if !strings.Contains(err.Error(), "shares an encryption key") {
		t.Fatalf("Validate() = %v, want it to report a shared encryption key", err)
	}
	if !strings.Contains(err.Error(), "laptop-secondary") || !strings.Contains(err.Error(), "laptop-primary") {
		t.Fatalf("Validate() = %v, want it to name both operators", err)
	}
}

// rotationPolicy returns a Policy parsed from validStandalone with a valid
// port_rotation block attached: knockport's own default window and range,
// and a correctly-sized (but all-zero) secret. None of the base fixture's
// declared ports (ssh/22, canary/62202) or the http carrier (unset here)
// fall inside the default range, so this is a clean positive control — every
// test below mutates exactly one field of it away from valid.
func rotationPolicy(t *testing.T) *config.Policy {
	t.Helper()
	p := parseOrFail(t, validStandalone)
	p.PortRotation = &config.PortRotation{
		Secret:  make([]byte, knockport.SecretSize),
		Window:  knockport.DefaultWindow,
		RangeLo: knockport.DefaultRangeLo,
		RangeHi: knockport.DefaultRangeHi,
	}
	return p
}

func TestConfig_Validate_RotationRangeOverlappingEphemeralIsRefused(t *testing.T) {
	p := rotationPolicy(t)
	p.PortRotation.RangeLo = 40000
	p.PortRotation.RangeHi = 50000 // inside the kernel ephemeral range 32768-60999
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "ephemeral") {
		t.Fatalf("a range overlapping the ephemeral range must be refused: %v", err)
	}
}

func TestConfig_Validate_RotationRangeOverAGatedServicePortIsRefused(t *testing.T) {
	p := rotationPolicy(t)
	// ssh is a gate on tcp/22; the range drop is udp, but a range that swallows a
	// gated port is still refused so an operator never bands a service away.
	p.PortRotation.RangeLo = 20
	p.PortRotation.RangeHi = 30 // covers 22
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("a range covering a gated service port must be refused: %v", err)
	}
}

func TestConfig_Validate_RotationRangeOverTheHTTPCarrierIsRefused(t *testing.T) {
	p := rotationPolicy(t)
	p.SPAHTTPPort = 25000
	p.PortRotation.RangeLo = 20000
	p.PortRotation.RangeHi = 30000 // covers 25000
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("a range covering the http carrier port must be refused: %v", err)
	}
}

func TestConfig_Validate_RotationRangeInvertedIsRefused(t *testing.T) {
	p := rotationPolicy(t)
	p.PortRotation.RangeLo = 30000
	p.PortRotation.RangeHi = 20000
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "range") {
		t.Fatalf("lo > hi must be refused: %v", err)
	}
}

func TestConfig_Validate_RotationSecretWrongLengthIsRefused(t *testing.T) {
	p := rotationPolicy(t)
	p.PortRotation.Secret = make([]byte, 16)
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("a secret that is not 32 bytes must be refused: %v", err)
	}
}

func TestConfig_Validate_RotationAllowsSPAPortZero(t *testing.T) {
	p := rotationPolicy(t)
	p.SPAPort = 0 // rotation drives the port; the fixed spa_port is not required
	if err := p.Validate(); err != nil {
		t.Fatalf("rotation must not require spa_port: %v", err)
	}
}

func TestConfig_Validate_FixedModeStillRequiresSPAPort(t *testing.T) {
	p := rotationPolicy(t)
	p.PortRotation = nil
	p.SPAPort = 0
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "spa_port") {
		t.Fatalf("fixed mode must still require spa_port: %v", err)
	}
}
