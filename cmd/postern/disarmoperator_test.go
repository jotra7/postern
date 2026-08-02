package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/config"
)

// --disarm-operator (#30) is init-standalone's easy way to express the split
// design section 6 recommends for a fleet: the everyday operator holds
// [ssh, confirm, liveness], and a separate recovery operator holds [disarm]
// alone. These tests exercise the flag itself; examples/inventory.yaml and
// internal/config/inventory_test.go cover the fleet inventory form of the
// same split.

// findOperator returns the operator named name, or nil.
func findOperator(p *config.Policy, name string) *config.Operator {
	for i := range p.Operators {
		if p.Operators[i].Identity.Name == name {
			return &p.Operators[i]
		}
	}
	return nil
}

func TestMain_InitStandalone_DisarmOperatorIsGrantedDisarmAlone(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	mainSign, mainEnc := publicKeyPairB64(t)
	recoverySign, recoveryEnc := publicKeyPairB64(t)

	code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--operator", "laptop-primary="+mainSign+","+mainEnc,
		"--disarm-operator", "recovery="+recoverySign+","+recoveryEnc,
	)
	if code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}

	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("the generated config does not parse:\n%v\n%s", err, body)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the generated config does not validate:\n%v\n%s", err, body)
	}

	recovery := findOperator(policy, "recovery")
	if recovery == nil {
		t.Fatalf("no operator named recovery in the generated config:\n%s", body)
	}
	if len(recovery.Grants) != 1 || len(recovery.Grants[0].Services) != 1 || recovery.Grants[0].Services[0] != "disarm" {
		t.Fatalf("recovery's grants = %+v, want exactly one grant of [disarm]", recovery.Grants)
	}

	// The everyday operator is untouched by the flag: --operator alone still
	// defaults to every service, so a standalone deployment that never uses
	// --disarm-operator keeps its disarm reachable by default (#30 does not
	// make disarm unreachable without a second key).
	main := findOperator(policy, "laptop-primary")
	if main == nil {
		t.Fatalf("no operator named laptop-primary in the generated config:\n%s", body)
	}
	wantMain := []string{"ssh", "confirm", "disarm", "liveness"}
	if len(main.Grants) != 1 || !equalStrings(main.Grants[0].Services, wantMain) {
		t.Fatalf("laptop-primary's grants = %+v, want %v", main.Grants, wantMain)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A colon-delimited service list on --disarm-operator would look exactly
// like --operator's own [:service,service] syntax and quietly do nothing
// useful — the whole grant is fixed at [disarm] regardless — so it is
// refused rather than silently accepted, the same reasoning enrollssh.go's
// own flag checks are built on.
//
// Mutation verified: deleting the `strings.Contains(v, ":")` check in
// disarmOperatorList.Set fails this — the run then succeeds and the
// assertion that the exit is a usage refusal fails.
func TestMain_InitStandalone_DisarmOperatorRefusesAServiceList(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--operator", "laptop-primary="+sign+","+enc,
		"--disarm-operator", "recovery="+sign+","+enc+":disarm,confirm",
	)
	if code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "always [disarm]") {
		t.Fatalf("the refusal does not explain why:\n%s", errBuf.String())
	}
}

// A --disarm-operator naming the same operator as --operator would produce
// two operator entries the agent's own name-based lookups cannot
// distinguish; refused at generation time rather than shipped as an
// ambiguous config.
func TestMain_InitStandalone_DisarmOperatorRefusesTheSameNameAsAnOperator(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--operator", "laptop-primary="+sign+","+enc,
		"--disarm-operator", "laptop-primary="+sign+","+enc,
	)
	if code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "its own name") {
		t.Fatalf("the refusal does not say what to do about it:\n%s", errBuf.String())
	}
}

// A host enrolled with only a --disarm-operator and no ordinary --operator
// would satisfy nothing an ssh knock could ever use: --disarm-operator must
// not count toward "at least one --operator is required", or a host could be
// generated whose only identity can disarm postern and nothing else.
//
// Mutation verified: merging --disarm-operator into o.operators before the
// "at least one operator" switch, instead of after, fails this — the run
// then succeeds where it must refuse.
func TestMain_InitStandalone_DisarmOperatorAloneDoesNotSatisfyTheOperatorRequirement(t *testing.T) {
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e,
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--disarm-operator", "recovery="+sign+","+enc,
	)
	if code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "--operator is required") {
		t.Fatalf("the refusal does not name the missing flag:\n%s", errBuf.String())
	}
}
