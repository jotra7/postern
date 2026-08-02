package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

// fleetSignerHex is a throwaway raw Ed25519 public key in the encoding
// --bundle-signers and the config's own bundle_signers list both take.
func fleetSignerHex(t *testing.T) string {
	t.Helper()
	s, err := identity.Generate("bundle-signer")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub := s.Public().Signing
	return hex.EncodeToString(pub[:])
}

// initFleetHost runs the real init-standalone for hostName with whatever
// extra flags a test wants, and returns the parsed policy it left on disk.
// Nothing is injected: this is the command the documentation tells an
// operator to type, and the config under test is the file it wrote.
func initFleetHost(t *testing.T, hostName string, extra ...string) (*config.Policy, string) {
	t.Helper()
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	args := append([]string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", hostName,
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}, extra...)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("no generated config: %v", err)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("the generated config does not parse:\n%v\n%s", err, body)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the generated config does not validate, so the agent would refuse to start on the "+
			"host this command just enrolled:\n%v\n%s", err, body)
	}
	return policy, string(body)
}

// initFleetHostExpectingRefusal runs the real init-standalone and requires it
// to refuse, returning what it printed on stderr.
func initFleetHostExpectingRefusal(t *testing.T, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	e, _, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)
	args := append([]string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary=" + sign + "," + enc,
	}, extra...)
	if code := runCLI(t, e, args...); code != exitUsage {
		t.Fatalf("exit = %d, want %d (a usage refusal); stderr:\n%s", code, exitUsage, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "postern.yaml")); err == nil {
		t.Error("a config was written despite the refusal")
	}
	return errBuf.String()
}

// The blocker, in one test. Two hosts enrolled the documented way have to
// land in ONE fleet, because bundle.Open refuses a bundle whose fleet_id does
// not match the fetching host's own — so two hosts that each minted their own
// fleet_id can never be served by one hub, and the entire bundle plane is
// unreachable by an operator following the instructions.
func TestMain_InitStandalone_FleetIDFlagPutsTwoHostsInOneFleet(t *testing.T) {
	first, _ := initFleetHost(t, "web-01")
	shared := hex.EncodeToString(first.FleetID[:])

	second, _ := initFleetHost(t, "web-02", "--fleet-id", shared)
	if second.FleetID != first.FleetID {
		t.Fatalf("second host's fleet_id = %x, want %x: --fleet-id did not join the existing fleet, so "+
			"bundle.Open would reject every bundle either host fetched", second.FleetID, first.FleetID)
	}
	// The host identity still rotates. fleet_id is the value a fleet shares;
	// host_id is the one that must never be shared, because the hub keys every
	// bundle and every heartbeat by it.
	if second.HostID == first.HostID {
		t.Fatal("both hosts got the same host_id; --fleet-id must join a fleet, not clone a host")
	}
}

// And the default is unchanged: without the flag every host still mints its
// own fleet, which is what a standalone enrollment wants.
//
// This is the control for the test above. Without it, an implementation that
// hard-coded one fleet_id for every host would pass that test and would
// silently put unrelated standalone hosts into a shared fleet.
func TestMain_InitStandalone_WithoutTheFleetIDFlagEachHostMintsItsOwn(t *testing.T) {
	first, _ := initFleetHost(t, "web-01")
	second, _ := initFleetHost(t, "web-02")
	if first.FleetID == second.FleetID {
		t.Fatalf("two independent enrollments produced the same fleet_id %x", first.FleetID)
	}
}

// The three keys Task 10 added to the standalone form, reachable from the
// command line at last — and asserted through the same wiring cmd_agent_linux
// uses, so what is proven is that a generated fleet config actually produces
// a puller, not merely that three strings landed in a file.
func TestMain_InitStandalone_HubFlagsProduceAConfigThatBuildsAPuller(t *testing.T) {
	signer := fleetSignerHex(t)
	policy, body := initFleetHost(t, "web-01",
		"--hub-url", "https://hub.example.com",
		"--bundle-signers", signer,
		"--enrollment-floor", "47")

	if policy.HubURL != "https://hub.example.com" {
		t.Errorf("HubURL = %q, want https://hub.example.com\n%s", policy.HubURL, body)
	}
	if policy.EnrollmentFloor != 47 {
		t.Errorf("EnrollmentFloor = %d, want 47\n%s", policy.EnrollmentFloor, body)
	}
	if len(policy.BundleSigners) != 1 || hex.EncodeToString(policy.BundleSigners[0][:]) != signer {
		t.Fatalf("BundleSigners = %x, want [%s]\n%s", policy.BundleSigners, signer, body)
	}

	// The wiring cmd_agent_linux.go performs, verbatim in shape: a config that
	// names a hub but cannot build a puller is a config posternd refuses to
	// start from, which on a fail-closed host is a lockout.
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, err = agent.NewPuller(agent.PullConfig{
		HubURL:          policy.HubURL,
		FleetID:         policy.FleetID,
		HostID:          policy.HostID,
		HostSigner:      host,
		TrustedSigners:  policy.BundleSigners,
		EnrollmentFloor: policy.EnrollmentFloor,
		StatePath:       filepath.Join(t.TempDir(), "bundle.json"),
	}, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("the generated fleet config does not build a puller, so posternd would not start: %v", err)
	}
}

// A standalone enrollment is byte-for-byte what it was before fleet mode
// existed: hub_url is the switch that decides whether a pull loop starts at
// all, and a generated empty one is indistinguishable in a diff from a value
// somebody meant to fill in.
func TestMain_InitStandalone_OmitsTheFleetKeysWhenNoHubIsNamed(t *testing.T) {
	policy, body := initFleetHost(t, "web-01")
	for _, key := range []string{"hub_url", "bundle_signers", "enrollment_floor"} {
		if strings.Contains(body, key) {
			t.Errorf("a standalone config carries %q:\n%s", key, body)
		}
	}
	if policy.HubURL != "" {
		t.Errorf("HubURL = %q, want empty for a standalone enrollment", policy.HubURL)
	}
}

// enrollment_floor is emitted at its zero value too, whenever a hub is named.
// Zero is a deliberate answer here — accept any version this fleet's signers
// have produced — and a key absent from a fleet config is a question an
// operator has to go and re-answer on a host they may not be able to reach.
func TestMain_InitStandalone_EmitsAZeroEnrollmentFloorWhenAHubIsNamed(t *testing.T) {
	_, body := initFleetHost(t, "web-01",
		"--hub-url", "https://hub.example.com",
		"--bundle-signers", fleetSignerHex(t))
	if !strings.Contains(body, "enrollment_floor: 0") {
		t.Fatalf("a fleet config with no --enrollment-floor omits the key:\n%s", body)
	}
}

// The four refusals, each named by the flag that fixes it. Every one of these
// writes a configuration that is either unstartable or inert, and enrollment
// is the last moment the operator still has a working way in.
func TestMain_InitStandalone_RefusesAnIncompleteFleetConfiguration(t *testing.T) {
	signer := fleetSignerHex(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			// posternd would refuse to build a puller with an empty trusted
			// set, so this config cannot start the agent at all.
			name: "hub with no signers",
			args: []string{"--hub-url", "https://hub.example.com"},
			want: "--hub-url without --bundle-signers",
		},
		{
			name: "signers with no hub",
			args: []string{"--bundle-signers", signer},
			want: "--bundle-signers",
		},
		{
			name: "floor with no hub",
			args: []string{"--enrollment-floor", "47"},
			want: "--enrollment-floor",
		},
		{
			// The value an operator copies by hand out of another host's
			// postern.yaml, which is exactly the operation a truncated paste
			// survives. The symptom would be every bundle rejected as
			// wrong_fleet, silently, on a host nobody is watching.
			name: "truncated fleet id",
			args: []string{"--fleet-id", "f5c8e44fefd5d08c314b2ca922d0d2"},
			want: "--fleet-id",
		},
		{
			name: "fleet id is not hex",
			args: []string{"--fleet-id", "not-hex-at-all-not-hex-at-all-xy"},
			want: "--fleet-id",
		},
		{
			name: "bundle signer is not a key",
			args: []string{"--hub-url", "https://hub.example.com", "--bundle-signers", "abcd"},
			want: "--bundle-signers",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr := initFleetHostExpectingRefusal(t, tc.args...)
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("the refusal does not name %q, so an operator cannot tell which flag to fix:\n%s",
					tc.want, stderr)
			}
		})
	}
}

// A fleet id pasted in upper case is the same fleet id. Normalising here
// rather than letting it through means the generated file does not depend on
// how somebody's terminal cased a value they copied.
func TestMain_InitStandalone_NormalisesTheCaseOfAPastedFleetID(t *testing.T) {
	first, _ := initFleetHost(t, "web-01")
	shared := hex.EncodeToString(first.FleetID[:])

	second, body := initFleetHost(t, "web-02", "--fleet-id", strings.ToUpper(shared))
	if second.FleetID != first.FleetID {
		t.Fatalf("second host's fleet_id = %x, want %x", second.FleetID, first.FleetID)
	}
	if !strings.Contains(body, shared) {
		t.Fatalf("the generated config does not carry the canonical lower-case fleet_id:\n%s", body)
	}
}
