package config_test

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gopkg.in/yaml.v3"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

// fullyPopulatedPolicy builds a *Policy with every field on Policy, Service,
// Operator, and Grant set to a non-zero value, including a fail-closed
// service, one service for each ListenerExpectation value, an action
// service, an operator with AllowSourceCIDR true and both prefix minimums
// set, and a non-default FreshnessWindowMax.
//
// The "confirm" action service also carries proto/ports/TTL/posture values,
// which Service.Validate would reject for an action — but ParseStandalone
// copies those fields through unconditionally regardless of Kind (see
// standalone.go), and this fixture exists only to hold MarshalStandalone and
// ParseStandalone to being exact inverses, not to be a valid Policy on its
// own terms.
//
// The same applies to script_path and script_timeout on the nftables-backed
// services: Service.Validate rejects those fields on any backend but
// "script", and they are set here for the one reason every other
// semantically-wrong value in this fixture is — the reflective test below
// requires no field on Service to be zero, and a field the round trip never
// carries a value for is a field the round trip never tests.
func fullyPopulatedPolicy(t *testing.T) *config.Policy {
	t.Helper()

	var fleetID, hostID [16]byte
	for i := range fleetID {
		fleetID[i] = byte(i + 1)
		hostID[i] = byte(i + 17)
	}

	var sigA, encA, sigB, encB, bundleSigner [32]byte
	for i := range sigA {
		sigA[i] = byte(i + 1)
		encA[i] = byte(i + 33)
		sigB[i] = byte(i + 65)
		encB[i] = byte(i + 97)
		bundleSigner[i] = byte(i + 129)
	}
	rotationSecret := make([]byte, 32)
	for i := range rotationSecret {
		rotationSecret[i] = byte(i + 161)
	}

	return &config.Policy{
		FleetID:            fleetID,
		HostID:             hostID,
		Revision:           7,
		SPAPort:            62201,
		SPAHTTPPort:        62202,
		AlwaysAllowIface:   "tailscale0",
		ConsoleRecovery:    true,
		Console:            "https://provider.example/console",
		RecoveryService:    "ssh",
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 48 * time.Hour, // non-default; DefaultFreshnessWindowMax is 24h
		MaxOperators:       config.DefaultMaxOperators,
		HubURL:             "https://hub.example.com",
		BundleSigners:      [][32]byte{bundleSigner},
		EnrollmentFloor:    47,
		PortRotation: &config.PortRotation{
			Secret:  rotationSecret,
			Window:  10 * time.Minute,
			RangeLo: 20000,
			RangeHi: 30000,
		},
		Services: map[string]config.Service{
			"ssh": {
				Name:                "ssh",
				Kind:                config.KindGate,
				Proto:               "tcp",
				Ports:               []uint16{22},
				DefaultTTL:          120 * time.Second,
				MaxTTL:              300 * time.Second,
				FailPosture:         config.PostureClosed, // the fail-closed service
				ListenerExpectation: config.ListenerPresent,
				Verification:        config.VerificationTCPRST,
				Backend:             config.BackendNFTables,
				ScriptPath:          "/opt/postern/ssh-gate.sh",
				ScriptTimeout:       9 * time.Second,
				Forward:             &config.Forward{To: netip.MustParseAddr("10.10.0.1"), Port: 2201},
			},
			"canary": {
				Name:                "canary",
				Kind:                config.KindGate,
				Proto:               "tcp",
				Ports:               []uint16{62202},
				DefaultTTL:          30 * time.Second,
				MaxTTL:              60 * time.Second,
				FailPosture:         config.PostureOpen,
				ListenerExpectation: config.ListenerAbsent,
				Verification:        config.VerificationTCPRST,
				Backend:             config.BackendNFTables,
				ScriptPath:          "/opt/postern/canary-gate.sh",
				ScriptTimeout:       11 * time.Second,
				Forward:             &config.Forward{To: netip.MustParseAddr("10.10.0.2"), Port: 2202},
			},
			"audit": {
				Name:                "audit",
				Kind:                config.KindGate,
				Proto:               "tcp",
				Ports:               []uint16{9000},
				DefaultTTL:          15 * time.Second,
				MaxTTL:              45 * time.Second,
				FailPosture:         config.PostureClosed,
				ListenerExpectation: config.ListenerUnchecked,
				Verification:        config.VerificationTCPRST,
				Backend:             config.BackendScript,
				ScriptPath:          "/opt/postern/audit-gate.sh",
				ScriptTimeout:       13 * time.Second,
				Forward:             &config.Forward{To: netip.MustParseAddr("fd00::3"), Port: 2203},
			},
			"confirm": {
				Name: "confirm",
				Kind: config.KindAction,
				// Not semantically valid for an action (see doc comment
				// above); present only so no field on this struct is zero.
				Proto:               "tcp",
				Ports:               []uint16{1},
				DefaultTTL:          5 * time.Second,
				MaxTTL:              10 * time.Second,
				FailPosture:         config.PostureOpen,
				ListenerExpectation: config.ListenerPresent,
				Verification:        config.VerificationTCPRST,
				Backend:             config.BackendNFTables,
				ScriptPath:          "/opt/postern/confirm-gate.sh",
				ScriptTimeout:       17 * time.Second,
				Forward:             &config.Forward{To: netip.MustParseAddr("10.10.0.4"), Port: 2204},
			},
		},
		Operators: []config.Operator{
			{
				Identity: identity.PublicIdentity{
					Name:       "laptop-primary",
					Alg:        identity.AlgEd25519X25519,
					Signing:    sigA,
					Encryption: encA,
				},
				Grants: []config.Grant{
					{
						Services:        []string{"ssh", "confirm"},
						MaxTTL:          300 * time.Second,
						AllowSourceCIDR: true,
						MinIPv4Prefix:   24,
						MinIPv6Prefix:   64,
					},
				},
			},
			{
				Identity: identity.PublicIdentity{
					Name:       "probe-remote",
					Alg:        identity.AlgEd25519X25519,
					Signing:    sigB,
					Encryption: encB,
				},
				Grants: []config.Grant{
					{
						Services:        []string{"canary"},
						MaxTTL:          60 * time.Second,
						AllowSourceCIDR: true,
						MinIPv4Prefix:   32,
						MinIPv6Prefix:   128,
					},
				},
			},
		},
	}
}

// The bundle payload is a standalone config file, so the marshaller and the
// parser have to be exact inverses. If they are not, a fleet host runs a
// policy subtly different from the one the operator reviewed in the
// inventory diff — the drift M2 exists to detect, introduced by the tool
// that is supposed to detect it.
func TestConfig_MarshalStandalone_RoundTripsThroughTheParser(t *testing.T) {
	want := fullyPopulatedPolicy(t)

	data, err := config.MarshalStandalone(want)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	got, err := config.ParseStandalone(data)
	if err != nil {
		t.Fatalf("ParseStandalone of our own output: %v\n---\n%s", err, data)
	}
	// netip.Addr keeps its representation unexported, so go-cmp refuses to walk
	// into one and needs telling that equality on it is the language's own.
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("round trip lost or changed fields (-want +got):\n%s", diff)
	}
}

// breakglass_services is what a human reads when auditing a fleet-compiled
// bundle's break-glass declarations before deploying it — M2's whole
// motivation — so it needs its own assertion on the marshalled bytes. The
// round-trip test above cannot catch a regression here: ParseStandalone only
// consults breakglass_services to default a service's fail_posture when that
// key is *absent* from the document (standalone.go), and the round-trip
// fixture must set an explicit, non-zero FailPosture on every service to
// satisfy the reflective fixture test — so whatever MarshalStandalone writes
// into breakglass_services, ParseStandalone's resulting Policy is identical.
// Deleting the computation entirely still passes both other tests in this
// file; this one is what actually observes it.
func TestConfig_MarshalStandalone_EmitsBreakglassServicesForFailOpenGates(t *testing.T) {
	p := fullyPopulatedPolicy(t)

	data, err := config.MarshalStandalone(p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}

	var doc struct {
		BreakglassServices []string `yaml:"breakglass_services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("yaml.Unmarshal of marshalled output: %v\n---\n%s", err, data)
	}

	// Of the fixture's services, only "canary" is Kind: gate with
	// FailPosture: open. "confirm" also carries FailPosture: open, but it is
	// Kind: action — the block under test gates on Kind == KindGate as well
	// as FailPosture, and this fixture is exactly the case that would go
	// unnoticed if that Kind check were dropped.
	want := []string{"canary"}
	if diff := cmp.Diff(want, doc.BreakglassServices); diff != "" {
		t.Errorf("breakglass_services in marshalled output (-want +got):\n%s", diff)
	}
}

// A round trip over a struct with unset fields passes while dropping exactly
// the fields it never set. This asserts the fixture itself is fully
// populated, by reflection, so the test above cannot quietly weaken as
// Policy grows fields.
func TestConfig_MarshalStandalone_FixtureLeavesNoFieldZero(t *testing.T) {
	assertNoZeroFields(t, reflect.ValueOf(*fullyPopulatedPolicy(t)), "Policy")
}

// assertNoZeroFields walks structs, maps, and slices and fails on any
// zero-valued field or empty container, naming its path. Fixed-size arrays
// (such as [16]byte identifiers and [32]byte keys) are treated as a single
// leaf value rather than recursed into byte by byte, since a mix of zero and
// non-zero bytes within one key is not itself a hole in the fixture.
func assertNoZeroFields(t *testing.T, v reflect.Value, path string) {
	t.Helper()

	switch v.Kind() {
	case reflect.Pointer:
		// Recursed into rather than treated as a leaf. A non-nil pointer is
		// not IsZero, so *config.Forward pointing at an empty Forward would
		// otherwise satisfy this test while the round trip carried neither of
		// its fields.
		if v.IsNil() {
			t.Errorf("%s: is a nil pointer", path)
			return
		}
		assertNoZeroFields(t, v.Elem(), path)
	case reflect.Struct:
		// netip.Addr is a leaf. Its unexported representation holds a zero
		// high half for every IPv4 address, so recursing would report a
		// perfectly populated address as an unset field.
		if v.Type() == reflect.TypeOf(netip.Addr{}) {
			if v.IsZero() {
				t.Errorf("%s: is zero-valued", path)
			}
			return
		}
		vt := v.Type()
		for i := 0; i < v.NumField(); i++ {
			assertNoZeroFields(t, v.Field(i), path+"."+vt.Field(i).Name)
		}
	case reflect.Map:
		if v.Len() == 0 {
			t.Errorf("%s: map has no entries", path)
			return
		}
		iter := v.MapRange()
		for iter.Next() {
			assertNoZeroFields(t, iter.Value(), fmt.Sprintf("%s[%v]", path, iter.Key().Interface()))
		}
	case reflect.Slice:
		if v.Len() == 0 {
			t.Errorf("%s: slice has no entries", path)
			return
		}
		for i := 0; i < v.Len(); i++ {
			assertNoZeroFields(t, v.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
	default:
		if v.IsZero() {
			t.Errorf("%s: is zero-valued", path)
		}
	}
}
