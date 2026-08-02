package config_test

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

func TestConfig_ServiceID_IsFirst16OfSHA256OfName(t *testing.T) {
	s := config.Service{Name: "ssh", Kind: config.KindGate}
	sum := sha256.Sum256([]byte("ssh"))
	var want [16]byte
	copy(want[:], sum[:16])
	if got := s.ID(); got != want {
		t.Fatalf("ID() = %x, want %x", got, want)
	}
}

func TestConfig_ValidateServiceName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "ssh", false},
		{"with digits", "postgres5432", false},
		{"with hyphen", "admin-panel", false},
		{"max length", strings.Repeat("a", 32), false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 33), true},
		{"uppercase", "SSH", true},
		{"underscore", "admin_panel", true},
		{"leading hyphen", "-ssh", true},
		{"trailing hyphen", "ssh-", true},
		{"non-ascii", "sshé", true},
		{"space", "my service", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := config.ValidateServiceName(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateServiceName(%q) = nil, want error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateServiceName(%q) = %v, want nil", tc.input, err)
			}
		})
	}
}

func TestConfig_Service_Validate(t *testing.T) {
	gate := func(mut func(*config.Service)) config.Service {
		s := config.Service{
			Name:                "postgres",
			Kind:                config.KindGate,
			Proto:               "tcp",
			Ports:               []uint16{5432},
			DefaultTTL:          300 * time.Second,
			MaxTTL:              900 * time.Second,
			ListenerExpectation: config.ListenerPresent,
		}
		if mut != nil {
			mut(&s)
		}
		return s
	}

	tests := []struct {
		name    string
		svc     config.Service
		wantErr string
	}{
		{"valid gate", gate(nil), ""},
		{
			"udp rejected in v1",
			gate(func(s *config.Service) { s.Proto = "udp" }),
			"only tcp",
		},
		{
			// ttl_seconds is uint16 on the wire, so a larger max_ttl cannot be
			// requested and must not be configurable (design section 5).
			"max_ttl above the uint16 wire limit",
			gate(func(s *config.Service) { s.MaxTTL = 70000 * time.Second }),
			"65535",
		},
		{
			"default_ttl above max_ttl",
			gate(func(s *config.Service) { s.DefaultTTL = 2000 * time.Second }),
			"default_ttl",
		},
		{
			"gate with no ports",
			gate(func(s *config.Service) { s.Ports = nil }),
			"at least one port",
		},
		{
			"action with ports",
			config.Service{Name: "disarm", Kind: config.KindAction, Ports: []uint16{22}},
			"ports",
		},
		{
			"action with a fail posture",
			config.Service{Name: "disarm", Kind: config.KindAction, FailPosture: config.PostureClosed},
			"fail_posture",
		},
		{
			"action with a listener expectation",
			config.Service{Name: "confirm", Kind: config.KindAction, ListenerExpectation: config.ListenerPresent},
			"listener_expectation",
		},
		{
			"reserved name used as a gate",
			gate(func(s *config.Service) { s.Name = "disarm" }),
			"reserved",
		},
		{
			"valid action",
			config.Service{Name: "confirm", Kind: config.KindAction},
			"",
		},
		{
			"unknown kind",
			config.Service{Name: "ssh", Kind: config.Kind("weird")},
			"kind",
		},
		{
			"valid tcp_rst verification on an absent listener",
			gate(func(s *config.Service) {
				s.ListenerExpectation = config.ListenerAbsent
				s.Verification = config.VerificationTCPRST
			}),
			"",
		},
		{
			"verification with an unsupported value",
			gate(func(s *config.Service) {
				s.ListenerExpectation = config.ListenerAbsent
				s.Verification = "bogus"
			}),
			"bogus",
		},
		{
			// A tcp_rst check on a port with a listener would report failure
			// forever: a successful connection is not a reset.
			"verification declared on a present listener",
			gate(func(s *config.Service) {
				s.ListenerExpectation = config.ListenerPresent
				s.Verification = config.VerificationTCPRST
			}),
			"only meaningful when listener_expectation is absent",
		},
		{
			"verification declared on an unchecked listener",
			gate(func(s *config.Service) {
				s.ListenerExpectation = config.ListenerUnchecked
				s.Verification = config.VerificationTCPRST
			}),
			"only meaningful when listener_expectation is absent",
		},
		{
			"action with a verification",
			config.Service{Name: "confirm", Kind: config.KindAction, Verification: config.VerificationTCPRST},
			"may not declare verification",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.svc.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestConfig_ErrorList_ReportsEveryProblemAtOnce checks that Validate
// accumulates every failure in one pass rather than stopping at the first.
// An operator fixing a config file should see all of it, not the first line
// that happened to fail.
//
// The substrings checked below are deliberately specific rather than bare
// words: "port" alone is a substring of "supports", so a proto-only error
// ("v1 supports only tcp") could satisfy a bare "port" check even with the
// ports-empty accumulation entirely broken, proving nothing about
// accumulation. "at least one port" can only come from the ports-empty
// check; "service name" can only come from ValidateServiceName; "only tcp"
// can only come from the proto check. Each phrase is anchored to the one
// check that produces it, so the test can only pass if all three checks
// actually ran and their results were kept.
func TestConfig_ErrorList_ReportsEveryProblemAtOnce(t *testing.T) {
	svc := config.Service{
		Name:  "BAD_NAME",
		Kind:  config.KindGate,
		Proto: "udp",
		Ports: nil,
	}
	err := svc.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want errors")
	}
	msg := err.Error()
	for _, want := range []string{"service name", "only tcp", "at least one port"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing mention of %q", msg, want)
		}
	}
}

// TestConfig_ServiceValidate_FlattensNameErrorsWithAccurateCount is a
// regression test for a known defect: Validate() used to wrap the whole
// result of ValidateServiceName as one Addf("%v", err) item, so a name with
// two independent problems produced a nested "N validation error(s):" block
// inside a single bullet, and the top-level count undercounted. This name
// has two independent problems on its own (too long, and starts with a
// hyphen — the invalid-character scan never runs, since '-' is a legal
// character, so these are genuinely two separate checks, not one check
// firing twice), plus a third, unrelated proto problem. The top-level count
// must be 3, and there must be exactly one "N validation error(s):" header
// in the message, not one nested inside another.
func TestConfig_ServiceValidate_FlattensNameErrorsWithAccurateCount(t *testing.T) {
	svc := config.Service{
		Name:                "-" + strings.Repeat("a", 32), // 33 bytes: too long AND leading hyphen
		Kind:                config.KindGate,
		Proto:               "udp",
		Ports:               []uint16{80},
		DefaultTTL:          10 * time.Second,
		MaxTTL:              20 * time.Second,
		ListenerExpectation: config.ListenerPresent,
	}
	err := svc.Validate()
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
