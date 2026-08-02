package config_test

import (
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/config"
)

// TestConfig_GrantAllowsSource_RejectsWhenCIDRNotAllowed covers the first
// half of the rule Policy.Validate's validateGrants enforces at config-load
// time: even a grant with a generous minimum prefix must not accept ANY
// asserted source when allow_source_cidr is false, which is the default.
func TestConfig_GrantAllowsSource_RejectsWhenCIDRNotAllowed(t *testing.T) {
	g := config.Grant{
		AllowSourceCIDR: false,
		MinIPv4Prefix:   24,
		MinIPv6Prefix:   64,
	}
	if err := g.AllowsSource(netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatal("AllowsSource = nil, want an error: allow_source_cidr is false")
	}
}

// TestConfig_GrantAllowsSource_RejectsNarrowerThanMinimum is the control the
// minimum prefix exists to enforce: without it an authorised operator could
// assert 0.0.0.0/0 or ::/0 (design section 5). One bit narrower than the
// configured minimum, for each family, must be rejected.
func TestConfig_GrantAllowsSource_RejectsNarrowerThanMinimum(t *testing.T) {
	g := config.Grant{
		AllowSourceCIDR: true,
		MinIPv4Prefix:   24,
		MinIPv6Prefix:   64,
	}
	if err := g.AllowsSource(netip.MustParsePrefix("198.51.100.0/23")); err == nil {
		t.Fatal("AllowsSource(/23) = nil, want an error: narrower than the /24 minimum")
	}
	if err := g.AllowsSource(netip.MustParsePrefix("0.0.0.0/0")); err == nil {
		t.Fatal("AllowsSource(0.0.0.0/0) = nil, want an error: the exact hole min_ipv4_prefix exists to close")
	}
	if err := g.AllowsSource(netip.MustParsePrefix("2001:db8::/63")); err == nil {
		t.Fatal("AllowsSource(/63) = nil, want an error: narrower than the /64 minimum")
	}
	if err := g.AllowsSource(netip.MustParsePrefix("::/0")); err == nil {
		t.Fatal("AllowsSource(::/0) = nil, want an error: the exact hole min_ipv6_prefix exists to close")
	}
}

// TestConfig_GrantAllowsSource_AcceptsExactlyAtMinimum proves the minimum is
// a floor, not an exclusive bound: a prefix exactly as wide as configured
// must be accepted, for both families independently.
func TestConfig_GrantAllowsSource_AcceptsExactlyAtMinimum(t *testing.T) {
	g := config.Grant{
		AllowSourceCIDR: true,
		MinIPv4Prefix:   24,
		MinIPv6Prefix:   64,
	}
	if err := g.AllowsSource(netip.MustParsePrefix("198.51.100.0/24")); err != nil {
		t.Fatalf("AllowsSource(/24) = %v, want nil: exactly at the minimum", err)
	}
	if err := g.AllowsSource(netip.MustParsePrefix("2001:db8::/64")); err != nil {
		t.Fatalf("AllowsSource(/64) = %v, want nil: exactly at the minimum", err)
	}
	// Narrower-numbered CIDR notation means a WIDER network, so a /25 (more
	// specific than the /24 floor) must also be accepted.
	if err := g.AllowsSource(netip.MustParsePrefix("198.51.100.0/25")); err != nil {
		t.Fatalf("AllowsSource(/25) = %v, want nil: narrower network than the /24 minimum", err)
	}
}

// TestConfig_GrantAllowsSource_ChecksV6PrefixAgainstV6Minimum is the
// cross-family regression this method exists to prevent: a v6 prefix must
// never be measured against MinIPv4Prefix. Set MinIPv4Prefix wide open (so
// it would accept anything if the check used the wrong field) and
// MinIPv6Prefix tight, and confirm a v6 prefix below the v6 minimum is still
// rejected — and the reverse, a v4 prefix must not be measured against
// MinIPv6Prefix either.
func TestConfig_GrantAllowsSource_ChecksV6PrefixAgainstV6Minimum(t *testing.T) {
	g := config.Grant{
		AllowSourceCIDR: true,
		MinIPv4Prefix:   1,   // would accept nearly anything if wrongly applied to v6
		MinIPv6Prefix:   120, // very tight
	}
	if err := g.AllowsSource(netip.MustParsePrefix("2001:db8::/64")); err == nil {
		t.Fatal("AllowsSource(v6 /64) = nil, want an error: /64 is narrower than the /120 v6 minimum, " +
			"and must not have been checked against the wide-open v4 minimum instead")
	}
	if err := g.AllowsSource(netip.MustParsePrefix("2001:db8::/120")); err != nil {
		t.Fatalf("AllowsSource(v6 /120) = %v, want nil: exactly at the v6 minimum", err)
	}

	g2 := config.Grant{
		AllowSourceCIDR: true,
		MinIPv4Prefix:   30, // tight
		MinIPv6Prefix:   1,  // would accept nearly anything if wrongly applied to v4
	}
	if err := g2.AllowsSource(netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatal("AllowsSource(v4 /24) = nil, want an error: /24 is narrower than the /30 v4 minimum, " +
			"and must not have been checked against the wide-open v6 minimum instead")
	}
}

func TestConfig_GrantAllowsSource_EnforcesIPv4FloorAgainstMappedIPv6(t *testing.T) {
	// ::ffff:0.0.0.0/96 is the entire IPv4 address space wearing a v6 encoding.
	// netip reports Is4() == false for it, so a naive family switch measures it
	// against MinIPv6Prefix and lets it past any floor of /96 or looser — which
	// is precisely the "an authorised operator could assert 0.0.0.0/0" hole
	// AllowsSource exists to close.
	g := config.Grant{
		AllowSourceCIDR: true,
		MinIPv4Prefix:   32,
		MinIPv6Prefix:   64,
	}

	tests := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{"all of ipv4 as mapped v6", "::ffff:0.0.0.0/96", true},
		{"mapped v6 below the v4 floor", "::ffff:198.51.100.0/120", true},
		{"mapped v6 at the v4 floor", "::ffff:198.51.100.7/128", false},
		{"plain v4 below the floor", "198.51.100.0/24", true},
		{"plain v4 at the floor", "198.51.100.7/32", false},
		{"genuine v6 at its own floor", "2001:db8::/64", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := g.AllowsSource(netip.MustParsePrefix(tc.prefix))
			if tc.wantErr && err == nil {
				t.Fatalf("AllowsSource(%s) = nil, want an error", tc.prefix)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("AllowsSource(%s) = %v, want nil", tc.prefix, err)
			}
		})
	}
}
