package client_test

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
)

// testHost builds a host entry whose knock_addr and SSH hostname are
// deliberately different values, since that difference is invariant 1. It
// records no always_allow_addr, so it is also the entry every operator
// enrolled before that field existed is holding.
func testHost(t *testing.T, hostEnc, hostSign [32]byte) *client.Host {
	t.Helper()
	return testHostWithLines(t, "", hostEnc, hostSign)
}

// testHostRotation is testHost's shape plus a port_rotation block, built
// from an explicit host identity rather than rotationHost's fixed one, for a
// test (like status/confirm's liveness ping) that also has to seal a reply
// as the host and needs the matching private key.
func testHostRotation(t *testing.T, hostEnc, hostSign [32]byte) *client.Host {
	t.Helper()
	extra := "    port_rotation: { secret: " + base64.StdEncoding.EncodeToString(rotationSecret()) +
		", window: 10m, range: 20000-30000 }\n"
	return testHostWithLines(t, extra, hostEnc, hostSign)
}

// testHostSplitPath is the same host as it looks on real hardware: reached
// publicly at 203.0.113.9 and over the mesh at 198.51.100.4. The two addresses
// differ on purpose, because a fixture where they collapse cannot tell an
// implementation that targets one from an implementation that targets the
// other, which is exactly how a client that pinged the public address shipped.
func testHostSplitPath(t *testing.T, hostEnc, hostSign [32]byte) *client.Host {
	t.Helper()
	return testHostWithLines(t, "    always_allow_addr: 198.51.100.4\n", hostEnc, hostSign)
}

func testHostWithLines(t *testing.T, extra string, hostEnc, hostSign [32]byte) *client.Host {
	t.Helper()
	yaml := "" +
		"operator: laptop-primary\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: " + hex.EncodeToString(bytes16(0x3a)) + "\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		extra +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(hostEnc[:]) + "\n" +
		"    host_signing: " + base64.StdEncoding.EncodeToString(hostSign[:]) + "\n" +
		"    recovery_service: ssh\n" +
		"    ssh: { host: web-01.example.com, user: ops, port: 22 }\n" +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n" +
		"      canary: { port: 62202 }\n"

	cfg, err := client.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

func bytes16(fill byte) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = fill
	}
	return b
}

func mustGenerate(t *testing.T, name string) identity.Signer {
	t.Helper()
	s, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("Generate(%q): %v", name, err)
	}
	return s
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

// fixedClock returns a NowMS function pinned to ms.
func fixedClock(ms uint64) func() uint64 { return func() uint64 { return ms } }

const testNowMS = uint64(1_800_000_000_000)
