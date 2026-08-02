package config

import (
	"strings"
	"testing"
	"time"
)

// carrierPolicy is the smallest policy that validates, so a failure below is
// attributable to the carrier rather than to something else missing.
func carrierPolicy() *Policy {
	return &Policy{
		SPAPort:            62201,
		AlwaysAllowIface:   "tailscale0",
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 24 * time.Hour,
		MaxOperators:       DefaultMaxOperators,
		Services: map[string]Service{
			"ssh": {
				Name: "ssh", Kind: KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: PostureOpen, ListenerExpectation: ListenerPresent,
				// Validate refuses a gate whose backend a resolver has not
				// assigned, and the carrier's port is registered against the
				// nftables backend, so this has to be the resolved value for
				// the collision below to be the thing under test.
				Backend: BackendNFTables,
			},
		},
	}
}

// The carrier's port is optional and its absence is the default: a config
// that never mentions it parses, validates, and describes a host with one
// carrier.
func TestConfig_SPAHTTPPort_IsOptionalAndDefaultsToOff(t *testing.T) {
	p, err := ParseStandalone([]byte(`
fleet_id: 00112233445566778899aabbccddeeff
host_id: ffeeddccbbaa99887766554433221100
spa_port: 62201
always_allow_iface: tailscale0
services:
  ssh: {kind: gate, proto: tcp, ports: [22], default_ttl: 120s, max_ttl: 300s}
`))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if p.SPAHTTPPort != 0 {
		t.Fatalf("SPAHTTPPort = %d with no spa_http_port key; the carrier must be off unless configured", p.SPAHTTPPort)
	}
}

func TestConfig_SPAHTTPPort_IsReadFromTheStandaloneFile(t *testing.T) {
	p, err := ParseStandalone([]byte(`
fleet_id: 00112233445566778899aabbccddeeff
host_id: ffeeddccbbaa99887766554433221100
spa_port: 62201
spa_http_port: 62443
always_allow_iface: tailscale0
services:
  ssh: {kind: gate, proto: tcp, ports: [22], default_ttl: 120s, max_ttl: 300s}
`))
	if err != nil {
		t.Fatalf("ParseStandalone: %v", err)
	}
	if p.SPAHTTPPort != 62443 {
		t.Fatalf("SPAHTTPPort = %d, want 62443", p.SPAHTTPPort)
	}
}

// The carrier owns a TCP port, and a port has exactly one owner.
//
// Sharing it with a gate service would put two accepts and two drops for one
// port in one chain: the gate's drop would swallow knocks the carrier's
// accept was for, and the carrier's accept would admit that service's port
// to anyone at all whenever agent_up held it. The one-owner rule already
// covers service against service; this extends it to the carrier, which owns
// a port without being a service.
func TestConfig_Validate_RejectsAGateServiceClaimingTheCarrierPort(t *testing.T) {
	p := carrierPolicy()
	p.SPAHTTPPort = 22 // the ssh gate's own port

	err := p.Validate()
	if err == nil {
		t.Fatal("a gate service and the http carrier claimed the same tcp port and Validate accepted it")
	}
	if !strings.Contains(err.Error(), "tcp/22") {
		t.Fatalf("the error does not name the contested port: %v", err)
	}
}

// The counterpart, so the rule above is not satisfied by a Validate that
// refuses every configured carrier: a port nothing else claims is fine.
func TestConfig_Validate_AcceptsACarrierPortNoServiceClaims(t *testing.T) {
	p := carrierPolicy()
	p.SPAHTTPPort = 62443

	if err := p.Validate(); err != nil {
		t.Fatalf("Validate refused an uncontested carrier port: %v", err)
	}
}

// A fail-closed gate on the UDP SPA port's own number is the world-open hole
// this registration closes.
//
// agent_up is one set consulted by both the udp and the tcp dead-man accept,
// and it holds spa_port as a bare number. So `udp dport @agent_up accept`
// (always present) and, with the http carrier on, `tcp dport @agent_up
// accept` both match a gate sitting on spa_port and shadow its drop, leaving
// it open to every source while the agent is alive whatever its posture. The
// only thing that refuses the configuration is this ownership check, so this
// test drives it directly.
//
// The gate here is fail_posture closed and on the SPA port, and nothing else
// in the policy claims that port, so the ownership check is the only control
// that can refuse it. spa_http_port is left unset so a second, http-carrier
// registration cannot be the thing refusing.
func TestConfig_Validate_RejectsAGateOnTheSPAPort(t *testing.T) {
	p := carrierPolicy()
	p.SPAHTTPPort = 0
	svc := p.Services["ssh"]
	svc.Ports = []uint16{p.SPAPort} // 62201, the udp SPA carrier's number
	svc.FailPosture = PostureClosed
	p.Services["ssh"] = svc

	err := p.Validate()
	if err == nil {
		t.Fatal("a gate claimed the SPA port and Validate accepted it; the dead-man accept would " +
			"shadow its drop and leave a fail-closed gate open to every source while the agent is alive")
	}
	if !strings.Contains(err.Error(), "62201") {
		t.Fatalf("the error does not name the contested port: %v", err)
	}
}
