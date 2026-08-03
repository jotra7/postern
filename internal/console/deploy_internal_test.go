package console

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
)

// TestSources_PlanDeploy_RotationShowsCurrentWindowPort covers the deploy
// preview's knock column. A rotation host must show the port its secret derives
// for the current window (where a knock actually lands), not the fixed spa_port
// it never answers on; a fixed-port host must still show its spa_port. The two
// hosts in one inventory guard against the regression of overriding both.
func TestSources_PlanDeploy_RotationShowsCurrentWindowPort(t *testing.T) {
	op, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatal(err)
	}
	rotor, err := identity.Generate("web-01")
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := identity.Generate("web-02")
	if err != nil {
		t.Fatal(err)
	}
	opPub, rotorPub, fixedPub := op.Public(), rotor.Public(), fixed.Public()

	secret := make([]byte, knockport.SecretSize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	inv := fmt.Sprintf(`fleet_id: "617d156a26e732c1b39225daf2ff84ea"
version: 11
bundle_signers: [laptop-primary]
operators:
  - name: laptop-primary
    alg: ed25519+x25519
    signing:    "%s"
    encryption: "%s"
    grants:
      - hosts: ["*"]
        services: ["ssh", "confirm", "liveness"]
        max_ttl: 300s
breakglass_services: [ssh]
services:
  ssh:      { kind: gate, proto: tcp, ports: [22], default_ttl: 120s, max_ttl: 300s, listener_expectation: present }
  confirm:  { kind: action }
  liveness: { kind: action }
defaults:
  spa_port: 62201
  always_allow_iface: tailscale0
  recovery_service: ssh
  port_rotation: { window: 600s, range: 20000-30000 }
hosts:
  - name: web-01
    host_id: "0f9bbc2a92481ef913c174830c892cbd"
    knock_addr: 203.0.113.9
    ssh: { host: host-01.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    "%s"
      encryption: "%s"
    port_rotation: { secret: "%s", window: 600s, range: 20000-30000 }
    services: [ssh]
    groups: [prod]
  - name: web-02
    host_id: "26ae18850c6764d08fb72f2be8858b5c"
    knock_addr: 203.0.113.10
    ssh: { host: host-02.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    "%s"
      encryption: "%s"
    port_rotation: disabled
    spa_port: 62210
    services: [ssh]
    groups: [prod]
`,
		base64.StdEncoding.EncodeToString(opPub.Signing[:]),
		base64.StdEncoding.EncodeToString(opPub.Encryption[:]),
		base64.StdEncoding.EncodeToString(rotorPub.Signing[:]),
		base64.StdEncoding.EncodeToString(rotorPub.Encryption[:]),
		base64.StdEncoding.EncodeToString(secret),
		base64.StdEncoding.EncodeToString(fixedPub.Signing[:]),
		base64.StdEncoding.EncodeToString(fixedPub.Encryption[:]),
	)

	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1785699000, 0)
	s := &sources{inventoryPath: path, now: func() time.Time { return now }}

	plan := s.planDeploy()
	if plan.Err != "" {
		t.Fatalf("planDeploy: %s", plan.Err)
	}
	if len(plan.Changes) != 2 {
		t.Fatalf("want 2 changes, got %d", len(plan.Changes))
	}

	w := knockport.Window(now.Unix(), 600*time.Second)
	wantRot := fmt.Sprintf("203.0.113.9:%d", knockport.Port(secret, w, 20000, 30000))
	if got := plan.Changes[0].Knock; got != wantRot {
		t.Fatalf("rotation host deploy knock = %q, want the current-window port %q; showing the fixed "+
			"spa_port would advertise a port the host never answers on", got, wantRot)
	}
	if got := plan.Changes[1].Knock; got != "203.0.113.10:62210" {
		t.Fatalf("fixed-port host deploy knock = %q, want its spa_port 203.0.113.10:62210", got)
	}
	for _, c := range plan.Changes {
		if c.PolicyErr != "" {
			t.Fatalf("host %s did not compile: %s", c.Host, c.PolicyErr)
		}
	}
}
