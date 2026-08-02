package agent_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fleetBootstrap is a fixture policy with the three fields a fail-closed host
// must set for Validate to pass, the same ones newDaemonHarness fills in, so a
// marshal-and-reparse round trip through LoadRunningPolicy validates.
func fleetBootstrap(t *testing.T) *config.Policy {
	t.Helper()
	p := newFixture(t).policy
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	return p
}

// writePersisted marshals p the way a confirm's persistRunningPolicy does and
// writes it where LoadRunningPolicy reads, so the test drives the same bytes
// the two halves of #52 exchange rather than a hand-built fixture.
func writePersisted(t *testing.T, path string, p *config.Policy) {
	t.Helper()
	data, err := config.MarshalStandalone(p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write persisted policy: %v", err)
	}
}

// #52. An empty path is standalone mode: there is no persisted policy and the
// bootstrap file is the running config.
func TestAgent_LoadRunningPolicy_EmptyPathRunsTheBootstrap(t *testing.T) {
	boot := fleetBootstrap(t)
	got, err := agent.LoadRunningPolicy(boot, "", discardLog())
	if err != nil {
		t.Fatalf("LoadRunningPolicy: %v", err)
	}
	if got != boot {
		t.Fatal("an empty persisted path did not run the bootstrap policy")
	}
}

// #52. A fleet host that has never confirmed a bundle has no persisted file yet
// and runs the bootstrap, so first boot is not a special case.
func TestAgent_LoadRunningPolicy_MissingFileRunsTheBootstrap(t *testing.T) {
	boot := fleetBootstrap(t)
	path := filepath.Join(t.TempDir(), "policy.yaml") // never written
	got, err := agent.LoadRunningPolicy(boot, path, discardLog())
	if err != nil {
		t.Fatalf("LoadRunningPolicy: %v", err)
	}
	if got != boot {
		t.Fatal("a missing persisted file did not run the bootstrap policy")
	}
}

// #52, the fix. A persisted policy for this host runs instead of the bootstrap,
// so a restart keeps the fetched configuration rather than reverting to the
// enrollment config.
func TestAgent_LoadRunningPolicy_APersistedPolicyForThisHostRunsInsteadOfTheBootstrap(t *testing.T) {
	boot := fleetBootstrap(t)
	persisted := *boot
	persisted.Revision = boot.Revision + 5 // a later, confirmed revision
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePersisted(t, path, &persisted)

	got, err := agent.LoadRunningPolicy(boot, path, discardLog())
	if err != nil {
		t.Fatalf("LoadRunningPolicy: %v", err)
	}
	if got.Revision != persisted.Revision {
		t.Fatalf("ran revision %d, want the persisted %d: a restart reverted to the bootstrap",
			got.Revision, persisted.Revision)
	}
}

// #52. A persisted policy naming a different fleet is from a prior enrollment
// that still lingers on disk; it is ignored and the bootstrap runs, rather than
// a re-enrolled host adopting its old fleet's config.
func TestAgent_LoadRunningPolicy_APersistedPolicyForAnotherFleetIsIgnored(t *testing.T) {
	boot := fleetBootstrap(t)
	stale := *boot
	stale.FleetID[0] ^= 0xff // a different fleet
	stale.Revision = boot.Revision + 5
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePersisted(t, path, &stale)

	got, err := agent.LoadRunningPolicy(boot, path, discardLog())
	if err != nil {
		t.Fatalf("LoadRunningPolicy: %v", err)
	}
	if got != boot {
		t.Fatal("a persisted policy from another fleet was run instead of the bootstrap")
	}
}

// #52. A corrupt persisted policy fails startup rather than falling back to the
// bootstrap: a fleet host must not silently re-admit operators a bundle removed
// because its durable config was damaged or tampered with.
func TestAgent_LoadRunningPolicy_ACorruptPersistedPolicyFailsRatherThanRevertingToBootstrap(t *testing.T) {
	boot := fleetBootstrap(t)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("this is not: valid: yaml: at all\n\t\x00"), 0o600); err != nil {
		t.Fatalf("write corrupt policy: %v", err)
	}
	got, err := agent.LoadRunningPolicy(boot, path, discardLog())
	if err == nil {
		t.Fatalf("a corrupt persisted policy was accepted (got revision %d); it must fail startup", got.Revision)
	}
}
