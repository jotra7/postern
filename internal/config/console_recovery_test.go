package config

import (
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/identity"
)

// consoleRecoveryFixture builds a minimal valid *Policy: one fail-closed gate
// service ("ssh", also the recovery_service), one operator holding a grant
// for it, positive freshness windows, and a valid always_allow_iface — with
// ConsoleRecovery and Console both set. Tests that exercise the console
// recovery exception blank AlwaysAllowIface (and, where relevant, Console)
// themselves; the fixture's own defaults describe an ordinary, fully-armed
// host that merely happens to have recorded the acknowledgment.
func consoleRecoveryFixture(t *testing.T) *Policy {
	t.Helper()

	var signing, encryption [32]byte
	signing[0] = 1
	encryption[0] = 2

	return &Policy{
		SPAPort:            62201,
		AlwaysAllowIface:   "tailscale0",
		RecoveryService:    "ssh",
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 24 * time.Hour,
		ConsoleRecovery:    true,
		Console:            "https://provider.example/console",
		Services: map[string]Service{
			"ssh": {
				Name:                "ssh",
				Kind:                KindGate,
				Proto:               "tcp",
				Ports:               []uint16{22},
				DefaultTTL:          120 * time.Second,
				MaxTTL:              300 * time.Second,
				FailPosture:         PostureClosed,
				ListenerExpectation: ListenerPresent,
				Backend:             BackendNFTables,
			},
		},
		Operators: []Operator{
			{
				Identity: identity.PublicIdentity{
					Name:       "laptop-primary",
					Alg:        identity.AlgEd25519X25519,
					Signing:    signing,
					Encryption: encryption,
				},
				Grants: []Grant{
					{
						Services: []string{"ssh"},
						MaxTTL:   300 * time.Second,
					},
				},
			},
		},
	}
}

// A console-recovery policy validates without an always_allow_iface: the
// operator has declared an out-of-band console as the recovery path.
func TestConfig_Validate_ConsoleRecoveryAllowsNoAlwaysAllowIface(t *testing.T) {
	p := consoleRecoveryFixture(t)
	p.AlwaysAllowIface = ""
	if err := p.Validate(); err != nil {
		t.Fatalf("a console-recovery policy with no always_allow_iface was refused: %v", err)
	}
}

// The acknowledgment is the only thing that permits the absence. A policy that
// simply forgot always_allow_iface, with no acknowledgment, still fails exactly
// as before: that is the whole point of the explicit flag.
func TestConfig_Validate_MissingAlwaysAllowIfaceStillFailsWithoutTheAck(t *testing.T) {
	p := consoleRecoveryFixture(t)
	p.ConsoleRecovery = false
	p.AlwaysAllowIface = ""
	if err := p.Validate(); err == nil {
		t.Fatal("a policy with no always_allow_iface and no console-recovery ack validated; the forgotten-iface case must still fail")
	}
}

// Turning off the verified path while recording no route at all is refused:
// there must be a documented last resort.
func TestConfig_Validate_ConsoleRecoveryRequiresAConsoleURL(t *testing.T) {
	p := consoleRecoveryFixture(t)
	p.AlwaysAllowIface = ""
	p.Console = ""
	if err := p.Validate(); err == nil {
		t.Fatal("console-recovery with no console URL validated; a recorded last-resort route is required")
	}
}

// A console-recovery policy warns at every load: the operator gave up a
// verified recovery path, and that must be visible in the journal each time
// the config is loaded, not just at validation time.
func TestConfig_Warnings_ConsoleRecoveryWarnsAtLoad(t *testing.T) {
	p := consoleRecoveryFixture(t)
	p.AlwaysAllowIface = ""
	found := false
	for _, w := range p.Warnings() {
		if strings.Contains(w, "console") && strings.Contains(w, "recovery") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no console-recovery warning at load: %v", p.Warnings())
	}
}
