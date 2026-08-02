package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
)

// In console-recovery mode there is no always-allow path to challenge, so the
// pre-arm always-allow precondition is not run and cannot hold the agent inert.
func TestAgent_PreArm_ConsoleRecoverySkipsTheAlwaysAllowCheck(t *testing.T) {
	p := &config.Policy{ConsoleRecovery: true, Console: "https://provider.example/console"}
	called := false
	checks := agent.PreArmChecks{
		AlwaysAllow: func(*config.Policy) error {
			called = true
			return errors.New("always-allow is down")
		},
	}
	res := agent.RunPreArm(context.Background(), p, checks)
	if called {
		t.Fatal("the always-allow precondition ran under console-recovery; there is no path to check")
	}
	if res.Inert() {
		t.Fatalf("console-recovery pre-arm went inert over a missing always-allow path: %v", res.Summary())
	}
}

// A host may declare console-recovery AND still name an always-allow
// interface: the design and the --console-recovery help both say that when an
// interface is given alongside it, the interface is used and verified
// normally, with the console as the documented last resort. So the skip is
// keyed on the interface being absent, not on the acknowledgment flag: with an
// interface present, the always-allow precondition still runs, and its verdict
// still governs whether the agent goes inert. Keying the skip on the flag
// instead would wire a dead mesh into the firewall (render emits its accept
// rule on interface presence) while never checking it.
func TestAgent_PreArm_ConsoleRecoveryStillChecksAPresentAlwaysAllowInterface(t *testing.T) {
	p := &config.Policy{
		ConsoleRecovery:  true,
		Console:          "https://provider.example/console",
		AlwaysAllowIface: "tailscale0",
	}
	called := false
	checks := agent.PreArmChecks{
		AlwaysAllow: func(*config.Policy) error {
			called = true
			return errors.New("interface \"tailscale0\": no such network interface")
		},
	}
	res := agent.RunPreArm(context.Background(), p, checks)
	if !called {
		t.Fatal("the always-allow precondition was skipped even though an interface is present; " +
			"console-recovery must not suppress verification of a mesh that is actually configured")
	}
	if !res.Inert() {
		t.Fatalf("a present but unresolvable always-allow interface did not hold the agent inert under "+
			"console-recovery: %v", res.Summary())
	}
}
