package gate

import (
	"strings"
	"testing"
)

// In console-recovery mode there is no always-allow interface, so the ruleset
// carries no `iifname accept` rule. The fail-closed drops still stand, so a
// fail-closed service is unreachable except via the console.
func TestGate_Render_ConsoleRecoveryOmitsTheAlwaysAllowAccept(t *testing.T) {
	p := fixturePolicy()
	p.AlwaysAllowIface = ""
	p.ConsoleRecovery = true
	p.Console = "https://provider.example/console"

	plan, err := BuildRulesetPlan(p)
	if err != nil {
		t.Fatalf("BuildRulesetPlan refused a console-recovery policy: %v", err)
	}
	out := RenderBootNFT(plan)

	if strings.Contains(out, "iifname") {
		t.Fatalf("console-recovery ruleset contains an iifname accept rule; there is no always-allow interface to accept on:\n%s", out)
	}
	if !strings.Contains(out, "tcp dport 62202 drop") {
		t.Fatalf("console-recovery ruleset dropped the fail-closed gate; the boot drops must still stand:\n%s", out)
	}
}
