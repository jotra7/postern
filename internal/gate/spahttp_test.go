package gate

import (
	"fmt"
	"strings"
	"testing"
)

// spaHTTPPort is not any fixture service's port, so a rule matching it can
// only have come from the carrier.
const spaHTTPPort = 62443

func httpCarrierPlan(t *testing.T) *RulesetPlan {
	t.Helper()
	policy := fixturePolicy()
	policy.SPAHTTPPort = spaHTTPPort
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	return plan
}

// The HTTP carrier's TCP port is gated exactly the way the UDP SPA port is:
// an accept conditional on membership in agent_up, carrying the same kernel
// rate limit, followed by an unconditional drop.
//
// The drop is the half that does the work, and it is checked explicitly. The
// boot chain's policy is accept, so without a drop the accept rule above it
// would be decoration: every packet the rate-limited accept did not take
// would fall through to the policy and reach the listener anyway, with the
// agent_up lease expired and the agent possibly dead. A new
// permanently-open TCP port on a break-glass host is precisely the
// regression this carrier must not be.
func TestGate_Render_HTTPCarrierPortIsGatedByAgentUpWithADrop(t *testing.T) {
	out := RenderBootNFT(httpCarrierPlan(t))

	accept := fmt.Sprintf("tcp dport @%s limit rate %d/second accept", AgentUpSet, AgentUpRateLimitPerSecond)
	if !strings.Contains(out, accept) {
		t.Errorf("boot.nft has no agent_up-gated accept for the http carrier; want %q:\n%s", accept, out)
	}
	drop := fmt.Sprintf("tcp dport %d drop", spaHTTPPort)
	if !strings.Contains(out, drop) {
		t.Errorf("boot.nft has no drop for the http carrier port; want %q:\n%s", drop, out)
	}

	// Order, not just presence: a drop rendered above its accept would close
	// the port permanently, which fails safe but means the carrier never
	// works and would be found only by an operator locked out.
	if strings.Index(out, accept) > strings.Index(out, drop) {
		t.Errorf("the http carrier's drop precedes its accept, so the port is never reachable:\n%s", out)
	}

	// And it lives in postern_boot, alongside agent_up, rather than in the
	// agent-created postern_open — a carrier whose gating vanished with the
	// agent would be ungated exactly when the agent is dead.
	if !strings.Contains(out, "table inet "+TableBoot) {
		t.Fatalf("precondition: RenderBootNFT did not render %s", TableBoot)
	}
}

// Off unless configured, expressed as the absence of rules rather than as a
// rule that matches nothing. An operator who never set spa_http_port must
// gain no listener and no rule mentioning one.
func TestGate_Render_NoHTTPCarrierRulesWhenTheCarrierIsNotConfigured(t *testing.T) {
	plan := mustPlan(t)
	if plan.SPAHTTPPort != 0 {
		t.Fatalf("precondition: the base fixture configures an http carrier (%d)", plan.SPAHTTPPort)
	}
	out := RenderBootNFT(plan)

	if strings.Contains(out, fmt.Sprintf("tcp dport @%s", AgentUpSet)) {
		t.Errorf("boot.nft gates a tcp port on agent_up with no carrier configured:\n%s", out)
	}
	if strings.Contains(out, fmt.Sprintf("tcp dport %d", spaHTTPPort)) {
		t.Errorf("boot.nft names the http carrier port with no carrier configured:\n%s", out)
	}
}

// One lease, not two. The carrier's accept looks up the same agent_up set the
// UDP accept looks up, so a single dead-man element governs both.
//
// Two sets would be two leases refreshed by two writes that can fail
// independently, and a host whose UDP port had gone silent while its TCP port
// stayed open would be advertising break-glass access through a carrier whose
// liveness nothing had established.
func TestGate_Render_BothCarriersLookUpTheSameDeadManSet(t *testing.T) {
	out := RenderBootNFT(httpCarrierPlan(t))

	var lookups int
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "dport @") {
			lookups++
			if !strings.Contains(line, "@"+AgentUpSet+" ") {
				t.Errorf("a carrier is gated on a set other than %s: %q", AgentUpSet, strings.TrimSpace(line))
			}
		}
	}
	if lookups != 2 {
		t.Fatalf("found %d carrier accept rules, want one per carrier", lookups)
	}
}
