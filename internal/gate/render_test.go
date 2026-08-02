package gate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func mustPlan(t *testing.T) *RulesetPlan {
	t.Helper()
	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	return plan
}

// rotationPlan is mustPlan's rotation-mode counterpart: a BuildRulesetPlan
// output with PortRotation set to knockport's default 20000-30000 band
// instead of a fixed spa_port.
func rotationPlan(t *testing.T) *RulesetPlan {
	t.Helper()
	plan, err := BuildRulesetPlan(rotationPolicy(t))
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	return plan
}

// TestGate_Render_UsesIifnameNeverIif is the pure half of invariant 1: the
// generated text must never contain the bare "iif" match, only "iifname".
// Break it by reverting writeServiceRules/RenderBootNFT's iifname literal
// to "iif" and this test fails; the kernel half (nft_linux_test.go) proves
// the load-with-absent-interface consequence.
func TestGate_Render_UsesIifnameNeverIif(t *testing.T) {
	out := RenderBootNFT(mustPlan(t))
	if !strings.Contains(out, "iifname \"tailscale0\" accept") {
		t.Fatalf("rendered boot.nft does not contain the expected iifname rule:\n%s", out)
	}
	bareIif := regexp.MustCompile(`(^|\s)iif\s`)
	if bareIif.MatchString(out) {
		t.Fatalf("rendered boot.nft contains a bare \"iif\" match, which resolves an interface index "+
			"at load time and fails the whole load if the interface does not exist yet:\n%s", out)
	}
}

// TestGate_Render_EstablishedAndAlwaysAllowPrecedeServiceRules covers the
// text half of invariant 2 for postern_boot: both rules appear, and ahead
// of any service-specific rule, in every table on the hook. The netlink
// writer's equivalent (nft_linux_test.go) proves it also holds for
// postern_open, which has no text form.
func TestGate_Render_EstablishedAndAlwaysAllowPrecedeServiceRules(t *testing.T) {
	out := RenderBootNFT(mustPlan(t))
	established := strings.Index(out, "ct state established,related accept")
	allow := strings.Index(out, "iifname \"tailscale0\" accept")
	firstService := strings.Index(out, "tcp dport 8443")
	if established == -1 || allow == -1 || firstService == -1 {
		t.Fatalf("rendered boot.nft is missing an expected line:\n%s", out)
	}
	if established >= firstService || allow >= firstService {
		t.Fatalf("established/allow rules must precede service rules so a service's own drop cannot "+
			"shadow them; got established=%d allow=%d firstService=%d", established, allow, firstService)
	}
}

// TestGate_Render_PolicyAcceptWithExplicitDrops is invariant 3: the chain
// declares "policy accept", and postern only drops the ports it actively
// gates.
func TestGate_Render_PolicyAcceptWithExplicitDrops(t *testing.T) {
	out := RenderBootNFT(mustPlan(t))
	if !strings.Contains(out, "policy accept;") {
		t.Fatalf("rendered boot.nft does not declare policy accept:\n%s", out)
	}
	if !strings.Contains(out, "tcp dport 62202 drop") {
		t.Fatalf("rendered boot.nft is missing canary's explicit drop:\n%s", out)
	}
	if !strings.Contains(out, "tcp dport 8443 drop") {
		t.Fatalf("rendered boot.nft is missing admin's explicit drop:\n%s", out)
	}
}

// TestGate_Render_EveryBootServiceHasADropRuleIncludingCanary is invariant
// 4. Break it by special-casing canary out of writeServiceRules's drop line
// and this test fails — the exact bug the brief calls out: without the
// drop, a closed gate returns RST exactly like an open one.
func TestGate_Render_EveryBootServiceHasADropRuleIncludingCanary(t *testing.T) {
	plan := mustPlan(t)
	out := RenderBootNFT(plan)
	for _, svc := range plan.BootServices() {
		for _, port := range svc.Ports {
			want := svc.Proto + " dport " + strconv.Itoa(int(port)) + " drop"
			if !strings.Contains(out, want) {
				t.Fatalf("service %q (port %d) has no drop rule in rendered boot.nft; "+
					"a gate with no drop is indistinguishable from an open one:\n%s", svc.Name, port, out)
			}
		}
	}
}

// TestGate_Render_SPAPortOwnedOnlyByBoot is the text half of invariant 5:
// only RenderBootNFT ever mentions the SPA port or the agent_up set — there
// is no second renderer for postern_open to have accidentally grown one.
func TestGate_Render_SPAPortOwnedOnlyByBoot(t *testing.T) {
	out := RenderBootNFT(mustPlan(t))
	if strings.Count(out, "@agent_up") != 1 {
		t.Fatalf("expected exactly one rule referencing @agent_up, got:\n%s", out)
	}
	if strings.Count(out, "62201") != 1 { // the static drop; the accept path matches via @agent_up, not the literal port
		t.Fatalf("expected the literal SPA port to appear exactly once (the static drop), got:\n%s", out)
	}
}

// TestGate_Render_RotationEmitsARangeDropNotASinglePortDrop covers rotation
// mode's widened drop: the whole candidate band is dark rather than one
// literal port, and the set-membership accept (unchanged from fixed mode)
// still precedes it so the live port stays reachable.
func TestGate_Render_RotationEmitsARangeDropNotASinglePortDrop(t *testing.T) {
	plan := rotationPlan(t)
	out := RenderBootNFT(plan)
	if !strings.Contains(out, "udp dport 20000-30000 drop") {
		t.Errorf("boot.nft has no range drop; want 'udp dport 20000-30000 drop':\n%s", out)
	}
	// The whole band is dark unless agent_up holds the live port: the accept is
	// still set-membership and precedes the range drop.
	accept := fmt.Sprintf("udp dport @%s limit rate %d/second accept", AgentUpSet, AgentUpRateLimitPerSecond)
	if strings.Index(out, accept) > strings.Index(out, "udp dport 20000-30000 drop") {
		t.Errorf("the range drop precedes the agent_up accept, so no port is ever reachable:\n%s", out)
	}
	// And the single-port drop is gone: a stray 'udp dport <n> drop' would leave
	// a hole or a redundant rule the parity test would then have to reconcile.
	if strings.Contains(out, "udp dport 62201 drop") {
		t.Errorf("boot.nft still emits the fixed single-port drop under rotation:\n%s", out)
	}
}

// TestGate_Render_FixedModeStillEmitsTheSinglePortDrop pins the unchanged
// fixed-mode behaviour so widening the drop for rotation cannot silently
// widen it for fixed-port hosts too.
func TestGate_Render_FixedModeStillEmitsTheSinglePortDrop(t *testing.T) {
	out := RenderBootNFT(mustPlan(t)) // existing fixed-port helper
	if !strings.Contains(out, "udp dport 62201 drop") {
		t.Errorf("fixed mode must keep its single-port drop:\n%s", out)
	}
	if strings.Contains(out, "20000-30000") {
		t.Errorf("fixed mode must not emit a range drop:\n%s", out)
	}
}

// TestGate_Render_FlushLinesNameExactlyTheBootFailClosedSets is renderer
// equivalence applied to the third artifact (invariant 6): the systemd
// ExecStopPost lines must flush precisely the sets that exist in
// postern_boot for fail-closed gate services — no more, no fewer, and never
// postern_open's sets, since ExecStopPost's sibling line already deletes
// that table outright (design section 7). Break it by adding a set to a
// service's plan without updating FlushSetNames and this test fails.
func TestGate_Render_FlushLinesNameExactlyTheBootFailClosedSets(t *testing.T) {
	plan := mustPlan(t)

	want := map[string]bool{}
	for _, svc := range plan.BootServices() {
		for _, s := range svc.Sets {
			want[s.Name] = true
		}
	}

	lines := RenderSystemdFlushLines(plan)
	if len(lines) != len(want) {
		t.Fatalf("got %d flush lines, want %d (one per postern_boot gate set)", len(lines), len(want))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "ExecStopPost=-/usr/sbin/nft flush set inet "+TableBoot+" ") {
			t.Fatalf("flush line has unexpected shape: %q", line)
		}
		fields := strings.Fields(line)
		name := fields[len(fields)-1]
		if !want[name] {
			t.Fatalf("flush line names set %q, which is not one of postern_boot's fail-closed gate sets %v", name, want)
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("flush lines are missing sets: %v", want)
	}
	// postern_open's sets must never appear, even by accident.
	for _, svc := range plan.OpenServices() {
		for _, s := range svc.Sets {
			for _, line := range lines {
				if strings.HasSuffix(line, " "+s.Name) {
					t.Fatalf("flush line %q names %q, a postern_open set; ExecStopPost deletes postern_open outright instead", line, s.Name)
				}
			}
		}
	}
}
