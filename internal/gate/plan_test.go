package gate

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/knockport"
)

// fixturePolicy builds a small, self-consistent policy with one fail-open
// service (ssh), one fail-closed service with no listener (canary), and one
// fail-closed service with a listener (admin) — enough surface for every
// pure invariant test in this package.
func fixturePolicy() *config.Policy {
	return &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
			},
			"canary": {
				Name: "canary", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{62202},
				DefaultTTL: 30 * time.Second, MaxTTL: 60 * time.Second,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerAbsent,
				Verification: config.VerificationTCPRST,
			},
			"admin": {
				Name: "admin", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8443},
				DefaultTTL: 600 * time.Second, MaxTTL: 1800 * time.Second,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
			},
			"confirm":  {Name: "confirm", Kind: config.KindAction},
			"disarm":   {Name: "disarm", Kind: config.KindAction},
			"liveness": {Name: "liveness", Kind: config.KindAction},
		},
	}
}

// rotationPolicy is fixturePolicy with the fixed spa_port replaced by a
// port_rotation block covering knockport's default band. It is used from
// both the pure render tests (render_test.go) and the kernel-backed renderer
// equivalence test (nft_linux_test.go, Linux-only), so it lives here
// alongside fixturePolicy rather than in either build-tagged file.
func rotationPolicy(t *testing.T) *config.Policy {
	t.Helper()
	p := fixturePolicy()
	p.SPAPort = 0
	p.PortRotation = &config.PortRotation{
		Secret:  bytes.Repeat([]byte{0x01}, knockport.SecretSize),
		Window:  30 * time.Second,
		RangeLo: knockport.DefaultRangeLo,
		RangeHi: knockport.DefaultRangeHi,
	}
	return p
}

// A script-backed service gets no nftables sets and, crucially, no nftables
// drop rule. Generating the drop would be worse than generating nothing:
// nothing would ever add an element to the accept rule's set, so the drop
// would be the only rule that ever matched and the port would be permanently
// unreachable through a service the operator declared as openable.
func TestGate_Plan_SkipsServicesOnAnotherBackend(t *testing.T) {
	p := fixturePolicy()
	svc := p.Services["admin"]
	svc.Backend = config.BackendScript
	svc.FailPosture = config.PostureOpen
	svc.ScriptPath = "/opt/postern/admin.sh"
	p.Services["admin"] = svc

	plan, err := BuildRulesetPlan(p)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	if _, ok := plan.ServiceByName("admin"); ok {
		t.Error("a script-backed service was planned into the nftables ruleset")
	}
	for _, name := range []string{"ssh", "canary"} {
		if _, ok := plan.ServiceByName(name); !ok {
			t.Errorf("%s is missing from the plan; only the script-backed service should have been skipped", name)
		}
	}

	// And the rendered boot ruleset names nothing about it, which is the
	// property an operator can check by eye.
	text := RenderBootNFT(plan)
	if strings.Contains(text, "admin") || strings.Contains(text, "8443") {
		t.Errorf("boot.nft mentions the script-backed service:\n%s", text)
	}
}

// An unresolved backend must plan as nftables, which is what keeps every
// hand-built policy in this package's own tests, and every config written
// before the field existed, behaving as it always did.
func TestGate_Plan_TreatsAnUnresolvedBackendAsNFTables(t *testing.T) {
	p := fixturePolicy()
	if svc := p.Services["ssh"]; svc.Backend != "" {
		t.Fatalf("fixture no longer leaves the backend unresolved: %q", svc.Backend)
	}

	plan, err := BuildRulesetPlan(p)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	if _, ok := plan.ServiceByName("ssh"); !ok {
		t.Error("a service with an unresolved backend was skipped")
	}
}

func TestGate_Plan_AssignsTableByFailPosture(t *testing.T) {
	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}

	ssh, ok := plan.ServiceByName("ssh")
	if !ok || ssh.Table != TableOpen {
		t.Fatalf("ssh (fail_posture open) got table %q, want %q", ssh.Table, TableOpen)
	}
	for _, name := range []string{"canary", "admin"} {
		svc, ok := plan.ServiceByName(name)
		if !ok || svc.Table != TableBoot {
			t.Fatalf("%s (fail_posture closed) got table %q, want %q", name, svc.Table, TableBoot)
		}
	}
}

func TestGate_Plan_ActionServicesProduceNoRuleset(t *testing.T) {
	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	for _, name := range []string{"confirm", "disarm", "liveness"} {
		if _, ok := plan.ServiceByName(name); ok {
			t.Fatalf("action service %q unexpectedly produced a ServicePlan; actions own no ports", name)
		}
	}
}

func TestGate_Plan_EachServiceGetsFourSetsInFixedOrder(t *testing.T) {
	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	svc, ok := plan.ServiceByName("admin")
	if !ok {
		t.Fatal("admin service missing from plan")
	}
	want := []struct {
		family AddrFamily
		kind   SetKind
	}{
		{FamilyIPv4, SetObserved},
		{FamilyIPv4, SetAsserted},
		{FamilyIPv6, SetObserved},
		{FamilyIPv6, SetAsserted},
	}
	if len(svc.Sets) != len(want) {
		t.Fatalf("admin has %d sets, want %d (two per address family: observed and asserted)", len(svc.Sets), len(want))
	}
	for i, w := range want {
		got := svc.Sets[i]
		if got.Family != w.family || got.Kind != w.kind {
			t.Fatalf("set[%d] = {%s,%s}, want {%s,%s}", i, got.Family, got.Kind, w.family, w.kind)
		}
	}
}

func TestGate_Plan_ObservedAndAssertedSetsHaveDistinctNames(t *testing.T) {
	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	svc, _ := plan.ServiceByName("admin")
	seen := map[string]bool{}
	for _, s := range svc.Sets {
		if seen[s.Name] {
			t.Fatalf("set name %q reused within one service's sets: an observed address and an asserted CIDR must never share a set (see package doc)", s.Name)
		}
		seen[s.Name] = true
	}
}

func TestGate_Plan_AssertedSetsAreIntervalObservedAreNot(t *testing.T) {
	plan, _ := BuildRulesetPlan(fixturePolicy())
	svc, _ := plan.ServiceByName("admin")
	for _, s := range svc.Sets {
		want := s.Kind == SetAsserted
		if s.Interval() != want {
			t.Fatalf("set %s (%s): Interval() = %v, want %v", s.Name, s.Kind, s.Interval(), want)
		}
	}
}

func TestGate_Plan_RejectsMissingAlwaysAllowIface(t *testing.T) {
	p := fixturePolicy()
	p.AlwaysAllowIface = ""
	if _, err := BuildRulesetPlan(p); err == nil {
		t.Fatal("BuildRulesetPlan accepted a policy with no always_allow_iface")
	} else if !strings.Contains(err.Error(), "always_allow_iface") {
		t.Fatalf("error %q does not mention always_allow_iface", err)
	}
}

func TestGate_Plan_RejectsUnresolvedFailPosture(t *testing.T) {
	p := fixturePolicy()
	svc := p.Services["admin"]
	svc.FailPosture = ""
	p.Services["admin"] = svc
	if _, err := BuildRulesetPlan(p); err == nil {
		t.Fatal("BuildRulesetPlan accepted a gate service with an unresolved fail_posture")
	}
}

func TestGate_Plan_ServicesAreSortedByName(t *testing.T) {
	plan, err := BuildRulesetPlan(fixturePolicy())
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	var names []string
	for _, s := range plan.Services {
		names = append(names, s.Name)
	}
	want := []string{"admin", "canary", "ssh"}
	if len(names) != len(want) {
		t.Fatalf("got services %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got services %v, want sorted %v", names, want)
		}
	}
}
