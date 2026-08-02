package agent_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
)

// prearmPolicy is the shape brief invariant 1 is about: a break-glass gate
// whose listener is up, an unrelated gate ("postgres") whose listener is
// down, and a canary that expects no listener. The invariant is that the
// second one's outage costs the operator postgres and nothing else.
func prearmPolicy() *config.Policy {
	return &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		RecoveryService:  "ssh",
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: time.Minute, MaxTTL: 5 * time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerPresent,
			},
			"postgres": {
				Name: "postgres", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{5432},
				DefaultTTL: time.Minute, MaxTTL: 5 * time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerPresent,
			},
			"canary": {
				Name: "canary", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{62202},
				DefaultTTL: 30 * time.Second, MaxTTL: time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerAbsent,
			},
			"confirm":  {Name: "confirm", Kind: config.KindAction},
			"liveness": {Name: "liveness", Kind: config.KindAction},
		},
	}
}

// passingChecks is every global precondition satisfied and a listener map
// that matches every service's expectation.
func passingChecks(listeners map[string]bool) agent.PreArmChecks {
	return agent.PreArmChecks{
		NFTBinary:     func() error { return nil },
		FirewallReady: func(context.Context) error { return nil },
		StoreWritable: func() error { return nil },
		OperatorKeys:  func(*config.Policy) error { return nil },
		AlwaysAllow:   func(*config.Policy) error { return nil },
		ListenerUp: func(_ context.Context, svc config.Service) (bool, error) {
			return listeners[svc.Name], nil
		},
	}
}

// Brief invariant 1, the degradation half: a listener_expectation "present"
// service whose listener is down disables only that service. Everything
// else — including the SPA listener and agent_up, which the daemon arms iff
// pre-arm is not inert — comes up normally.
//
// The mutation this catches: promoting the listener check to the global
// list (returning it from the same loop that collects nftables/nft/store
// failures). That is the design's stated bug — "a postgres daemon that
// fails to come back after a reboot would fail pre-arm, keep the agent
// inert, leave agent_up unset, and silence the SPA port for every service
// including ssh" — and it makes Inert() true here.
func TestAgent_PreArm_ListenerOutageDisablesOnlyThatService(t *testing.T) {
	policy := prearmPolicy()
	checks := passingChecks(map[string]bool{"ssh": true, "postgres": false, "canary": false})

	res := agent.RunPreArm(context.Background(), policy, checks)

	if res.Inert() {
		t.Fatalf("a single service's listener outage made the whole agent inert; SPA is now silent "+
			"for ssh too. global failures: %v", res.Global)
	}
	if res.ServiceEnabled("postgres") {
		t.Fatal("postgres declares listener_expectation present and has no listener; it must not be armed")
	}
	for _, name := range []string{"ssh", "canary"} {
		if !res.ServiceEnabled(name) {
			t.Fatalf("service %q was disabled by an unrelated service's listener outage: %v", name, res.Disabled[name])
		}
	}
	if !res.SPAEnabled() {
		t.Fatal("the SPA listener was silenced by an unrelated service's listener outage")
	}
}

// The inverse expectation mismatch is red for the same reason (I2): a
// listener found on an "absent"-expectation service means the canary's
// post-knock connect would return RST from something real rather than from
// the gate, so the verification it exists to provide is worthless.
func TestAgent_PreArm_ListenerFoundOnAnAbsentExpectationServiceDisablesIt(t *testing.T) {
	policy := prearmPolicy()
	checks := passingChecks(map[string]bool{"ssh": true, "postgres": true, "canary": true})

	res := agent.RunPreArm(context.Background(), policy, checks)

	if res.Inert() {
		t.Fatalf("an expectation mismatch must not be global: %v", res.Global)
	}
	if res.ServiceEnabled("canary") {
		t.Fatal("canary expects no listener but one was found; arming it would make its RST proof meaningless")
	}
	if !res.ServiceEnabled("ssh") || !res.ServiceEnabled("postgres") {
		t.Fatal("canary's mismatch disabled an unrelated service")
	}
}

// An "unchecked" expectation is exactly that: the probe is not consulted and
// the service arms either way. Without this, a service the operator
// deliberately declined to check would be disabled by whatever the probe
// happened to return.
func TestAgent_PreArm_UncheckedExpectationIgnoresTheProbe(t *testing.T) {
	policy := prearmPolicy()
	svc := policy.Services["postgres"]
	svc.ListenerExpectation = config.ListenerUnchecked
	policy.Services["postgres"] = svc

	probed := false
	checks := passingChecks(nil)
	checks.ListenerUp = func(_ context.Context, s config.Service) (bool, error) {
		if s.Name == "postgres" {
			probed = true
		}
		return s.Name == "ssh", nil
	}

	res := agent.RunPreArm(context.Background(), policy, checks)
	if probed {
		t.Fatal("an unchecked service's listener was probed anyway")
	}
	if !res.ServiceEnabled("postgres") {
		t.Fatalf("an unchecked service was disabled: %v", res.Disabled["postgres"])
	}
}

// Brief invariant 1, the global half: each of the five global preconditions
// keeps the agent inert on its own, because nothing works without them.
// Inert is asserted as "no service armed AND no SPA listener", not merely a
// boolean, since a version that reported Inert() while still arming gates
// would pass a flag-only check.
func TestAgent_PreArm_EachGlobalPreconditionKeepsTheAgentInert(t *testing.T) {
	boom := errors.New("precondition failed")
	cases := []struct {
		name   string
		break_ func(*agent.PreArmChecks)
	}{
		{"nft binary absent", func(c *agent.PreArmChecks) { c.NFTBinary = func() error { return boom } }},
		{"firewall backend unusable", func(c *agent.PreArmChecks) {
			c.FirewallReady = func(context.Context) error { return boom }
		}},
		{"replay store not writable", func(c *agent.PreArmChecks) { c.StoreWritable = func() error { return boom } }},
		{"no operator keys", func(c *agent.PreArmChecks) {
			c.OperatorKeys = func(*config.Policy) error { return boom }
		}},
		{"always-allow path unresolvable", func(c *agent.PreArmChecks) {
			c.AlwaysAllow = func(*config.Policy) error { return boom }
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := prearmPolicy()
			checks := passingChecks(map[string]bool{"ssh": true, "postgres": true, "canary": false})
			tc.break_(&checks)

			res := agent.RunPreArm(context.Background(), policy, checks)

			if !res.Inert() {
				t.Fatal("a global precondition failed and the agent is not inert")
			}
			if res.SPAEnabled() {
				t.Fatal("the SPA listener is enabled on an inert agent")
			}
			for name, svc := range policy.Services {
				if svc.Kind != config.KindGate {
					continue
				}
				if res.ServiceEnabled(name) {
					t.Fatalf("gate %q is armed on an inert agent", name)
				}
			}
			if len(res.Global) == 0 {
				t.Fatal("Inert() is true but no global failure was recorded; the reason must be reportable")
			}
		})
	}
}

// Design section 7's "What 'inert' actually means on a fail-closed host":
// the words understate the state, so pre-arm must be able to say it out
// loud. An inert agent on a host with a fail-closed service is not a host
// with nothing dropping traffic — boot.nft already loaded the drops, and
// inert means nothing can open them.
func TestAgent_PreArm_InertOnAFailClosedHostReportsTheDropsAreAlreadyLive(t *testing.T) {
	policy := prearmPolicy() // every gate here is fail-closed
	checks := passingChecks(nil)
	checks.NFTBinary = func() error { return errors.New("nft: not found") }

	res := agent.RunPreArm(context.Background(), policy, checks)
	if !res.Inert() {
		t.Fatal("expected inert")
	}
	if !res.FailClosedDropsLive {
		t.Fatal("this host has fail-closed services, so boot.nft's drop rules are already live and " +
			"nothing can open them; an inert agent that does not report this reads as \"nothing is happening\"")
	}
	if !strings.Contains(res.Summary(), "reachable only via the always-allow path or console") {
		t.Fatalf("inert summary does not state the operator's actual position: %q", res.Summary())
	}
}

// A gate whose ports cannot be bound into the ruleset is the design's other
// per-service precondition. It disables that service alone, on the same
// footing as a listener mismatch.
func TestAgent_PreArm_APortThatCannotBeArmedDisablesOnlyThatService(t *testing.T) {
	policy := prearmPolicy()
	checks := passingChecks(map[string]bool{"ssh": true, "postgres": true, "canary": false})
	checks.PortsArmable = func(_ context.Context, svc config.Service) error {
		if svc.Name == "postgres" {
			return errors.New("set gate_postgres_v6_cidr: interval sets unsupported")
		}
		return nil
	}

	res := agent.RunPreArm(context.Background(), policy, checks)
	if res.Inert() {
		t.Fatalf("one service's ports failing to arm must not be global: %v", res.Global)
	}
	if res.ServiceEnabled("postgres") {
		t.Fatal("postgres's ports could not be armed but the service is enabled")
	}
	if !res.ServiceEnabled("ssh") {
		t.Fatal("ssh was disabled by postgres's ruleset failure")
	}
}

// --- always-allow resolvability (design section 7, global preconditions) ---

// The lockout this whole check exists for: `always_allow_iface: lo` passed
// both of postern's checks, because both were non-emptiness. A host enrolled
// that way armed fail-closed, rebooted, and was never reachable again.
//
// This probes the real ProductionChecks value rather than an injected one.
// PortsArmable shipped documented, tested against an injected probe, and
// never populated, and only direct probing caught it.
//
// The mutation this catches: deleting the AlwaysAllow branch from
// ProductionChecks. checks.AlwaysAllow is then nil and the first assertion
// fails; RunPreArm would skip the precondition entirely.
func TestAgent_ProductionChecks_WiresAlwaysAllowResolvability(t *testing.T) {
	production := agent.ProductionChecks(agent.PreArmChecks{}, &daemonGate{}, "/tmp/replay.db", "")
	if production.AlwaysAllow == nil {
		t.Fatal("ProductionChecks did not wire AlwaysAllow; design section 7 lists always-allow " +
			"resolvability among the global preconditions, and an unwired check is the non-emptiness " +
			"test that let `always_allow_iface: lo` arm a host into permanent lockout")
	}

	// Only the probe under test comes from production; the rest pass, so
	// what Inert() reports below is this precondition and not an incidental
	// failure of nft(8) or the operator key set on the machine running this.
	withProduction := func() agent.PreArmChecks {
		c := passingChecks(map[string]bool{"ssh": true, "postgres": true, "canary": false})
		c.AlwaysAllow = production.AlwaysAllow
		return c
	}

	t.Run("a name no interface answers to keeps the agent inert", func(t *testing.T) {
		policy := prearmPolicy()
		policy.AlwaysAllowIface = "postern-no-such-iface0"

		if err := production.AlwaysAllow(policy); err == nil {
			t.Fatal("an always_allow_iface naming no interface on this host passed the check; " +
				"\"resolvable\" has to mean more than \"non-empty\"")
		} else if errors.Is(err, agent.ErrAlwaysAllowDegraded) {
			t.Fatalf("an unresolvable interface was reported as merely degraded: %v", err)
		}

		res := agent.RunPreArm(context.Background(), policy, withProduction())
		if !res.Inert() {
			t.Fatalf("an always-allow interface that does not exist did not keep the agent inert: %q", res.Summary())
		}
	})

	// The real loopback on this machine, whatever it is called here. It is
	// reported — the bug was that it was not — but as degraded, not as a
	// reason to take the SPA port down with it.
	t.Run("loopback is reported without silencing the agent", func(t *testing.T) {
		policy := prearmPolicy()
		policy.AlwaysAllowIface = loopbackName(t)

		err := production.AlwaysAllow(policy)
		if err == nil {
			t.Fatalf("interface %q is loopback and the resolvability check said nothing; that is "+
				"exactly the configuration that locked a host out", policy.AlwaysAllowIface)
		}
		if !errors.Is(err, agent.ErrAlwaysAllowDegraded) {
			t.Fatalf("a loopback always-allow interface was made a global failure: %v.\n"+
				"Inert on a fail-closed host means the drops are live, nothing can open them, and SPA "+
				"is silent — so this would brick every host already enrolled with lo at its next "+
				"agent restart, which is the lockout it exists to prevent. The refusal belongs at "+
				"enrollment, where the operator still has a way in.", err)
		}

		res := agent.RunPreArm(context.Background(), policy, withProduction())
		if res.Inert() {
			t.Fatalf("a loopback always-allow interface made the agent inert: %v", res.Global)
		}
		if len(res.Warnings) != 1 {
			t.Fatalf("Warnings = %v, want exactly the one loopback finding", res.Warnings)
		}
	})
}

// loopbackName is whatever this kernel calls its loopback interface — "lo"
// on Linux, "lo0" on darwin — found by the flag rather than by name, so the
// test asks the same question the production probe does.
func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("enumerate interfaces: %v", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	t.Skip("this machine reports no loopback interface")
	return ""
}

// The judgment the design does not make for us: "absent entirely" and
// "present but currently no use" are not the same finding.
//
// Absent is a configuration nothing but an edit fixes. Down, address-less,
// or loopback all resolve — the name is right — and the first two are the
// ordinary shape of a transient. Inert on a fail-closed host takes the SPA
// port down with it, so going inert over a mesh flap would lock out a host
// that was fine.
//
// The mutation this catches: dropping the ErrAlwaysAllowDegraded wrap from
// any classifyAlwaysAllowIface branch. That branch's case then lands in
// Global, and RunPreArm reports inert.
func TestAgent_PreArm_ADegradedAlwaysAllowInterfaceWarnsRatherThanGoingInert(t *testing.T) {
	const iface = "tailscale0"
	cases := []struct {
		name    string
		flags   net.Flags
		addrs   int
		addrErr error
		want    bool // want a finding at all
	}{
		{"up, addressed, not loopback", net.FlagUp | net.FlagRunning, 1, nil, false},
		{"down", net.FlagRunning, 1, nil, true},
		{"up but unaddressed", net.FlagUp | net.FlagRunning, 0, nil, true},
		{"up but its addresses cannot be read", net.FlagUp, 0, errors.New("netlink: EPERM"), true},
		{"loopback", net.FlagUp | net.FlagLoopback, 1, nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := agent.ClassifyAlwaysAllowIface(iface, tc.flags, tc.addrs, tc.addrErr)
			if !tc.want {
				if err != nil {
					t.Fatalf("a usable always-allow interface was flagged: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("an always-allow interface in this state was reported as fine")
			}
			if !errors.Is(err, agent.ErrAlwaysAllowDegraded) {
				t.Fatalf("this state was classified as a global failure: %v.\n"+
					"A global failure keeps the agent inert, and inert on a fail-closed host means "+
					"boot.nft's drops are live with nothing able to open them and no SPA to knock "+
					"with — so a transient here would lock out a host that was reachable.", err)
			}

			// And the classification has to survive the trip through
			// RunPreArm, which is where it decides the agent's fate.
			policy := prearmPolicy()
			checks := passingChecks(map[string]bool{"ssh": true, "postgres": true, "canary": false})
			checks.AlwaysAllow = func(*config.Policy) error { return err }

			res := agent.RunPreArm(context.Background(), policy, checks)
			if res.Inert() {
				t.Fatalf("a degraded always-allow path made the agent inert: %v", res.Global)
			}
			if !res.SPAEnabled() {
				t.Fatal("a degraded always-allow path silenced the SPA port, which is the one way " +
					"into this host that still works")
			}
			if len(res.Warnings) != 1 {
				t.Fatalf("Warnings = %v, want exactly the one degraded-path finding; a finding that "+
					"is not an interlock is worthless if it is also not reported", res.Warnings)
			}
			if !strings.Contains(res.Summary(), "WARNING") || !strings.Contains(res.Summary(), iface) {
				t.Fatalf("the summary an operator reads does not carry the warning: %q", res.Summary())
			}
		})
	}
}

// TestAgent_PreArm_AForeignFirewallFindingWarnsRatherThanGoingInert is
// ErrForeignFirewall's contract: unlike AlwaysAllow, this precondition has
// only one verdict, and it is always a warning. A foreign nftables chain
// that could override postern's gate (invariant 2 — a drop verdict in one
// base chain on a hook is terminal regardless of an accept in another) is
// routinely a firewall the operator configured on purpose, so it must never
// keep the agent inert, never silence the SPA port, and never disable any
// service — it only has to be visible in the summary an operator reads.
//
// The mutation this catches: wiring ForeignFirewall's error into res.Global
// instead of res.Warnings, or gating it on errors.Is the way AlwaysAllow
// gates two different sentinels — ForeignFirewall has no global branch at
// all, so any such gate would be dead code hiding a silent regression to
// "always inert" the moment it stopped matching.
func TestAgent_PreArm_AForeignFirewallFindingWarnsRatherThanGoingInert(t *testing.T) {
	policy := prearmPolicy()
	checks := passingChecks(map[string]bool{"ssh": true, "postgres": true, "canary": false})
	checks.ForeignFirewall = func() error {
		return fmt.Errorf("%w: ip table \"filter\" chain \"INPUT\" (hook input) carries a rule-level drop or reject",
			agent.ErrForeignFirewall)
	}

	res := agent.RunPreArm(context.Background(), policy, checks)

	if res.Inert() {
		t.Fatalf("a foreign firewall finding made the agent inert: %v", res.Global)
	}
	if !res.SPAEnabled() {
		t.Fatal("a foreign firewall finding silenced the SPA port; it is advisory, not an interlock")
	}
	for _, name := range []string{"ssh", "postgres"} {
		if !res.ServiceEnabled(name) {
			t.Fatalf("service %q was disabled by an unrelated foreign-firewall finding: %v", name, res.Disabled[name])
		}
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want exactly the one foreign-firewall finding", res.Warnings)
	}
	if !errors.Is(res.Warnings[0], agent.ErrForeignFirewall) {
		t.Fatalf("Warnings[0] = %v, want it to wrap ErrForeignFirewall", res.Warnings[0])
	}
	if !strings.Contains(res.Summary(), "WARNING") || !strings.Contains(res.Summary(), "INPUT") {
		t.Fatalf("the summary an operator reads does not carry the foreign-firewall warning: %q", res.Summary())
	}
}

// Actions (confirm, disarm, liveness) own no ports and no listener, so they
// are never subject to a per-service precondition. If they were, a policy
// declaring liveness would probe a listener that cannot exist and disable
// the one action that proves the always-allow path works.
func TestAgent_PreArm_ActionsAreNeverDisabledByPerServiceChecks(t *testing.T) {
	policy := prearmPolicy()
	checks := passingChecks(nil) // every listener down
	checks.ListenerUp = func(context.Context, config.Service) (bool, error) {
		return false, errors.New("probe failed")
	}

	res := agent.RunPreArm(context.Background(), policy, checks)
	for _, name := range []string{"confirm", "liveness"} {
		if !res.ServiceEnabled(name) {
			t.Fatalf("action %q was disabled by a listener probe it has no listener for: %v", name, res.Disabled[name])
		}
	}
}
