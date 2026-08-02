package main

import (
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// twoPostureplan builds a plan with one fail-closed gate (so postern_boot
// has sets to flush) and one fail-open gate (so postern_open exists to be
// deleted). Both are needed: a plan with only one posture cannot tell the
// two commands apart.
func twoPosturePlan(t *testing.T) *gate.RulesetPlan {
	t.Helper()
	policy := &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		RecoveryService:  "ssh",
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 2 * time.Minute, MaxTTL: 5 * time.Minute,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
			},
			"canary": {
				Name: "canary", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{62202},
				DefaultTTL: 30 * time.Second, MaxTTL: time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerAbsent,
			},
		},
	}
	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	return plan
}

// gate-flush is documented as "empty every fail-closed gate set, leaving its
// drop rules standing". A version that also deleted postern_open would take
// down every fail-open service on the host — silently, since the command
// would still report each argv it ran and exit 0.
//
// The property is asserted on the verb rather than on a slice index. The
// previous implementation was `cmds[1:]`, which encoded "the postern_open
// delete is first in gate.TeardownCommands" as an unexpressed cross-package
// invariant; changing it to `cmds[0:]` made gate-flush delete a table with
// nothing failing on either platform.
//
// Mutation verified: `return all` for both commands fails this test's flush
// case; filtering the flushes instead of the delete fails the teardown case.
func TestMain_GateCommands_OnlyTeardownRemovesATable(t *testing.T) {
	plan := twoPosturePlan(t)
	const nft = "/usr/sbin/nft"

	teardown := gateCommands(plan, nft, true)
	flush := gateCommands(plan, nft, false)

	deletes := 0
	for _, argv := range teardown {
		if isDeleteCommand(argv) {
			deletes++
			if !containsArg(argv, gate.TableOpen) {
				t.Errorf("gate-teardown deletes a table other than %s: %v", gate.TableOpen, argv)
			}
		}
	}
	if deletes != 1 {
		t.Fatalf("gate-teardown issued %d delete commands, want exactly one (%s)", deletes, gate.TableOpen)
	}

	for _, argv := range flush {
		if isDeleteCommand(argv) {
			t.Fatalf("gate-flush deletes a table: %v — its documented job is to empty the fail-closed "+
				"gate sets and leave everything else standing, and deleting %s takes every fail-open "+
				"service down with it", argv, gate.TableOpen)
		}
	}
	if len(flush) == 0 {
		t.Fatal("gate-flush issued no commands at all, so the fail-closed gate sets stay populated " +
			"after the agent is gone")
	}
	if len(flush) != len(teardown)-1 {
		t.Fatalf("gate-flush ran %d commands and gate-teardown %d; they must differ by exactly the "+
			"one table delete", len(flush), len(teardown))
	}
}

// Neither command may flush a *table*: that deletes postern_boot's drop
// rules and inverts the posture, which is the silent failure I3 exists to
// prevent. The renderer enforces this and internal/gate tests it; asserting
// it here too is cheap and this is the other place those argvs are executed.
func TestMain_GateCommands_NeverFlushATable(t *testing.T) {
	plan := twoPosturePlan(t)
	for _, includeOpen := range []bool{true, false} {
		for _, argv := range gateCommands(plan, "/usr/sbin/nft", includeOpen) {
			line := strings.Join(argv, " ")
			if strings.Contains(line, "flush table") {
				t.Fatalf("%q flushes a table, which deletes the drop rules and inverts the posture", line)
			}
		}
	}
}

// Both commands come from gate.TeardownCommands, the same source the
// rendered unit's ExecStopPost lines come from, so what an operator types
// and what systemd runs cannot drift.
func TestMain_GateCommands_ComeFromTheUnitsOwnTeardownSource(t *testing.T) {
	plan := twoPosturePlan(t)
	want := gate.TeardownCommands(plan, "/usr/sbin/nft")
	got := gateCommands(plan, "/usr/sbin/nft", true)

	if len(got) != len(want) {
		t.Fatalf("gate-teardown ran %d commands, the unit runs %d", len(got), len(want))
	}
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Fatalf("command %d differs from the unit's:\n got: %v\nwant: %v", i, got[i], want[i])
		}
	}
}

func containsArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}
