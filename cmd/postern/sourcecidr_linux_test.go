//go:build linux

package main

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/gate"
)

// A generated config that validates is not the same claim as a generated
// config that arms. Validate runs on a struct; arming runs against the
// kernel, and the whole failure this task exists to fix was a host that could
// not be reached — so the last step is asserted against real netfilter rather
// than against postern's own view of what it wrote.
//
// This runs in the privileged, network-isolated container
// scripts/linux-test.sh provides. It drives the real init-standalone, arms
// the config that command left on disk, and opens the ssh gate for an
// asserted /24 — the carrier-NAT prefix the whole feature exists to admit —
// then reads the element back out of `nft list`.
//
// Mutation verified: emitting allow_source_cidr without the two minimum
// prefixes makes init-standalone itself fail, so this test fails at
// enrolledHost before touching the kernel; routing an asserted source into
// the observed set instead of the interval one fails at the Open below, with
// the kernel refusing the element.
func TestMain_InitStandalone_AnAllowSourceCIDRConfigArmsAndOpensForTheAssertedPrefix(t *testing.T) {
	sign, enc := publicKeyPairB64(t)
	dir, _ := enrolledHost(t, "laptop-primary", sign, enc, "--allow-source-cidr", "laptop-primary")
	policy := generatedPolicy(t, dir)

	g, err := gate.NewNFTables(policy)
	if err != nil {
		t.Fatalf("NewNFTables on a freshly generated config: %v", err)
	}
	t.Cleanup(func() {
		_ = g.Close(context.Background())
		dropPosternTables()
	})
	dropPosternTables() // in case an earlier failure left state behind

	ctx := context.Background()
	if err := g.Apply(ctx); err != nil {
		t.Fatalf("the config init-standalone generated does not arm: %v", err)
	}
	if err := g.ApplyOpen(ctx); err != nil {
		t.Fatalf("ApplyOpen: %v", err)
	}

	asserted := netip.MustParsePrefix("10.2.0.0/24")
	if err := g.Open(ctx, "ssh", gate.Source{Kind: gate.SourceAsserted, Prefix: asserted}, 2*time.Minute); err != nil {
		t.Fatalf("the gate would not open for an asserted %s, so the CGNAT mitigation this config "+
			"grants cannot actually be applied: %v", asserted, err)
	}

	// Which table holds ssh is the plan's decision, not this test's: ssh is
	// break-glass and therefore fail-open, so it lives in postern_open, and
	// hard-coding either name here would make the readback depend on a posture
	// the config is free to change.
	svcPlan, ok := g.Plan().ServiceByName("ssh")
	if !ok {
		t.Fatal("the generated plan has no ssh service")
	}
	out, err := exec.Command("nft", "list", "table", "inet", svcPlan.Table).CombinedOutput() //nolint:gosec // a name from postern's own plan
	if err != nil {
		t.Fatalf("nft list table inet %s: %v: %s", svcPlan.Table, err, out)
	}
	if !strings.Contains(string(out), "10.2.0.0") {
		t.Fatalf("the asserted prefix is not in the armed ruleset, so nothing behind the carrier NAT "+
			"would reach ssh:\n%s", out)
	}

	state, err := g.State(ctx, "ssh")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	var found bool
	for _, el := range state.Elements {
		if el.Source.Kind == gate.SourceAsserted && el.Source.Prefix == asserted {
			found = true
		}
	}
	if !found {
		t.Fatalf("the gate reports no asserted element for %s: %+v", asserted, state.Elements)
	}
}

func dropPosternTables() {
	_ = exec.Command("nft", "delete", "table", "inet", gate.TableBoot).Run() //nolint:gosec // a package constant, not input
	_ = exec.Command("nft", "delete", "table", "inet", gate.TableOpen).Run() //nolint:gosec // a package constant, not input
}
