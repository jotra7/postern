package gate

import (
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// The flush drop-in names exactly the fail-closed gate sets the plan has, no
// more and no fewer — the same equivalence RenderSystemdFlushLines and the
// live Close hold, now applied where systemd actually reads the flush lines
// from. postern_open's sets must never appear: its whole table is deleted by
// the main unit's sibling line, and flushing one of its sets here would be a
// line for a set this drop-in has no business naming.
func TestGate_RenderFlushDropIn_NamesExactlyTheBootFailClosedSets(t *testing.T) {
	plan := mustPlan(t)
	dropIn := RenderFlushDropIn(plan, DefaultNFTPath)

	if !strings.HasPrefix(dropIn, "[Service]\n") {
		t.Fatalf("drop-in is not a [Service] override:\n%s", dropIn)
	}

	want := map[string]bool{}
	for _, svc := range plan.BootServices() {
		for _, s := range svc.Sets {
			want[s.Name] = true
		}
	}
	if len(want) == 0 {
		t.Fatal("fixture has no fail-closed gate sets; this test would be vacuous")
	}

	got := map[string]bool{}
	for _, line := range execStopPostLines(t, dropIn) {
		fields := strings.Fields(line)
		if len(fields) != 6 || fields[1] != "flush" || fields[2] != "set" || fields[3] != "inet" || fields[4] != TableBoot {
			t.Fatalf("drop-in line %q is not a flush of an inet %s set", line, TableBoot)
		}
		name := fields[5]
		if !want[name] {
			t.Fatalf("drop-in flushes %q, which is not a %s fail-closed gate set", name, TableBoot)
		}
		if got[name] {
			t.Fatalf("set %q is flushed by more than one line", name)
		}
		got[name] = true
	}
	if len(got) != len(want) {
		t.Fatalf("drop-in flushes %d sets, want one per fail-closed gate set (%d): got %v want %v",
			len(got), len(want), got, want)
	}

	for _, svc := range plan.OpenServices() {
		for _, s := range svc.Sets {
			if strings.Contains(dropIn, " "+s.Name+"\n") {
				t.Fatalf("drop-in names postern_open set %q; that table is deleted whole, not flushed", s.Name)
			}
		}
	}
}

// The regression #47 is about: the drop-in tracks the live catalogue, so a
// fail-closed service that a bundle adds AFTER enrollment gets a flush line.
// The frozen-at-enrollment unit did not, and that set's grant outlived a
// crashed agent. Break the fix by rendering the drop-in from a fixed list
// instead of FlushSetNames and the added set's line goes missing here.
func TestGate_RenderFlushDropIn_TracksASetAddedAfterEnrollment(t *testing.T) {
	base := mustPlan(t)
	baseDropIn := RenderFlushDropIn(base, DefaultNFTPath)

	// A second fail-closed service, the shape a bundle adds to a host that was
	// enrolled without it.
	p := fixturePolicy()
	p.Services["vault"] = config.Service{
		Name: "vault", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{8200},
		DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
		FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
	}
	grown, err := BuildRulesetPlan(p)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	grownDropIn := RenderFlushDropIn(grown, DefaultNFTPath)

	var addedSets []string
	for _, svc := range grown.BootServices() {
		if svc.Name == "vault" {
			for _, s := range svc.Sets {
				addedSets = append(addedSets, s.Name)
			}
		}
	}
	if len(addedSets) == 0 {
		t.Fatal("precondition: the added fail-closed service produced no gate set")
	}

	for _, name := range addedSets {
		if strings.Contains(baseDropIn, name) {
			t.Fatalf("precondition: base drop-in already names %q", name)
		}
		if !strings.Contains(grownDropIn, "flush set inet "+TableBoot+" "+name) {
			t.Fatalf("the drop-in for the grown catalogue has no flush line for the added set %q:\n%s", name, grownDropIn)
		}
	}
	if got, want := len(execStopPostLines(t, grownDropIn)), len(execStopPostLines(t, baseDropIn))+len(addedSets); got != want {
		t.Fatalf("adding one fail-closed service changed the flush-line count to %d, want %d (base + its %d sets):\nbase:\n%s\ngrown:\n%s",
			got, want, len(addedSets), baseDropIn, grownDropIn)
	}
}

// A host whose services are all fail-open has nothing to flush. The drop-in
// is then a valid, inert [Service] override with no ExecStopPost lines rather
// than a missing file the agent would have to special-case.
func TestGate_RenderFlushDropIn_IsInertWhenNoFailClosedSetsExist(t *testing.T) {
	p := &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
			},
		},
	}
	plan, err := BuildRulesetPlan(p)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}
	dropIn := RenderFlushDropIn(plan, DefaultNFTPath)
	if strings.TrimSpace(dropIn) != "[Service]" {
		t.Fatalf("a host with no fail-closed sets should render an inert [Service] drop-in, got:\n%q", dropIn)
	}
}

// The drop-in names the same nft(8) the operator enrolled with, so a host
// whose nft lives off the default path is torn down by a binary that exists.
// An empty nftPath falls back to DefaultNFTPath, matching the unit renderer.
func TestGate_RenderFlushDropIn_HonorsTheConfiguredNFTPath(t *testing.T) {
	plan := mustPlan(t)
	const custom = "/opt/sbin/nft"
	dropIn := RenderFlushDropIn(plan, custom)
	for _, line := range execStopPostLines(t, dropIn) {
		if !strings.HasPrefix(line, custom+" ") {
			t.Fatalf("drop-in line %q does not use the configured nft path %q", line, custom)
		}
	}
	if def := RenderFlushDropIn(plan, ""); !strings.Contains(def, DefaultNFTPath+" flush set") {
		t.Fatalf("empty nftPath did not fall back to %s:\n%s", DefaultNFTPath, def)
	}
}
