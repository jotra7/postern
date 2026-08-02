package metrics_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const rulesPath = "../../dashboards/rules.yml"

// dashboards/rules.yml is where "health is the join" is computed. Nothing in
// this repository can evaluate PromQL, so what these tests can establish is
// bounded and worth stating plainly: they check that every metric the rules
// name is one postern actually exports, that every recording rule the
// dashboard reads is one this file records, and that the join rule reads both
// halves rather than one. They do not check that the expressions mean what
// they say.
//
// That bound is exactly why they matter. The failure this whole piece of work
// exists to remove is a check that is defined, documented and tested and never
// wired to the thing that runs — and a dashboard panel querying a recording
// rule nobody records is that failure again, rendering as "no data", which an
// operator reads as "nothing is wrong".

type ruleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Record string `yaml:"record"`
			Alert  string `yaml:"alert"`
			Expr   string `yaml:"expr"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

// recordedNamePattern matches a recording rule's name. Prometheus separates
// the levels with colons, which is what keeps them out of the postern_* scan
// the dashboard test does.
var recordedNamePattern = regexp.MustCompile(`postern:[a-z0-9_:]+`)

func loadRules(t *testing.T) ruleFile {
	t.Helper()
	raw, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read %s: %v", rulesPath, err)
	}
	var doc ruleFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid YAML, so Prometheus would refuse to load it: %v", rulesPath, err)
	}
	if len(doc.Groups) == 0 {
		t.Fatalf("%s declares no rule groups; the rest of this test would pass vacuously", rulesPath)
	}
	return doc
}

// recordedAndReferenced returns what the file records and what it reads.
func recordedAndReferenced(t *testing.T) (recorded map[string]bool, families map[string]bool, refs map[string]bool) {
	t.Helper()
	recorded, families, refs = map[string]bool{}, map[string]bool{}, map[string]bool{}
	exprs := 0
	for _, g := range loadRules(t).Groups {
		for _, r := range g.Rules {
			if r.Record != "" {
				recorded[r.Record] = true
			}
			if r.Expr == "" {
				t.Errorf("%s: rule %q%q has no expr", rulesPath, r.Record, r.Alert)
				continue
			}
			exprs++
			for _, name := range metricNamePattern.FindAllString(r.Expr, -1) {
				families[familyOf(name)] = true
			}
			for _, name := range recordedNamePattern.FindAllString(r.Expr, -1) {
				refs[name] = true
			}
		}
	}
	if exprs == 0 || len(families) == 0 {
		t.Fatalf("%s yielded no expressions or no metric names; a broken walk would pass every "+
			"assertion below", rulesPath)
	}
	return recorded, families, refs
}

func TestMetrics_Rules_ReferenceOnlyMetricsPosternExports(t *testing.T) {
	recorded, families, refs := recordedAndReferenced(t)
	have := exported(t)

	var missing []string
	for name := range families {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	for name := range refs {
		if !recorded[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%s reads series nothing produces: %s\nA rule over a metric nobody exports evaluates "+
			"to an empty vector, and an alert that never fires is indistinguishable from a system that "+
			"is fine.", rulesPath, strings.Join(missing, ", "))
	}
}

// TestMetrics_Rules_TheJoinReadsBothHalves is the substantive one. A join rule
// that had lost one side would still be valid PromQL, would still record a
// series, and would still light the dashboard panel — while reporting only
// half of the condition design section 8 calls the most valuable state the
// system surfaces.
func TestMetrics_Rules_TheJoinReadsBothHalves(t *testing.T) {
	const join = "postern:health_join_red:host_id"
	var expr string
	for _, g := range loadRules(t).Groups {
		for _, r := range g.Rules {
			if r.Record == join {
				expr = r.Expr
			}
		}
	}
	if expr == "" {
		t.Fatalf("%s records no rule named %s, so nothing computes the join", rulesPath, join)
	}
	for _, half := range []string{"postern:probe_red:host_id", "postern:agent_healthy:host_id"} {
		if !strings.Contains(expr, half) {
			t.Fatalf("%s does not read %s. The join is the conjunction of the agent's self-attestation "+
				"and the probe's independent measurement; one of them alone is a different, weaker "+
				"claim.\n--- expr ---\n%s", join, half, expr)
		}
	}
	// And the two halves must be keyed on something both scrape targets carry.
	// Without the join key this degenerates into a many-to-many match that
	// Prometheus refuses, or worse, a match on labels that happen to line up.
	if !strings.Contains(expr, "on (host_id)") {
		t.Fatalf("%s does not join on host_id. The agent is identified by the address Prometheus "+
			"scrapes and the probe by the name an operator typed; host_id is the only identifier both "+
			"sides hold.\n--- expr ---\n%s", join, expr)
	}
}

// TestMetrics_Rules_EveryRecordingRuleTheDashboardReadsIsRecorded closes the
// loop between the two shipped artifacts. The "Health is the join" panel is
// the one panel on the dashboard that reads a derived series rather than an
// exported one, precisely because no postern process can export it.
func TestMetrics_Rules_EveryRecordingRuleTheDashboardReadsIsRecorded(t *testing.T) {
	recorded, _, _ := recordedAndReferenced(t)

	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read %s: %v", dashboardPath, err)
	}
	found := recordedNamePattern.FindAllString(string(raw), -1)
	if len(found) == 0 {
		t.Fatalf("%s reads no postern:* recording rule at all, so the join is on no panel", dashboardPath)
	}
	for _, name := range found {
		if !recorded[name] {
			t.Fatalf("%s queries %s, which %s does not record. The panel would render \"no data\", "+
				"which an operator reads as \"nothing is wrong\".", dashboardPath, name, rulesPath)
		}
	}
}

// TestMetrics_Rules_EveryRuleHasAPromtoolTest closes the last hole in this
// file's reach.
//
// The tests above establish that the rules name metrics that exist and that
// the join reads both halves. They cannot evaluate PromQL — nothing in this
// repository can, and no dependency may be added to change that — so what
// actually proves the expressions mean what they say is
// dashboards/rules_test.yml, run against the real evaluator by
// scripts/promtool-test.sh.
//
// That test is only worth what its coverage is worth, and it lives in a file
// `go test` does not read. So this asserts the one thing Go can: that every
// rule shipped has a promtool case naming it. A rule added without one is a
// rule whose behaviour nobody has run.
func TestMetrics_Rules_EveryRuleHasAPromtoolTest(t *testing.T) {
	const promtoolTestPath = "../../dashboards/rules_test.yml"
	raw, err := os.ReadFile(promtoolTestPath)
	if err != nil {
		t.Fatalf("read %s: %v\nThe rules are shipped with no evaluation at all if this file is gone.",
			promtoolTestPath, err)
	}
	body := string(raw)
	if !strings.Contains(body, "rules.yml") {
		t.Fatalf("%s does not load rules.yml, so it is testing nothing", promtoolTestPath)
	}

	var untested []string
	names := 0
	for _, g := range loadRules(t).Groups {
		for _, r := range g.Rules {
			name := r.Record
			if name == "" {
				name = r.Alert
			}
			if name == "" {
				continue
			}
			names++
			if !strings.Contains(body, name) {
				untested = append(untested, name)
			}
		}
	}
	if names == 0 {
		t.Fatalf("%s declares no named rules, so this test asserted nothing", rulesPath)
	}
	sort.Strings(untested)
	if len(untested) > 0 {
		t.Fatalf("%s has no case for: %s\nRun `make test-rules`. A recording rule or alert with no "+
			"promtool case has never been evaluated by anything.", promtoolTestPath, strings.Join(untested, ", "))
	}
}
