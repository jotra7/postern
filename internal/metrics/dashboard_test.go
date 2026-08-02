package metrics_test

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/metrics"
)

const dashboardPath = "../../dashboards/postern.json"

// A shipped dashboard is only worth anything if it names metrics that exist.
// The two directions are checked separately because they fail for different
// reasons: a panel naming a metric nobody exports is a dead panel that reads
// as "no data" and therefore as "nothing is wrong", and an exported metric no
// panel names is a signal the operator was never given.

var metricNamePattern = regexp.MustCompile(`postern_[a-z0-9_]+`)

// exported renders every family a fully-populated Recorder emits, keyed by
// family name. The recorder is populated through its own methods rather than
// by reaching into the collectors, so a family that no method can write is
// absent here and fails the test.
func exported(t *testing.T) map[string]bool {
	t.Helper()
	r := metrics.New()
	// The probe half is populated by running a real sweep through a real
	// probe.Runner, for the same reason the agent half is populated through
	// the Recorder's own methods: a family that only some hand-written call
	// site can write is a family the running system may never produce.
	newCanaryFixture(t, r, passing()...).once(t)

	now := time.Now()
	r.SetHostID("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
	r.SetInert(false)
	r.SetHealthRed(metrics.HealthSourceAgentUp, false)
	r.AgentUpRenewal(true, now)
	r.SetServiceArmed("ssh", true)
	r.SetGateOpenSources("ssh", 1, 0)
	r.GateOpened("ssh", now)
	r.GateOpenFailed("ssh")
	r.SPAHandled()
	r.SPAAccepted("ssh")
	r.SPARejected("too_old")
	r.ObserveClockSkew(time.Second)
	r.AcceptedBeyondFreshnessWindow()
	r.SetTransactionPending(true, now.Add(time.Minute))
	r.TransactionReverted()
	r.BundlePullRejected("fetch_failed")
	r.BundlePullApplied()
	r.HeartbeatSent()
	r.HeartbeatRejected("send_failed")

	names := map[string]bool{}
	for _, line := range strings.Split(scrape(t, r), "\n") {
		if !strings.HasPrefix(line, "# HELP ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		names[fields[2]] = true
	}
	if len(names) == 0 {
		t.Fatal("parsed no metric families out of the scrape; the rest of this test would pass vacuously")
	}
	return names
}

// dashboardMetrics pulls every postern_* name out of every PromQL expression
// in the shipped dashboard, folding a histogram's _bucket/_sum/_count series
// back onto the family they belong to.
func dashboardMetrics(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read %s: %v", dashboardPath, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid JSON, so Grafana would refuse to import it: %v", dashboardPath, err)
	}

	found := map[string]bool{}
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "expr" {
					if expr, ok := child.(string); ok {
						for _, name := range metricNamePattern.FindAllString(expr, -1) {
							found[familyOf(name)] = true
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)

	if len(found) == 0 {
		// Without this the whole test passes on an empty extraction, which is
		// exactly what a broken walk or a mistyped panel key produces.
		t.Fatalf("found no postern_* metric names in any expr in %s", dashboardPath)
	}
	return found
}

func familyOf(series string) string {
	for _, suffix := range []string{"_bucket", "_sum", "_count"} {
		if base := strings.TrimSuffix(series, suffix); base != series {
			return base
		}
	}
	return series
}

func TestMetrics_Dashboard_ReferencesOnlyMetricsTheAgentExports(t *testing.T) {
	have := exported(t)
	var missing []string
	for name := range dashboardMetrics(t) {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%s queries metrics nothing exports: %s\nA panel like that renders as \"no data\", which "+
			"an operator reads as \"nothing is wrong\".", dashboardPath, strings.Join(missing, ", "))
	}
}

func TestMetrics_Dashboard_ShowsEveryMetricTheAgentExports(t *testing.T) {
	shown := dashboardMetrics(t)
	var unshown []string
	for name := range exported(t) {
		if !shown[name] {
			unshown = append(unshown, name)
		}
	}
	sort.Strings(unshown)
	if len(unshown) > 0 {
		t.Fatalf("nothing in %s reads: %s\nA metric with no panel is a signal the operator was never "+
			"given.", dashboardPath, strings.Join(unshown, ", "))
	}
}
