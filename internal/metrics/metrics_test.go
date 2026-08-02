package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/metrics"
)

// scrape renders the exposition text the way a Prometheus server would see
// it. Asserting against the rendered text rather than against the collectors
// is deliberate: the thing that leaks is what a scraper reads.
func scrape(t *testing.T, r *metrics.Recorder) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func mustContain(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Fatalf("scrape does not contain %q\n--- scrape ---\n%s", want, body)
	}
}

// TestMetrics_GateOpenSources_IsACountLabelledOnlyByServiceAndKind pins the
// exact series a gate-state scrape produces. The label set is the disclosure
// decision: an admitted source address as a label would be both "who is
// logged in from where" and one unbounded series per knocking address, so the
// only labels here are the service (a fixed set from the config file) and the
// source kind (two values). Adding an address label would change this line.
func TestMetrics_GateOpenSources_IsACountLabelledOnlyByServiceAndKind(t *testing.T) {
	r := metrics.New()
	r.SetGateOpenSources("ssh", 2, 1)

	body := scrape(t, r)
	mustContain(t, body, `postern_gate_open_sources{service="ssh",source_kind="observed"} 2`)
	mustContain(t, body, `postern_gate_open_sources{service="ssh",source_kind="asserted"} 1`)
}

// TestMetrics_ClockSkew_BucketsSpanBothFreshnessBounds is the load-bearing
// one. freshness_window defaults to 60s and freshness_window_max to 24h, and
// a host drifting between the two keeps admitting gate packets because the
// counter path carries them. Buckets that stopped short of 24h would show
// every such host as a saturated +Inf and reveal nothing about how far it had
// drifted.
func TestMetrics_ClockSkew_BucketsSpanBothFreshnessBounds(t *testing.T) {
	r := metrics.New()
	// One hour of drift: well past freshness_window, well inside
	// freshness_window_max. This is the population the counter path serves.
	r.ObserveClockSkew(time.Hour)

	body := scrape(t, r)
	// Below the observation.
	mustContain(t, body, `postern_spa_clock_skew_seconds_bucket{le="60"} 0`)
	mustContain(t, body, `postern_spa_clock_skew_seconds_bucket{le="900"} 0`)
	// At and above it. A bucket boundary at 3600 is what makes an hour of
	// drift distinguishable from a day of it.
	mustContain(t, body, `postern_spa_clock_skew_seconds_bucket{le="3600"} 1`)
	mustContain(t, body, `postern_spa_clock_skew_seconds_bucket{le="86400"} 1`)
}

// TestMetrics_ClockSkew_KeepsDirectionSeparately proves the signed gauge is
// not just the histogram again: a host whose clock is behind the operator's
// looks identical to one that is ahead in the magnitude histogram.
func TestMetrics_ClockSkew_KeepsDirectionSeparately(t *testing.T) {
	r := metrics.New()
	r.ObserveClockSkew(-90 * time.Second)

	body := scrape(t, r)
	mustContain(t, body, "postern_spa_clock_skew_last_seconds -90")
	// The histogram still took the magnitude, so a negative observation is
	// not silently dropped into a bucket it does not belong in.
	mustContain(t, body, `postern_spa_clock_skew_seconds_bucket{le="120"} 1`)
	mustContain(t, body, `postern_spa_clock_skew_seconds_bucket{le="60"} 0`)
}

func TestMetrics_Reason_UnrecognisedReasonBecomesOther(t *testing.T) {
	if got := metrics.Reason("bad_signature"); got != "bad_signature" {
		t.Fatalf("Reason(bad_signature) = %q, want it preserved", got)
	}
	if got := metrics.Reason("../../etc/passwd"); got != metrics.ReasonOther {
		t.Fatalf("Reason(unknown) = %q, want %q; a reason derived from anything attacker-influenced "+
			"would mint an unbounded series", got, metrics.ReasonOther)
	}
}

// TestMetrics_SPARejected_NormalisesTheReasonLabel proves the normalisation
// is applied at the recording site, not merely available as a helper.
func TestMetrics_SPARejected_NormalisesTheReasonLabel(t *testing.T) {
	r := metrics.New()
	r.SPARejected("not_granted")
	r.SPARejected("something-a-packet-made-up")

	body := scrape(t, r)
	mustContain(t, body, `postern_spa_rejections_total{reason="not_granted"} 1`)
	mustContain(t, body, `postern_spa_rejections_total{reason="other"} 1`)
	if strings.Contains(body, "something-a-packet-made-up") {
		t.Fatalf("an unrecognised reason reached a label value\n--- scrape ---\n%s", body)
	}
}

// TestMetrics_HeartbeatRejected_NormalisesTheReasonLabel proves the
// normalisation is applied at the recording site, mirroring
// TestMetrics_SPARejected_NormalisesTheReasonLabel for the heartbeat family.
func TestMetrics_HeartbeatRejected_NormalisesTheReasonLabel(t *testing.T) {
	r := metrics.New()
	r.HeartbeatRejected("send_failed")
	r.HeartbeatRejected("something-a-hub-made-up")

	body := scrape(t, r)
	mustContain(t, body, `postern_heartbeat_rejections_total{reason="send_failed"} 1`)
	mustContain(t, body, `postern_heartbeat_rejections_total{reason="other"} 1`)
	if strings.Contains(body, "something-a-hub-made-up") {
		t.Fatalf("an unrecognised reason reached a label value\n--- scrape ---\n%s", body)
	}
}

// TestMetrics_SetHealthRed_RefusesAnUnknownSource keeps the health gauge's
// label set closed too. The reason text an unhealthy agent carries is error
// text — netlink messages and paths — and must never become a label.
func TestMetrics_SetHealthRed_RefusesAnUnknownSource(t *testing.T) {
	r := metrics.New()
	r.SetHealthRed("replay store unusable: open /var/lib/postern/replay.db: read-only file system", true)

	body := scrape(t, r)
	if strings.Contains(body, "/var/lib/postern") {
		t.Fatalf("a health reason string reached a label value\n--- scrape ---\n%s", body)
	}
	mustContain(t, body, `postern_agent_health_red{source="agent_up"} 0`)
	mustContain(t, body, `postern_agent_health_red{source="standing"} 0`)
}

// TestMetrics_New_SeedsHealthGreen matters because an alert cannot tell a
// gauge that has never been written from a scrape target that is down.
func TestMetrics_New_SeedsHealthGreen(t *testing.T) {
	body := scrape(t, metrics.New())
	mustContain(t, body, `postern_agent_health_red{source="agent_up"} 0`)
	mustContain(t, body, `postern_agent_health_red{source="standing"} 0`)
}

// #49. The applied bundle version reaches the exposition, so a host stuck below
// the fleet's current version -- refusing bundles -- is a value an alert reads
// rather than something only the throttled rejection log would surface.
func TestMetrics_AppliedBundleVersion_IsExported(t *testing.T) {
	r := metrics.New()
	r.SetAppliedBundleVersion(48)
	mustContain(t, scrape(t, r), "postern_bundle_applied_version 48")
}

// TestMetrics_Handler_DoesNotExposeTheGoRuntime records a deliberate choice:
// the default Go and process collectors would publish the daemon's command
// line, file descriptors and memory layout, and nothing in the shipped
// dashboard reads them.
func TestMetrics_Handler_DoesNotExposeTheGoRuntime(t *testing.T) {
	body := scrape(t, metrics.New())
	for _, unwanted := range []string{"go_goroutines", "process_open_fds", "go_memstats_alloc_bytes"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("scrape exposes %s; the Go and process collectors are deliberately not registered"+
				"\n--- scrape ---\n%s", unwanted, body)
		}
	}
}

// TestMetrics_Recorder_NilIsSafe is what lets the daemon call every recorder
// method unconditionally. A guard at each call site is a guard someone
// forgets, and a forgotten one is a nil dereference in the packet loop of a
// root daemon.
func TestMetrics_Recorder_NilIsSafe(t *testing.T) {
	var r *metrics.Recorder
	r.SetInert(true)
	r.SetHealthRed(metrics.HealthSourceAgentUp, true)
	r.AgentUpRenewal(true, time.Now())
	r.SetServiceArmed("ssh", true)
	r.SetGateOpenSources("ssh", 1, 0)
	r.GateOpened("ssh", time.Now())
	r.GateOpenFailed("ssh")
	r.SPAHandled()
	r.SPAAccepted("ssh")
	r.SPARejected("too_old")
	r.ObserveClockSkew(time.Second)
	r.AcceptedBeyondFreshnessWindow()
	r.SetTransactionPending(true, time.Now())
	r.TransactionReverted()
	r.BundlePullRejected("fetch_failed")
	r.BundlePullApplied()
	r.SetAppliedBundleVersion(48)
	r.HeartbeatSent()
	r.HeartbeatRejected("send_failed")
	r.SetHostID("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
	if err := r.Register(); err != nil {
		t.Fatalf("Register on a nil Recorder: %v", err)
	}
	if r.Handler() == nil {
		t.Fatal("Handler on a nil Recorder returned nil")
	}
}
