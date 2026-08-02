package probe_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/probe"
)

// The webhook is the M1 reporting path that needs no dependency, and what it
// carries is the point: both phase outcomes, separately, so a receiver can
// tell "the gate did not open" from "the port answers with no gate at all".
// A payload carrying only the verdict would reproduce the exact blindness
// the phase-1 assertion exists to remove.
func TestProbe_Webhook_CarriesBothPhaseOutcomes(t *testing.T) {
	var got probe.WebhookReport
	var auth, contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("the webhook body is not the declared shape: %v\n%s", err, body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	r, _, _ := newRunner(t, refused)
	r.Reporter = &probe.Webhook{URL: srv.URL, Token: "s3cret", Client: srv.Client(), Timeout: 5 * time.Second}
	var reportErrs []error
	r.OnError = func(err error) { reportErrs = append(reportErrs, err) }

	sw, st, err := r.Once(context.Background())
	if err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(reportErrs) != 0 {
		t.Fatalf("the reporter failed: %v", reportErrs)
	}
	if got.ClosedPhaseOutcome != string(sw.Closed.Outcome) || got.ClosedPhaseOutcome != "refused" {
		t.Errorf("closed_phase_outcome = %q, want %q", got.ClosedPhaseOutcome, sw.Closed.Outcome)
	}
	if got.Reason != probe.ReasonGateNotClosed {
		t.Errorf("reason = %q, want %q", got.Reason, probe.ReasonGateNotClosed)
	}
	if got.Verdict != probe.Fail {
		t.Errorf("verdict = %q, want %q", got.Verdict, probe.Fail)
	}
	if got.Health != st.Health || got.ConsecutiveFailures != 1 || got.Sequence != 1 {
		t.Errorf("health = %q, failures = %d, sequence = %d; want %q, 1, 1",
			got.Health, got.ConsecutiveFailures, got.Sequence, st.Health)
	}
	if got.KnockAddr != "203.0.113.9:62201" || got.ConnectAddr != "203.0.113.9:62202" {
		t.Errorf("addresses = %s / %s", got.KnockAddr, got.ConnectAddr)
	}
	if auth != "Bearer s3cret" {
		t.Errorf("Authorization = %q", auth)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q", contentType)
	}
}

// A host that has never passed must not serialize as an age of zero. A
// receiver rendering "0s ago" is the cached green design section 8 forbids,
// arriving through the wire format instead of the terminal.
func TestProbe_Webhook_DistinguishesNeverPassedFromZeroAge(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	never := probe.NewWebhookReport(probe.Sweep{Host: "web-01"}, probe.State{Host: "web-01"}, now)
	if never.LastPass != nil || never.LastPassAgeS != nil {
		t.Errorf("a host that never passed serialized last_pass = %v, age = %v", never.LastPass, never.LastPassAgeS)
	}
	body, err := json.Marshal(never)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(body), `"last_pass":null`) {
		t.Errorf("last_pass is not null for a host that never passed:\n%s", body)
	}

	passed := probe.NewWebhookReport(
		probe.Sweep{Host: "web-01"},
		probe.State{Host: "web-01", LastPass: now.Add(-90 * time.Second)},
		now)
	if passed.LastPass == nil || passed.LastPassAgeS == nil || *passed.LastPassAgeS != 90 {
		t.Errorf("a host that passed 90s ago serialized age = %v", passed.LastPassAgeS)
	}
}

// A sink that answers with an error status has not accepted the report, and
// saying otherwise would let a fleet's verification quietly stop being
// delivered.
func TestProbe_Webhook_TreatsANonSuccessStatusAsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	w := &probe.Webhook{URL: srv.URL, Client: srv.Client()}
	err := w.Report(context.Background(), probe.Sweep{Host: "web-01"}, probe.State{Host: "web-01"})
	if err == nil {
		t.Fatal("a 500 from the sink was reported as a delivered report")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the error does not name the status: %v", err)
	}
}

// A webhook with no URL is the default configuration and must be a silent
// no-op rather than an error on every sweep.
func TestProbe_Webhook_WithNoURLReportsNothingAndSucceeds(t *testing.T) {
	var w *probe.Webhook
	if err := w.Report(context.Background(), probe.Sweep{}, probe.State{}); err != nil {
		t.Errorf("a nil webhook returned %v", err)
	}
	if err := (&probe.Webhook{}).Report(context.Background(), probe.Sweep{}, probe.State{}); err != nil {
		t.Errorf("an unconfigured webhook returned %v", err)
	}
}

// The POST is bounded independently of the caller's context. A sink that
// accepts the connection and never answers must not be able to stall the
// sweep loop behind it — a probe blocked on its own webhook notices nothing.
func TestProbe_Webhook_BoundsAHangingSinkWithItsOwnTimeout(t *testing.T) {
	// The handler has a bound of its own, so that a Webhook which lost its
	// timeout fails this test rather than hanging it. A test whose failure
	// under mutation is a hang emits neither a pass nor a --- FAIL and is
	// invisible in a batch run, which for a package built out of timeouts is
	// the failure class most worth engineering against.
	const handlerBound = 1500 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(handlerBound):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	w := &probe.Webhook{URL: srv.URL, Client: srv.Client(), Timeout: 50 * time.Millisecond}
	start := time.Now()
	// context.Background() deliberately: the bound under test is the
	// webhook's own, not one the caller supplied.
	err := w.Report(context.Background(), probe.Sweep{Host: "web-01"}, probe.State{Host: "web-01"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("a sink that stalled for %s was reported as delivered after %s; the webhook's own "+
			"timeout did not bound it", handlerBound, elapsed)
	}
	if elapsed >= handlerBound {
		t.Errorf("the POST took %s, which is the sink's own bound rather than the webhook's %s timeout",
			elapsed, 50*time.Millisecond)
	}
}
