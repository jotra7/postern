package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultWebhookTimeout bounds one POST. A reporting sink that has stopped
// answering must not be able to stall the sweep loop behind it — the probe's
// job is to notice unreachability, and a probe blocked on its own webhook
// notices nothing.
const DefaultWebhookTimeout = 5 * time.Second

// Webhook posts each sweep as JSON. It is the M1 reporting path that needs
// no dependency and no hub; Prometheus is the other, through Metrics.
type Webhook struct {
	// URL receives one POST per sweep.
	URL string
	// Token, when set, is sent as an Authorization: Bearer header. The
	// receiving end has no other way to tell a real report from an invented
	// one in M1 — design section 8's signed (epoch, sequence) reports are a
	// hub-side mechanism and the hub is M2 — so this is authentication of
	// the transport, and the report says so rather than implying more.
	Token string
	// Client defaults to a client with Timeout set. Injected so a test can
	// serve the endpoint in-process.
	Client *http.Client
	// Timeout defaults to DefaultWebhookTimeout and bounds each POST
	// independently of the caller's context.
	Timeout time.Duration
	// Now defaults to time.Now and supplies the age fields.
	Now func() time.Time
}

// WebhookReport is the wire form. It is a declared struct rather than a map
// so the field names are reviewable in a diff, and every field is either an
// observation or a plainly derived one.
type WebhookReport struct {
	Host    string `json:"host"`
	Service string `json:"service"`
	// Sequence is monotonic within this probe process's lifetime. Design
	// section 8 pairs it with an epoch so a reinstalled probe is not rejected
	// forever; the epoch is issued at enrollment and checked by the hub,
	// neither of which exists in M1, so this reports the sequence and does
	// not pretend to the replay resistance the pair provides.
	Sequence int `json:"sequence"`

	Verdict Verdict `json:"verdict"`
	Reason  Reason  `json:"reason,omitempty"`
	Summary string  `json:"summary"`
	Detail  string  `json:"detail"`
	Error   string  `json:"error,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`

	KnockAddr   string `json:"knock_addr"`
	ConnectAddr string `json:"connect_addr"`
	Knocked     bool   `json:"knocked"`

	// The two phases, reported separately and by outcome name, because "it
	// failed" and "phase 1 returned a reset" call for different responses.
	ClosedPhaseOutcome  string `json:"closed_phase_outcome"`
	ClosedPhaseAttempts int    `json:"closed_phase_attempts"`
	OpenPhaseOutcome    string `json:"open_phase_outcome"`
	OpenPhaseAttempts   int    `json:"open_phase_attempts"`

	Health              Health `json:"health"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	Sweeps              int    `json:"sweeps"`
	Passes              int    `json:"passes"`
	Failures            int    `json:"failures"`

	// LastPass is nil when this host has never passed. A receiver rendering
	// a zero timestamp as an epoch date is a smaller problem than one
	// rendering "never" as "0s ago", which is the green a stale probe must
	// never be able to produce.
	LastPass     *time.Time `json:"last_pass"`
	LastPassAgeS *float64   `json:"last_pass_age_seconds"`
}

// NewWebhookReport builds the wire form from a sweep and the state it
// produced.
func NewWebhookReport(sw Sweep, st State, now time.Time) WebhookReport {
	rep := WebhookReport{
		Host:                st.Host,
		Service:             sw.Service,
		Sequence:            st.Sweeps,
		Verdict:             sw.Verdict,
		Reason:              sw.Reason,
		Summary:             sw.Summary,
		Detail:              sw.Detail,
		StartedAt:           sw.Start,
		DurationMS:          sw.Duration.Milliseconds(),
		Knocked:             sw.Knocked,
		ClosedPhaseOutcome:  string(sw.Closed.Outcome),
		ClosedPhaseAttempts: sw.Closed.Attempts,
		OpenPhaseOutcome:    string(sw.Open.Outcome),
		OpenPhaseAttempts:   sw.Open.Attempts,
		Health:              st.Health,
		ConsecutiveFailures: st.ConsecutiveFailures,
		Sweeps:              st.Sweeps,
		Passes:              st.Passes,
		Failures:            st.Failures,
	}
	if rep.Host == "" {
		rep.Host = sw.Host
	}
	if sw.KnockAddr.IsValid() {
		rep.KnockAddr = sw.KnockAddr.String()
	}
	if sw.ConnectAddr.IsValid() {
		rep.ConnectAddr = sw.ConnectAddr.String()
	}
	switch {
	case sw.Err != nil:
		rep.Error = sw.Err.Error()
	case sw.KnockErr != nil:
		rep.Error = sw.KnockErr.Error()
	}
	if age, ok := st.Age(now); ok {
		t := st.LastPass
		secs := age.Seconds()
		rep.LastPass = &t
		rep.LastPassAgeS = &secs
	}
	return rep
}

// Report posts one sweep.
func (w *Webhook) Report(ctx context.Context, sw Sweep, st State) error {
	if w == nil || w.URL == "" {
		return nil
	}
	nowFn := w.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	body, err := json.Marshal(NewWebhookReport(sw, st, nowFn()))
	if err != nil {
		return fmt.Errorf("encode webhook report: %w", err)
	}

	timeout := orDuration(w.Timeout, DefaultWebhookTimeout)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "postern-probe")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}

	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook report: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook %s answered %s", w.URL, resp.Status)
	}
	return nil
}
