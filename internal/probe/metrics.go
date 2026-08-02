package probe

import "time"

// Metrics is the probe's entire reporting surface, and it is deliberately
// small and owned here rather than imported.
//
// Design section 8 says metrics instead of a bespoke UI, and internal/metrics
// is where the Prometheus registry lives. This interface is what the probe
// needs from it, expressed in the probe's own vocabulary, so that this
// package never depends on prometheus/client_golang and the probe's tests
// never need a registry. The dependency runs metrics → probe and must not be
// turned around. The no-op default means a Runner with no Metrics wired is a
// working probe with silent instrumentation rather than a nil-pointer panic
// on the first sweep.
//
// The Prometheus implementation is metrics.Canary, and the mapping it
// settled on is:
//
//	ObserveSweep           → postern_probe_sweeps_total{host,service,verdict,reason}
//	SetHealth              → postern_probe_health{host,state}, one series per
//	                         state with exactly one of them at 1
//	SetConsecutiveFailures → postern_probe_consecutive_failures{host}
//	SetLastPass            → postern_probe_last_pass_timestamp_seconds{host}
//
// last_pass is a unix timestamp rather than an age precisely because design
// section 8 refuses to let cached status render as plain green: an age
// computed at scrape time from a timestamp cannot silently freeze, while a
// gauge holding an age can sit at "12s" forever if the process that updates
// it stops.
//
// SetConsecutiveFailures is the reason this interface passes the streak
// rather than letting the metrics side count it. Runner already keeps that
// number and it is what decides HealthRed — the thing that alerts — so a
// second count derived from the sweep results would be a number on the
// dashboard that can drift from the number that pages someone.
//
// Nothing here carries the target's identity beyond the operator-facing
// name. The join key an alert needs — the host_id both the host's config and
// the operator's client config already hold — is published once at startup
// through metrics.Canary.SetTarget, because the probe reads it from the
// client config and this interface is about sweeps.
type Metrics interface {
	// ObserveSweep records one completed sweep, pass or fail.
	ObserveSweep(sw Sweep)
	// SetHealth records the host's current health.
	SetHealth(host string, h Health)
	// SetConsecutiveFailures records the current failure streak.
	SetConsecutiveFailures(host string, n int)
	// SetLastPass records when this host last supplied both halves of the
	// proof. The zero time means never.
	SetLastPass(host string, t time.Time)
}

// NopMetrics is the default: a probe that is wired to nothing still runs.
type NopMetrics struct{}

func (NopMetrics) ObserveSweep(Sweep)                 {}
func (NopMetrics) SetHealth(string, Health)           {}
func (NopMetrics) SetConsecutiveFailures(string, int) {}
func (NopMetrics) SetLastPass(string, time.Time)      {}
