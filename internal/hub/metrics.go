package hub

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace prefixes every metric this package exports.
const namespace = "postern_hub"

// Metrics is the hub's Prometheus surface. It has its own registry, served
// on Config.MetricsAddr, and is never reachable from the public listener —
// design section 8 is explicit that /metrics there "would publish fleet
// size and per-host health to anyone who asked."
//
// bundleFetches and heartbeats are labelled by result only, from a small
// fixed enumeration this file controls (see BundleFetch and Heartbeat) —
// never by host_id or by anything derived from request content, for the
// same reason internal/metrics never labels by source address: an
// unbounded or attacker-influenced label value is both a leak and a memory
// cost on a process meant to keep running.
//
// knownHosts is the one number in this file that approximates fleet size: it
// is the count of distinct hosts that have beaten since THIS hub process
// started, which equals fleet size only once every host has checked in and
// resets to zero on a hub restart (Beats holds nothing across one; see
// doc.go). It is computed from Beats at scrape time via
// prometheus.NewGaugeFunc rather than pushed on every Accept, so there is
// exactly one place that number comes from.
type Metrics struct {
	reg *prometheus.Registry

	bundleFetches *prometheus.CounterVec
	heartbeats    *prometheus.CounterVec
}

// NewMetrics builds the hub's registry. beats is read at scrape time only,
// for the known_hosts gauge; nothing here calls its methods on the request
// path.
func NewMetrics(beats *Beats) *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}

	m.bundleFetches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "bundle_fetches_total",
		Help: "Bundle fetches on the public listener, by result: ok, not_found, or invalid_host_id.",
	}, []string{"result"})
	m.heartbeats = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "heartbeats_total",
		Help: "Heartbeats posted to the public listener, by result: ok, bad_signature, unknown_host, " +
			"stale, malformed, or too_large.",
	}, []string{"result"})
	knownHosts := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Name: "known_hosts",
		Help: "Distinct hosts with at least one heartbeat accepted since this hub process started. " +
			"This approximates fleet size, which is exactly why it is only ever on this listener.",
	}, func() float64 { return float64(beats.Count()) })

	m.reg.MustRegister(m.bundleFetches, m.heartbeats, knownHosts)
	return m
}

// Every method below is safe on a nil *Metrics, matching
// metrics.Recorder, whose own methods are all nil-safe and documented as
// such. A hub built without a registry is not reachable through Serve today —
// it always builds one — but the two types are used the same way by handlers
// that call them unconditionally, and a pair of otherwise-identical types
// where one panics on nil and the other does not is a difference somebody
// will eventually discover from a stack trace on the one process a fleet's
// operators talk to.

// BundleFetch records one bundle fetch's outcome.
func (m *Metrics) BundleFetch(result string) {
	if m == nil {
		return
	}
	m.bundleFetches.WithLabelValues(result).Inc()
}

// Heartbeat records one heartbeat post's outcome.
func (m *Metrics) Heartbeat(result string) {
	if m == nil {
		return
	}
	m.heartbeats.WithLabelValues(result).Inc()
}

// Handler serves this registry's exposition format, or 404s when there is no
// registry to serve.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
