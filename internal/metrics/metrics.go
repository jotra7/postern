// Package metrics is postern's Prometheus surface. Design section 8 chose
// metrics over a bespoke UI — "less to maintain, and it plugs into monitoring
// operators already run" — so this package is the only place the agent's
// internal state is published for machines to read.
//
// # What is a label and what is a bare count
//
// /metrics on a root daemon holding a fleet's gate state is an
// information-disclosure surface, so every label here was chosen against two
// questions rather than one: what does it leak, and how many series can it
// mint.
//
// Nothing in this package is ever labelled with a source address, a prefix,
// or an operator key_id. Which addresses are currently admitted through a
// break-glass gate is close to "who is logged in from where", and the label
// would also be unbounded: Prometheus keeps a series alive for the lifetime
// of the process that first exported it, so one label value per knocking
// address is both the leak and an unbounded memory cost on a daemon that is
// supposed to be the thing you can still reach when everything else is down.
// Gate state is therefore published as a count per service, never as a set of
// admitted sources.
//
// The labels that are used are all bounded by the host's own configuration or
// by a fixed enumeration in this file: service names (a fixed set per host,
// already implied by the ruleset), source kind (observed or asserted, two
// values, and the distinction changes how wide the hole is), rejection reason
// (the enumeration in reasons, with anything unrecognised folded into
// "other"), and result-style enums. Free-form strings never reach a label —
// notably health reasons, which are error text and would carry paths and
// netlink messages into a label value.
//
// The Go and process collectors are deliberately not registered. Nothing in
// the shipped dashboard reads them, and they would publish the daemon's
// command line, open file descriptors and memory layout to every scraper.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jotra7/postern/internal/probe"
	"github.com/jotra7/postern/internal/version"
)

// Namespace prefixes every metric this package exports.
const Namespace = "postern"

// Health sources. A red agent has two independent halves (see
// agent.Daemon.Health) and they are kept apart here for the same reason they
// are kept apart there: a successful renewal clears one and must not clear
// the other.
const (
	HealthSourceAgentUp  = "agent_up"
	HealthSourceStanding = "standing"
)

// Source kinds, mirroring gate.SourceKind without importing it — this
// package must stay importable by both the agent and the probe, and it
// publishes a count per kind rather than anything derived from the addresses
// themselves.
const (
	SourceObserved = "observed"
	SourceAsserted = "asserted"
)

// ReasonOther is where an unrecognised rejection or sweep-failure reason
// lands. It exists so that a caller passing a string this package does not
// know about cannot mint an unbounded series: the label value is normalised
// before it is ever used.
const ReasonOther = "other"

// pullReasons is the closed set of rejection reasons that may appear in the
// reason label of postern_bundle_pull_rejections_total. Closed for the same
// reason the SPA rejection set is: the hub is reachable to anyone who can
// reach the agent's outbound path, so a label derived from its response text
// would be attacker- (or at least hub-) influenced and unbounded.
var pullReasons = map[string]bool{
	"fetch_failed":     true,
	"unseal_failed":    true,
	"malformed":        true,
	"untrusted_signer": true,
	"bad_signature":    true,
	"wrong_fleet":      true,
	"wrong_host":       true,
	"below_floor":      true,
	"not_newer":        true,
	"parse_failed":     true,
	"validate_failed":  true,
	"apply_failed":     true,
	// state_failed: the durable record of the version this host has applied
	// could not be read, so an older bundle cannot be told from a newer one
	// and nothing is fetched at all. Same label, same meaning, as the
	// heartbeat's own durable-state failure below.
	"state_failed": true,
	// not_armed is distinct from apply_failed and the distinction is the
	// point: the bundle verified and nothing went wrong, but the arm step
	// declined to install this revision — it was already tried and left
	// pending, or already reverted. An operator seeing this needs to confirm
	// or bump a revision, not to go looking for a broken apply.
	"not_armed": true,
	ReasonOther: true,
}

// PullReason normalises a bundle-pull rejection reason into the closed label
// set.
func PullReason(s string) string {
	if pullReasons[s] {
		return s
	}
	return ReasonOther
}

// heartbeatReasons is the closed set of rejection reasons that may appear in
// the reason label of postern_heartbeat_rejections_total. Closed for the same
// reason pullReasons is: the label must not be derived from anything a hub
// (compromised or merely wrong) could shape.
var heartbeatReasons = map[string]bool{
	"send_failed":  true, // transport-level: refused, unreachable, timed out
	"rejected":     true, // a response came back, but not 204
	"state_failed": true, // the durable sequence store could not be read or written
	ReasonOther:    true,
}

// HeartbeatReason normalises a heartbeat-send rejection reason into the
// closed label set.
func HeartbeatReason(s string) string {
	if heartbeatReasons[s] {
		return s
	}
	return ReasonOther
}

// reasons is the closed set of rejection reasons that may appear in the
// reason label of postern_spa_rejections_total. Anything else becomes
// ReasonOther. The set is closed on purpose: a rejection reason derived from
// error text would be attacker-influenced, unbounded, and would leak the
// contents of errors to anyone who can scrape.
var reasons = map[string]bool{
	"wrong_size":          true,
	"not_canonical":       true,
	"unsupported_version": true,
	"unknown_kind":        true,
	"undecryptable":       true,
	"key_id_mismatch":     true,
	"bad_signature":       true,
	"wrong_host":          true,
	"too_old":             true,
	"not_fresh":           true,
	"unknown_service":     true,
	"not_granted":         true,
	"kind_mismatch":       true,
	"confirm_unbound":     true,
	"source_not_allowed":  true,
	"unsupported_action":  true,
	"liveness_off_path":   true,
	"replay":              true,
	"replay_capacity":     true,
	"store":               true,
	ReasonOther:           true,
}

// Reason normalises a rejection reason into the closed label set.
func Reason(s string) string {
	if reasons[s] {
		return s
	}
	return ReasonOther
}

// skewBuckets spans both of the freshness bounds design section 5 defines,
// because the population this histogram exists to find lives between them.
// freshness_window defaults to 60s and freshness_window_max to 24h; a host
// whose clock has drifted past the first but not the second still admits gate
// packets — the counter path carries them — and nothing else in the system
// says so. Buckets that stopped at a few minutes would show every such host
// as a single saturated +Inf bucket, which is why they run all the way to
// 86400.
var skewBuckets = []float64{0.5, 1, 2, 5, 10, 30, 60, 120, 300, 900, 3600, 10800, 43200, 86400}

// Recorder holds postern's registry and every metric family the agent
// updates. Every method is safe on a nil *Recorder, so a daemon built without
// metrics calls them unconditionally rather than guarding each call site —
// which is what keeps "the metric exists but nothing updates it" from being
// reachable by forgetting a nil check.
type Recorder struct {
	reg *prometheus.Registry
	// collectors is what was registered, kept so the shipped dashboard can be
	// checked against the metric names this package actually exports.
	collectors []prometheus.Collector

	info      *prometheus.GaugeVec
	startTime prometheus.Gauge

	inert              prometheus.Gauge
	healthRed          *prometheus.GaugeVec
	agentUpRenewals    *prometheus.CounterVec
	agentUpLastSuccess prometheus.Gauge
	agentUpExpires     prometheus.Gauge

	serviceArmed     *prometheus.GaugeVec
	openSources      *prometheus.GaugeVec
	gateOpens        *prometheus.CounterVec
	gateOpenFailures *prometheus.CounterVec
	lastOpen         prometheus.Gauge

	datagrams    prometheus.Counter
	accepted     *prometheus.CounterVec
	rejected     *prometheus.CounterVec
	skew         prometheus.Histogram
	lastSkew     prometheus.Gauge
	beyondWindow prometheus.Counter

	txPending  prometheus.Gauge
	txDeadline prometheus.Gauge
	txReverts  prometheus.Counter

	pullRejections *prometheus.CounterVec
	pullApplied    prometheus.Counter
	appliedVersion prometheus.Gauge

	heartbeatsSent      prometheus.Counter
	heartbeatRejections *prometheus.CounterVec
}

// New builds a Recorder with its own registry.
func New() *Recorder {
	r := &Recorder{reg: prometheus.NewRegistry()}

	r.info = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "info",
		Help: "Always 1. The version label carries the agent build, and host_id the identity enrollment " +
			"issued — which is the key that joins this target's series to the external probe's.",
	}, []string{"version", "host_id"})
	r.startTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "start_timestamp_seconds",
		Help: "Unix time at which this agent process started.",
	})
	r.inert = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "inert",
		Help: "1 when a global pre-arm precondition failed, so no gate can be opened and the SPA port is silent.",
	})
	r.healthRed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "health_red",
		Help: "1 when the agent considers itself red. The two sources are independent: agent_up is the live " +
			"renewal signal, standing is a condition a later successful renewal must not clear.",
	}, []string{"source"})
	r.agentUpRenewals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "up_renewals_total",
		Help: "agent_up lease renewals attempted, by result. A failure means the SPA port is already neither " +
			"concealed nor openable.",
	}, []string{"result"})
	r.agentUpLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "up_last_success_timestamp_seconds",
		Help: "Unix time of the last successful agent_up renewal.",
	})

	r.agentUpExpires = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "agent", Name: "up_expires_timestamp_seconds",
		Help: "Unix time at which the agent_up dead-man element lapses and the SPA port goes silent, " +
			"read back from the firewall rather than computed from the last renewal. 0 means the " +
			"element is not there, so the SPA port is closed right now. A value in the past is the " +
			"same thing: break-glass access is gone and nothing else reports it.",
	})

	r.serviceArmed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "gate", Name: "service_armed",
		Help: "1 when pre-arm left this gate service armed, 0 when pre-arm disabled it.",
	}, []string{"service"})
	r.openSources = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "gate", Name: "open_sources",
		Help: "How many sources are currently admitted through this gate. A count, never the addresses: " +
			"which addresses are admitted is close to who is logged in from where.",
	}, []string{"service", "source_kind"})
	r.gateOpens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "gate", Name: "opens_total",
		Help: "Gate elements successfully installed, by service.",
	}, []string{"service"})
	r.gateOpenFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "gate", Name: "open_failures_total",
		Help: "Authorized opens the firewall backend refused, by service.",
	}, []string{"service"})
	r.lastOpen = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "gate", Name: "last_open_timestamp_seconds",
		Help: "Unix time at which a gate element was last genuinely installed by this agent. This is the " +
			"agent-side definition of a successful end-to-end open: the SPA path never replies, so the " +
			"client cannot prove the gate acted, but the agent can.",
	})

	r.datagrams = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "spa", Name: "datagrams_total",
		Help: "Datagrams the packet loop finished handling, whatever the outcome.",
	})
	r.accepted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "spa", Name: "accepted_total",
		Help: "Datagrams that passed the full validation pipeline, by the service they named.",
	}, []string{"service"})
	r.rejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "spa", Name: "rejections_total",
		Help: "Datagrams rejected, by reason. Design section 8 asks for counters rather than a log record " +
			"per rejection, because logging every decision would turn the flood defense into an I/O attack.",
	}, []string{"reason"})
	r.skew = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace, Subsystem: "spa", Name: "clock_skew_seconds",
		Help: "Absolute difference between this host's clock and the timestamp inside an authenticated " +
			"packet. Buckets span freshness_window (60s) through freshness_window_max (24h).",
		Buckets: skewBuckets,
	})
	r.lastSkew = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "spa", Name: "clock_skew_last_seconds",
		Help: "Signed skew of the most recent authenticated packet: positive means this host's clock is " +
			"ahead of the operator's. The histogram gives the distribution, this gives the direction.",
	})
	r.beyondWindow = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "spa", Name: "accepted_beyond_freshness_window_total",
		Help: "Gate packets admitted by the counter path alone, their timestamp already outside " +
			"freshness_window. This is exactly the drifting-clock population, and nothing else reports it.",
	})

	r.txPending = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "transaction", Name: "pending",
		Help: "1 while an armed configuration is waiting for a bound confirm.",
	})
	r.txDeadline = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "transaction", Name: "deadline_timestamp_seconds",
		Help: "Unix time at which the dead-man timer reverts the pending transaction. 0 when none is pending.",
	})
	r.txReverts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "transaction", Name: "reverts_total",
		Help: "Transactions the dead-man timer reverted because no bound confirm arrived.",
	})

	r.pullRejections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "bundle", Name: "pull_rejections_total",
		Help: "Fetched bundles rejected, by reason, never logged per rejection: a hub down for a " +
			"month must not write a month of identical lines, the same reasoning design section 8 " +
			"already applies to SPA rejections.",
	}, []string{"reason"})
	r.pullApplied = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "bundle", Name: "pull_applied_total",
		Help: "Fetched bundles that were verified, newer than this host's enrollment floor and " +
			"current version, and armed through the confirm-or-revert transaction.",
	})
	r.appliedVersion = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: "bundle", Name: "applied_version",
		Help: "The bundle version this host is actually running. Held against the fleet's current " +
			"version it makes a host that has stopped accepting bundles a state an alert can read, " +
			"rather than something only the throttled pull-rejection log would show.",
	})

	r.heartbeatsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "heartbeat", Name: "sent_total",
		Help: "Heartbeats the hub accepted (204). The hub is a management convenience: this " +
			"family says nothing about whether the packet path is working, only whether the " +
			"telemetry channel is.",
	})
	r.heartbeatRejections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: "heartbeat", Name: "rejections_total",
		Help: "Heartbeats that did not reach the hub or were not accepted, by reason, never " +
			"logged per rejection for the same reason bundle pull rejections are not: a hub down " +
			"for a month must not write a month of identical lines.",
	}, []string{"reason"})

	r.mustRegister(
		r.info, r.startTime,
		r.inert, r.healthRed, r.agentUpRenewals, r.agentUpLastSuccess, r.agentUpExpires,
		r.serviceArmed, r.openSources, r.gateOpens, r.gateOpenFailures, r.lastOpen,
		r.datagrams, r.accepted, r.rejected, r.skew, r.lastSkew, r.beyondWindow,
		r.txPending, r.txDeadline, r.txReverts,
		r.pullRejections, r.pullApplied, r.appliedVersion,
		r.heartbeatsSent, r.heartbeatRejections,
	)

	r.info.WithLabelValues(version.Version(), "").Set(1)
	r.startTime.Set(float64(time.Now().Unix()))
	// Seeded so an operator's alert can distinguish "green" from "this label
	// has never been written". A gauge that only appears once it goes red is
	// indistinguishable from a scrape target that is down.
	r.healthRed.WithLabelValues(HealthSourceAgentUp).Set(0)
	r.healthRed.WithLabelValues(HealthSourceStanding).Set(0)
	return r
}

func (r *Recorder) mustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		r.reg.MustRegister(c)
		r.collectors = append(r.collectors, c)
	}
}

// Register adds a collector owned by another part of postern — today the
// probe's canary metrics, which land in the same registry so one scrape and
// one dashboard cover both halves of design section 8's "health is the join".
func (r *Recorder) Register(cs ...prometheus.Collector) error {
	if r == nil {
		return nil
	}
	for _, c := range cs {
		if err := r.reg.Register(c); err != nil {
			return err
		}
		r.collectors = append(r.collectors, c)
	}
	return nil
}

// Handler serves the exposition format. It is an http.Handler rather than a
// server so the caller owns the listener, which is where the bind constraint
// design section 8 imposes is enforced (see ResolveBind).
func (r *Recorder) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// --- agent-side updates ------------------------------------------------

// SetHostID publishes the identity enrollment issued this host, as the same
// 32 hex characters the standalone config and every operator's client config
// already carry.
//
// It is the join key. The probe knows a host by the name an operator typed
// and reaches it over the network; Prometheus knows this target by the
// address it scrapes. Neither is the other, and neither can be derived from
// the other, so without a shared identifier "health is the join" would depend
// on an operator hand-writing a matching label into their scrape config — a
// join that is documented and never wired, which is the failure this whole
// piece of work exists to remove. host_id is the one identifier both sides
// already hold.
//
// It goes on the info metric rather than on every family, which is the
// standard shape: one series per target carries the identity, and a query
// carries it onto the rest with group_left.
func (r *Recorder) SetHostID(hostID string) {
	if r == nil {
		return
	}
	// Reset rather than add: the version/host_id pair is one series per
	// process, and leaving the seeded empty-host_id series behind would give
	// a join two candidates to match, one of which matches nothing.
	r.info.Reset()
	r.info.WithLabelValues(version.Version(), hostID).Set(1)
}

// SetInert records whether a global pre-arm precondition failed.
func (r *Recorder) SetInert(inert bool) {
	if r == nil {
		return
	}
	r.inert.Set(boolValue(inert))
}

// SetHealthRed records one half of the agent's self-assessment. source is
// HealthSourceAgentUp or HealthSourceStanding; the reason string is
// deliberately not carried, because it is error text.
func (r *Recorder) SetHealthRed(source string, red bool) {
	if r == nil {
		return
	}
	if source != HealthSourceAgentUp && source != HealthSourceStanding {
		return
	}
	r.healthRed.WithLabelValues(source).Set(boolValue(red))
}

// AgentUpRenewal records one beat's renewal attempt.
func (r *Recorder) AgentUpRenewal(ok bool, at time.Time) {
	if r == nil {
		return
	}
	if ok {
		r.agentUpRenewals.WithLabelValues("ok").Inc()
		r.agentUpLastSuccess.Set(float64(at.Unix()))
		return
	}
	r.agentUpRenewals.WithLabelValues("failed").Inc()
}

// SetAgentUpExpiry publishes when the SPA port will go silent, from a read of
// what the firewall actually holds.
//
// This is the metric that would have made the worst bug in this project
// visible on the day it shipped. RefreshAgentUp returned nil every beat and
// silently extended nothing, so the port lapsed on a fixed clock while
// postern_agent_up_renewals_total{result="ok"} climbed and the health gauge
// stayed green. Every signal the agent had was about the call; none was about
// the effect. A non-positive remaining lifetime here means no knock can reach
// this host, whatever else the agent is reporting about itself.
func (r *Recorder) SetAgentUpExpiry(now time.Time, remaining time.Duration) {
	if r == nil {
		return
	}
	if remaining <= 0 {
		// Zero rather than a past timestamp, so "the element is not there" is
		// one specific value an operator can match on rather than something
		// they have to infer from arithmetic against time().
		r.agentUpExpires.Set(0)
		return
	}
	r.agentUpExpires.Set(float64(now.Add(remaining).Unix()))
}

// SetServiceArmed records pre-arm's per-service verdict.
func (r *Recorder) SetServiceArmed(service string, armed bool) {
	if r == nil {
		return
	}
	r.serviceArmed.WithLabelValues(service).Set(boolValue(armed))
}

// SetGateOpenSources publishes how many sources are currently admitted
// through a gate, split only by kind. The addresses themselves never leave
// the daemon.
func (r *Recorder) SetGateOpenSources(service string, observed, asserted int) {
	if r == nil {
		return
	}
	r.openSources.WithLabelValues(service, SourceObserved).Set(float64(observed))
	r.openSources.WithLabelValues(service, SourceAsserted).Set(float64(asserted))
}

// GateOpened records that a gate element was genuinely installed, and moves
// the last-open timestamp an operator checks at 3am. It is called only after
// the firewall backend returned success, never on the authorization alone.
func (r *Recorder) GateOpened(service string, at time.Time) {
	if r == nil {
		return
	}
	r.gateOpens.WithLabelValues(service).Inc()
	r.lastOpen.Set(float64(at.Unix()))
}

// GateOpenFailed records an authorized open the backend refused. It
// deliberately does not touch the last-open timestamp.
func (r *Recorder) GateOpenFailed(service string) {
	if r == nil {
		return
	}
	r.gateOpenFailures.WithLabelValues(service).Inc()
}

// SPAHandled counts a datagram the loop finished with, whatever the outcome.
func (r *Recorder) SPAHandled() {
	if r == nil {
		return
	}
	r.datagrams.Inc()
}

// SPAAccepted counts a datagram that passed the whole pipeline.
func (r *Recorder) SPAAccepted(service string) {
	if r == nil {
		return
	}
	r.accepted.WithLabelValues(service).Inc()
}

// SPARejected counts a rejection under a normalised reason.
func (r *Recorder) SPARejected(reason string) {
	if r == nil {
		return
	}
	r.rejected.WithLabelValues(Reason(reason)).Inc()
}

// ObserveClockSkew records the difference between this host's clock and an
// authenticated packet's timestamp. skew is signed — positive means this
// host is ahead — and the histogram takes its magnitude.
func (r *Recorder) ObserveClockSkew(skew time.Duration) {
	if r == nil {
		return
	}
	r.lastSkew.Set(skew.Seconds())
	if skew < 0 {
		skew = -skew
	}
	r.skew.Observe(skew.Seconds())
}

// AcceptedBeyondFreshnessWindow counts a gate packet the counter path alone
// admitted, its timestamp already outside freshness_window.
func (r *Recorder) AcceptedBeyondFreshnessWindow() {
	if r == nil {
		return
	}
	r.beyondWindow.Inc()
}

// SetTransactionPending records the dead-man state. A zero deadline publishes
// 0, which is what "nothing is pending" reads as.
func (r *Recorder) SetTransactionPending(pending bool, deadline time.Time) {
	if r == nil {
		return
	}
	r.txPending.Set(boolValue(pending))
	if pending && !deadline.IsZero() {
		r.txDeadline.Set(float64(deadline.Unix()))
		return
	}
	r.txDeadline.Set(0)
}

// TransactionReverted counts one dead-man revert.
func (r *Recorder) TransactionReverted() {
	if r == nil {
		return
	}
	r.txReverts.Inc()
}

// BundlePullRejected counts a fetched bundle that was not applied, under a
// normalised reason. It is safe to call on every rejection regardless of how
// often pulls happen: unlike a log line, a counter increment costs nothing a
// hub down for a month would notice.
func (r *Recorder) BundlePullRejected(reason string) {
	if r == nil {
		return
	}
	r.pullRejections.WithLabelValues(PullReason(reason)).Inc()
}

// BundlePullApplied counts a fetched bundle that was armed.
func (r *Recorder) BundlePullApplied() {
	if r == nil {
		return
	}
	r.pullApplied.Inc()
}

// SetAppliedBundleVersion publishes the bundle version this host is running,
// seeded from the persisted record at startup and moved on each apply. A host
// stuck below the fleet's current version -- because it is refusing every
// bundle, the failure mode #49's carrier-port guard used to produce silently
// -- is then a gauge an alert reads rather than a throttled log line.
func (r *Recorder) SetAppliedBundleVersion(version uint64) {
	if r == nil {
		return
	}
	r.appliedVersion.Set(float64(version))
}

// HeartbeatSent counts a beat the hub accepted.
func (r *Recorder) HeartbeatSent() {
	if r == nil {
		return
	}
	r.heartbeatsSent.Inc()
}

// HeartbeatRejected counts a beat that did not reach the hub or was not
// accepted, under a normalised reason. Safe to call on every rejection
// regardless of how often beats are attempted: unlike a log line, a counter
// increment costs nothing a hub down for a month would notice.
func (r *Recorder) HeartbeatRejected(reason string) {
	if r == nil {
		return
	}
	r.heartbeatRejections.WithLabelValues(HeartbeatReason(reason)).Inc()
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// --- the probe's half of "health is the join" --------------------------

// canaryReasons maps every probe failure reason onto a label token. The set
// is closed for the same reason the rejection reasons are: a reason derived
// from a connect error would carry addresses and error text into a label and
// would be unbounded. The tokens are snake_case rather than the probe's own
// prose because a label value is something an operator types into a query.
//
// A test asserts that every value in probe.Reasons appears here, so a reason
// added to the probe without a token is a failure rather than a sweep that
// silently records itself as "other" — which would fold "the port answers
// with no gate at all" into the same bucket as everything else, and that
// distinction is the entire reason the probe exists.
var canaryReasons = map[probe.Reason]string{
	probe.ReasonNone:            "none",
	probe.ReasonGateNotClosed:   "gate_not_closed",
	probe.ReasonListenerPresent: "listener_present",
	probe.ReasonKnockNotSent:    "knock_not_sent",
	probe.ReasonGateNotOpened:   "gate_not_opened",
	probe.ReasonNoRoute:         "no_route",
	probe.ReasonUnclassified:    "unclassified",
	probe.ReasonInternal:        "probe_error",
}

// CanaryReason normalises a sweep's reason into the closed label set.
func CanaryReason(r probe.Reason) string {
	if s, ok := canaryReasons[r]; ok {
		return s
	}
	return ReasonOther
}

// canaryStates is every value postern_probe_health publishes a series for.
// All four are written on every SetHealth, so an alert can tell "not red"
// from "this label has never existed" — the same reason the agent's health
// gauge is seeded in New.
var canaryStates = []probe.Health{
	probe.HealthUnknown, probe.HealthGreen, probe.HealthAmber, probe.HealthRed,
}

// Canary implements probe.Metrics against Prometheus.
//
// It lives here rather than in internal/probe so the probe does not depend on
// prometheus/client_golang. The dependency runs metrics → probe and never the
// other way, which is what lets this file use the probe's own types instead of
// re-deriving its vocabulary from strings: the compiler keeps the two halves
// in step, rather than a comment asking someone to.
//
// # Where the join is computed, and why it is not here
//
// Design section 8: "an agent reporting itself healthy while the probe cannot
// reach it is the most valuable state the system surfaces". It is tempting to
// publish that as one number. Nothing can.
//
// The probe is a client role: it runs on an operator's laptop or a monitoring
// box, never on the gated host. The agent's /metrics is on the host, bound to
// the always-allow interface. So the two halves arrive from two scrape
// targets — and that is not an implementation shortcut that a better design
// would remove. At the moment the joined state becomes true, the two facts are
// on opposite sides of a path that is broken; that is what the state *is*. A
// probe that could ask the agent how it feels would not be red, and an agent
// that could see the probe's verdict would already know it was unreachable.
// Neither endpoint can hold both halves at the instant they disagree.
//
// The join is therefore computed where both series land: in Prometheus, by the
// recording rules in dashboards/rules.yml. What this file owes that
// computation is a key it can join on without an operator hand-writing one —
// see postern_probe_target_info and Recorder.SetHostID, which both carry the
// host_id enrollment issued.
//
// One deployment does collapse to a single scrape target: a probe running
// beside an agent, where NewCanary(daemon.Metrics()) registers into the
// agent's registry. That is supported and is why NewCanary takes a Recorder.
// It is not the M1 default, because a probe sharing a host with the agent it
// measures cannot measure the network between them.
//
// # The streak
//
// probe.Runner already keeps a consecutive-failure count, and that count is
// what decides probe.HealthRed — the thing that alerts. This type publishes
// that number rather than deriving a second one from the sweep results,
// because two definitions of "consecutive failures" that can drift apart is
// worse than one, and the one that is already load-bearing should be the one
// on the dashboard.
type Canary struct {
	reg *prometheus.Registry

	target   *prometheus.GaugeVec
	sweeps   *prometheus.CounterVec
	health   *prometheus.GaugeVec
	failures *prometheus.GaugeVec
	lastPass *prometheus.GaugeVec
}

// Compile-time proof that the probe's interface is satisfied. The probe
// defines Metrics; nothing there imports this package, so without this line
// the two halves could drift until a call site failed to build.
var _ probe.Metrics = (*Canary)(nil)

// NewCanary builds the probe's collectors.
//
// When r is non-nil they are registered into the agent's registry, so a probe
// co-located with an agent is one scrape target. When r is nil the Canary gets
// a registry of its own, which is the hub-less M1 shape: `postern probe
// --metrics-listen` serves it, and Prometheus scrapes it as a second target.
func NewCanary(r *Recorder) (*Canary, error) {
	c := &Canary{
		target: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: "probe", Name: "target_info",
			Help: "Always 1, one series per host this probe sweeps. host is the name an operator types; " +
				"host_id is what enrollment issued, and is the key that joins these series to that " +
				"host's own postern_agent_info.",
		}, []string{"host", "host_id"}),
		sweeps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: "probe", Name: "sweeps_total",
			Help: "Canary sweeps completed, by verdict and reason. Both phases are asserted every sweep, " +
				"so a sweep whose closed phase returned a reset is a failure (gate_not_closed) rather " +
				"than a pass.",
		}, []string{"host", "service", "verdict", "reason"}),
		health: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: "probe", Name: "health",
			Help: "1 for the host's current probe verdict and 0 for the other states. An enumeration " +
				"rather than a number, so unknown — nothing has been measured — cannot be read as a " +
				"value on the same scale as green.",
		}, []string{"host", "state"}),
		failures: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: "probe", Name: "consecutive_failures",
			Help: "Current streak of failed sweeps, as the probe counts it. Three turn a host red.",
		}, []string{"host"}),
		lastPass: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: "probe", Name: "last_pass_timestamp_seconds",
			Help: "Unix time of the last sweep that proved the gate both closed and openable. 0 means " +
				"never, which reads as an enormous age — the correct alarm. A timestamp rather than " +
				"an age, because an age gauge sits at its last value forever once nothing updates it.",
		}, []string{"host"}),
	}
	cols := []prometheus.Collector{c.target, c.sweeps, c.health, c.failures, c.lastPass}
	if r != nil {
		if err := r.Register(cols...); err != nil {
			return nil, err
		}
		c.reg = r.reg
		return c, nil
	}
	c.reg = prometheus.NewRegistry()
	for _, col := range cols {
		if err := c.reg.Register(col); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Handler serves the registry this Canary publishes into — its own when it was
// built without a Recorder, the agent's when it was built with one, so a
// co-located probe and agent stay one scrape target rather than two on the
// same host.
func (c *Canary) Handler() http.Handler {
	if c == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{})
}

// SetTarget declares a host this probe sweeps and the identity enrollment
// issued it. It is called once per host at startup rather than per sweep, so
// the join key is published before the first measurement — a host that is
// unreachable from the very first sweep still has a series to join on.
func (c *Canary) SetTarget(host, hostID string) {
	if c == nil {
		return
	}
	c.target.WithLabelValues(host, hostID).Set(1)
}

// ObserveSweep records one completed sweep.
func (c *Canary) ObserveSweep(sw probe.Sweep) {
	if c == nil {
		return
	}
	c.sweeps.WithLabelValues(sw.Host, sw.Service, string(sw.Verdict), CanaryReason(sw.Reason)).Inc()
}

// SetHealth publishes the host's current verdict as an enumeration: exactly
// one state is 1 and the rest are 0.
func (c *Canary) SetHealth(host string, h probe.Health) {
	if c == nil {
		return
	}
	for _, state := range canaryStates {
		c.health.WithLabelValues(host, string(state)).Set(boolValue(state == h))
	}
}

// SetConsecutiveFailures publishes the probe's streak.
func (c *Canary) SetConsecutiveFailures(host string, n int) {
	if c == nil {
		return
	}
	c.failures.WithLabelValues(host).Set(float64(n))
}

// SetLastPass publishes when this host last supplied both halves of the proof.
// The zero time publishes 0 rather than being skipped, because a missing
// series and a host that has never passed are the same picture to an alert and
// must not be.
func (c *Canary) SetLastPass(host string, t time.Time) {
	if c == nil {
		return
	}
	if t.IsZero() {
		c.lastPass.WithLabelValues(host).Set(0)
		return
	}
	c.lastPass.WithLabelValues(host).Set(float64(t.Unix()))
}
