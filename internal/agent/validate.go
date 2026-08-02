package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

var (
	// ErrWrongHost means the packet's host_id does not name this host. A
	// packet captured en route to one host must be inert against every
	// other (design section 5, "host_id inside the sealed payload is the
	// anti-relay control").
	ErrWrongHost = errors.New("agent: host_id does not match this host")

	// ErrTooOld means a gate packet's timestamp is outside
	// freshness_window_max. This bound is unconditional and runs before the
	// counter path is even consulted: it is what stops an attacker who
	// captured and suppressed a knock from holding a packet that stays
	// replayable indefinitely because its counter never gets superseded.
	ErrTooOld = errors.New("agent: timestamp exceeds freshness_window_max")

	// ErrNotFresh means the packet failed every freshness path available to
	// its kind: for a gate, the counter is not above the high-water mark
	// and the timestamp is outside freshness_window; for an action, the
	// timestamp alone is outside freshness_window (actions have no counter
	// path at all).
	ErrNotFresh = errors.New("agent: packet is not fresh")

	// ErrUnknownService means service_id does not resolve to any configured
	// service.
	ErrUnknownService = errors.New("agent: service_id does not resolve to a configured service")

	// ErrNotGranted means the operator that signed this packet has no grant
	// covering the resolved service.
	ErrNotGranted = errors.New("agent: operator is not granted this service")

	// ErrKindMismatch means the packet's own kind byte (gate or action)
	// disagrees with the Kind of the service its service_id resolves to.
	// See docs/phase-b-carry-forward.md item 2: a kind=gate record naming
	// the action service "confirm" parses clean at the spa layer, and
	// accepting it would raise the operator's counter high-water mark and
	// silently disable drift tolerance for their later gate requests.
	ErrKindMismatch = errors.New("agent: packet kind does not agree with the resolved service's kind")

	// ErrConfirmUnbound means a confirm packet's pending_revision and
	// deployment_nonce do not match the transaction currently awaiting
	// confirmation — including the case where a transaction is pending but
	// a different one was named. An unbound confirm is not a
	// stale-authorization problem a shorter window would mitigate; it
	// authorizes the wrong thing by construction (design section 5).
	ErrConfirmUnbound = errors.New("agent: confirm does not match the pending transaction")

	// ErrSourceNotAllowed means an asserted source was rejected by
	// Grant.AllowsSource: either the grant does not permit an asserted
	// source at all, or the asserted prefix is narrower than the grant's
	// configured minimum (docs/phase-b-carry-forward.md item 3).
	ErrSourceNotAllowed = errors.New("agent: asserted source rejected")

	// ErrUnsupportedAction means the resolved service is declared
	// kind:action but is not one of the three reserved action names this
	// package knows how to interpret a payload for. config.Service.Validate
	// already rejects this at config-load time, so reaching this at
	// runtime means a Policy was hand-built or a resolver bug let one
	// through.
	ErrUnsupportedAction = errors.New("agent: service is not a supported action")

	// ErrLivenessOffPath means a liveness packet arrived somewhere other
	// than the configured always-allow path. Design section 5 binds
	// liveness to that path the same way confirm is bound to a pending
	// transaction: liveness is the one case where the agent transmits at
	// all (the signed pong), so a Decision reaching the caller for a
	// liveness packet that arrived on the public, unauthenticated SPA port
	// would answer a probe nobody should get an answer to.
	ErrLivenessOffPath = errors.New("agent: liveness did not arrive on the always-allow path")
)

// PendingTransaction is the transaction, if any, the caller (the daemon
// built in Task 3, which owns confirm-or-revert) currently considers
// awaiting a confirm action's binding check. Pending is false when no
// transaction is armed, in which case any confirm is refused outright —
// not a null check standing in for the comparison, but the same refusal a
// mismatched revision or nonce produces.
type PendingTransaction struct {
	Pending  bool
	Revision uint64
	Nonce    [16]byte
}

// Decision is what a validated packet authorizes. Validate performs no
// network or firewall I/O itself — applying a Decision (opening Source in
// Service for TTL, executing a confirm or disarm, answering a liveness
// challenge) belongs entirely to the caller.
type Decision struct {
	// ServiceKind and Service identify what was authorized.
	ServiceKind config.Kind
	Service     string
	// KeyID is the operator whose signature authorized this decision.
	KeyID [16]byte
	// RequestID is the packet's own request identifier. A liveness pong must
	// echo it alongside the challenge nonce — either check alone would let a
	// captured pong answer a different later ping that happened to share the
	// other value (internal/spa.Pong.Verify) — so the caller needs it and
	// must not have to re-parse the datagram to get it.
	RequestID [16]byte

	// Source and TTL are meaningful only when ServiceKind is
	// config.KindGate.
	Source gate.Source
	TTL    time.Duration

	// PendingRevision and DeploymentNonce are meaningful only for a
	// confirm decision (Service == "confirm"): the transaction Validate
	// confirmed the packet was bound to.
	PendingRevision uint64
	DeploymentNonce [16]byte

	// Challenge is meaningful only for a liveness decision (Service ==
	// "liveness"): the nonce a pong must echo. Validate only ever returns
	// this Decision for a packet the caller told it arrived on the
	// always-allow path (see arrivedOnAlwaysAllowPath).
	Challenge [16]byte

	// Skew is this host's clock minus the packet's timestamp, signed:
	// positive means this host is ahead of the operator who sent it.
	//
	// It is reported rather than merely consumed because the packet
	// timestamp is the only external clock reference the agent has, and
	// design section 8 lists clock skew as a metric. The freshness window
	// defaults to 60s while the hard bound is 24h, so a host drifting
	// between the two keeps working — the counter path carries its gate
	// packets — and nothing else in the system would say so.
	Skew time.Duration

	// FreshByCounterOnly reports that a gate packet's timestamp was already
	// outside freshness_window and only the counter path admitted it. That
	// is exactly the drifting-clock population above, observed at the moment
	// it happens; it is always false for an action, which has no counter
	// path at all.
	FreshByCounterOnly bool
}

// Validate runs one datagram through the full packet-validation pipeline
// (design section 5's validation order, reconciled to what internal/spa's
// TrialOpen already does) and returns either a Decision the caller may act
// on or an error. now is passed in rather than read, and policy is read
// live on every call rather than captured once — an operator widening
// freshness_window_max must apply to the very next packet, not to one
// cached at startup (docs/phase-b-carry-forward.md item 1).
//
// pending is the transaction, if any, currently awaiting a confirm's
// binding check, and arrivedOnAlwaysAllowPath tells Validate whether this
// datagram was received on the configured always-allow path rather than
// the public SPA port — both are data the caller already has and passes
// in, the same as now, rather than something this package could discover
// on its own from a datagram and an address alone.
//
// Order matters: this runs as root against unauthenticated input, so an
// expensive check reachable before a cheap one is a denial-of-service
// lever. Rejections never explain themselves beyond the returned error —
// nothing in this package writes to the network, so there is no reply for
// an explanation to leak through, but a caller must not relay these errors
// back onto the wire either.
func Validate(
	datagram []byte,
	observedSource netip.Addr,
	policy *config.Policy,
	opener *spa.Opener,
	store replay.Store,
	pending PendingTransaction,
	arrivedOnAlwaysAllowPath bool,
	now time.Time,
) (Decision, error) {
	// 1. spa.TrialOpen: exact length, trial decrypt, key_id cross-check
	//    against the key that actually decrypted it, signature, canonical
	//    encoding. Everything upstream of this function's own checks.
	req, who, err := opener.TrialOpen(datagram)
	if err != nil {
		return Decision{}, err
	}

	// 2. host_id must match this host.
	if req.HostID != policy.HostID {
		return Decision{}, ErrWrongHost
	}

	nowMS := uint64(now.UnixMilli())
	age := ageMS(nowMS, req.TimestampMS)

	// 3. Freshness by kind. The gate bound is unconditional and runs before
	//    the counter path is even consulted: without it, a captured and
	//    suppressed knock holds a packet whose request_id is forever unseen
	//    and whose counter stays above the high-water mark, valid
	//    indefinitely from anywhere. Ordering bounds sequence; only a clock
	//    bounds age.
	freshByCounterOnly := false
	switch req.Kind {
	case spa.KindGate:
		if age > durationMS(policy.FreshnessWindowMax) {
			return Decision{}, ErrTooOld
		}
		byCounter := req.Counter > store.HighWater(req.KeyID)
		byTimestamp := age <= durationMS(policy.FreshnessWindow)
		if !byCounter && !byTimestamp {
			return Decision{}, ErrNotFresh
		}
		freshByCounterOnly = !byTimestamp
	case spa.KindAction:
		// Actions get no counter path at all: a suppressed-and-replayed
		// disarm or confirm is a fleet-exposure primitive, not a
		// tolerable residual the way it is for a gate.
		if age > durationMS(policy.FreshnessWindow) {
			return Decision{}, ErrNotFresh
		}
	default:
		return Decision{}, spa.ErrUnknownKind
	}

	// 4. Policy: is this operator granted this service on this host.
	svc, ok := policy.ServiceByID(req.ServiceID)
	if !ok {
		return Decision{}, ErrUnknownService
	}
	grant, ok := policy.Grants(who.KeyID(), svc.Name)
	if !ok {
		return Decision{}, ErrNotGranted
	}

	// 5. Kind agreement, checked before any kind-specific payload is read
	//    as anything more than the generic gate/action shape spa.Parse
	//    already canonicalized. A kind:gate record naming an action
	//    service's service_id must be rejected here, before its payload is
	//    ever read as a gate source assertion (docs/phase-b-carry-forward.md
	//    item 2).
	if err := checkKindAgreement(req.Kind, svc.Kind); err != nil {
		return Decision{}, err
	}

	var decision Decision
	switch req.Kind {
	case spa.KindGate:
		decision, err = resolveGate(req, svc, grant, observedSource)
	case spa.KindAction:
		decision, err = resolveAction(req, svc, pending, arrivedOnAlwaysAllowPath)
	}
	if err != nil {
		return Decision{}, err
	}
	decision.KeyID = req.KeyID
	decision.RequestID = req.RequestID
	decision.Skew = signedSkew(nowMS, req.TimestampMS)
	decision.FreshByCounterOnly = freshByCounterOnly

	// 6. Reserve: atomic check-and-persist, immediately before acting —
	//    the last step, so a reservation is written at most once, only for
	//    a packet that survived every earlier rejection. ExpiresAtMS is
	//    computed here, live off policy, per the retention formula
	//    (docs/phase-b-carry-forward.md item 1): freshness_window_max for
	//    gates, freshness_window for actions.
	if err := store.Reserve(replay.Reservation{
		KeyID:       req.KeyID,
		RequestID:   req.RequestID,
		Counter:     req.Counter,
		IsGate:      req.Kind == spa.KindGate,
		ExpiresAtMS: nowMS + retentionMS(req.Kind, policy),
	}); err != nil {
		// Marked with ErrStore so the caller can tell a store failure from an
		// ordinary rejection. Both are "an error from Validate", and only one
		// of them may take the agent down — see ErrStore's comment for the
		// unauthenticated shutdown that follows from conflating them.
		return Decision{}, fmt.Errorf("%w: %w", ErrStore, err)
	}

	return decision, nil
}

// ageMS is the absolute difference between two unix-millisecond clocks,
// computed without signed overflow: both now and ts come from a uint64
// wire field or time.Time.UnixMilli(), which for any real timestamp fits
// comfortably in the non-negative range this subtraction needs.
func ageMS(now, ts uint64) uint64 {
	if now >= ts {
		return now - ts
	}
	return ts - now
}

// maxSkewMS caps the magnitude signedSkew will report, at roughly 139 years.
// The cap is not about plausibility — it is what keeps the millisecond count
// inside the range time.Duration's nanoseconds can hold, so a packet claiming
// a timestamp near the top of its uint64 field produces a very large skew
// rather than a wrapped, small-looking one.
const maxSkewMS = uint64(1) << 42

// signedSkew is ageMS with its direction kept: positive means this host's
// clock is ahead of the timestamp inside the packet.
func signedSkew(nowMS, tsMS uint64) time.Duration {
	d := ageMS(nowMS, tsMS)
	if d > maxSkewMS {
		d = maxSkewMS
	}
	//nolint:gosec // G115: d is capped at 2^42 immediately above, so the
	// uint64->int64 conversion and the nanosecond multiply both stay in range.
	out := time.Duration(int64(d)) * time.Millisecond
	if nowMS >= tsMS {
		return out
	}
	return -out
}

func durationMS(d time.Duration) uint64 {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 0
	}
	//nolint:gosec // G115: ms > 0 is checked immediately above, so this
	// int64->uint64 conversion never wraps.
	return uint64(ms)
}

// retentionMS is the carry-forward formula: gates retain for
// freshness_window_max, actions for freshness_window, read live off policy
// on every call rather than captured once (docs/phase-b-carry-forward.md
// item 1).
func retentionMS(kind spa.Kind, policy *config.Policy) uint64 {
	if kind == spa.KindGate {
		return durationMS(policy.FreshnessWindowMax)
	}
	return durationMS(policy.FreshnessWindow)
}

func checkKindAgreement(reqKind spa.Kind, svcKind config.Kind) error {
	var want config.Kind
	switch reqKind {
	case spa.KindGate:
		want = config.KindGate
	case spa.KindAction:
		want = config.KindAction
	default:
		return spa.ErrUnknownKind
	}
	if svcKind != want {
		return fmt.Errorf("%w: packet kind %v names a service declared kind %q", ErrKindMismatch, reqKind, svcKind)
	}
	return nil
}

func resolveGate(req *spa.Request, svc config.Service, grant config.Grant, observedSource netip.Addr) (Decision, error) {
	payload, err := req.GatePayload()
	if err != nil {
		return Decision{}, err
	}

	src := gate.Source{
		Kind:   gate.SourceObserved,
		Prefix: netip.PrefixFrom(observedSource, observedSource.BitLen()),
	}
	if payload.SourceKind == spa.SourceAsserted {
		// Asserted-source validation: docs/phase-b-carry-forward.md item 3.
		// Grant.AllowsSource is the enforcement; it is not re-derived here.
		if err := grant.AllowsSource(payload.Prefix); err != nil {
			return Decision{}, fmt.Errorf("%w: %v", ErrSourceNotAllowed, err)
		}
		src = gate.Source{Kind: gate.SourceAsserted, Prefix: payload.Prefix}
	}

	return Decision{
		ServiceKind: config.KindGate,
		Service:     svc.Name,
		Source:      src,
		TTL:         clampTTL(req.TTLSeconds, svc, grant),
	}, nil
}

// clampTTL turns the packet's requested ttl_seconds (0 meaning "use the
// service default") into the TTL actually granted, bounded by both the
// service's own max_ttl and the operator's grant-level max_ttl — whichever
// is tighter wins.
func clampTTL(requestedSeconds uint16, svc config.Service, grant config.Grant) time.Duration {
	ttl := time.Duration(requestedSeconds) * time.Second
	if ttl <= 0 {
		ttl = svc.DefaultTTL
	}
	if svc.MaxTTL > 0 && ttl > svc.MaxTTL {
		ttl = svc.MaxTTL
	}
	if grant.MaxTTL > 0 && ttl > grant.MaxTTL {
		ttl = grant.MaxTTL
	}
	return ttl
}

func resolveAction(req *spa.Request, svc config.Service, pending PendingTransaction, arrivedOnAlwaysAllowPath bool) (Decision, error) {
	switch svc.Name {
	case "confirm":
		rev, nonce, err := req.ConfirmPayload()
		if err != nil {
			return Decision{}, err
		}
		// Transaction binding: refused whenever no transaction is pending,
		// or a different one was named — proving binding exists rather
		// than a null check (design section 5, "Actions need stricter
		// rules than gates").
		if !pending.Pending || pending.Revision != rev || pending.Nonce != nonce {
			return Decision{}, ErrConfirmUnbound
		}
		return Decision{
			ServiceKind:     config.KindAction,
			Service:         svc.Name,
			PendingRevision: rev,
			DeploymentNonce: nonce,
		}, nil

	case "disarm":
		if err := req.DisarmPayload(); err != nil {
			return Decision{}, err
		}
		return Decision{ServiceKind: config.KindAction, Service: svc.Name}, nil

	case "liveness":
		// Binding: liveness must arrive on the always-allow path (design
		// section 5), the same table row structure as confirm's
		// revision/nonce binding — checked before the payload is read, since
		// it is the cheaper of the two and a packet failing it is refused
		// regardless of what its challenge nonce says.
		if !arrivedOnAlwaysAllowPath {
			return Decision{}, ErrLivenessOffPath
		}
		challenge, err := req.LivenessPayload()
		if err != nil {
			return Decision{}, err
		}
		return Decision{ServiceKind: config.KindAction, Service: svc.Name, Challenge: challenge}, nil

	default:
		return Decision{}, fmt.Errorf("%w: %q", ErrUnsupportedAction, svc.Name)
	}
}
