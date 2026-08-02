package agent_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

var observed = netip.MustParseAddr("203.0.113.5")

// Invariant 1: a replayed request_id is refused, and the refusal happens
// before any gate is touched. Validate performs no firewall I/O of its own
// (that is the whole point of its contract), so "before any gate is
// touched" is proven here by the second call returning an error rather
// than a Decision — there is nothing downstream of Validate for a second,
// accidental Reserve to have fed.
func TestAgent_Validate_ReplayedRequestIDRefused(t *testing.T) {
	f := newFixture(t)
	dg := f.seal(f.gateRequest())

	if _, err := agent.Validate(dg, observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("first Validate: %v", err)
	}

	_, err := agent.Validate(dg, observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
	if !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("second Validate error = %v, want replay.ErrDuplicate", err)
	}
}

// Invariant 2: a gate packet older than freshness_window_max is refused
// even when its counter is above the high-water mark — the
// suppressed-knock-replayed-later case. A test that only checked a stale
// timestamp with a stale counter would prove nothing, since a low counter
// would be rejected on the counter path regardless; the counter here is
// deliberately set above the mark established by an earlier accept, so
// the only thing standing between this packet and acceptance is the
// unconditional freshness_window_max bound.
func TestAgent_Validate_GateOlderThanFreshnessWindowMaxRefused_EvenWithCounterAboveHighWater(t *testing.T) {
	f := newFixture(t)

	warm := f.gateRequest()
	warm.Counter = 5000
	if _, err := agent.Validate(f.seal(warm), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("warm-up Validate: %v", err)
	}
	if got := f.store.HighWater(f.operator.Public().KeyID()); got != 5000 {
		t.Fatalf("high water after warm-up = %d, want 5000", got)
	}

	stale := f.gateRequest()
	stale.Counter = 6000 // above the 5000 high-water mark
	stale.TimestampMS = uint64(f.now.Add(-f.policy.FreshnessWindowMax - time.Hour).UnixMilli())

	_, err := agent.Validate(f.seal(stale), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
	if !errors.Is(err, agent.ErrTooOld) {
		t.Fatalf("stale-but-high-counter Validate error = %v, want agent.ErrTooOld", err)
	}
}

// Invariant 3: a timestamp-path acceptance with a lower counter does not
// lower the high-water mark. The store's max() semantics do this in
// principle; this test proves Validate actually threads the packet's real
// counter through to Reserve for a gate, rather than e.g. always passing 0
// or skipping the field.
func TestAgent_Validate_TimestampPathAcceptance_DoesNotLowerHighWater(t *testing.T) {
	f := newFixture(t)
	keyID := f.operator.Public().KeyID()

	high := f.gateRequest()
	high.Counter = 5000
	if _, err := agent.Validate(f.seal(high), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("first Validate: %v", err)
	}

	low := f.gateRequest()
	low.Counter = 100 // below the mark; must ride the timestamp path (fresh) to be accepted at all
	if _, err := agent.Validate(f.seal(low), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("second Validate: %v", err)
	}

	if got := f.store.HighWater(keyID); got != 5000 {
		t.Fatalf("high water = %d, want 5000 (unchanged by the lower-counter timestamp-path accept)", got)
	}
}

// Invariant 4: an accepted action does not move the gate high-water mark.
// spa.Parse already forces an action's counter to zero, which makes the
// mark itself unfalsifiable as an observation point (0 can never exceed an
// existing mark), so this test inspects what Validate actually hands the
// store via a spy — proving the IsGate flag threaded through for an
// action is false, not merely that its effect happens to be invisible.
func TestAgent_Validate_AcceptedActionDoesNotMoveGateHighWaterMark(t *testing.T) {
	f := newFixture(t)
	spy := &spyStore{}

	disarm := f.actionRequest(disarmName, [32]byte{})
	if _, err := agent.Validate(f.seal(disarm), observed, f.policy, f.opener, spy, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("Validate disarm: %v", err)
	}

	if len(spy.reservations) != 1 {
		t.Fatalf("reservations = %d, want exactly 1", len(spy.reservations))
	}
	if spy.reservations[0].IsGate {
		t.Fatal("accepted action reserved with IsGate = true; an action must never be able to move the gate high-water mark")
	}
}

// Invariant 5: a disarm older than freshness_window is refused even with a
// valid counter elsewhere in the system. Actions have no counter path at
// all — critically, the age chosen here (12h) sits strictly between
// freshness_window (60s) and freshness_window_max (24h), so this fails only
// if the action path actually enforces freshness_window. A packet older
// than freshness_window_max would fail even a buggy implementation that
// mistakenly gave the action the gate's wider unconditional bound, which
// would prove nothing about which bound the action path really uses.
func TestAgent_Validate_DisarmOlderThanFreshnessWindowRefused_EvenWithValidCounterElsewhere(t *testing.T) {
	f := newFixture(t)

	// Establish a "valid counter" elsewhere in the system: a normal, fresh
	// gate accept that raises this operator's high-water mark. The stale
	// disarm below must still be refused — actions never get to borrow a
	// gate's counter path.
	warm := f.gateRequest()
	warm.Counter = 5000
	if _, err := agent.Validate(f.seal(warm), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("warm-up Validate: %v", err)
	}

	disarm := f.actionRequest(disarmName, [32]byte{})
	// 12h: older than freshness_window (60s) but younger than
	// freshness_window_max (24h) — see the discriminating-age note above.
	disarm.TimestampMS = uint64(f.now.Add(-12 * time.Hour).UnixMilli())

	_, err := agent.Validate(f.seal(disarm), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
	if !errors.Is(err, agent.ErrNotFresh) {
		t.Fatalf("stale disarm Validate error = %v, want agent.ErrNotFresh (a nil error here would mean the action path is tolerating drift up to freshness_window_max instead of freshness_window)", err)
	}
}

// Invariant 6: a confirm naming a pending_revision/deployment_nonce other
// than the pending transaction is refused, including when a transaction is
// pending but a different one was named — the case that proves binding
// exists rather than a null check.
func TestAgent_Validate_ConfirmBindingMismatchRefused(t *testing.T) {
	nonceA := [16]byte{1, 2, 3, 4}
	nonceB := [16]byte{9, 9, 9, 9}

	cases := []struct {
		name        string
		pending     agent.PendingTransaction
		reqRevision uint64
		reqNonce    [16]byte
	}{
		{"no transaction pending", agent.PendingTransaction{Pending: false}, 7, nonceA},
		{"different revision pending", agent.PendingTransaction{Pending: true, Revision: 7, Nonce: nonceA}, 8, nonceA},
		{"same revision, different nonce pending", agent.PendingTransaction{Pending: true, Revision: 7, Nonce: nonceA}, 7, nonceB},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			payload, err := spa.EncodeConfirmPayload(tc.reqRevision, tc.reqNonce)
			if err != nil {
				t.Fatalf("EncodeConfirmPayload: %v", err)
			}
			req := f.actionRequest(confirmName, payload)

			_, err = agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store, tc.pending, false, f.now)
			if !errors.Is(err, agent.ErrConfirmUnbound) {
				t.Fatalf("Validate error = %v, want agent.ErrConfirmUnbound", err)
			}
		})
	}
}

// Positive control for invariant 6: a confirm whose revision and nonce
// match the pending transaction exactly is accepted, proving the mismatch
// tests above exercise a real comparison rather than a check that always
// fails.
func TestAgent_Validate_ConfirmBindingMatchAccepted(t *testing.T) {
	f := newFixture(t)
	nonce := [16]byte{4, 5, 6, 7}
	payload, err := spa.EncodeConfirmPayload(42, nonce)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	req := f.actionRequest(confirmName, payload)

	dec, err := agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store,
		agent.PendingTransaction{Pending: true, Revision: 42, Nonce: nonce}, false, f.now)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if dec.Service != confirmName || dec.PendingRevision != 42 || dec.DeploymentNonce != nonce {
		t.Fatalf("decision = %+v, want a confirm bound to revision 42", dec)
	}
}

// Invariant 7: an asserted prefix below the grant's minimum is refused,
// for both address families and for the IPv4-mapped-IPv6 encoding — the
// case where an operator wears a /0-equivalent IPv4 assertion in a v6
// costume to sail past a v6-only floor.
func TestAgent_Validate_AssertedSourceBelowGrantMinimumRefused(t *testing.T) {
	cases := []struct {
		name   string
		assert netip.Prefix
	}{
		{"ipv4 below /24 minimum", netip.MustParsePrefix("10.0.0.0/8")},
		{"ipv6 below /64 minimum", netip.MustParsePrefix("2001:db8::/32")},
		{"ipv4-mapped-ipv6 below the ipv4 minimum", netip.MustParsePrefix("::ffff:0.0.0.0/96")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			payload, err := spa.EncodeGatePayload(spa.GatePayload{SourceKind: spa.SourceAsserted, Prefix: tc.assert})
			if err != nil {
				t.Fatalf("EncodeGatePayload: %v", err)
			}
			req := f.gateRequest()
			req.Payload = payload

			_, err = agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
			if !errors.Is(err, agent.ErrSourceNotAllowed) {
				t.Fatalf("Validate error = %v, want agent.ErrSourceNotAllowed", err)
			}
		})
	}
}

// docs/phase-b-carry-forward.md item 2: a kind=gate record naming the
// action service "confirm" parses clean at the spa layer and must be
// rejected by the resolution layer before its payload is read as
// anything, or it would raise the operator's counter high-water mark and
// silently disable drift tolerance for their later gate requests.
func TestAgent_Validate_GateKindNamingActionServiceRejected(t *testing.T) {
	f := newFixture(t)

	req := f.gateRequest()
	req.ServiceID = serviceID(confirmName) // kind byte says gate; service_id names an action

	_, err := agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
	if !errors.Is(err, agent.ErrKindMismatch) {
		t.Fatalf("Validate error = %v, want agent.ErrKindMismatch", err)
	}
	if got := f.store.HighWater(f.operator.Public().KeyID()); got != 0 {
		t.Fatalf("high water = %d, want 0: a rejected kind-mismatched gate must never touch the high-water mark", got)
	}
}

// Carry-forward item 1: the retention formula. ExpiresAtMS must be
// now + freshness_window_max for a gate, now + freshness_window for an
// action, and read live off Policy on every call — not a value captured
// once. Nothing asserted this before; it is the property with no test the
// review flagged, so this checks all three claims and, critically, widens
// FreshnessWindowMax between two Reserve calls to prove the second read is
// live rather than cached from the first.
func TestAgent_Validate_RetentionExpiresAtMS_ReadsWindowsLiveNotCached(t *testing.T) {
	f := newFixture(t)
	spy := &spyStore{}
	nowMS := uint64(f.now.UnixMilli())

	gate1 := f.gateRequest()
	if _, err := agent.Validate(f.seal(gate1), observed, f.policy, f.opener, spy, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("gate1 Validate: %v", err)
	}
	wantGate1 := nowMS + msSince(f.policy.FreshnessWindowMax)
	if got := spy.reservations[0].ExpiresAtMS; got != wantGate1 {
		t.Fatalf("gate ExpiresAtMS = %d, want %d (now + freshness_window_max)", got, wantGate1)
	}

	disarm := f.actionRequest(disarmName, [32]byte{})
	if _, err := agent.Validate(f.seal(disarm), observed, f.policy, f.opener, spy, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("disarm Validate: %v", err)
	}
	wantAction := nowMS + msSince(f.policy.FreshnessWindow)
	if got := spy.reservations[1].ExpiresAtMS; got != wantAction {
		t.Fatalf("action ExpiresAtMS = %d, want %d (now + freshness_window)", got, wantAction)
	}

	// Widen freshness_window_max between two Reserve calls (an operator's
	// legitimate per-host tuning decision) and confirm the next gate's
	// expiry reflects the live value, not one captured earlier.
	f.policy.FreshnessWindowMax = 48 * time.Hour
	gate2 := f.gateRequest()
	if _, err := agent.Validate(f.seal(gate2), observed, f.policy, f.opener, spy, agent.PendingTransaction{}, false, f.now); err != nil {
		t.Fatalf("gate2 Validate: %v", err)
	}
	wantGate2 := nowMS + msSince(48*time.Hour)
	if got := spy.reservations[2].ExpiresAtMS; got != wantGate2 {
		t.Fatalf("widened gate ExpiresAtMS = %d, want %d (48h, read live off policy)", got, wantGate2)
	}
}

// msSince mirrors internal/agent's own durationMS for test-side expected
// values: every caller here passes a positive literal duration, so the
// conversion cannot wrap.
func msSince(d time.Duration) uint64 {
	//nolint:gosec // G115: every call site above passes a positive duration.
	return uint64(d.Milliseconds())
}

// Liveness's binding: a liveness packet is accepted only when it arrived on
// the always-allow path.
func TestAgent_Validate_LivenessOnAlwaysAllowPathAccepted(t *testing.T) {
	f := newFixture(t)
	challenge := [16]byte{1, 2, 3}
	payload, err := spa.EncodeLivenessPayload(challenge)
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}
	req := f.actionRequest(livenessName, payload)

	dec, err := agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, true, f.now)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if dec.Service != livenessName || dec.Challenge != challenge {
		t.Fatalf("decision = %+v, want a liveness decision carrying the challenge", dec)
	}
}

// The other direction: a liveness packet that did not arrive on the
// always-allow path must be refused. This is the case the review called
// out as the one where a missed check hands Task 3 a loaded gun — a
// Decision reaching the caller for a liveness packet off that path would
// let the agent answer an unauthenticated probe on the public SPA port.
func TestAgent_Validate_LivenessOffAlwaysAllowPathRefused(t *testing.T) {
	f := newFixture(t)
	payload, err := spa.EncodeLivenessPayload([16]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}
	req := f.actionRequest(livenessName, payload)

	_, err = agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
	if !errors.Is(err, agent.ErrLivenessOffPath) {
		t.Fatalf("Validate error = %v, want agent.ErrLivenessOffPath", err)
	}
}

// Minor: a general "a rejected packet never reserves" property, over every
// rejection reason that can be produced by mutating a single fixture's
// request. ("Not granted" needs a different signer entirely and gets its
// own test below.) Previously this rested on one incidental HighWater==0
// assertion inside the kind-mismatch test alone.
func TestAgent_Validate_RejectedPacketNeverReserves(t *testing.T) {
	cases := []struct {
		name  string
		build func(f *fixture) *spa.Request
	}{
		{"wrong host_id", func(f *fixture) *spa.Request {
			r := f.gateRequest()
			r.HostID[0] ^= 0xFF
			return r
		}},
		{"gate older than freshness_window_max", func(f *fixture) *spa.Request {
			r := f.gateRequest()
			r.TimestampMS = uint64(f.now.Add(-f.policy.FreshnessWindowMax - time.Hour).UnixMilli())
			return r
		}},
		{"gate not fresh on either path", func(f *fixture) *spa.Request {
			r := f.gateRequest()
			r.Counter = 0 // a fresh fixture's high-water starts at 0, so this must not exceed it
			r.TimestampMS = uint64(f.now.Add(-12 * time.Hour).UnixMilli())
			return r
		}},
		{"unknown service_id", func(f *fixture) *spa.Request {
			r := f.gateRequest()
			r.ServiceID = serviceID("no-such-service")
			return r
		}},
		{"gate kind naming an action service", func(f *fixture) *spa.Request {
			r := f.gateRequest()
			r.ServiceID = serviceID(confirmName)
			return r
		}},
		{"asserted source below grant minimum", func(f *fixture) *spa.Request {
			r := f.gateRequest()
			payload, err := spa.EncodeGatePayload(spa.GatePayload{SourceKind: spa.SourceAsserted, Prefix: netip.MustParsePrefix("10.0.0.0/8")})
			if err != nil {
				f.t.Fatalf("EncodeGatePayload: %v", err)
			}
			r.Payload = payload
			return r
		}},
		{"confirm not bound to a pending transaction", func(f *fixture) *spa.Request {
			payload, err := spa.EncodeConfirmPayload(1, [16]byte{1})
			if err != nil {
				f.t.Fatalf("EncodeConfirmPayload: %v", err)
			}
			return f.actionRequest(confirmName, payload)
		}},
		{"liveness off the always-allow path", func(f *fixture) *spa.Request {
			payload, err := spa.EncodeLivenessPayload([16]byte{1})
			if err != nil {
				f.t.Fatalf("EncodeLivenessPayload: %v", err)
			}
			return f.actionRequest(livenessName, payload)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			spy := &spyStore{}
			req := tc.build(f)

			_, err := agent.Validate(f.seal(req), observed, f.policy, f.opener, spy, agent.PendingTransaction{}, false, f.now)
			if err == nil {
				t.Fatal("Validate = nil error, want a rejection")
			}
			if len(spy.reservations) != 0 {
				t.Fatalf("reservations = %d, want 0: a rejected packet must never reserve", len(spy.reservations))
			}
		})
	}
}

// The "not granted" rejection needs a signer the opener trusts but the
// policy does not grant anything to, so it gets its own fixture rather than
// a slot in the table above.
func TestAgent_Validate_NotGrantedOperatorNeverReserves(t *testing.T) {
	f := newFixture(t)
	spy := &spyStore{}

	stranger, err := identity.Generate("stranger")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	opener, _, err := spa.NewOpenerFromSigner(f.host, []identity.PublicIdentity{f.operator.Public(), stranger.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	req := f.gateRequest()
	req.KeyID = stranger.Public().KeyID()
	dg, err := spa.Seal(req, stranger, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = agent.Validate(dg, observed, f.policy, opener, spy, agent.PendingTransaction{}, false, f.now)
	if !errors.Is(err, agent.ErrNotGranted) {
		t.Fatalf("Validate error = %v, want agent.ErrNotGranted", err)
	}
	if len(spy.reservations) != 0 {
		t.Fatalf("reservations = %d, want 0: a rejected packet must never reserve", len(spy.reservations))
	}
}

// Minor: a future-dated packet is bounded the same as a stale one, because
// ageMS takes an absolute difference. This is the discriminating case: 30s
// in the future is inside freshness_window (60s), so it must be accepted.
// A naive now-ts subtraction without an absolute value would wrap a small
// negative delta into a huge uint64, incorrectly rejecting this packet as
// centuries old.
func TestAgent_Validate_FutureTimestampWithinWindowAccepted(t *testing.T) {
	f := newFixture(t)
	req := f.gateRequest()
	req.TimestampMS = uint64(f.now.Add(30 * time.Second).UnixMilli())
	req.Counter = 1 // deliberately low: only the timestamp path can accept this

	_, err := agent.Validate(f.seal(req), observed, f.policy, f.opener, f.store, agent.PendingTransaction{}, false, f.now)
	if err != nil {
		t.Fatalf("future-but-fresh Validate error = %v, want acceptance", err)
	}
}

// spyStore is a replay.Store that records every Reservation it is handed,
// so a test can inspect exactly what Validate passed rather than only the
// (unfalsifiable, for a zero-counter action) resulting HighWater value.
type spyStore struct {
	reservations []replay.Reservation
	seen         map[[32]byte]bool
	high         map[[16]byte]uint64
}

func (s *spyStore) Reserve(r replay.Reservation) error {
	var k [32]byte
	copy(k[:16], r.KeyID[:])
	copy(k[16:], r.RequestID[:])
	if s.seen == nil {
		s.seen = map[[32]byte]bool{}
	}
	if s.seen[k] {
		return replay.ErrDuplicate
	}
	s.seen[k] = true
	s.reservations = append(s.reservations, r)
	if s.high == nil {
		s.high = map[[16]byte]uint64{}
	}
	if r.IsGate && r.Counter > s.high[r.KeyID] {
		s.high[r.KeyID] = r.Counter
	}
	return nil
}

func (s *spyStore) HighWater(keyID [16]byte) uint64 { return s.high[keyID] }
func (s *spyStore) Close() error                    { return nil }
