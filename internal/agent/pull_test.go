package agent_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

// --- servers -------------------------------------------------------------

// newGarbageServer answers 200 with random bytes that are not a bundle at
// all: a fetch that succeeds, wrapping a payload nothing downstream can
// unseal.
func newGarbageServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 256)
		_, _ = rand.Read(buf)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newSlowLorisServer accepts the connection and never writes a header,
// holding it open until the client's own Timeout gives up and disconnects —
// at which point r.Context() is cancelled and the handler returns, so this
// leaks no goroutine across tests.
func newSlowLorisServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newBundleServer answers whatever bytes set last handed it, letting a test
// change what the hub serves between two PullOnce calls.
func newBundleServer(t *testing.T) (srv *httptest.Server, set func([]byte)) {
	t.Helper()
	var mu sync.Mutex
	var body []byte
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		b := body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, func(b []byte) {
		mu.Lock()
		body = b
		mu.Unlock()
	}
}

// --- harness ---------------------------------------------------------------

// bundleHarness is a daemonHarness wired for fleet mode: a real Transactions
// (so applyBundlePolicy has something to arm through), a hub signer trusted
// by the daemon's own PullConfig, and this host's real fleet_id, so a test
// can build bundles that verify against exactly what the running daemon
// checks them against.
type bundleHarness struct {
	*daemonHarness
	txn       *txnHarness
	hubSigner identity.Signer
	fleetID   [16]byte
}

// newBundleHarness builds a daemon whose Options.Pull points at hubURL,
// trusts hubSigner, and enforces enrollmentFloor. tune, if non-nil, runs
// after everything above is wired, so a test can adjust the PullConfig (a
// shorter Timeout, for instance) without repeating the rest.
func newBundleHarness(t *testing.T, hubURL string, enrollmentFloor uint64, tune func(*agent.PullConfig)) *bundleHarness {
	t.Helper()
	return newBundleHarnessTuned(t, hubURL, enrollmentFloor, tune, nil)
}

// newBundleHarnessTuned is newBundleHarness with a second seam, onto the
// daemon's own Options rather than only its PullConfig, for a test that needs
// something the puller does not own, such as the daemon's logger, which is
// where the shutdown path writes.
func newBundleHarnessTuned(
	t *testing.T,
	hubURL string,
	enrollmentFloor uint64,
	tune func(*agent.PullConfig),
	tuneOpts func(*agent.Options),
) *bundleHarness {
	t.Helper()
	tx := newTxnHarness(t)
	hubSigner, err := identity.Generate("hub")
	if err != nil {
		t.Fatalf("generate hub signer: %v", err)
	}
	var fleetID [16]byte
	if _, err := rand.Read(fleetID[:]); err != nil {
		t.Fatalf("rand fleet_id: %v", err)
	}

	d := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision
		o.Policy.FleetID = fleetID

		cfg := agent.PullConfig{
			StatePath:       filepath.Join(t.TempDir(), "bundle.json"),
			HubURL:          hubURL,
			FleetID:         fleetID,
			HostID:          o.Policy.HostID,
			Interval:        time.Hour, // these tests drive PullOnce directly
			Timeout:         2 * time.Second,
			HostSigner:      o.Host,
			TrustedSigners:  [][32]byte{hubSigner.Public().Signing},
			EnrollmentFloor: enrollmentFloor,
		}
		if tune != nil {
			tune(&cfg)
		}
		o.Pull = &cfg
		if tuneOpts != nil {
			tuneOpts(o)
		}
	})
	return &bundleHarness{daemonHarness: d, txn: tx, hubSigner: hubSigner, fleetID: fleetID}
}

// validPolicyBytes marshals a Policy that will parse, validate, and plan a
// ruleset: this harness's own fixture policy (services, operators, host_id),
// with the fields gate.BuildRulesetPlan and Policy.Validate require and the
// bare fixture does not set, at the given revision.
func (h *bundleHarness) validPolicyBytes(t *testing.T, revision uint64) []byte {
	t.Helper()
	p := *h.policy
	p.Revision = revision
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	return data
}

// sealValid builds a bundle this harness's own daemon accepts outright:
// signed by hubSigner, sealed to the daemon's own host key, naming this
// harness's fleet_id and host_id, at version, wrapping policyYAML (or, if
// nil, validPolicyBytes(revision)).
func (h *bundleHarness) sealValid(t *testing.T, version uint64, policyYAML []byte) bundle.Sealed {
	t.Helper()
	if policyYAML == nil {
		policyYAML = h.validPolicyBytes(t, version)
	}
	c := &bundle.Contents{
		FleetID:  h.fleetID,
		HostID:   h.policy.HostID,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   policyYAML,
	}
	sealed, err := bundle.Seal(c, h.hubSigner, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	return sealed
}

// sealForAnotherHost is sealed correctly (so OpenAnonymous succeeds) and
// signed by the trusted hub signer, but the record's own host_id names a
// host other than this one — the check that fires once the seal and the
// signature have both already passed.
func (h *bundleHarness) sealForAnotherHost(t *testing.T, version uint64) bundle.Sealed {
	t.Helper()
	var other [16]byte
	if _, err := rand.Read(other[:]); err != nil {
		t.Fatalf("rand host_id: %v", err)
	}
	c := &bundle.Contents{
		FleetID:  h.fleetID,
		HostID:   other,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   h.validPolicyBytes(t, version),
	}
	sealed, err := bundle.Seal(c, h.hubSigner, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	return sealed
}

// sealWithWrongFleet is sealed correctly (so OpenAnonymous succeeds), signed
// by the trusted hub signer, and names this host's own host_id correctly —
// isolating the fleet_id check specifically. bundle.Open checks fleet_id
// before host_id, so with everything else about the record legitimate, a
// wrong fleet_id is the only control that can reject this input.
func (h *bundleHarness) sealWithWrongFleet(t *testing.T, version uint64) bundle.Sealed {
	t.Helper()
	var otherFleet [16]byte
	if _, err := rand.Read(otherFleet[:]); err != nil {
		t.Fatalf("rand fleet_id: %v", err)
	}
	c := &bundle.Contents{
		FleetID:  otherFleet,
		HostID:   h.policy.HostID,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   h.validPolicyBytes(t, version),
	}
	sealed, err := bundle.Seal(c, h.hubSigner, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	return sealed
}

// sealMalformed unseals fine (sealed to the real host) and is validly signed
// by the trusted hub signer over fields that are all otherwise legitimate,
// but carries a format-version byte openInner has never heard of. This
// isolates the format-version check specifically: membership and signature
// verification never even run, because the format check rejects it first,
// before either of those fields is consulted.
func (h *bundleHarness) sealMalformed(t *testing.T, version uint64) bundle.Sealed {
	t.Helper()
	policy := h.validPolicyBytes(t, version)

	signed := make([]byte, bundle.PolicyOff+len(policy)+bundle.SignerKeyLen)
	copy(signed[bundle.OffMagic:], bundle.Magic)
	signed[bundle.OffFormat] = 0xEE // no such format version
	copy(signed[bundle.OffFleetID:], h.fleetID[:])
	copy(signed[bundle.OffHostID:], h.policy.HostID[:])
	binary.BigEndian.PutUint64(signed[bundle.OffVersion:], version)
	binary.BigEndian.PutUint64(signed[bundle.OffIssuedAt:], uint64(time.Now().UnixMilli()))
	binary.BigEndian.PutUint32(signed[bundle.OffPolicyLen:], uint32(len(policy))) //nolint:gosec // G115: this test's own marshalled policy
	copy(signed[bundle.PolicyOff:], policy)
	signerKey := h.hubSigner.Public().Signing
	copy(signed[bundle.PolicyOff+len(policy):], signerKey[:])

	sig, err := h.hubSigner.Sign(signed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	record := append(signed, sig...)

	hostEnc := h.host.Public().Encryption
	sealed, err := box.SealAnonymous(nil, record, &hostEnc, rand.Reader)
	if err != nil {
		t.Fatalf("box.SealAnonymous: %v", err)
	}
	return bundle.Sealed(sealed)
}

// sealByUntrustedSigner is sealed correctly to this host, but authored by a
// key that is not in TrustedSigners: membership fails before ed25519.Verify
// is ever reached.
func (h *bundleHarness) sealByUntrustedSigner(t *testing.T, version uint64) bundle.Sealed {
	t.Helper()
	attacker, err := identity.Generate("attacker")
	if err != nil {
		t.Fatalf("generate attacker signer: %v", err)
	}
	c := &bundle.Contents{
		FleetID:  h.fleetID,
		HostID:   h.policy.HostID,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   h.validPolicyBytes(t, version),
	}
	sealed, err := bundle.Seal(c, attacker, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	return sealed
}

// sealWithForgedSignature claims the TRUSTED signer's own public key in the
// record's signer field — so membership passes — but carries a signature
// that does not verify against it, built by hand from bundle's own exported
// wire-layout constants rather than through Seal, which never lets a caller
// separate "whose key is named" from "who actually signed".
func (h *bundleHarness) sealWithForgedSignature(t *testing.T, version uint64) bundle.Sealed {
	t.Helper()
	policy := h.validPolicyBytes(t, version)

	signed := make([]byte, bundle.PolicyOff+len(policy)+bundle.SignerKeyLen)
	copy(signed[bundle.OffMagic:], bundle.Magic)
	signed[bundle.OffFormat] = bundle.FormatV1
	copy(signed[bundle.OffFleetID:], h.fleetID[:])
	copy(signed[bundle.OffHostID:], h.policy.HostID[:])
	binary.BigEndian.PutUint64(signed[bundle.OffVersion:], version)
	binary.BigEndian.PutUint64(signed[bundle.OffIssuedAt:], uint64(time.Now().UnixMilli()))
	binary.BigEndian.PutUint32(signed[bundle.OffPolicyLen:], uint32(len(policy))) //nolint:gosec // G115: this test's own marshalled policy, nowhere near 4GiB
	copy(signed[bundle.PolicyOff:], policy)
	signerKey := h.hubSigner.Public().Signing
	copy(signed[bundle.PolicyOff+len(policy):], signerKey[:])

	sig, err := h.hubSigner.Sign(signed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Corrupt the signature the trusted key actually produced, rather than
	// signing with a different key: this is what makes membership (the
	// signerKey bytes above) pass while ed25519.Verify fails, isolating the
	// signature-verification control from the membership one.
	sig[0] ^= 0xFF
	record := append(signed, sig...)

	hostEnc := h.host.Public().Encryption
	sealed, err := box.SealAnonymous(nil, record, &hostEnc, rand.Reader)
	if err != nil {
		t.Fatalf("box.SealAnonymous: %v", err)
	}
	return bundle.Sealed(sealed)
}

// --- helpers ---------------------------------------------------------------

func assertKnockOpensGate(t *testing.T, h *daemonHarness, wantOpens int) {
	t.Helper()
	h.send(t, h.seal(h.gateRequest()), false)
	waitFor(t, "the gate to open", func() bool { return len(h.gate.openCalls()) >= wantOpens })
}

func waitForPullFailure(t *testing.T, h *daemonHarness) {
	t.Helper()
	waitFor(t, "the pull loop to record a rejection", func() bool {
		return h.daemon.Puller().Stats().Rejections >= 1
	})
}

// --- TestAgent_Puller_AKnockSucceedsWhileTheHubIsUnreachable ---------------

// The invariant the whole product rests on. The hub is a management
// convenience; if a pull failure could stop a knock, postern would have
// reintroduced the external control-plane dependency it exists to remove.
// Asserted against a hub that is not merely down but actively hostile: a
// connection refused, a black hole that never answers at all, a 200 wrapping
// garbage, and a server that accepts the connection and never sends a
// header. The last is the one that distinguishes a real implementation from
// one that merely looks right — "the hub is down" is the easy case; "the hub
// is answering slowly and wrongly" is the one that takes a lock.
func TestAgent_Puller_AKnockSucceedsWhileTheHubIsUnreachable(t *testing.T) {
	garbage := newGarbageServer(t)
	loris := newSlowLorisServer(t)

	hubs := map[string]string{
		"connection_refused": "http://127.0.0.1:1",
		"black_hole":         "http://240.0.0.1:9",
		"garbage_200":        garbage.URL,
		"slow_loris":         loris.URL,
	}
	for name, hubURL := range hubs {
		t.Run(name, func(t *testing.T) {
			hubSigner, err := identity.Generate("hub")
			if err != nil {
				t.Fatalf("generate hub signer: %v", err)
			}
			tx := newTxnHarness(t)
			h := newDaemonHarness(t, func(o *agent.Options) {
				o.Transactions = tx.txns
				o.Policy.Revision = txnHarnessRecordedRevision
				o.Pull = &agent.PullConfig{
					StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
					HubURL:         hubURL,
					FleetID:        o.Policy.FleetID,
					HostID:         o.Policy.HostID,
					Interval:       20 * time.Millisecond,
					Timeout:        150 * time.Millisecond,
					HostSigner:     o.Host,
					TrustedSigners: [][32]byte{hubSigner.Public().Signing},
				}
			})
			h.start(t)

			// Do not wait for the pull to fail first: the point is that the two
			// are independent, so knock immediately and knock again after the
			// pull has definitely errored.
			assertKnockOpensGate(t, h, 1)
			waitForPullFailure(t, h)
			assertKnockOpensGate(t, h, 2)
		})
	}
}

// --- TestAgent_Puller_KeepsLastGoodOnEveryRejection -------------------------

// Last-good is what stops a bad bundle from becoming an outage. Every
// rejection path must leave the running policy exactly as it was.
//
// Two cases ("not newer" and "below the floor") need the daemon primed with
// a real accepted version first — otherwise both would be indistinguishable
// from "no current version at all", which is exactly the pairwise trap the
// brief calls out: a version below the floor and a version that is merely
// not newer both reject a bundle, and a test that cannot tell them apart
// would pass whichever control actually decided.
func TestAgent_Puller_KeepsLastGoodOnEveryRejection(t *testing.T) {
	t.Run("garbage (200 wrapping bytes that are not a bundle)", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		buf := make([]byte, 400)
		_, _ = rand.Read(buf)
		set(buf)

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after garbage (-before +after):\n%s", diff)
		}
	})

	t.Run("sealed for another host", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		set(h.sealForAnotherHost(t, 100))

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a wrong host_id (-before +after):\n%s", diff)
		}
	})

	t.Run("sealed by an untrusted signer", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		set(h.sealByUntrustedSigner(t, 100))

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after an untrusted signer (-before +after):\n%s", diff)
		}
	})

	t.Run("sealed with a forged signature from a trusted key", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		set(h.sealWithForgedSignature(t, 100))

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a forged signature (-before +after):\n%s", diff)
		}
	})

	t.Run("unparseable policy", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		set(h.sealValid(t, 100, []byte("fail_postur: closed\n")))

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after an unparseable policy (-before +after):\n%s", diff)
		}
	})

	t.Run("policy that parses but fails Validate", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		p := *h.policy
		p.Revision = 100
		p.SPAPort = 62201
		p.AlwaysAllowIface = "tailscale0"
		p.RecoveryService = "" // ssh is fail-closed; Validate requires a recovery_service
		data, err := config.MarshalStandalone(&p)
		if err != nil {
			t.Fatalf("MarshalStandalone: %v", err)
		}
		set(h.sealValid(t, 100, data))

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a policy that fails Validate (-before +after):\n%s", diff)
		}
	})

	t.Run("below the enrollment floor", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 10, nil) // floor 10, no prior accepted version
		set(h.sealValid(t, 5, nil))

		before := h.daemon.Policy()
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a below-floor version (-before +after):\n%s", diff)
		}
	})

	t.Run("not newer than the current version", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)

		// Prime a real current version, above the floor, so this case is
		// distinguishable from "below the floor": HasCurrent is true here and
		// false there.
		set(h.sealValid(t, 20, nil))
		if err := h.daemon.Puller().PullOnce(context.Background()); err != nil {
			t.Fatalf("priming pull failed: %v", err)
		}
		before := h.daemon.Policy()

		set(h.sealValid(t, 15, nil)) // above the floor (0), but not newer than 20
		if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a not-newer version (-before +after):\n%s", diff)
		}
	})
}

// --- rotation, at the transaction guard (Task 6) ---------------------------

// baseRotation is a valid port_rotation block that does not overlap the
// kernel ephemeral range, ssh's port 22, or an unset http carrier port —
// picked once so every test below shares one "known good" starting
// configuration and only ever moves one field away from it.
func baseRotation() *config.PortRotation {
	return &config.PortRotation{
		Secret:  testRotationSecret(9),
		Window:  30 * time.Second,
		RangeLo: 20000,
		RangeHi: 20100,
	}
}

// rotatingPolicyBytes is (*bundleHarness).validPolicyBytes's counterpart for
// a fetched bundle that needs its own port_rotation block: that helper
// leaves PortRotation at whatever the fixture policy already carries, which
// is nil unless a test's tune already set one.
func rotatingPolicyBytes(t *testing.T, h *bundleHarness, revision uint64, rot *config.PortRotation) []byte {
	t.Helper()
	p := *h.policy
	p.Revision = revision
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	p.PortRotation = rot
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	return data
}

// A running rotation daemon; a fetched policy identical except
// PortRotation.Secret differs. applyBundlePolicy must refuse, naming the
// secret, and leave the running policy untouched.
func TestAgent_ApplyBundle_RefusesMovingTheRotationSecret(t *testing.T) {
	srv, set := newBundleServer(t)
	rot := baseRotation()
	h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
		o.Policy.PortRotation = rot
	})

	moved := *rot
	moved.Secret = testRotationSecret(rot.Secret[0] + 1)
	set(h.sealValid(t, 100, rotatingPolicyBytes(t, h, 100, &moved)))

	before := h.daemon.Policy()
	err := h.daemon.Puller().PullOnce(context.Background())
	if err == nil {
		t.Fatal("PullOnce() = nil, want an error refusing to move the port_rotation secret")
	}
	if !strings.Contains(err.Error(), "secret") {
		t.Fatalf("PullOnce() error = %q, want it to name the secret", err.Error())
	}
	if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
		t.Errorf("running policy changed after a bundle moved the rotation secret (-before +after):\n%s", diff)
	}
}

// Same, for Window and for RangeLo/RangeHi.
func TestAgent_ApplyBundle_RefusesMovingTheRotationWindowOrRange(t *testing.T) {
	t.Run("window", func(t *testing.T) {
		srv, set := newBundleServer(t)
		rot := baseRotation()
		h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
			o.Policy.PortRotation = rot
		})

		moved := *rot
		moved.Window = rot.Window * 2
		set(h.sealValid(t, 100, rotatingPolicyBytes(t, h, 100, &moved)))

		before := h.daemon.Policy()
		err := h.daemon.Puller().PullOnce(context.Background())
		if err == nil {
			t.Fatal("PullOnce() = nil, want an error refusing to move the port_rotation window")
		}
		if !strings.Contains(err.Error(), "window") {
			t.Fatalf("PullOnce() error = %q, want it to name the window", err.Error())
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a bundle moved the rotation window (-before +after):\n%s", diff)
		}
	})

	t.Run("range", func(t *testing.T) {
		srv, set := newBundleServer(t)
		rot := baseRotation()
		h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
			o.Policy.PortRotation = rot
		})

		moved := *rot
		moved.RangeLo, moved.RangeHi = rot.RangeLo+200, rot.RangeHi+200
		set(h.sealValid(t, 100, rotatingPolicyBytes(t, h, 100, &moved)))

		before := h.daemon.Policy()
		err := h.daemon.Puller().PullOnce(context.Background())
		if err == nil {
			t.Fatal("PullOnce() = nil, want an error refusing to move the port_rotation range")
		}
		if !strings.Contains(err.Error(), "range") {
			t.Fatalf("PullOnce() error = %q, want it to name the range", err.Error())
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a bundle moved the rotation range (-before +after):\n%s", diff)
		}
	})
}

// A bundle that toggles port_rotation on or off is refused by the mode-switch
// check at the top of checkCarrierPortsUnchanged, in both directions: a
// running rotation host cannot be dropped to fixed mode, and a running
// fixed-port host cannot be switched into rotation, by a fetched bundle
// alone. Deleting that check would pass every other test in this file, since
// none of the others cross modes.
func TestAgent_ApplyBundle_RefusesTogglingPortRotationMode(t *testing.T) {
	t.Run("rotation_to_fixed", func(t *testing.T) {
		srv, set := newBundleServer(t)
		rot := baseRotation()
		h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
			o.Policy.PortRotation = rot
		})

		set(h.sealValid(t, 100, rotatingPolicyBytes(t, h, 100, nil)))

		before := h.daemon.Policy()
		err := h.daemon.Puller().PullOnce(context.Background())
		if err == nil {
			t.Fatal("PullOnce() = nil, want an error refusing to turn port rotation off")
		}
		if !strings.Contains(err.Error(), "rotation") {
			t.Fatalf("PullOnce() error = %q, want it to name rotation", err.Error())
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a bundle turned rotation off (-before +after):\n%s", diff)
		}
	})

	t.Run("fixed_to_rotation", func(t *testing.T) {
		srv, set := newBundleServer(t)
		h := newBundleHarness(t, srv.URL, 0, nil)
		rot := baseRotation()

		set(h.sealValid(t, 100, rotatingPolicyBytes(t, h, 100, rot)))

		before := h.daemon.Policy()
		err := h.daemon.Puller().PullOnce(context.Background())
		if err == nil {
			t.Fatal("PullOnce() = nil, want an error refusing to turn port rotation on")
		}
		if !strings.Contains(err.Error(), "rotation") {
			t.Fatalf("PullOnce() error = %q, want it to name rotation", err.Error())
		}
		if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
			t.Errorf("running policy changed after a bundle turned rotation on (-before +after):\n%s", diff)
		}
	})
}

// The rotation guard's accept path: a fetched bundle whose port_rotation
// secret, window, and range are byte-for-byte identical to the running
// policy's is allowed through the transaction, exactly as a fixed-mode
// bundle that leaves spa_port untouched is (see
// TestAgent_Puller_AppliesANewerBundleThroughTheTransaction). Every other
// rotation test in this file asserts only a refusal, so a mutation that made
// the rotation branch of checkCarrierPortsUnchanged refuse unconditionally
// would pass all of them; this is the one that catches it.
func TestAgent_ApplyBundle_AcceptsRotationBundleWithUnchangedSecretWindowAndRange(t *testing.T) {
	srv, set := newBundleServer(t)
	rot := baseRotation()
	h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
		o.Policy.PortRotation = rot
	})
	if err := h.txn.unit.SetEnabled(context.Background(), false); err != nil {
		t.Fatalf("stage the boot unit disabled: %v", err)
	}

	set(h.sealValid(t, 100, rotatingPolicyBytes(t, h, 100, rot)))

	if err := h.daemon.Puller().PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v, want nil for a bundle whose port_rotation block is unchanged", err)
	}

	if !strings.Contains(h.txn.ruleset.live(), "table inet") {
		t.Fatalf("live ruleset after applying an unchanged-rotation bundle = %q, want the generated table",
			h.txn.ruleset.live())
	}
	if !h.txn.unit.state() {
		t.Fatal("the boot unit was not enabled by the unchanged-rotation bundle's arm step")
	}
	if got := h.daemon.Policy().Revision; got != 100 {
		t.Fatalf("running policy revision = %d, want 100", got)
	}
	if diff := cmp.Diff(rot, h.daemon.Policy().PortRotation); diff != "" {
		t.Errorf("running policy's port_rotation changed after an unchanged-rotation bundle applied (-want +got):\n%s", diff)
	}
	if got := h.daemon.Puller().Stats().Applied; got != 1 {
		t.Fatalf("Stats().Applied = %d, want 1", got)
	}
}

// The existing guard is unchanged for a fixed-port host: a bundle that moves
// spa_port is still refused, by name, with the running policy untouched.
func TestAgent_ApplyBundle_FixedModeStillRefusesMovingSPAPort(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)

	p := *h.policy
	p.Revision = 100
	p.SPAPort = 62202 // moved from the fixture's 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	set(h.sealValid(t, 100, data))

	before := h.daemon.Policy()
	pullErr := h.daemon.Puller().PullOnce(context.Background())
	if pullErr == nil {
		t.Fatal("PullOnce() = nil, want an error refusing to move spa_port")
	}
	if !strings.Contains(pullErr.Error(), "spa_port") {
		t.Fatalf("PullOnce() error = %q, want it to name spa_port", pullErr.Error())
	}
	if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
		t.Errorf("running policy changed after a bundle moved spa_port (-before +after):\n%s", diff)
	}
}

// --- TestAgent_Puller_AppliesANewerBundleThroughTheTransaction --------------

// The happy path still has to work, and applying has to go through the same
// confirm-or-revert transaction an operator-driven change does — a bundle
// that locks the host out must roll itself back exactly like a bad local
// config does. Asserted three ways: the ruleset generated from the fetched
// policy is what actually loaded, the boot unit was enabled, and a pending
// transaction naming this revision was published — the same three things
// TestAgent_Daemon_ArmingANewRevisionLoadsTheRulesetAndEnablesTheBootUnit and
// TestAgent_Daemon_PublishesThePendingRevisionAndNonceBeforeArming assert for
// a locally-driven arm.
func TestAgent_Puller_AppliesANewerBundleThroughTheTransaction(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)
	if err := h.txn.unit.SetEnabled(context.Background(), false); err != nil {
		t.Fatalf("stage the boot unit disabled: %v", err)
	}

	const version = txnHarnessRecordedRevision + 1
	set(h.sealValid(t, version, nil))

	if err := h.daemon.Puller().PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v, want nil", err)
	}

	if !strings.Contains(h.txn.ruleset.live(), "table inet") {
		t.Fatalf("live ruleset after applying a fetched bundle = %q, want the generated table", h.txn.ruleset.live())
	}
	if !h.txn.unit.state() {
		t.Fatal("the boot unit was not enabled by a fetched bundle's arm step")
	}
	rec, ok, err := h.txn.txns.LastArm()
	if err != nil {
		t.Fatalf("LastArm: %v", err)
	}
	if !ok || rec.Revision != version || rec.Outcome != agent.ArmPending {
		t.Fatalf("LastArm = %+v (ok=%v), want revision %d pending", rec, ok, version)
	}
	if got := h.daemon.Policy().Revision; got != version {
		t.Fatalf("running policy revision = %d, want %d", got, version)
	}
	if got := h.daemon.Puller().Stats().Applied; got != 1 {
		t.Fatalf("Stats().Applied = %d, want 1", got)
	}
}

// --- TestAgent_Puller_DoesNotApplyWhileATransactionIsPending ----------------

// A pull that arrives mid-transaction must not start a second one: a repeat
// fetch of a bundle that is already armed and awaiting confirm must not mint
// a new nonce out from under an operator who may already be holding the
// first one.
func TestAgent_Puller_DoesNotApplyWhileATransactionIsPending(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)

	const version = txnHarnessRecordedRevision + 1
	set(h.sealValid(t, version, nil))
	if err := h.daemon.Puller().PullOnce(context.Background()); err != nil {
		t.Fatalf("first PullOnce() = %v, want nil", err)
	}
	first, ok, err := h.txn.txns.LastArm()
	if err != nil || !ok {
		t.Fatalf("LastArm after first pull: %+v, ok=%v, err=%v", first, ok, err)
	}
	appliedBefore := h.daemon.Puller().Stats().Applied

	// The identical, still-unconfirmed bundle is fetched again.
	set(h.sealValid(t, version, nil))
	if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
		t.Fatal("a repeat pull of an already-pending bundle was accepted")
	}

	second, ok, err := h.txn.txns.LastArm()
	if err != nil || !ok {
		t.Fatalf("LastArm after second pull: %+v, ok=%v, err=%v", second, ok, err)
	}
	if second.Nonce != first.Nonce {
		t.Fatalf("the pending nonce changed (%s -> %s); a second transaction was started for a "+
			"revision already pending", first.Nonce, second.Nonce)
	}
	if got := h.daemon.Puller().Stats().Applied; got != appliedBefore {
		t.Fatalf("Applied went from %d to %d; apply ran again for an already-pending revision", appliedBefore, got)
	}
}

// --- TestAgent_Puller_SpreadsIntervalsAcrossTheJitterBand -------------------

// Jitter, so a fleet restarted together does not synchronise into a
// thundering herd against the one component with a public address.
func TestAgent_Puller_SpreadsIntervalsAcrossTheJitterBand(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	cfg := agent.PullConfig{
		StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		HubURL:         "http://127.0.0.1:1",
		HostSigner:     host,
		TrustedSigners: [][32]byte{{1}},
		Interval:       100 * time.Millisecond,
		Jitter:         0.2,
	}
	p, err := agent.NewPuller(cfg, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}

	min, max := 80*time.Millisecond, 120*time.Millisecond
	var below, above bool
	for i := 0; i < 500; i++ {
		d := agent.PullerNextInterval(p)
		if d < min || d > max {
			t.Fatalf("jittered interval %s outside [%s, %s]", d, min, max)
		}
		switch {
		case d < cfg.Interval:
			below = true
		case d > cfg.Interval:
			above = true
		}
	}
	if !below || !above {
		t.Fatalf("500 samples never spread to both sides of Interval (below=%v above=%v)", below, above)
	}
}

// Jitter zero is a real, supported configuration (a test wanting a
// deterministic cadence), and it must not silently pick up a nonzero spread
// from a stale default.
func TestAgent_Puller_ZeroJitterNeverVaries(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	cfg := agent.PullConfig{
		StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		HubURL:         "http://127.0.0.1:1",
		HostSigner:     host,
		TrustedSigners: [][32]byte{{1}},
		Interval:       100 * time.Millisecond,
	}
	p, err := agent.NewPuller(cfg, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	for i := 0; i < 20; i++ {
		if d := agent.PullerNextInterval(p); d != cfg.Interval {
			t.Fatalf("jittered interval = %s, want exactly %s with Jitter 0", d, cfg.Interval)
		}
	}
}

// --- fetch-layer defenses ----------------------------------------------

// The context-timeout control and the io.LimitReader cap both truncate a
// hostile response, and each is what catches a scenario the other cannot:
// the slow-loris case above never sends enough bytes to trip the cap, so
// only Timeout catches it. This test is the other half of that pair — a
// server that answers instantly with a body far larger than the cap, so
// nothing about it could ever approach the generous Timeout below, and only
// the cap can be what decides.
func TestAgent_Puller_FetchTruncatesAnOversizedResponseEvenWellWithinTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, agent.MaxBundleResponseBytesForTest+4096)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	p, err := agent.NewPuller(agent.PullConfig{
		StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		HubURL:         srv.URL,
		HostSigner:     host,
		TrustedSigners: [][32]byte{{1}},
		Timeout:        5 * time.Second, // generous: proves the cap decides, not a timeout race
	}, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}

	start := time.Now()
	err = p.PullOnce(context.Background())
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("PullOnce() = %v, want an error naming the size cap", err)
	}
	if elapsed > time.Second {
		t.Fatalf("took %s against a 5s timeout; a response this fast approaching it means the cap, "+
			"not the timeout, decided too slowly to trust", elapsed)
	}
}

// --- construction guards -----------------------------------------------

// Every one of NewPuller's construction-time refusals, each isolated: only
// the field under test is broken, everything else about validConfig stays
// legitimate, so a mutation deleting one guard cannot hide behind another.
func TestAgent_Puller_NewPuller_RejectsIncompleteConfig(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	validConfig := func() agent.PullConfig {
		return agent.PullConfig{
			StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
			HubURL:         "https://hub.example.com",
			HostSigner:     host,
			TrustedSigners: [][32]byte{{1}},
		}
	}
	noopApply := func(*config.Policy) (bool, error) { return true, nil }

	t.Run("empty HubURL", func(t *testing.T) {
		cfg := validConfig()
		cfg.HubURL = ""
		if _, err := agent.NewPuller(cfg, noopApply); err == nil {
			t.Fatal("NewPuller accepted an empty HubURL")
		}
	})
	t.Run("nil HostSigner", func(t *testing.T) {
		cfg := validConfig()
		cfg.HostSigner = nil
		if _, err := agent.NewPuller(cfg, noopApply); err == nil {
			t.Fatal("NewPuller accepted a nil HostSigner")
		}
	})
	t.Run("empty TrustedSigners", func(t *testing.T) {
		cfg := validConfig()
		cfg.TrustedSigners = nil
		if _, err := agent.NewPuller(cfg, noopApply); err == nil {
			t.Fatal("NewPuller accepted an empty TrustedSigners; a puller with no trusted signer can " +
				"accept no bundle at all, so this should be a construction error, not a runtime rejection")
		}
	})
	t.Run("nil apply", func(t *testing.T) {
		if _, err := agent.NewPuller(validConfig(), nil); err == nil {
			t.Fatal("NewPuller accepted a nil apply")
		}
	})
	t.Run("Jitter at 1 (exclusive upper bound)", func(t *testing.T) {
		cfg := validConfig()
		cfg.Jitter = 1
		if _, err := agent.NewPuller(cfg, noopApply); err == nil {
			t.Fatal("NewPuller accepted Jitter = 1; a factor of 1 + 1*(-1) can reach 0, collapsing the interval")
		}
	})
	t.Run("negative Jitter", func(t *testing.T) {
		cfg := validConfig()
		cfg.Jitter = -0.1
		if _, err := agent.NewPuller(cfg, noopApply); err == nil {
			t.Fatal("NewPuller accepted a negative Jitter")
		}
	})
	t.Run("every field legitimate", func(t *testing.T) {
		if _, err := agent.NewPuller(validConfig(), noopApply); err != nil {
			t.Fatalf("NewPuller rejected a legitimate config: %v", err)
		}
	})
}

// The hub serves GET /bundle/<host_id_hex> (design section 6), and the
// Puller has to build that path itself from HostID — nothing else in
// PullConfig carries a pre-built URL. This is the direct test: it inspects
// the request the Puller actually sent, rather than inferring the path was
// right from a fetch that happened to succeed.
func TestAgent_Puller_RequestsTheHostsOwnBundlePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	hostID := [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	p, err := agent.NewPuller(agent.PullConfig{
		StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		HubURL:         srv.URL,
		HostID:         hostID,
		HostSigner:     host,
		TrustedSigners: [][32]byte{{1}},
	}, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}

	_ = p.PullOnce(context.Background()) // the empty 200 body will fail to unseal; only the path matters here

	want := "/bundle/deadbeef0102030405060708090a0b0c"
	if gotPath != want {
		t.Fatalf("requested path = %q, want %q", gotPath, want)
	}
}

// --- daemon-level construction guard -------------------------------------

// A puller with nothing to arm through must be refused at construction, not
// discovered the first time a bundle is fetched: confirm-or-revert is the
// only mechanism that can roll a bad bundle back, so a daemon skipping it
// entirely for fleet mode is a construction mistake, the same class New
// already refuses for a Transactions with a BootUnit and no AgentUnit.
func TestAgent_New_RefusesPullWithoutTransactions(t *testing.T) {
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.AlwaysAllowIface = "tailscale0"

	_, err := agent.New(agent.Options{
		Policy:    f.policy,
		Gate:      &daemonGate{},
		Opener:    f.opener,
		Store:     f.store,
		Host:      f.host,
		StorePath: "/var/lib/postern/replay.db",
		Receiver:  newFakeReceiver(),
		Pull: &agent.PullConfig{
			StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
			HubURL:         "https://hub.example.com",
			HostSigner:     f.host,
			TrustedSigners: [][32]byte{{1}},
		},
		// Transactions deliberately left nil.
	})
	if err == nil {
		t.Fatal("New accepted Options.Pull with no Options.Transactions; a fetched bundle would have " +
			"nothing to arm it through")
	}
}

// --- reject reason labelling ---------------------------------------------

// wrong_fleet, isolated: sealWithWrongFleet is otherwise a completely
// legitimate record (real seal, real trusted signature, this host's own
// host_id, a version within bounds), so fleet_id is the only thing that can
// reject it. See the fix report for the mutation that proves it — deleting
// bundle.Open's fleet_id check makes this bundle apply cleanly.
func TestAgent_Puller_RejectReason_WrongFleet(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, func(cfg *agent.PullConfig) { cfg.Logger = logger })
	set(h.sealWithWrongFleet(t, 100))

	if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
		t.Fatal("PullOnce() = nil, want an error")
	}
	if !strings.Contains(buf.String(), "reason=wrong_fleet") {
		t.Fatalf("log output = %q, want a line naming reason=wrong_fleet", buf.String())
	}
}

// malformed, isolated: sealMalformed is properly sealed and validly signed by
// a trusted key over an otherwise legitimate record; only the format-version
// byte is wrong, and openInner rejects that before membership or signature
// verification ever run.
func TestAgent_Puller_RejectReason_Malformed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, func(cfg *agent.PullConfig) { cfg.Logger = logger })
	set(h.sealMalformed(t, 100))

	if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
		t.Fatal("PullOnce() = nil, want an error")
	}
	if !strings.Contains(buf.String(), "reason=malformed") {
		t.Fatalf("log output = %q, want a line naming reason=malformed", buf.String())
	}
}

// --- log throttling -------------------------------------------------------

// Every rejection increments a labelled counter and logs at most once per
// window — the M1-ledger item this is: a hub down for a month must not write
// a month of identical lines.
//
// Driven at the cadence the loop actually runs at, jitter included, rather
// than at one instant. The previous version of this test made two calls with
// the clock frozen, which is a state Run never produces: every sleep between
// attempts is jittered, so roughly half of them come out LONGER than the
// nominal interval, and a window equal to the interval therefore suppressed
// almost nothing. The test passed and the journal filled up anyway.
//
// Mutation verified: setting logWindow back to interval produces 5,737 lines
// over 8,650 attempts here — most of a month of identical lines — and fails
// the bound below.
func TestAgent_Puller_ThrottlesRejectionLogsAcrossAMonthOfFailures(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	const interval = 300 * time.Second
	now := time.Now()

	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	p, err := agent.NewPuller(agent.PullConfig{
		StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		HubURL:         "http://127.0.0.1:1", // connection refused: fast and deterministic
		HostSigner:     host,
		TrustedSigners: [][32]byte{{1}},
		Interval:       interval,
		Jitter:         0.1,
		Logger:         logger,
		Now:            func() time.Time { return now },
	}, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	rejections := func() int { return strings.Count(buf.String(), "bundle pull rejected") }

	// Thirty days of a hub that is down, stepped by the loop's own jittered
	// sleep so the clock advances exactly the way Run advances it.
	const month = 30 * 24 * time.Hour
	attempts := 0
	for elapsed := time.Duration(0); elapsed < month; {
		if err := p.PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil against a refused connection, want an error")
		}
		attempts++
		step := agent.PullerNextInterval(p)
		now = now.Add(step)
		elapsed += step
	}

	if got := uint64(attempts); p.Stats().Rejections != got {
		t.Fatalf("Stats().Rejections = %d after %d attempts, want %d: the counter must move on every "+
			"rejection even when the log line does not", p.Stats().Rejections, attempts, got)
	}
	// The bound is what the claim means. A month at this interval is about
	// 8,600 attempts; anything close to that is a month of identical lines.
	const bound = 1000
	t.Logf("a month against a dead hub: %d attempts, %d log lines", attempts, rejections())
	if got := rejections(); got > bound {
		t.Fatalf("a month against a dead hub wrote %d log lines over %d attempts, want at most %d; "+
			"the throttle window has to be a multiple of the interval, because jitter puts half of "+
			"all sleeps past a window that merely equals it", got, attempts, bound)
	}
	// And it is still logging SOMETHING: a throttle that silenced the
	// condition entirely would pass the bound above and tell an operator
	// nothing.
	if got := rejections(); got < 2 {
		t.Fatalf("a month against a dead hub wrote %d log lines; an operator reading the journal has "+
			"no evidence the condition persisted", got)
	}
}

// The first rejection always logs, and the second inside the same window does
// not. This is the mechanism, held still: the test above measures what it
// produces at the loop's real cadence, and this one says which call is
// suppressed.
func TestAgent_Puller_TheSecondRejectionInsideOneWindowIsSuppressed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	now := time.Now()

	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	p, err := agent.NewPuller(agent.PullConfig{
		StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		HubURL:         "http://127.0.0.1:1",
		HostSigner:     host,
		TrustedSigners: [][32]byte{{1}},
		Interval:       time.Minute,
		Logger:         logger,
		Now:            func() time.Time { return now },
	}, func(*config.Policy) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	rejections := func() int { return strings.Count(buf.String(), "bundle pull rejected") }

	for i := 0; i < 2; i++ {
		if err := p.PullOnce(context.Background()); err == nil {
			t.Fatal("PullOnce() = nil, want an error")
		}
	}
	if got := rejections(); got != 1 {
		t.Fatalf("log lines after two rejections inside one window = %d, want 1", got)
	}
	if got := p.Stats().Rejections; got != 2 {
		t.Fatalf("Stats().Rejections = %d, want 2; the counter must move on every rejection even when "+
			"the log line is throttled", got)
	}

	// Past the window: the next rejection logs again.
	now = now.Add(time.Minute*agent.RejectLogWindowFactorForTest + time.Second)
	if err := p.PullOnce(context.Background()); err == nil {
		t.Fatal("PullOnce() = nil, want an error")
	}
	if got := rejections(); got != 2 {
		t.Fatalf("log lines after the throttle window elapsed = %d, want 2", got)
	}
}

// --- a bundle that degrades pre-arm without tearing the daemon down -------

// applyBundlePolicy's post-arm pre-arm recheck can find a bundle that arms
// clean but should not have been trusted operationally — here, a policy with
// no operators at all, which OperatorKeys (a per-policy check) refuses.
// The daemon must still be running the fetched policy afterward (arming
// already went through confirm-or-revert; an operator who does not confirm
// is what rolls it back, not this check) and must be standing red, not torn
// down: a hub-driven pre-arm failure returning an error from applyBundlePolicy
// would only ever reach the pull loop, and the pull loop tearing down the
// packet loop is exactly the failure this task exists to rule out.
func TestAgent_Puller_ABundleThatDegradesPreArmStandsRatherThanTearsDown(t *testing.T) {
	srv, set := newBundleServer(t)
	tx := newTxnHarness(t)
	hubSigner, err := identity.Generate("hub")
	if err != nil {
		t.Fatalf("generate hub signer: %v", err)
	}
	var fleetID [16]byte
	if _, err := rand.Read(fleetID[:]); err != nil {
		t.Fatalf("rand fleet_id: %v", err)
	}

	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision
		o.Policy.FleetID = fleetID

		checks := passingChecks(map[string]bool{sshName: true})
		checks.OperatorKeys = func(p *config.Policy) error {
			if len(p.Operators) == 0 {
				return errors.New("no operator key is loaded")
			}
			return nil
		}
		o.Checks = checks

		o.Pull = &agent.PullConfig{
			StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
			HubURL:         srv.URL,
			FleetID:        fleetID,
			HostID:         o.Policy.HostID,
			Interval:       time.Hour,
			Timeout:        2 * time.Second,
			HostSigner:     o.Host,
			TrustedSigners: [][32]byte{hubSigner.Public().Signing},
		}
	})

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	p.Operators = nil // the check above refuses this, post-arm
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	c := &bundle.Contents{
		FleetID:  fleetID,
		HostID:   h.policy.HostID,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   data,
	}
	sealed, err := bundle.Seal(c, hubSigner, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	// Served BEFORE Run starts, and picked up by the puller's own automatic
	// first pull rather than an explicit PullOnce call from the test: with
	// Run active, its background goroutine calls PullOnce on its own the
	// instant it starts, and a second, explicit call from here would race it
	// on the same *Puller — a real hazard this rewrite avoids rather than
	// merely tolerates. waitFor below is the synchronisation point.
	set(sealed)
	h.start(t)

	// applyBundlePolicy calls setPolicy, then RunPreArm, then flagStanding, and
	// only after it returns does PullOnce (its caller, on the same goroutine)
	// count the apply in Stats(). Each of those is independently observable,
	// and the assertions below depend on all of them, so the wait has to name
	// all of them: waiting on the policy revision alone is waiting on the
	// first of the four, true the instant setPolicy returns and before
	// RunPreArm has even started; waiting on Health alone would still leave
	// Stats().Applied to catch up, since that is set one step later still, in
	// the caller, after applyBundlePolicy has already returned. Under load
	// this goroutine can and does read one of these before the others have
	// happened.
	waitFor(t, "pre-arm to flag the daemon standing and the puller to record the apply", func() bool {
		health := h.daemon.Health()
		return health.Red && strings.Contains(health.Reason, "pre-arm failed after a bundle update") &&
			h.daemon.Policy().Revision == version &&
			h.daemon.Puller().Stats().Applied == 1
	})

	health := h.daemon.Health()
	if !health.Red || !strings.Contains(health.Reason, "pre-arm failed after a bundle update") {
		t.Fatalf("Health() = %+v, want red naming a bundle-update pre-arm failure", health)
	}
	if got := h.daemon.Policy().Revision; got != version {
		t.Fatalf("Policy().Revision = %d, want %d: the daemon must still be running the fetched "+
			"policy, since arming already went through confirm-or-revert and this check is what "+
			"stands it, not what rolls it back", got, version)
	}
	if got := h.daemon.Puller().Stats().Applied; got != 1 {
		t.Fatalf("Stats().Applied = %d, want 1: arming succeeded, degrading pre-arm afterward is a "+
			"stand, not a rejection", got)
	}
	select {
	case <-h.done:
		t.Fatal("Run returned after a bundle degraded pre-arm; a bad bundle must never take the packet loop down")
	default:
	}
}

// armAndInert starts a daemon whose next pulled bundle arms cleanly and then
// fails a global pre-arm precondition, leaving the agent inert-but-standing:
// the running policy is the fetched one, but ServiceEnabled returns false for
// every service, so the knock path refuses them all. The global failure is the
// always-allow interface: the bundle names one the check rejects (a plain
// error, not ErrAlwaysAllowDegraded, so it is inert not merely a warning),
// while the enrolled policy names one it accepts, so a revert to the enrolled
// policy is healthy again. Operators are left intact in the fetched policy, so
// a knock still validates and the only thing refusing it is inert.
//
// clock, when non-nil, drives the daemon and the transaction manager together,
// so a caller can advance past the confirmation window and force the dead-man
// revert. It returns after the puller has applied the bundle and pre-arm has
// flagged the daemon standing, and reports the version it armed.
func armAndInert(t *testing.T, clock *testClock, window time.Duration, tune func(*agent.Options)) (*daemonHarness, *txnHarness, uint64) {
	t.Helper()
	const inertIface = "gone0"

	srv, set := newBundleServer(t)
	tx := newTxnHarness(t)
	hubSigner, err := identity.Generate("hub")
	if err != nil {
		t.Fatalf("generate hub signer: %v", err)
	}
	var fleetID [16]byte
	if _, err := rand.Read(fleetID[:]); err != nil {
		t.Fatalf("rand fleet_id: %v", err)
	}

	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		o.Policy.Revision = txnHarnessRecordedRevision
		o.Policy.FleetID = fleetID
		o.ConfirmWindow = window
		if clock != nil {
			o.Now = clock.Now
			tx.txns.Now = clock.Now
		}

		checks := passingChecks(map[string]bool{sshName: true})
		// A global precondition that depends on policy content: the enrolled
		// interface resolves, the bundle's does not. This is what makes the
		// fetched policy inert and the reverted-to enrolled policy healthy.
		checks.AlwaysAllow = func(p *config.Policy) error {
			if p.AlwaysAllowIface == inertIface {
				return errors.New("always-allow interface not found")
			}
			return nil
		}
		o.Checks = checks

		o.Pull = &agent.PullConfig{
			StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
			HubURL:         srv.URL,
			FleetID:        fleetID,
			HostID:         o.Policy.HostID,
			Interval:       time.Hour,
			Timeout:        2 * time.Second,
			HostSigner:     o.Host,
			TrustedSigners: [][32]byte{hubSigner.Public().Signing},
		}
		if tune != nil {
			tune(o)
		}
	})

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = inertIface // the global-inert trigger; operators left intact
	p.RecoveryService = sshName
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	c := &bundle.Contents{
		FleetID:  fleetID,
		HostID:   h.policy.HostID,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   data,
	}
	sealed, err := bundle.Seal(c, hubSigner, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	set(sealed)
	h.start(t)

	waitFor(t, "pre-arm to flag the daemon standing and the puller to record the apply", func() bool {
		health := h.daemon.Health()
		return health.Red && strings.Contains(health.Reason, "pre-arm failed after a bundle update") &&
			h.daemon.Policy().Revision == version &&
			h.daemon.Puller().Stats().Applied == 1
	})
	return h, tx, version
}

// #51, the metric half. A bundle that arms and then fails a GLOBAL pre-arm
// precondition leaves the agent inert: ServiceEnabled returns false for every
// service and the knock path refuses them all. recordPreArm read only the
// per-service Disabled map, which a global failure never populates, so
// postern_gate_service_armed reported 1 for a service the agent was refusing.
// An operator reading that gauge would see "ssh is fine" while every knock
// bounced. It now follows ServiceEnabled, the function the gate decision uses.
func TestAgent_Puller_AnInertBundleReportsEveryServiceUnarmed(t *testing.T) {
	h, _, _ := armAndInert(t, nil, 0, func(o *agent.Options) {
		o.MetricsListen = "127.0.0.1:0"
	})
	wantScraped(t, h, "postern_agent_inert 1")
	wantScraped(t, h, `postern_gate_service_armed{service="ssh"} 0`)
}

// #51, the recovery half. The dead-man revert must restore the pre-arm verdict,
// not just the ruleset and policy. Pre-arm is derived state over the live
// ruleset and policy; a bundle apply that went inert set d.prearm inert, and
// the revert rolled policy and ruleset back to the last good revision but left
// d.prearm inert, so ServiceEnabled kept refusing every knock for the life of
// the process, on a host the rollback had otherwise made healthy again. After
// the revert re-derives pre-arm, a knock opens the gate.
func TestAgent_Puller_AnInertBundleRevertRestoresTheGateForTheNextKnock(t *testing.T) {
	clock := &testClock{at: time.Now()}
	h, _, _ := armAndInert(t, clock, 5*time.Minute, nil)

	// While inert, the knock path refuses every service: a valid ssh knock
	// validates but opens nothing, because apply consults prearmed().
	h.now = clock.Now()
	h.send(t, h.seal(h.gateRequest()), false)
	h.awaitProcessed(t, 1)
	if opens := len(h.gate.openCalls()); opens != 0 {
		t.Fatalf("an inert agent opened the gate %d times; it must refuse every service", opens)
	}

	// The confirmation window elapses with no confirm; the dead-man reverts the
	// bundle to the enrolled revision, whose always-allow interface resolves and
	// so passes pre-arm.
	clock.advance(6 * time.Minute)
	h.tick(t, true)
	waitFor(t, "the dead-man to revert the bundle to the enrolled revision", func() bool {
		return h.daemon.Policy().Revision == txnHarnessRecordedRevision
	})

	// The restored host is healthy: a knock now opens the gate. Before the fix
	// the revert left d.prearm inert and this knock opened nothing.
	h.now = clock.Now()
	h.send(t, h.seal(h.gateRequest()), false)
	h.awaitProcessed(t, 2)
	waitFor(t, "the restored gate to open for a knock", func() bool {
		return len(h.gate.openCalls()) == 1
	})
}

// --- anti-rollback across a restart --------------------------------------

// A host that has applied version 48 must refuse a validly-signed version 47
// after a restart, and before this the only durable guard was
// EnrollmentFloor: it is stamped once at enrollment and never advances, and
// Transactions.Commit deletes pending.json, so a confirmed revision left
// nothing behind to block a lower one. Demonstrated on a real host: recorded
// revision 48, floor 47, freshly started, offered a validly-signed
// version-47 bundle — PullOnce returned nil and the policy became 47.
//
// The threat is not hypothetical from the wire's point of view either.
// hub_url may be http://, so anyone who can serve /bundle/<host_id> replays a
// historical bundle and waits for a reboot; AcceptCriteria's own doc names
// what that costs, an old but validly-signed bundle still naming a
// since-removed operator.
//
// The restart is real: the second Puller is a fresh object over the same
// StatePath, exactly as a fresh process would open it.
//
// Mutation verified: dropping the readAppliedVersion seed from NewPuller (so
// version/haveVersion start at zero) makes the second Puller apply the
// version-47 bundle, and this fails on the applied count.
func TestAgent_Puller_ARestartStillRefusesAnOlderBundle(t *testing.T) {
	srv, set := newBundleServer(t)
	f, fleetID, sealFor := newVersionedBundleFixture(t)

	statePath := filepath.Join(t.TempDir(), "bundle.json")
	hubSigner, err := identity.Generate("hub")
	if err != nil {
		t.Fatalf("generate hub signer: %v", err)
	}
	cfg := agent.PullConfig{
		HubURL:          srv.URL,
		FleetID:         fleetID,
		HostID:          f.policy.HostID,
		Interval:        time.Hour, // this test drives PullOnce directly
		HostSigner:      f.host,
		TrustedSigners:  [][32]byte{hubSigner.Public().Signing},
		EnrollmentFloor: 47,
		StatePath:       statePath,
	}
	applied := 0
	apply := func(*config.Policy) (bool, error) { applied++; return true, nil }

	p1, err := agent.NewPuller(cfg, apply)
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	set(sealFor(t, hubSigner, 48))
	if err := p1.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce for version 48: %v", err)
	}
	if applied != 1 {
		t.Fatalf("applies after version 48 = %d, want 1", applied)
	}

	// The restart. A fresh Puller over the same state path, the way a fresh
	// process opens it.
	p2, err := agent.NewPuller(cfg, apply)
	if err != nil {
		t.Fatalf("NewPuller after restart: %v", err)
	}
	set(sealFor(t, hubSigner, 47))
	err = p2.PullOnce(context.Background())
	if err == nil {
		t.Fatal("a freshly restarted host applied a validly-signed version-47 bundle over the 48 it " +
			"was already running; anyone who can serve /bundle/<host_id> replays a historical bundle " +
			"and waits for a reboot")
	}
	if !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("PullOnce for version 47 after a restart failed with %v, want the not-newer refusal; "+
			"some other control rejected this and the anti-rollback guard is untested", err)
	}
	if applied != 1 {
		t.Fatalf("applies after the replayed version 47 = %d, want still 1", applied)
	}

	// And the guard is an ordering, not a blanket refusal: 49 still applies
	// afterwards, so this is not passing because the restarted Puller rejects
	// everything.
	set(sealFor(t, hubSigner, 49))
	if err := p2.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce for version 49 after the restart: %v", err)
	}
	if applied != 2 {
		t.Fatalf("applies after version 49 = %d, want 2", applied)
	}
}

// A recorded-version file that exists and cannot be read is not the same as
// one that is absent, and it must not be treated as one: absent means "this
// host has applied nothing", which is exactly the state that makes every
// older bundle acceptable. The Puller refuses to fetch at all until it can
// read its own guard — the control plane declining to act, which costs
// nothing the packet plane needs.
//
// NewPuller itself must still succeed, for C1's reason: it is called from
// agent.New, and a control-plane file that stops the daemon being built is a
// host that never binds its SPA port.
//
// Mutation verified: swallowing the read error in NewPuller (treating a
// corrupt file as absent) lets the version-47 bundle through and fails this
// on the applied count.
func TestAgent_Puller_AnUnreadableVersionRecordStopsPullingRatherThanForgetting(t *testing.T) {
	srv, set := newBundleServer(t)
	f, fleetID, sealFor := newVersionedBundleFixture(t)
	hubSigner, err := identity.Generate("hub")
	if err != nil {
		t.Fatalf("generate hub signer: %v", err)
	}

	statePath := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(statePath, []byte("{ not json at all"), 0o600); err != nil {
		t.Fatalf("stage a corrupt version record: %v", err)
	}

	applied := 0
	p, err := agent.NewPuller(agent.PullConfig{
		HubURL:         srv.URL,
		FleetID:        fleetID,
		HostID:         f.policy.HostID,
		Interval:       time.Hour,
		HostSigner:     f.host,
		TrustedSigners: [][32]byte{hubSigner.Public().Signing},
		StatePath:      statePath,
	}, func(*config.Policy) (bool, error) { applied++; return true, nil })
	if err != nil {
		t.Fatalf("NewPuller must not fail over an unreadable version record; a control-plane file "+
			"cannot be allowed to stop posternd starting: %v", err)
	}

	set(sealFor(t, hubSigner, 47))
	if err := p.PullOnce(context.Background()); err == nil {
		t.Fatal("a Puller that cannot read its own anti-rollback record applied a bundle anyway")
	}
	if applied != 0 {
		t.Fatalf("applies = %d, want 0", applied)
	}
	if got := p.Stats().Rejections; got != 1 {
		t.Fatalf("Stats().Rejections = %d, want 1", got)
	}
}

// newVersionedBundleFixture returns a host fixture, the fleet it belongs to,
// and a sealer that produces a bundle at any version carrying a policy that
// really parses and validates — so the version ordering is the only thing
// that can decide whether a bundle is accepted.
func newVersionedBundleFixture(t *testing.T) (*fixture, [16]byte, func(*testing.T, identity.Signer, uint64) []byte) {
	t.Helper()
	f := newFixture(t)
	f.policy.SPAPort = 62201
	f.policy.AlwaysAllowIface = "tailscale0"
	f.policy.RecoveryService = sshName
	var fleetID [16]byte
	if _, err := rand.Read(fleetID[:]); err != nil {
		t.Fatalf("rand fleet_id: %v", err)
	}
	f.policy.FleetID = fleetID

	seal := func(t *testing.T, signer identity.Signer, version uint64) []byte {
		t.Helper()
		p := *f.policy
		p.Revision = version
		data, err := config.MarshalStandalone(&p)
		if err != nil {
			t.Fatalf("MarshalStandalone: %v", err)
		}
		sealed, err := bundle.Seal(&bundle.Contents{
			FleetID:  fleetID,
			HostID:   f.policy.HostID,
			Version:  version,
			IssuedAt: time.Now(),
			Policy:   data,
		}, signer, f.host.Public().Encryption)
		if err != nil {
			t.Fatalf("bundle.Seal: %v", err)
		}
		return sealed
	}
	return f, fleetID, seal
}

// --- a refused arm is not an apply ---------------------------------------

// The journal showed these two lines one after the other on a real host:
//
//	level=ERROR msg="refusing to re-arm" revision=42 outcome=pending
//	level=INFO  msg="applied a fetched bundle" version=42
//
// applyBundlePolicy returned nil when armRevision refused, and the puller
// read that as success: it counted the apply, incremented
// postern_bundle_pull_applied_total, logged the convergence, and advanced its
// own notion of the current version past a revision that was never installed.
// The metric and the journal reported convergence that did not happen, during
// exactly the incident an operator reads them in.
//
// The second half is the cost of the advanced version: a corrected bundle
// re-issued at the same version would be refused as not_newer, so the fix for
// the bad deploy could not be delivered at all. That is what the last third
// of this test drives.
//
// Mutation verified: having applyBundlePolicy return (true, nil) on the
// !armed branch fails this on the applied count and on the recorded revision.
func TestAgent_Puller_ARefusedArmIsNotCountedOrLoggedAsAnApply(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)

	const version = txnHarnessRecordedRevision + 1
	// A published record naming this same revision, already reverted: the
	// state armRevision refuses to re-arm from, and the one a host lands in
	// after a bundle it never confirmed rolled itself back.
	writeFile(t, h.txn.paths.Pending,
		`{"revision":42,"deployment_nonce":"00000000000000000000000000000000","outcome":"reverted"}`)

	set(h.sealValid(t, version, nil))
	h.start(t)

	p := h.daemon.Puller()
	waitFor(t, "the pull that meets the refusing arm step", func() bool {
		return p.Stats().Attempts >= 1 && p.Stats().Rejections >= 1
	})
	if got := p.Stats().Applied; got != 0 {
		t.Fatalf("Stats().Applied = %d, want 0: the arm step refused this revision, and counting it "+
			"as an apply is a false all-clear in the metric an operator reads during the incident", got)
	}
	if got := h.daemon.Policy().Revision; got != txnHarnessRecordedRevision {
		t.Fatalf("running policy is revision %d, want %d: a refused arm must leave the last good "+
			"policy exactly where it was", got, txnHarnessRecordedRevision)
	}

	// And the version was not advanced. The operator clears the stale pending
	// record — the way out the refusal's own message names — and the SAME
	// version must then be installable, because it never was installed.
	if err := os.Remove(h.txn.paths.Pending); err != nil {
		t.Fatalf("clear the pending record: %v", err)
	}
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatalf("re-pulling version %d after clearing the stale pending record: %v; a refused arm "+
			"that advanced the puller's version makes a corrected bundle at the same version "+
			"undeliverable", version, err)
	}
	if got := p.Stats().Applied; got != 1 {
		t.Fatalf("Stats().Applied = %d after the arm actually succeeded, want 1", got)
	}
	if got := h.daemon.Policy().Revision; got != version {
		t.Fatalf("running policy is revision %d after a real arm, want %d", got, version)
	}
}

// --- the policy body's own identity --------------------------------------

// bundle.Open checks the RECORD HEADER's fleet_id and host_id. The policy
// body carries its own pair, under the same signature and in different
// fields, and nothing checked those — so a record correctly addressed to this
// host could carry another host's policy: its gates, its ports, its operator
// set, installed here. That is a signer mistake rather than an attack, since
// forging either half needs the signing key, and it is precisely the kind of
// mistake a compile step makes once and a fleet inherits everywhere.
//
// Isolated by construction. The record header names THIS host and this fleet
// correctly, so bundle.Open passes every check it has, and the policy body is
// the only thing left that can reject this input.
//
// Mutation verified: removing either check applies the mismatched policy and
// fails this row on the applied count.
func TestAgent_Puller_RejectsAPolicyBodyNamingAnotherHostOrFleet(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mangle     func(*config.Policy)
		wantReason string
	}{
		{"another host's policy", func(p *config.Policy) { p.HostID = [16]byte{0x99} }, "policy names host_id"},
		{"another fleet's policy", func(p *config.Policy) { p.FleetID = [16]byte{0x99} }, "policy names fleet_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, set := newBundleServer(t)
			f, fleetID, _ := newVersionedBundleFixture(t)
			hubSigner, err := identity.Generate("hub")
			if err != nil {
				t.Fatalf("generate hub signer: %v", err)
			}

			// The body, mangled. The header below still names this host and
			// this fleet correctly.
			body := *f.policy
			body.Revision = 48
			tc.mangle(&body)
			data, err := config.MarshalStandalone(&body)
			if err != nil {
				t.Fatalf("MarshalStandalone: %v", err)
			}
			sealed, err := bundle.Seal(&bundle.Contents{
				FleetID:  fleetID,
				HostID:   f.policy.HostID,
				Version:  48,
				IssuedAt: time.Now(),
				Policy:   data,
			}, hubSigner, f.host.Public().Encryption)
			if err != nil {
				t.Fatalf("bundle.Seal: %v", err)
			}
			set(sealed)

			applied := 0
			p, err := agent.NewPuller(agent.PullConfig{
				HubURL:         srv.URL,
				FleetID:        fleetID,
				HostID:         f.policy.HostID,
				Interval:       time.Hour,
				HostSigner:     f.host,
				TrustedSigners: [][32]byte{hubSigner.Public().Signing},
				StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
			}, func(*config.Policy) (bool, error) { applied++; return true, nil })
			if err != nil {
				t.Fatalf("NewPuller: %v", err)
			}

			err = p.PullOnce(context.Background())
			if err == nil {
				t.Fatal("a bundle addressed to this host, carrying another host's policy body, was " +
					"installed; its gates, ports and operator set are now this host's")
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("PullOnce() = %v, want a refusal naming %q", err, tc.wantReason)
			}
			if applied != 0 {
				t.Fatalf("applies = %d, want 0", applied)
			}
		})
	}
}
