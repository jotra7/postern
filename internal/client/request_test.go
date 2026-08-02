package client_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

// Invariant 4. Version and alg are stamped by the constructor.
//
// The assertion is deliberately made twice, in two different currencies. The
// field check states the property directly; the round trip is what proves it
// matters — a Version = 0 record signs and seals without complaint and is
// rejected by the far side at spa.Parse's first branch, silently, with no
// reply, which is indistinguishable from a dead agent.
//
// Mutation verified: dropping `Version: spa.Version1` from Builder.base
// fails every row of this test, on both assertions.
func TestClient_Builder_StampsVersionAndAlgorithmOnEveryKind(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)
	b := client.Builder{Signer: op}

	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	build := map[string]func() (*spa.Request, error){
		"gate": func() (*spa.Request, error) {
			return b.Gate(h, "ssh", 120*time.Second, nil, 42, testNowMS)
		},
		"confirm": func() (*spa.Request, error) {
			return b.Confirm(h, 47, [16]byte{1, 2, 3}, testNowMS)
		},
		"disarm": func() (*spa.Request, error) {
			return b.Disarm(h, testNowMS)
		},
		"liveness": func() (*spa.Request, error) {
			req, _, err := b.Liveness(h, testNowMS)
			return req, err
		},
	}

	for name, mk := range build {
		t.Run(name, func(t *testing.T) {
			req, err := mk()
			if err != nil {
				t.Fatalf("build %s: %v", name, err)
			}
			if req.Version != spa.Version1 {
				t.Errorf("version = %d, want %d; the caller never sets this and a zero seals fine "+
					"and is dropped by the far side with no diagnostic", req.Version, spa.Version1)
			}
			if req.Alg != spa.AlgEd25519X25519 {
				t.Errorf("alg = %d, want %d", req.Alg, spa.AlgEd25519X25519)
			}

			datagram, err := b.Seal(req, h)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if _, _, err := opener.TrialOpen(datagram); err != nil {
				t.Fatalf("the far side rejected a constructed %s request: %v", name, err)
			}
		})
	}
}

// The negative half of invariant 4: prove the round trip above is capable of
// catching an unstamped record at all, by building one by hand the way a
// caller who bypassed the constructor would.
func TestClient_Builder_AnUnstampedRequestIsDroppedByTheFarSide(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	handmade := &spa.Request{ // Version and Alg left at their zero values.
		Kind:        spa.KindAction,
		KeyID:       op.Public().KeyID(),
		HostID:      h.HostID,
		ServiceID:   client.ServiceID("disarm"),
		TimestampMS: testNowMS,
	}
	datagram, err := spa.Seal(handmade, op, h.HostEncrypt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := opener.TrialOpen(datagram); !errors.Is(err, spa.ErrUnsupportedVersion) {
		t.Fatalf("TrialOpen on an unstamped record = %v, want ErrUnsupportedVersion; if this ever "+
			"stops being the failure mode, the round-trip assertion above stops proving anything", err)
	}
}

func TestClient_Builder_ActionsCarryNoCounterAndNoTTL(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)
	b := client.Builder{Signer: op}

	for _, tc := range []struct {
		name string
		mk   func() (*spa.Request, error)
	}{
		{"confirm", func() (*spa.Request, error) { return b.Confirm(h, 47, [16]byte{9}, testNowMS) }},
		{"disarm", func() (*spa.Request, error) { return b.Disarm(h, testNowMS) }},
		{"liveness", func() (*spa.Request, error) { r, _, e := b.Liveness(h, testNowMS); return r, e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := tc.mk()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			// A non-zero counter on an action raises the operator's high-water
			// mark and silently disables drift tolerance for their later gate
			// requests (design section 5).
			if req.Counter != 0 || req.TTLSeconds != 0 {
				t.Fatalf("action carries counter=%d ttl=%d, want both zero", req.Counter, req.TTLSeconds)
			}
			if _, err := spa.Parse(req.Marshal()); err != nil {
				t.Fatalf("Parse rejected a constructed action: %v", err)
			}
		})
	}
}

func TestClient_Builder_GateAssertsTheMaskedPrefix(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)
	b := client.Builder{Signer: op}

	// An operator typing their own address with a prefix length is the
	// common case, and its host bits have no canonical encoding.
	pfx := mustPrefix(t, "203.0.113.9/24")
	req, err := b.Gate(h, "ssh", time.Minute, &pfx, 1, testNowMS)
	if err != nil {
		t.Fatalf("Gate: %v", err)
	}
	payload, err := req.GatePayload()
	if err != nil {
		t.Fatalf("GatePayload: %v", err)
	}
	if payload.SourceKind != spa.SourceAsserted {
		t.Fatalf("source kind = %v, want asserted", payload.SourceKind)
	}
	if got := payload.Prefix.String(); got != "203.0.113.0/24" {
		t.Fatalf("asserted prefix = %s, want 203.0.113.0/24", got)
	}
}

func TestClient_Builder_RejectsATTLBeyondTheWireLimit(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)
	b := client.Builder{Signer: op}

	if _, err := b.Gate(h, "ssh", 100*time.Hour, nil, 1, testNowMS); err == nil {
		t.Fatal("a ttl above the uint16 wire limit was accepted; it would have silently wrapped")
	}
}

func TestClient_Builder_GateRequestNamesTheServiceItWasAskedFor(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)
	b := client.Builder{Signer: op}

	req, err := b.Gate(h, "canary", time.Minute, nil, 1, testNowMS)
	if err != nil {
		t.Fatalf("Gate: %v", err)
	}
	if req.ServiceID != client.ServiceID("canary") {
		t.Fatal("the request's service_id is not the one for canary")
	}
	if req.ServiceID == client.ServiceID("ssh") {
		t.Fatal("canary and ssh hashed to the same service_id")
	}
	if req.HostID != h.HostID {
		t.Fatal("the request does not carry the host's own host_id; a packet for one host would be " +
			"valid against another, which is the anti-relay control")
	}
}
