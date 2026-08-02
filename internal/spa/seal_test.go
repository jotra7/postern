package spa_test

import (
	"errors"
	"testing"

	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

type sealFixture struct {
	operator identity.Signer
	host     identity.Signer
	opener   *spa.Opener
}

func newSealFixture(t *testing.T) sealFixture {
	t.Helper()
	op, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate operator: %v", err)
	}
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate host: %v", err)
	}
	// The opener needs the host's private encryption key. Generate exposes it
	// only through Precompute, so build the opener from the host signer.
	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}
	return sealFixture{operator: op, host: host, opener: opener}
}

func TestSPA_SealTrialOpen_RoundTrips(t *testing.T) {
	f := newSealFixture(t)
	req := sampleGate()
	req.KeyID = f.operator.Public().KeyID()

	dg, err := spa.Seal(req, f.operator, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(dg) != spa.DatagramSize {
		t.Fatalf("datagram = %d bytes, want %d", len(dg), spa.DatagramSize)
	}

	got, who, err := f.opener.TrialOpen(dg)
	if err != nil {
		t.Fatalf("TrialOpen: %v", err)
	}
	if who.KeyID() != f.operator.Public().KeyID() {
		t.Fatal("TrialOpen identified the wrong operator")
	}
	if got.RequestID != req.RequestID {
		t.Fatal("round trip lost the request id")
	}
}

func TestSPA_TrialOpen_RejectsUnknownOperator(t *testing.T) {
	f := newSealFixture(t)
	stranger, err := identity.Generate("stranger")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := sampleGate()
	req.KeyID = stranger.Public().KeyID()

	dg, err := spa.Seal(req, stranger, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := f.opener.TrialOpen(dg); !errors.Is(err, spa.ErrNoOperator) {
		t.Fatalf("TrialOpen = %v, want ErrNoOperator", err)
	}
}

func TestSPA_TrialOpen_RejectsKeyIDInconsistentWithDecryptingKey(t *testing.T) {
	// The packet claims one operator while a different operator's shared
	// secret opened it. Catching this keeps audit attribution honest.
	f := newSealFixture(t)
	other, err := identity.Generate("other")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := sampleGate()
	req.KeyID = other.Public().KeyID() // lie about who sent it

	dg, err := spa.Seal(req, f.operator, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := f.opener.TrialOpen(dg); !errors.Is(err, spa.ErrKeyIDMismatch) {
		t.Fatalf("TrialOpen = %v, want ErrKeyIDMismatch", err)
	}
}

func TestSPA_TrialOpen_RejectsTamperedSignedRegion(t *testing.T) {
	f := newSealFixture(t)
	req := sampleGate()
	req.KeyID = f.operator.Public().KeyID()

	dg, err := spa.Seal(req, f.operator, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a ciphertext byte: Poly1305 must reject before anything else runs.
	dg[spa.NonceSize+10] ^= 0x01
	if _, _, err := f.opener.TrialOpen(dg); !errors.Is(err, spa.ErrNoOperator) {
		t.Fatalf("TrialOpen = %v, want ErrNoOperator for a corrupted datagram", err)
	}
}

func TestSPA_TrialOpen_RejectsLengthOutsideBounds(t *testing.T) {
	// Padding makes any length in [DatagramSize, MaxDatagram] legitimate, so
	// only a datagram shorter than the record or longer than MaxDatagram is
	// rejected on length. DatagramSize+1 is no longer wrong: it is a one-byte
	// padded datagram, and rejecting it here would break the relaxed contract.
	f := newSealFixture(t)
	for _, n := range []int{0, spa.DatagramSize - 1, spa.MaxDatagram + 1} {
		if _, _, err := f.opener.TrialOpen(make([]byte, n)); !errors.Is(err, spa.ErrWrongSize) {
			t.Errorf("TrialOpen(%d bytes) = %v, want ErrWrongSize", n, err)
		}
	}
}

func TestSPA_TrialOpen_AcceptsPaddedDatagram(t *testing.T) {
	// A padded datagram of several lengths opens to the byte-identical Request
	// that the unpadded record opens to. The padding is appended directly here
	// rather than drawn by Pad, so the boundary lengths (exactly the record,
	// mid-range, and MaxDatagram) are exercised deterministically.
	f := newSealFixture(t)
	req := sampleGate()
	req.KeyID = f.operator.Public().KeyID()

	dg, err := spa.Seal(req, f.operator, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	want, _, err := f.opener.TrialOpen(dg)
	if err != nil {
		t.Fatalf("TrialOpen unpadded: %v", err)
	}

	for _, total := range []int{spa.DatagramSize, spa.DatagramSize + 137, spa.MaxDatagram} {
		padded := make([]byte, total)
		copy(padded, dg)
		got, who, err := f.opener.TrialOpen(padded)
		if err != nil {
			t.Fatalf("TrialOpen(%d bytes): %v", total, err)
		}
		if who.KeyID() != f.operator.Public().KeyID() {
			t.Errorf("TrialOpen(%d bytes) identified the wrong operator", total)
		}
		if got.RequestID != want.RequestID || got.KeyID != want.KeyID {
			t.Errorf("TrialOpen(%d bytes) parsed a different request than the unpadded datagram", total)
		}
	}
}

// TestSPA_TrialOpen_RejectsBadSignature constructs a datagram whose
// encryption is entirely valid (correct nonce, correct shared secret,
// correct AEAD tag) but whose signature was corrupted after signing. That
// is the only way to isolate step 5 (signature verification) from steps 2-4
// (trial decrypt, parse, key_id match): every one of those must succeed
// first, or this test would pass for the wrong reason — see the sibling
// tests above for what tamper-before-encryption (ErrNoOperator) and
// wrong-claimed-operator (ErrKeyIDMismatch) look like instead.
func TestSPA_TrialOpen_RejectsBadSignature(t *testing.T) {
	f := newSealFixture(t)
	req := sampleGate()
	req.KeyID = f.operator.Public().KeyID()

	// Sign normally, exactly as Seal would, then corrupt the signature and
	// encrypt the tampered record directly, bypassing Seal's own signing
	// step. This produces a datagram that decrypts, parses, and key_id-
	// matches cleanly, and fails only ed25519.Verify.
	sig, err := f.operator.Sign(req.SigningInput())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	copy(req.Signature[:], sig)
	req.Signature[0] ^= 0xff

	dg, err := spa.SealPresigned(req, f.operator, f.host.Public().Encryption)
	if err != nil {
		t.Fatalf("SealPresigned: %v", err)
	}
	if _, _, err := f.opener.TrialOpen(dg); !errors.Is(err, spa.ErrBadSignature) {
		t.Fatalf("TrialOpen = %v, want ErrBadSignature", err)
	}
}

// TestSPA_NewOpenerFromSigner_SkipsRejectedOperatorButReportsIt is the
// partial-failure case the brief's semantics section calls out: one
// operator with a low-order encryption key (all-zero, which X25519 refuses
// as input) must not prevent the Opener from serving every other trusted
// operator, and the rejection must be visible in the returned rejected slice
// rather than silently dropped — and, critically, must NOT surface as a
// non-nil error, which would be indistinguishable from total failure to a
// caller checking only err.
func TestSPA_NewOpenerFromSigner_SkipsRejectedOperatorButReportsIt(t *testing.T) {
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate host: %v", err)
	}
	good, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate good: %v", err)
	}
	bad := good.Public()
	bad.Name = "bricked-yubikey"
	bad.Encryption = [32]byte{} // the identity point: a known low-order key

	opener, rejected, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{good.Public(), bad})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner error = %v, want nil: partial success must not report as an error", err)
	}
	if len(rejected) != 1 || rejected[0] != "bricked-yubikey" {
		t.Fatalf("NewOpenerFromSigner rejected = %v, want exactly [bricked-yubikey]", rejected)
	}
	if opener == nil {
		t.Fatal("NewOpenerFromSigner = nil Opener, want a usable Opener for the surviving operator")
	}

	req := sampleGate()
	req.KeyID = good.Public().KeyID()
	dg, err := spa.Seal(req, good, host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, who, err := opener.TrialOpen(dg); err != nil || who.KeyID() != good.Public().KeyID() {
		t.Fatalf("TrialOpen with surviving operator = (_, %v, %v), want (_, good, nil)", who, err)
	}
}

// TestSPA_NewOpenerFromSigner_FailsWhenNoOperatorIsUsable covers the other
// half of the semantics: if every operator's key is rejected, there is
// nothing to trial-decrypt against, so a nil Opener and a non-nil error are
// correct — this is the one case where the universal Go idiom's
// "if err != nil { return err }" should in fact refuse to start.
func TestSPA_NewOpenerFromSigner_FailsWhenNoOperatorIsUsable(t *testing.T) {
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate host: %v", err)
	}
	other, err := identity.Generate("placeholder")
	if err != nil {
		t.Fatalf("Generate placeholder: %v", err)
	}
	bad := other.Public()
	bad.Encryption = [32]byte{}

	opener, rejected, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{bad})
	if err == nil {
		t.Fatal("NewOpenerFromSigner = nil error, want an error when no operator is usable")
	}
	if opener != nil {
		t.Fatal("NewOpenerFromSigner returned a non-nil Opener with zero usable operators")
	}
	if len(rejected) != 1 || rejected[0] != "placeholder" {
		t.Fatalf("NewOpenerFromSigner rejected = %v, want exactly [placeholder]", rejected)
	}
}

// TestSPA_NewOpenerFromSigner_PhaseBIdiomSurvivesOnePartialRejection is the
// case that motivated splitting rejected out of err: a Phase B author
// writing the universal Go idiom
//
//	opener, err := spa.NewOpenerFromSigner(host, ops)
//	if err != nil { return err }
//
// must get a usable, started agent when only some operators in the bundle
// have a bad key — the opposite of the availability failure a combined
// (*Opener, error) return produced, where this exact idiom refused to start
// on any single bad key in the bundle.
func TestSPA_NewOpenerFromSigner_PhaseBIdiomSurvivesOnePartialRejection(t *testing.T) {
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate host: %v", err)
	}
	good, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate good: %v", err)
	}
	bad := good.Public()
	bad.Name = "bricked-yubikey"
	bad.Encryption = [32]byte{}

	run := func(host identity.Signer, ops []identity.PublicIdentity) (*spa.Opener, error) {
		// This is exactly the idiom a Phase B caller would write: discard the
		// rejected slice entirely and act on err alone.
		opener, _, err := spa.NewOpenerFromSigner(host, ops)
		if err != nil {
			return nil, err
		}
		return opener, nil
	}

	opener, err := run(host, []identity.PublicIdentity{good.Public(), bad})
	if err != nil {
		t.Fatalf("idiom returned err = %v, want nil: one rejected operator must not block startup", err)
	}
	if opener == nil {
		t.Fatal("idiom returned a nil Opener despite a nil error")
	}

	req := sampleGate()
	req.KeyID = good.Public().KeyID()
	dg, err := spa.Seal(req, good, host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, who, err := opener.TrialOpen(dg); err != nil || who.KeyID() != good.Public().KeyID() {
		t.Fatalf("TrialOpen via idiom-built opener = (_, %v, %v), want (_, good, nil)", who, err)
	}
}
