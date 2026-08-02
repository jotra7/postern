package identity

// This file is package identity (not identity_test), deliberately: proving
// Precompute's output is byte-for-byte what box.Precompute produces, and
// that it's genuinely interoperable with the box API in both directions,
// requires the raw private scalars that Signer intentionally has no public
// accessor for. Reaching into memorySigner's unexported fields here is a
// white-box test of an internal property, not a new public API surface —
// nothing exported changes because of this file.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// TestIdentity_Precompute_MatchesBoxPrecomputeByteForByte is the
// byte-equivalence check: across many random keypairs, Precompute's output
// must be identical to calling box.Precompute directly with the same raw
// keys. This is what makes "validate with X25519, derive with box.Precompute"
// (see Precompute's doc comment) actually correct rather than merely
// plausible.
func TestIdentity_Precompute_MatchesBoxPrecomputeByteForByte(t *testing.T) {
	const trials = 200
	for i := 0; i < trials; i++ {
		a, err := Generate("a")
		if err != nil {
			t.Fatalf("trial %d: Generate a: %v", i, err)
		}
		b, err := Generate("b")
		if err != nil {
			t.Fatalf("trial %d: Generate b: %v", i, err)
		}
		am := a.(*memorySigner)
		bm := b.(*memorySigner)

		got, err := a.Precompute(bm.pub.Encryption)
		if err != nil {
			t.Fatalf("trial %d: Precompute: %v", i, err)
		}

		var want [32]byte
		peerPub := bm.pub.Encryption
		box.Precompute(&want, &peerPub, &am.encrypt)

		if *got != want {
			t.Fatalf("trial %d: Precompute = %x, want box.Precompute = %x", i, *got, want)
		}
	}
}

// TestIdentity_Precompute_CrossesBoxAPIBoundary is the fix for a defect that
// appeared three times in this project: a "compatibility" test where both
// sides of the assertion come from the same derivation, so it proves only
// self-consistency and would pass even if that derivation were wrong. Here,
// one side of each check is genuinely the box package's own internals
// (box.Seal / box.Open, which compute their own precomputed key internally
// from raw private/public keys), and the other side is Precompute's output,
// crossed in both directions.
func TestIdentity_Precompute_CrossesBoxAPIBoundary(t *testing.T) {
	opSigner, err := Generate("operator")
	if err != nil {
		t.Fatalf("Generate operator: %v", err)
	}
	hostSigner, err := Generate("host")
	if err != nil {
		t.Fatalf("Generate host: %v", err)
	}
	op := opSigner.(*memorySigner)
	host := hostSigner.(*memorySigner)

	opPub := op.pub.Encryption
	opPriv := op.encrypt
	hostPub := host.pub.Encryption
	hostPriv := host.encrypt

	opsOwnKey, err := opSigner.Precompute(hostPub)
	if err != nil {
		t.Fatalf("opSigner.Precompute: %v", err)
	}
	hostsOwnKey, err := hostSigner.Precompute(opPub)
	if err != nil {
		t.Fatalf("hostSigner.Precompute: %v", err)
	}

	msg := []byte("cross-boundary check")

	// Direction 1: the library seals (box.Seal computes its own precomputed
	// key internally from opPriv and hostPub), our derivation opens.
	var nonce1 [24]byte
	if _, err := rand.Read(nonce1[:]); err != nil {
		t.Fatalf("read nonce1: %v", err)
	}
	sealedByLibrary := box.Seal(nil, msg, &nonce1, &hostPub, &opPriv)
	openedByOurs, ok := box.OpenAfterPrecomputation(nil, sealedByLibrary, &nonce1, hostsOwnKey)
	if !ok {
		t.Fatal("our Precompute key could not open a message box.Seal produced")
	}
	if !bytes.Equal(openedByOurs, msg) {
		t.Fatalf("opened = %q, want %q", openedByOurs, msg)
	}

	// Direction 2: our derivation seals, the library opens (box.Open computes
	// its own precomputed key internally from hostPriv and opPub).
	var nonce2 [24]byte
	if _, err := rand.Read(nonce2[:]); err != nil {
		t.Fatalf("read nonce2: %v", err)
	}
	sealedByOurs := box.SealAfterPrecomputation(nil, msg, &nonce2, opsOwnKey)
	openedByLibrary, ok := box.Open(nil, sealedByOurs, &nonce2, &opPub, &hostPriv)
	if !ok {
		t.Fatal("box.Open could not open a message sealed with our Precompute key")
	}
	if !bytes.Equal(openedByLibrary, msg) {
		t.Fatalf("opened = %q, want %q", openedByLibrary, msg)
	}
}
