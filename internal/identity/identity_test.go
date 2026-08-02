package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/identity"
)

func TestIdentity_KeyID_IsFirst16OfSHA256OfSigningKey(t *testing.T) {
	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub := s.Public()

	sum := sha256.Sum256(pub.Signing[:])
	var want [16]byte
	copy(want[:], sum[:16])

	if got := pub.KeyID(); got != want {
		t.Fatalf("KeyID() = %x, want %x", got, want)
	}
}

func TestIdentity_Sign_ProducesVerifiableEd25519Signature(t *testing.T) {
	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	msg := []byte("the signed region of an spa request")

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	pub := s.Public()
	if !ed25519.Verify(pub.Signing[:], msg, sig) {
		t.Fatal("signature did not verify against the public signing key")
	}
	if ed25519.Verify(pub.Signing[:], []byte("different message"), sig) {
		t.Fatal("signature verified against the wrong message")
	}
}

func TestIdentity_Precompute_IsSymmetricBetweenPeers(t *testing.T) {
	// The agent precomputes one shared secret per trusted operator at startup
	// and trials them (design section 5). That only works if both sides derive
	// the same secret.
	a, err := identity.Generate("operator")
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	b, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}
	c, err := identity.Generate("third")
	if err != nil {
		t.Fatalf("Generate c: %v", err)
	}

	fromA, err := a.Precompute(b.Public().Encryption)
	if err != nil {
		t.Fatalf("a.Precompute: %v", err)
	}
	fromB, err := b.Precompute(a.Public().Encryption)
	if err != nil {
		t.Fatalf("b.Precompute: %v", err)
	}

	if !bytes.Equal(fromA[:], fromB[:]) {
		t.Fatal("precomputed shared secrets differ between peers")
	}

	// Symmetry alone doesn't prove the secret is actually bound to the peer:
	// a Precompute that always returns the same constant (or that only
	// depends on the caller's own key) would satisfy the check above while
	// being useless as a shared secret. Confirm the result actually depends
	// on which peer key was supplied, and that it isn't a trivial zero value.
	fromAWithC, err := a.Precompute(c.Public().Encryption)
	if err != nil {
		t.Fatalf("a.Precompute(c): %v", err)
	}
	if bytes.Equal(fromA[:], fromAWithC[:]) {
		t.Fatal("precomputed shared secret did not change when the peer did")
	}

	var zero [32]byte
	if bytes.Equal(fromA[:], zero[:]) {
		t.Fatal("precomputed shared secret is all zero")
	}
}

func TestIdentity_Precompute_RejectsLowOrderPeerKey(t *testing.T) {
	// box.Precompute calls the deprecated curve25519.ScalarMult, which its
	// own docs say writes an all-zero intermediate for a low-order peer
	// point regardless of the caller's scalar. HSalsa20 over that all-zero
	// value is a fixed, publicly computable constant with no error signal —
	// and because it's a nonzero constant, a same-value-across-peers check
	// alone (as in the test above) cannot catch it: two different identities
	// would both "successfully" derive that same wrong constant. Precompute
	// must reject this input outright instead.
	a, err := identity.Generate("operator")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var allZero [32]byte // the canonical low-order (order 1) point
	if _, err := a.Precompute(allZero); err == nil {
		t.Fatal("Precompute accepted an all-zero (low-order) peer key")
	}

	// A second, independently generated identity must fail the same way
	// rather than silently succeeding with a shared constant.
	b, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := b.Precompute(allZero); err == nil {
		t.Fatal("a second identity's Precompute accepted the same low-order peer key")
	}
}

// A prior version of this file had a
// TestIdentity_Precompute_IsCompatibleWithBoxSealAfterPrecomputation test
// here that sealed with a.Precompute and opened with h.Precompute — both
// sides using this package's own derivation. That proves only
// self-consistency (equivalent to the symmetry test above) and would pass
// unchanged even if the derivation were wrong. The real cross-implementation
// check needs one side of the assertion to come from box's own internals
// (box.Seal / box.Open), which needs the raw private keys Signer
// deliberately doesn't expose here; see
// TestIdentity_Precompute_CrossesBoxAPIBoundary and
// TestIdentity_Precompute_MatchesBoxPrecomputeByteForByte in
// precompute_internal_test.go, which is package identity for exactly that
// reason.

func TestIdentity_Generate_AlgorithmIsTagged(t *testing.T) {
	// The algorithm tag exists so a hardware-backed key on another curve can
	// land later without a protocol break (design section 5).
	s, err := identity.Generate("x")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got := s.Public().Alg; got != identity.AlgEd25519X25519 {
		t.Fatalf("Alg = %q, want %q", got, identity.AlgEd25519X25519)
	}
}

func TestIdentity_String_RedactsPrivateKeyMaterial(t *testing.T) {
	// Unexported fields are not a defense against fmt's reflection-based
	// verbs: %v and %+v on a struct print private key bytes held in
	// unexported fields regardless of any interface the type satisfies
	// elsewhere. A log.Printf("%v", signer) or a panic that formats a
	// struct holding one would otherwise leak the fleet's root key.
	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	out := fmt.Sprintf("%v", s)
	outPlus := fmt.Sprintf("%+v", s)
	outGo := fmt.Sprintf("%#v", s)

	// The redacted form is a tightly bound shape: name and key_id only. If
	// the Stringer/GoStringer methods were removed, fmt would fall back to
	// its default struct dump, which would not match this pattern (it would
	// print unexported field names like "signing:" and "encrypt:" instead,
	// or the raw byte slices).
	want := regexp.MustCompile(`^identity\.Signer\{name:"laptop-primary" key_id:[0-9a-f]{32}\}$`)
	for _, got := range []string{out, outPlus, outGo} {
		if !want.MatchString(got) {
			t.Fatalf("formatted Signer = %q, want match for %s", got, want)
		}
		if strings.Contains(got, "signing") || strings.Contains(got, "encrypt") {
			t.Fatalf("formatted Signer leaked an internal field name: %q", got)
		}
	}
}

func TestIdentity_OpenAnonymous_OpensWhatWasSealedToItsEncryptionKey(t *testing.T) {
	// A sealed bundle reaches a host as anonymous ciphertext (design section
	// 6): nothing in it names the sender, and the host's own encryption key
	// is the only thing that opens it.
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := []byte("a policy nobody else may read")
	pub := host.Public().Encryption
	sealed, err := box.SealAnonymous(nil, want, &pub, rand.Reader)
	if err != nil {
		t.Fatalf("SealAnonymous: %v", err)
	}

	got, ok, err := host.OpenAnonymous(sealed)
	if err != nil {
		t.Fatalf("OpenAnonymous: %v", err)
	}
	if !ok {
		t.Fatal("OpenAnonymous refused a ciphertext sealed to this identity")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("plaintext = %q, want %q", got, want)
	}
}

func TestIdentity_OpenAnonymous_RefusesAnotherIdentitysCiphertext(t *testing.T) {
	// Anonymous sealing hides the recipient as well as the sender, so a hub
	// serving one host's ciphertext to another must leak nothing rather than
	// fail loudly.
	a, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	b, err := identity.Generate("web-02")
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}
	pub := a.Public().Encryption
	sealed, err := box.SealAnonymous(nil, []byte("for web-01 only"), &pub, rand.Reader)
	if err != nil {
		t.Fatalf("SealAnonymous: %v", err)
	}

	plain, ok, err := b.OpenAnonymous(sealed)
	if ok {
		t.Fatalf("OpenAnonymous opened another identity's ciphertext: %q", plain)
	}
	// A ciphertext that is simply not ours is not an error: an in-memory key
	// cannot fail to be available, and reporting one here would tell a caller
	// to go looking for a broken key instead of a misrouted bundle.
	if err != nil {
		t.Fatalf("err = %v, want nil for a ciphertext that merely did not open", err)
	}
}

func TestIdentity_OpenAnonymous_RefusesAlteredOrTruncatedCiphertext(t *testing.T) {
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub := host.Public().Encryption
	sealed, err := box.SealAnonymous(nil, []byte("a policy"), &pub, rand.Reader)
	if err != nil {
		t.Fatalf("SealAnonymous: %v", err)
	}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"ephemeral key only", sealed[:32]},
		{"one byte short", sealed[:len(sealed)-1]},
		{"flipped bit in the ephemeral key", flipByte(sealed, 0)},
		{"flipped bit in the ciphertext", flipByte(sealed, len(sealed)-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, ok, err := host.OpenAnonymous(tc.in)
			if ok {
				t.Fatalf("OpenAnonymous accepted %s: %q", tc.name, plain)
			}
			if err != nil {
				t.Fatalf("%s: err = %v, want nil", tc.name, err)
			}
		})
	}
}

func flipByte(b []byte, i int) []byte {
	out := slices.Clone(b)
	out[i] ^= 0x01
	return out
}
