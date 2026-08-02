package bundle_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

// samplePolicy stands in for the standalone YAML a compiled policy marshals
// to. Most tests here do not care what the bytes say — only that they arrive
// unchanged and that a single flipped bit in them is refused — so a short
// literal keeps the per-byte mutation test cheap. One test below carries a
// genuinely compiled policy instead.
var samplePolicy = []byte("spa_port: 62201\nservices:\n  ssh: {kind: gate, port: 22}\n")

// fixture holds the cast: one trusted bundle signer, one signer outside the
// trusted set, and two hosts. hostB exists so "sealed to someone else" is a
// real key rather than a corrupted ciphertext.
type fixture struct {
	t        *testing.T
	signer   identity.Signer
	attacker identity.Signer
	hostA    identity.Signer
	hostB    identity.Signer
	trusted  [][32]byte
	fleetID  [16]byte
	hostAID  [16]byte
	hostBID  [16]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		t:        t,
		signer:   newSigner(t, "bundle-signer"),
		attacker: newSigner(t, "attacker"),
		hostA:    newSigner(t, "web-01"),
		hostB:    newSigner(t, "web-02"),
		fleetID:  [16]byte{0xf1, 0xee, 0x70},
		hostAID:  [16]byte{0xa0, 0x01},
		hostBID:  [16]byte{0xb0, 0x02},
	}
	// A second trusted signer, unrelated to any of the above, so membership
	// is a set test rather than an equality test against one key.
	f.trusted = [][32]byte{
		newSigner(t, "other-signer").Public().Signing,
		f.signer.Public().Signing,
	}
	return f
}

func newSigner(t *testing.T, name string) identity.Signer {
	t.Helper()
	s, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("identity.Generate(%q): %v", name, err)
	}
	return s
}

// contents builds a bundle destined for hostA at the given version.
func (f *fixture) contents(version uint64) *bundle.Contents {
	return &bundle.Contents{
		FleetID:  f.fleetID,
		HostID:   f.hostAID,
		Version:  version,
		IssuedAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		Policy:   samplePolicy,
	}
}

// criteria is what hostA knows about itself: no bundle accepted yet, no
// floor. Tests tighten the fields they are about.
func (f *fixture) criteria() bundle.AcceptCriteria {
	return bundle.AcceptCriteria{FleetID: f.fleetID, HostID: f.hostAID}
}

// seal signs with the trusted signer and seals to hostA.
func (f *fixture) seal(c *bundle.Contents) bundle.Sealed {
	f.t.Helper()
	return f.sealWith(c, f.signer, f.hostA)
}

func (f *fixture) sealWith(c *bundle.Contents, signer, host identity.Signer) bundle.Sealed {
	f.t.Helper()
	s, err := bundle.Seal(c, signer, host.Public().Encryption)
	if err != nil {
		f.t.Fatalf("Seal: %v", err)
	}
	return s
}

// innerOf recovers the signed record from inside the seal, which is where
// tampering has to happen for it to be reachable: mutating the ciphertext
// only ever exercises Poly1305.
func (f *fixture) innerOf(s bundle.Sealed) []byte {
	f.t.Helper()
	inner, ok, err := f.hostA.OpenAnonymous(s)
	if err != nil || !ok {
		f.t.Fatalf("OpenAnonymous on a bundle sealed to this host: ok=%v err=%v", ok, err)
	}
	return inner
}

// sealInner seals bytes to hostA without going through Seal, so a test can
// control every byte of the record the agent will parse.
func (f *fixture) sealInner(inner []byte) bundle.Sealed {
	f.t.Helper()
	pub := f.hostA.Public().Encryption
	out, err := box.SealAnonymous(nil, inner, &pub, rand.Reader)
	if err != nil {
		f.t.Fatalf("SealAnonymous: %v", err)
	}
	return out
}

// reseal rebuilds a record with one field rewritten and re-signs it with the
// trusted signer. Re-signing is the point: these tests are about the
// acceptance rules, not about detecting tampering, so the record has to be as
// authentic as a real one.
func (f *fixture) reseal(mutate func(*bundle.Contents)) bundle.Sealed {
	f.t.Helper()
	c := f.contents(1)
	mutate(c)
	return f.seal(c)
}

// buildInner renders a record straight from the documented layout, without
// going through bundle.go's own encoder, and signs it. Tests use it for
// records Seal will not produce — an over-cap policy, chiefly — and it
// doubles as a second opinion on the layout: a parser that read a field from
// the wrong offset would disagree with it.
func (f *fixture) buildInner(c *bundle.Contents, signer identity.Signer) []byte {
	f.t.Helper()
	key := signer.Public().Signing
	b := make([]byte, 0, bundle.FixedLen+len(c.Policy))
	b = append(b, bundle.Magic...)
	b = append(b, bundle.FormatV1)
	b = append(b, c.FleetID[:]...)
	b = append(b, c.HostID[:]...)
	b = binary.BigEndian.AppendUint64(b, c.Version)
	b = binary.BigEndian.AppendUint64(b, uint64(c.IssuedAt.UnixMilli())) //nolint:gosec // G115: a test's own fixed timestamp.
	b = binary.BigEndian.AppendUint32(b, uint32(len(c.Policy)))          //nolint:gosec // G115: a test's own policy length.
	b = append(b, c.Policy...)
	b = append(b, key[:]...)
	sig, err := signer.Sign(b)
	if err != nil {
		f.t.Fatalf("Sign: %v", err)
	}
	return append(b, sig...)
}

func TestBundle_Open_AcceptsWhatSealProduced(t *testing.T) {
	f := newFixture(t)
	want := f.contents(47)

	got, err := bundle.Open(f.seal(want), f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if got.FleetID != want.FleetID {
		t.Errorf("FleetID = %x, want %x", got.FleetID, want.FleetID)
	}
	if got.HostID != want.HostID {
		t.Errorf("HostID = %x, want %x", got.HostID, want.HostID)
	}
	if got.Version != want.Version {
		t.Errorf("Version = %d, want %d", got.Version, want.Version)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("IssuedAt = %s, want %s", got.IssuedAt, want.IssuedAt)
	}
	if diff := cmp.Diff(want.Policy, got.Policy); diff != "" {
		t.Errorf("Policy (-want +got):\n%s", diff)
	}
	if got.SignerKey != f.signer.Public().Signing {
		t.Errorf("SignerKey = %x, want the signing key %x", got.SignerKey, f.signer.Public().Signing)
	}
}

// The policy is carried as opaque bytes, so what a caller actually ships —
// a compiled policy marshalled to standalone YAML — has to survive the round
// trip byte for byte, not merely "some bytes" do.
func TestBundle_Open_CarriesACompiledPolicyUnchanged(t *testing.T) {
	f := newFixture(t)
	policy, err := bundle.Compile(baseInventory(), "web-01")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	yamlBytes, err := config.MarshalStandalone(policy)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}

	c := f.contents(3)
	c.Policy = yamlBytes
	got, err := bundle.Open(f.seal(c), f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got.Policy, yamlBytes) {
		t.Fatalf("policy did not survive the bundle:\n got %q\nwant %q", got.Policy, yamlBytes)
	}
	// And it is still parseable on the far side — Open returning it unparsed
	// must not mean returning it mangled.
	if _, err := config.ParseStandalone(got.Policy); err != nil {
		t.Fatalf("ParseStandalone on the opened policy: %v", err)
	}
}

// An empty policy is a legal record: policy_len zero must not be confused
// with a truncated one.
func TestBundle_Open_AcceptsAnEmptyPolicy(t *testing.T) {
	f := newFixture(t)
	c := f.contents(1)
	c.Policy = nil

	got, err := bundle.Open(f.seal(c), f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got.Policy) != 0 {
		t.Fatalf("Policy = %q, want empty", got.Policy)
	}
}

// A record assembled straight from the documented layout, by a test encoder
// that shares no code with Seal, must open. Without this the tests that build
// records by hand — the over-cap policy, chiefly — could be passing because
// the hand-built record is malformed in some way nobody intended.
func TestBundle_Open_AcceptsAHandBuiltRecordMatchingTheDocumentedLayout(t *testing.T) {
	f := newFixture(t)
	want := f.contents(47)

	got, err := bundle.Open(f.sealInner(f.buildInner(want, f.signer)), f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Version != want.Version || got.FleetID != want.FleetID || got.HostID != want.HostID {
		t.Fatalf("got fleet %x host %x version %d, want %x / %x / %d",
			got.FleetID, got.HostID, got.Version, want.FleetID, want.HostID, want.Version)
	}
	if !bytes.Equal(got.Policy, want.Policy) {
		t.Fatalf("Policy = %q, want %q", got.Policy, want.Policy)
	}
}

// The other direction: what Seal writes must land on the documented offsets,
// checked against the bytes rather than against this package's own decoder.
func TestBundle_Seal_EncodesTheDocumentedLayout(t *testing.T) {
	f := newFixture(t)
	c := f.contents(47)
	inner := f.innerOf(f.seal(c))

	if len(inner) != bundle.FixedLen+len(c.Policy) {
		t.Fatalf("record is %d bytes, want %d", len(inner), bundle.FixedLen+len(c.Policy))
	}
	if got := string(inner[bundle.OffMagic : bundle.OffMagic+bundle.MagicLen]); got != bundle.Magic {
		t.Errorf("magic = %q, want %q", got, bundle.Magic)
	}
	if inner[bundle.OffFormat] != bundle.FormatV1 {
		t.Errorf("format = %d, want %d", inner[bundle.OffFormat], bundle.FormatV1)
	}
	if got := inner[bundle.OffFleetID : bundle.OffFleetID+bundle.IDSize]; !bytes.Equal(got, c.FleetID[:]) {
		t.Errorf("fleet_id = %x, want %x", got, c.FleetID)
	}
	if got := inner[bundle.OffHostID : bundle.OffHostID+bundle.IDSize]; !bytes.Equal(got, c.HostID[:]) {
		t.Errorf("host_id = %x, want %x", got, c.HostID)
	}
	if got := binary.BigEndian.Uint64(inner[bundle.OffVersion:]); got != c.Version {
		t.Errorf("version = %d, want %d", got, c.Version)
	}
	if got := binary.BigEndian.Uint64(inner[bundle.OffIssuedAt:]); got != uint64(c.IssuedAt.UnixMilli()) { //nolint:gosec // G115: a test's own fixed timestamp.
		t.Errorf("issued_at = %d, want %d", got, c.IssuedAt.UnixMilli())
	}
	if got := binary.BigEndian.Uint32(inner[bundle.OffPolicyLen:]); got != uint32(len(c.Policy)) { //nolint:gosec // G115: a test's own policy length.
		t.Errorf("policy_len = %d, want %d", got, len(c.Policy))
	}
	if got := inner[bundle.PolicyOff : bundle.PolicyOff+len(c.Policy)]; !bytes.Equal(got, c.Policy) {
		t.Errorf("policy = %q, want %q", got, c.Policy)
	}
	keyOff := bundle.PolicyOff + len(c.Policy)
	key := f.signer.Public().Signing
	if got := inner[keyOff : keyOff+bundle.SignerKeyLen]; !bytes.Equal(got, key[:]) {
		t.Errorf("signer key = %x, want %x", got, key)
	}
	// The signature covers everything before it, signer key included.
	if !ed25519.Verify(key[:], inner[:keyOff+bundle.SignerKeyLen], inner[keyOff+bundle.SignerKeyLen:]) {
		t.Error("signature does not verify over [0, 100+N)")
	}
}

// c.SignerKey is an output of Open, never an input to Seal: Seal ignores
// whatever the caller left there and writes the key that produced the
// signature. If it copied the caller's value into the record instead, a
// bundle could name a trusted signer while being signed by anyone.
func TestBundle_Seal_WritesTheSigningKeyNotTheCallersSignerKeyField(t *testing.T) {
	f := newFixture(t)
	c := f.contents(1)
	c.SignerKey = [32]byte{0xde, 0xad, 0xbe, 0xef}

	got, err := bundle.Open(f.seal(c), f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.SignerKey != f.signer.Public().Signing {
		t.Fatalf("SignerKey = %x, want %x", got.SignerKey, f.signer.Public().Signing)
	}
}

// Two seals of identical contents must differ: box.SealAnonymous draws a
// fresh ephemeral key per call, and identical ciphertext would tell a hub
// observer that a host's policy had not changed.
func TestBundle_Seal_ProducesDistinctCiphertextForIdenticalContents(t *testing.T) {
	f := newFixture(t)
	c := f.contents(1)

	if first, second := f.seal(c), f.seal(c); bytes.Equal(first, second) {
		t.Fatal("two seals of the same contents produced identical ciphertext")
	}
}

func TestBundle_Seal_RejectsAnOversizedPolicy(t *testing.T) {
	f := newFixture(t)
	c := f.contents(1)
	c.Policy = make([]byte, bundle.MaxPolicyLen+1)

	if _, err := bundle.Seal(c, f.signer, f.hostA.Public().Encryption); !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// The boundary itself. MaxPolicyLen+1 is refused above; a policy of exactly
// MaxPolicyLen has to round-trip, or the cap is off by one in the direction
// that rejects a legitimate bundle — which on a fleet is every host refusing
// to converge, silently, on a bundle the signer believes it published.
//
// The enrollment floor got its exact-boundary test when it was written and
// this cap did not, which is the whole reason to add it: a bound tested only
// from one side is a bound half-checked.
//
// Mutation verified: changing Seal's guard to `>=` and openInner's to `>=`
// fails this, each in its own half.
func TestBundle_SealOpen_AcceptAPolicyOfExactlyMaxPolicyLen(t *testing.T) {
	f := newFixture(t)
	c := f.contents(1)
	c.Policy = bytes.Repeat([]byte("y"), bundle.MaxPolicyLen)

	sealed, err := bundle.Seal(c, f.signer, f.hostA.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal a policy of exactly MaxPolicyLen (%d): %v", bundle.MaxPolicyLen, err)
	}
	got, err := bundle.Open(sealed, f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open a policy of exactly MaxPolicyLen (%d): %v", bundle.MaxPolicyLen, err)
	}
	if len(got.Policy) != bundle.MaxPolicyLen {
		t.Fatalf("policy came back %d bytes, want %d", len(got.Policy), bundle.MaxPolicyLen)
	}
	if !bytes.Equal(got.Policy, c.Policy) {
		t.Fatal("the policy at the exact cap did not round-trip byte for byte")
	}
}

func TestBundle_Seal_PropagatesASignerFailure(t *testing.T) {
	f := newFixture(t)
	boom := errors.New("hsm unplugged")

	_, err := bundle.Seal(f.contents(1), &stubSigner{Signer: f.signer, signErr: boom}, f.hostA.Public().Encryption)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the signer's own error", err)
	}
}

// A Signer is a seam a hardware key lands behind later. One that returns a
// short signature must not produce a record whose trailing 64 bytes are
// partly the signer key.
func TestBundle_Seal_RejectsASignatureOfTheWrongLength(t *testing.T) {
	f := newFixture(t)

	_, err := bundle.Seal(f.contents(1), &stubSigner{Signer: f.signer, truncateSig: true}, f.hostA.Public().Encryption)
	if err == nil {
		t.Fatal("Seal accepted a 63-byte signature")
	}
}

// A low-order recipient key drives the X25519 exchange to a fixed, publicly
// computable shared secret, and the anonymous nonce derives from public
// values only — so the "sealed" bundle is readable by anyone who fetches it
// from the hub. box.SealAnonymous accepts such a key without complaint, and
// nothing downstream notices: the signature is still valid, and the only
// symptom is the target host being unable to open its own bundle, which
// looks like a delivery fault. identity.Signer.Precompute already refuses
// these keys on the SPA path; Seal has to refuse them here.
func TestBundle_Seal_RejectsALowOrderRecipientKey(t *testing.T) {
	f := newFixture(t)

	// The small-order points of Curve25519, the same set libsodium screens
	// for. config.decodeKey validates base64 and length only, so any of these
	// can reach Seal from a hand-edited inventory.
	for _, hexKey := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		t.Run(hexKey[:8], func(t *testing.T) {
			raw, err := hex.DecodeString(hexKey)
			if err != nil {
				t.Fatalf("DecodeString: %v", err)
			}
			var key [32]byte
			copy(key[:], raw)

			sealed, err := bundle.Seal(f.contents(1), f.signer, key)
			if !errors.Is(err, bundle.ErrRecipientKey) {
				t.Fatalf("err = %v, want ErrRecipientKey", err)
			}
			if sealed != nil {
				t.Fatalf("Seal returned %d bytes of ciphertext alongside the rejection", len(sealed))
			}
		})
	}
}

// The check must reject low-order points and nothing else: a fleet whose
// bundles stop sealing is a fleet nobody can get back into.
func TestBundle_Seal_AcceptsAGeneratedRecipientKey(t *testing.T) {
	f := newFixture(t)
	for i := range 16 {
		host := newSigner(t, fmt.Sprintf("host-%d", i))
		if _, err := bundle.Seal(f.contents(1), f.signer, host.Public().Encryption); err != nil {
			t.Fatalf("Seal to a freshly generated host key: %v", err)
		}
	}
}

// A key that cannot be used at all is not a key mismatch. Collapsing a
// hardware failure into ErrUnseal sends an operator debugging a break-glass
// tool after a mismatch that does not exist.
func TestBundle_Open_ReportsAnUnusableKeyRatherThanAMismatch(t *testing.T) {
	f := newFixture(t)
	sealed := f.seal(f.contents(1))
	boom := errors.New("token removed")

	_, err := bundle.Open(sealed, &stubSigner{Signer: f.hostA, openErr: boom}, f.trusted, f.criteria())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the device's own error", err)
	}
	if errors.Is(err, bundle.ErrUnseal) {
		t.Fatal("a device failure was reported as ErrUnseal")
	}
}

// Sealing is anonymous, so the ciphertext names no recipient — but it opens
// for exactly one host key. Another host holding the same ciphertext learns
// nothing, which is what makes it safe to serve an unauthenticated fetch.
func TestBundle_Open_RefusesAnotherHostsKey(t *testing.T) {
	f := newFixture(t)
	sealed := f.seal(f.contents(1))

	crit := f.criteria()
	crit.HostID = f.hostBID
	if _, err := bundle.Open(sealed, f.hostB, f.trusted, crit); !errors.Is(err, bundle.ErrUnseal) {
		t.Fatalf("err = %v, want ErrUnseal", err)
	}
}

// Authenticity comes from the signature, not the seal. A bundle sealed to the
// right host but signed by a key outside bundle_signers is the compromise
// case: someone who learned a host's public key can produce ciphertext it can
// open, and only the signature stops that from becoming policy.
//
// The record here is otherwise perfect — correct fleet, correct host, valid
// Ed25519 signature over its own contents — so only the membership check can
// reject it.
func TestBundle_Open_RejectsAnUntrustedSigner(t *testing.T) {
	f := newFixture(t)
	sealed := f.sealWith(f.contents(1), f.attacker, f.hostA)

	if _, err := bundle.Open(sealed, f.hostA, f.trusted, f.criteria()); !errors.Is(err, bundle.ErrUntrustedSigner) {
		t.Fatalf("err = %v, want ErrUntrustedSigner", err)
	}
}

func TestBundle_Open_RejectsAnEmptyTrustedSet(t *testing.T) {
	f := newFixture(t)
	sealed := f.seal(f.contents(1))

	if _, err := bundle.Open(sealed, f.hostA, nil, f.criteria()); !errors.Is(err, bundle.ErrUntrustedSigner) {
		t.Fatalf("err = %v, want ErrUntrustedSigner", err)
	}
}

// The mirror of RejectsAnUntrustedSigner: this record names a trusted signer
// and the policy under it has been rewritten. Membership passes and only the
// signature check can reject it, which is what shows the two checks are
// independent rather than one covering for the other.
func TestBundle_Open_RejectsATrustedSignersRecordWithARewrittenPolicy(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(1)))
	// Rewrite a policy byte in place, leaving policy_len and the signer key
	// exactly as the trusted signer wrote them.
	inner[bundle.PolicyOff]++

	_, err := bundle.Open(f.sealInner(inner), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A signature is verified over this record, not over some record: a valid
// signature lifted from another bundle must not verify here.
func TestBundle_Open_RejectsASignatureFromADifferentRecord(t *testing.T) {
	f := newFixture(t)
	victim := f.innerOf(f.seal(f.contents(1)))
	other := f.innerOf(f.seal(f.contents(2)))
	copy(victim[len(victim)-bundle.SigLen:], other[len(other)-bundle.SigLen:])

	_, err := bundle.Open(f.sealInner(victim), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A single flipped bit anywhere in the signed region must fail verification,
// including inside the policy where the interesting tampering would be. The
// mutation happens to the record before it is sealed, so every byte is
// actually reachable — mutating the ciphertext would only ever exercise
// Poly1305.
//
// The expected error is asserted per region rather than "some error", which
// also pins the ordering: bytes of the signer key must come back as
// ErrUntrustedSigner, proving membership is decided before the signature is
// verified.
func TestBundle_Open_RejectsEverySingleByteMutation(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(47)))
	signerKeyOff := len(inner) - bundle.SigLen - bundle.SignerKeyLen

	for i := range inner {
		for _, bit := range []byte{0x01, 0x80} {
			mutated := slices.Clone(inner)
			mutated[i] ^= bit

			want := bundle.ErrBadSignature
			switch {
			case i < bundle.PolicyOff && i >= bundle.OffPolicyLen:
				// policy_len no longer agrees with the record's length.
				want = bundle.ErrFormat
			case i < bundle.MagicLen, i == bundle.OffFormat:
				want = bundle.ErrFormat
			case i >= signerKeyOff && i < signerKeyOff+bundle.SignerKeyLen:
				want = bundle.ErrUntrustedSigner
			}

			_, err := bundle.Open(f.sealInner(mutated), f.hostA, f.trusted, f.criteria())
			if !errors.Is(err, want) {
				t.Fatalf("byte %d bit %#x: err = %v, want %v", i, bit, err, want)
			}
		}
	}
}

// The replay this exists to stop: a validly-signed OLD bundle, still
// containing an operator who has since been removed, resent to a host. It is
// correctly signed by a trusted key, so only the version ordering rejects it.
func TestBundle_Open_RejectsAnOlderValidlySignedBundle(t *testing.T) {
	f := newFixture(t)
	old := f.seal(f.contents(46))

	crit := f.criteria()
	crit.CurrentVersion, crit.HasCurrent = 47, true
	if _, err := bundle.Open(old, f.hostA, f.trusted, crit); !errors.Is(err, bundle.ErrNotNewer) {
		t.Fatalf("err = %v, want ErrNotNewer", err)
	}
}

// Equal is not newer. An agent that re-applies its current version on every
// pull would re-arm and re-enter the confirm window on a schedule.
func TestBundle_Open_RejectsAnEqualVersion(t *testing.T) {
	f := newFixture(t)
	same := f.seal(f.contents(47))

	crit := f.criteria()
	crit.CurrentVersion, crit.HasCurrent = 47, true
	if _, err := bundle.Open(same, f.hostA, f.trusted, crit); !errors.Is(err, bundle.ErrNotNewer) {
		t.Fatalf("err = %v, want ErrNotNewer", err)
	}
}

func TestBundle_Open_AcceptsTheNextVersion(t *testing.T) {
	f := newFixture(t)
	next := f.seal(f.contents(48))

	crit := f.criteria()
	crit.CurrentVersion, crit.HasCurrent = 47, true
	if _, err := bundle.Open(next, f.hostA, f.trusted, crit); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

// HasCurrent, not CurrentVersion == 0, is what says "nothing accepted yet":
// version 0 is a legal bundle version, and an agent holding it must still
// reject a second version 0.
func TestBundle_Open_RejectsVersionZeroWhenZeroIsAlreadyCurrent(t *testing.T) {
	f := newFixture(t)
	zero := f.seal(f.contents(0))

	crit := f.criteria()
	crit.CurrentVersion, crit.HasCurrent = 0, true
	if _, err := bundle.Open(zero, f.hostA, f.trusted, crit); !errors.Is(err, bundle.ErrNotNewer) {
		t.Fatalf("err = %v, want ErrNotNewer", err)
	}
}

func TestBundle_Open_AcceptsVersionZeroWhenNothingIsCurrent(t *testing.T) {
	f := newFixture(t)
	zero := f.seal(f.contents(0))

	if _, err := bundle.Open(zero, f.hostA, f.trusted, f.criteria()); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

// Section 6: a freshly enrolled agent holds no version, so without a floor
// the same removed-operator bundle replays cleanly against it. The floor is
// stamped at enrollment precisely because "no current version" would
// otherwise accept anything.
func TestBundle_Open_RejectsBelowTheEnrollmentFloorWithNoCurrentVersion(t *testing.T) {
	f := newFixture(t)
	old := f.seal(f.contents(12))

	crit := f.criteria()
	crit.HasCurrent = false
	crit.EnrollmentFloor = 47
	if _, err := bundle.Open(old, f.hostA, f.trusted, crit); !errors.Is(err, bundle.ErrBelowFloor) {
		t.Fatalf("err = %v, want ErrBelowFloor", err)
	}
}

// The floor is the first version an enrolled host may accept, not the first
// it must exceed: enrollment records the version that is about to be rolled
// out, and refusing it would leave the host with nothing to apply.
func TestBundle_Open_AcceptsExactlyTheEnrollmentFloor(t *testing.T) {
	f := newFixture(t)
	atFloor := f.seal(f.contents(47))

	crit := f.criteria()
	crit.EnrollmentFloor = 47
	if _, err := bundle.Open(atFloor, f.hostA, f.trusted, crit); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

// The floor keeps applying after the first bundle lands. An agent whose
// current version somehow sits below its floor must not be walked back up
// from underneath it.
func TestBundle_Open_ReportsTheFloorWhenBothTheFloorAndOrderingWouldReject(t *testing.T) {
	f := newFixture(t)
	old := f.seal(f.contents(12))

	crit := f.criteria()
	crit.CurrentVersion, crit.HasCurrent = 20, true
	crit.EnrollmentFloor = 47
	if _, err := bundle.Open(old, f.hostA, f.trusted, crit); !errors.Is(err, bundle.ErrBelowFloor) {
		t.Fatalf("err = %v, want ErrBelowFloor", err)
	}
}

// host_id is inside the signed record, so a bundle correctly built for one
// host cannot be served to another by a hub that mixed up its keys — the same
// anti-misrouting control host_id plays inside an SPA packet.
func TestBundle_Open_RejectsAHostIDMismatch(t *testing.T) {
	f := newFixture(t)
	forSomeoneElse := f.reseal(func(c *bundle.Contents) { c.HostID = f.hostBID })

	if _, err := bundle.Open(forSomeoneElse, f.hostA, f.trusted, f.criteria()); !errors.Is(err, bundle.ErrWrongHost) {
		t.Fatalf("err = %v, want ErrWrongHost", err)
	}
}

func TestBundle_Open_RejectsAFleetIDMismatch(t *testing.T) {
	f := newFixture(t)
	otherFleet := f.reseal(func(c *bundle.Contents) { c.FleetID = [16]byte{0x99} })

	if _, err := bundle.Open(otherFleet, f.hostA, f.trusted, f.criteria()); !errors.Is(err, bundle.ErrWrongFleet) {
		t.Fatalf("err = %v, want ErrWrongFleet", err)
	}
}

// Attacker-controlled length prefix. policy_len is read before the signature
// is checked, because the signature covers the policy, so it must not be
// trusted to size an allocation.
func TestBundle_Open_RejectsAnOversizedPolicyLength(t *testing.T) {
	f := newFixture(t)
	// A record that is internally consistent and correctly signed by a
	// trusted signer, differing from a valid bundle only in being one byte
	// over the cap. Nothing but the bound rejects it.
	c := f.contents(1)
	c.Policy = make([]byte, bundle.MaxPolicyLen+1)

	_, err := bundle.Open(f.sealInner(f.buildInner(c, f.signer)), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// The bound has to be applied to the prefix itself, before it is used to
// index anything: a short record claiming a 4 GiB policy must be refused,
// not allocated for or sliced with.
func TestBundle_Open_RejectsAnAbsurdPolicyLengthOnAShortRecord(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(1)))
	binary.BigEndian.PutUint32(inner[bundle.OffPolicyLen:], ^uint32(0))

	_, err := bundle.Open(f.sealInner(inner), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestBundle_Open_RejectsATruncatedRecord(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(1)))

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"header only", bundle.PolicyOff},
		{"one byte short", len(inner) - 1},
		{"missing the signature", len(inner) - bundle.SigLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bundle.Open(f.sealInner(inner[:tc.n]), f.hostA, f.trusted, f.criteria())
			if !errors.Is(err, bundle.ErrFormat) {
				t.Fatalf("err = %v, want ErrFormat", err)
			}
		})
	}
}

// Trailing bytes would give one meaning two encodings, and only one of them
// is under the signature.
func TestBundle_Open_RejectsTrailingBytes(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(1)))

	_, err := bundle.Open(f.sealInner(append(inner, 0)), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestBundle_Open_RejectsWrongMagic(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(1)))
	copy(inner, "postern-BUNDLE\x00")

	_, err := bundle.Open(f.sealInner(inner), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// A format the agent does not understand is refused outright rather than
// parsed as v1: the layout after byte 15 is only meaningful under a version
// this code knows.
func TestBundle_Open_RejectsAnUnknownFormatVersion(t *testing.T) {
	f := newFixture(t)
	inner := f.innerOf(f.seal(f.contents(1)))
	inner[bundle.OffFormat] = 2

	_, err := bundle.Open(f.sealInner(inner), f.hostA, f.trusted, f.criteria())
	if !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// The returned policy must not alias the record it came from: a caller that
// appends to it would otherwise overwrite the signer key and signature still
// sitting in the same backing array.
func TestBundle_Open_ReturnsAPolicyThatDoesNotAliasTheRecord(t *testing.T) {
	f := newFixture(t)
	got, err := bundle.Open(f.seal(f.contents(1)), f.hostA, f.trusted, f.criteria())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if cap(got.Policy) != len(got.Policy) {
		t.Fatalf("Policy cap %d exceeds len %d, so it still points into the record", cap(got.Policy), len(got.Policy))
	}
}

// Every sentinel this package returns has to be distinguishable from every
// other one, or a caller checking for a specific rejection silently matches
// the wrong thing.
func TestBundle_Errors_AreDistinct(t *testing.T) {
	all := []error{
		bundle.ErrFormat, bundle.ErrUnseal, bundle.ErrRecipientKey, bundle.ErrUntrustedSigner,
		bundle.ErrBadSignature, bundle.ErrWrongFleet, bundle.ErrWrongHost, bundle.ErrNotNewer,
		bundle.ErrBelowFloor,
	}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("errors.Is(%v, %v) is true, but they are different rejections", a, b)
			}
		}
	}
}

// FuzzBundle_Open asserts that neither the seal nor the record parser panics
// on arbitrary bytes, and that anything the parser does accept satisfies
// every rule Open claims to enforce. The record is parsed on an agent, as
// root, from data fetched over the network, which is what earns a fuzz
// target.
func FuzzBundle_Open(f *testing.F) {
	signer, err := identity.Generate("fuzz-signer")
	if err != nil {
		f.Fatalf("identity.Generate: %v", err)
	}
	host, err := identity.Generate("fuzz-host")
	if err != nil {
		f.Fatalf("identity.Generate: %v", err)
	}
	trusted := [][32]byte{signer.Public().Signing}
	want := bundle.AcceptCriteria{
		FleetID:         [16]byte{1},
		HostID:          [16]byte{2},
		CurrentVersion:  5,
		HasCurrent:      true,
		EnrollmentFloor: 3,
	}

	valid, err := bundle.Seal(&bundle.Contents{
		FleetID:  want.FleetID,
		HostID:   want.HostID,
		Version:  9,
		IssuedAt: time.Unix(0, 0),
		Policy:   samplePolicy,
	}, signer, host.Public().Encryption)
	if err != nil {
		f.Fatalf("Seal: %v", err)
	}
	inner, ok, err := host.OpenAnonymous(valid)
	if err != nil || !ok {
		f.Fatalf("OpenAnonymous on a freshly sealed bundle: ok=%v err=%v", ok, err)
	}

	f.Add([]byte(valid))
	f.Add(inner)
	f.Add([]byte{})
	f.Add(inner[:bundle.PolicyOff])
	f.Add(inner[:len(inner)-1])
	oversize := slices.Clone(inner)
	binary.BigEndian.PutUint32(oversize[bundle.OffPolicyLen:], ^uint32(0))
	f.Add(oversize)

	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := bundle.Open(data, host, trusted, want); err != nil {
			if c != nil {
				t.Fatal("Open returned both contents and an error")
			}
		} else if err := check(c, trusted, want); err != nil {
			t.Fatalf("Open accepted a bundle that %v", err)
		}

		// Random bytes will essentially never open the seal, so the record
		// parser is also driven directly.
		if c, err := bundle.OpenInner(data, trusted, want); err != nil {
			if c != nil {
				t.Fatal("OpenInner returned both contents and an error")
			}
		} else if err := check(c, trusted, want); err != nil {
			t.Fatalf("OpenInner accepted a record that %v", err)
		}
	})
}

// check restates Open's guarantees independently of how Open computes them.
func check(c *bundle.Contents, trusted [][32]byte, want bundle.AcceptCriteria) error {
	switch {
	case c.FleetID != want.FleetID:
		return fmt.Errorf("belongs to fleet %x, not %x", c.FleetID, want.FleetID)
	case c.HostID != want.HostID:
		return fmt.Errorf("belongs to host %x, not %x", c.HostID, want.HostID)
	case c.Version < want.EnrollmentFloor:
		return fmt.Errorf("is version %d, below the floor %d", c.Version, want.EnrollmentFloor)
	case want.HasCurrent && c.Version <= want.CurrentVersion:
		return fmt.Errorf("is version %d, not newer than %d", c.Version, want.CurrentVersion)
	case !slices.Contains(trusted, c.SignerKey):
		return fmt.Errorf("was signed by the untrusted key %x", c.SignerKey)
	case len(c.Policy) > bundle.MaxPolicyLen:
		return fmt.Errorf("carries a %d byte policy, over the %d cap", len(c.Policy), bundle.MaxPolicyLen)
	}
	return nil
}

// stubSigner wraps a real signer so a test can break exactly one thing about
// it. Everything not overridden is genuine, so a failure is attributable to
// the override.
type stubSigner struct {
	identity.Signer
	signErr     error
	truncateSig bool
	openErr     error
}

// OpenAnonymous stands in for a key held in hardware that has become
// unusable: the token pulled, the device locked. Nothing is wrong with the
// ciphertext.
func (s *stubSigner) OpenAnonymous(sealed []byte) ([]byte, bool, error) {
	if s.openErr != nil {
		return nil, false, s.openErr
	}
	return s.Signer.OpenAnonymous(sealed)
}

func (s *stubSigner) Sign(msg []byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	sig, err := s.Signer.Sign(msg)
	if err != nil {
		return nil, err
	}
	if s.truncateSig {
		return sig[:len(sig)-1], nil
	}
	return sig, nil
}
