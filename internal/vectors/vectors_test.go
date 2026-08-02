package vectors_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/vectors"
)

// The checks here fall into two halves that must not be confused.
//
// The first half establishes that docs/vectors/postern-v1.json is internally
// consistent using nothing but crypto/ed25519, crypto/sha256 and
// golang.org/x/crypto: the public keys really are the published seeds', the
// key_id really is the truncated hash, and every published signature really
// verifies over the published signing input under the published key. None of
// that consults a line of postern's own code, so it holds whatever postern
// does, and it is what an independent implementation can lean on.
//
// The second half checks internal/bundle and internal/attest against the file.
// internal/spa and the pong are checked in internal/spa/vectors_test.go, which
// is where that package's fixtures and seams already live.

func load(t *testing.T) *vectors.File {
	t.Helper()
	f, err := vectors.Load()
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	return f
}

func decode(t *testing.T, h vectors.Hex) []byte {
	t.Helper()
	b, err := h.Bytes()
	if err != nil {
		t.Fatalf("decode vector hex: %v", err)
	}
	return b
}

func decode32(t *testing.T, h vectors.Hex) [32]byte {
	t.Helper()
	b := decode(t, h)
	if len(b) != 32 {
		t.Fatalf("value is %d bytes, want 32", len(b))
	}
	return [32]byte(b)
}

func decode16(t *testing.T, h vectors.Hex) [16]byte {
	t.Helper()
	b := decode(t, h)
	if len(b) != 16 {
		t.Fatalf("value is %d bytes, want 16", len(b))
	}
	return [16]byte(b)
}

func publishedKeys(f *vectors.File) map[string]vectors.Key {
	return map[string]vectors.Key{
		"operator":      f.Keys.Operator,
		"host":          f.Keys.Host,
		"bundle_signer": f.Keys.Signer,
		"untrusted":     f.Keys.Untrusted,
	}
}

// TestVectors_Keys_AreDerivableFromThePublishedSeeds is the first thing an
// independent implementation does with this file: take the seven ASCII
// strings, derive everything else, and check it got the same answer.
func TestVectors_Keys_AreDerivableFromThePublishedSeeds(t *testing.T) {
	f := load(t)
	for role, k := range publishedKeys(f) {
		t.Run(role, func(t *testing.T) {
			if len(k.SigningSeedASCII) != 32 {
				t.Fatalf("signing seed %q is %d bytes, want 32", k.SigningSeedASCII, len(k.SigningSeedASCII))
			}
			seed := decode(t, k.SigningSeedHex)
			if string(seed) != k.SigningSeedASCII {
				t.Fatalf("signing_seed_hex decodes to %q, want the published ASCII %q", seed, k.SigningSeedASCII)
			}

			priv := ed25519.NewKeyFromSeed(seed)
			if want := decode(t, k.SigningPrivateHex); !bytes.Equal(priv, want) {
				t.Errorf("Ed25519 private key from the seed = %x, want the published %x", priv, want)
			}
			pub := decode32(t, k.SigningPublicHex)
			if !bytes.Equal(priv[32:], pub[:]) {
				t.Errorf("published signing public key %x is not the seed's %x", pub, priv[32:])
			}

			sum := sha256.Sum256(pub[:])
			if want := decode(t, k.KeyIDHex); !bytes.Equal(sum[:identity.KeyIDSize], want) {
				t.Errorf("SHA-256(signing public)[:16] = %x, want the published key_id %x", sum[:identity.KeyIDSize], want)
			}

			if len(k.EncryptionPrivateASCII) != 32 {
				t.Fatalf("encryption key %q is %d bytes, want 32", k.EncryptionPrivateASCII, len(k.EncryptionPrivateASCII))
			}
			encPriv := decode(t, k.EncryptionPrivateHex)
			if string(encPriv) != k.EncryptionPrivateASCII {
				t.Fatalf("encryption_private_hex decodes to %q, want the published ASCII %q", encPriv, k.EncryptionPrivateASCII)
			}
			encPub, err := curve25519.X25519(encPriv, curve25519.Basepoint)
			if err != nil {
				t.Fatalf("X25519: %v", err)
			}
			if want := decode(t, k.EncryptionPublicHex); !bytes.Equal(encPub, want) {
				t.Errorf("X25519 public key = %x, want the published %x", encPub, want)
			}
		})
	}
}

// signedRecord is one published record reduced to what a signature check
// needs, so every record type can be walked by the same loop.
type signedRecord struct {
	name string
	// tag is the domain-separation tag. tagged says whether it is already
	// inside signedRegion, which is the difference between a tag the record
	// transmits and one it reconstructs.
	tag          []byte
	tagInRegion  bool
	signedRegion []byte
	signingInput []byte
	signature    []byte
	publicKey    []byte
	record       []byte
}

func allSignedRecords(t *testing.T, f *vectors.File) []signedRecord {
	t.Helper()
	keys := publishedKeys(f)
	key := func(role string) []byte {
		k, ok := keys[role]
		if !ok {
			t.Fatalf("the vector file names a signing role %q it does not publish a key for", role)
		}
		return decode(t, k.SigningPublicHex)
	}

	var out []signedRecord
	for _, v := range f.SPARequests {
		out = append(out, signedRecord{
			name:         "spa_request/" + v.Name,
			tag:          decode(t, v.DomainTagHex),
			signedRegion: decode(t, v.SignedRegionHex),
			signingInput: decode(t, v.SigningInputHex),
			signature:    decode(t, v.SignatureHex),
			publicKey:    key(v.SignedBy),
			record:       decode(t, v.RecordHex),
		})
	}
	out = append(out, signedRecord{
		name:         "pong/" + f.Pong.Name,
		tag:          decode(t, f.Pong.DomainTagHex),
		signedRegion: decode(t, f.Pong.SignedRegionHex),
		signingInput: decode(t, f.Pong.SigningInputHex),
		signature:    decode(t, f.Pong.SignatureHex),
		publicKey:    key(f.Pong.SignedBy),
		record:       decode(t, f.Pong.RecordHex),
	})
	region := decode(t, f.Bundle.SignedRegionHex)
	out = append(out, signedRecord{
		name:         "bundle/" + f.Bundle.Name,
		tag:          decode(t, f.Bundle.DomainTagHex),
		tagInRegion:  true,
		signedRegion: region,
		signingInput: region,
		signature:    decode(t, f.Bundle.SignatureHex),
		publicKey:    key(f.Bundle.SignedBy),
		record:       decode(t, f.Bundle.RecordHex),
	})
	region = decode(t, f.Beat.SignedRegionHex)
	out = append(out, signedRecord{
		name:         "beat/" + f.Beat.Name,
		tag:          decode(t, f.Beat.DomainTagHex),
		tagInRegion:  true,
		signedRegion: region,
		signingInput: region,
		signature:    decode(t, f.Beat.SignatureHex),
		publicKey:    key(f.Beat.SignedBy),
		record:       decode(t, f.Beat.RecordHex),
	})
	return out
}

// TestVectors_SignedRecords_AreSelfConsistent proves the file stands on its
// own. Every signature verifies over the published signing input under the
// published key, that input is the published tag in front of the published
// signed region, and the record is that region with the signature appended.
// An implementation that reproduces the region and knows the tag can therefore
// check itself without ever running postern.
func TestVectors_SignedRecords_AreSelfConsistent(t *testing.T) {
	f := load(t)
	records := allSignedRecords(t, f)
	if len(records) == 0 {
		t.Fatal("the vector file publishes no signed records")
	}

	for _, r := range records {
		t.Run(r.name, func(t *testing.T) {
			if r.tagInRegion {
				if !bytes.HasPrefix(r.signedRegion, r.tag) {
					t.Fatalf("signed region %x does not begin with the transmitted tag %q", r.signedRegion, r.tag)
				}
			} else {
				want := append(append([]byte{}, r.tag...), r.signedRegion...)
				if !bytes.Equal(r.signingInput, want) {
					t.Fatalf("signing input %x is not the tag %q followed by the signed region", r.signingInput, r.tag)
				}
				if bytes.HasPrefix(r.record, r.tag) {
					t.Fatalf("record %x begins with the tag %q, which this record type does not transmit", r.record, r.tag)
				}
			}

			if len(r.signature) != ed25519.SignatureSize {
				t.Fatalf("signature is %d bytes, want %d", len(r.signature), ed25519.SignatureSize)
			}
			if want := len(r.signedRegion) + len(r.signature); len(r.record) != want {
				t.Fatalf("record is %d bytes, want the signed region plus the signature, %d", len(r.record), want)
			}
			if !bytes.Equal(r.record[:len(r.signedRegion)], r.signedRegion) {
				t.Error("the record does not begin with its own published signed region")
			}
			if !bytes.Equal(r.record[len(r.signedRegion):], r.signature) {
				t.Error("the record does not end with its own published signature")
			}

			if !ed25519.Verify(r.publicKey, r.signingInput, r.signature) {
				t.Fatal("the published signature does not verify over the published signing input")
			}
			// The tag is load-bearing rather than decorative: the same
			// signature must not verify over the region without it.
			if !r.tagInRegion && ed25519.Verify(r.publicKey, r.signedRegion, r.signature) {
				t.Fatal("the published signature also verifies over the untagged region, so the tag separates nothing")
			}
		})
	}
}

// TestVectors_Signers_MatchThePublishedKeys ties the Go helpers in this
// package to the file, so a test that reaches for vectors.Operator() and a
// reader who reaches for the JSON are handed the same identity.
func TestVectors_Signers_MatchThePublishedKeys(t *testing.T) {
	f := load(t)
	for _, tc := range []struct {
		role   string
		signer identity.Signer
		key    vectors.Key
	}{
		{"operator", vectors.Operator(), f.Keys.Operator},
		{"host", vectors.Host(), f.Keys.Host},
		{"bundle_signer", vectors.BundleSigner(), f.Keys.Signer},
		{"untrusted", vectors.Untrusted(), f.Keys.Untrusted},
	} {
		t.Run(tc.role, func(t *testing.T) {
			pub := tc.signer.Public()
			if got, want := pub.Signing, decode32(t, tc.key.SigningPublicHex); got != want {
				t.Errorf("signing public = %x, want %x", got, want)
			}
			if got, want := pub.Encryption, decode32(t, tc.key.EncryptionPublicHex); got != want {
				t.Errorf("encryption public = %x, want %x", got, want)
			}
			if got, want := pub.KeyID(), decode16(t, tc.key.KeyIDHex); got != want {
				t.Errorf("key_id = %x, want %x", got, want)
			}
		})
	}
}

// TestVectors_KeyIDDerivation_MatchesTheImplementation checks the derivation
// on its own, so an implementer can get key_id right without first getting a
// whole record right.
func TestVectors_KeyIDDerivation_MatchesTheImplementation(t *testing.T) {
	f := load(t)
	if len(f.KeyIDDerivations) == 0 {
		t.Fatal("the vector file publishes no key_id derivations")
	}
	for _, v := range f.KeyIDDerivations {
		t.Run(v.Name, func(t *testing.T) {
			pub := identity.PublicIdentity{Signing: decode32(t, v.SigningPublicHex)}
			if got, want := pub.KeyID(), decode16(t, v.KeyIDHex); got != want {
				t.Fatalf("KeyID() = %x, want the published %x", got, want)
			}
			sum := sha256.Sum256(pub.Signing[:])
			if want := decode(t, v.SHA256Hex); !bytes.Equal(sum[:], want) {
				t.Fatalf("SHA-256 of the signing key = %x, want the published %x", sum, want)
			}
		})
	}
}

// TestVectors_ServiceIDDerivation_MatchesTheImplementation is the same for a
// service name, whose hash keeps the record fixed-width and keeps the name out
// of a captured packet.
func TestVectors_ServiceIDDerivation_MatchesTheImplementation(t *testing.T) {
	f := load(t)
	if len(f.ServiceIDDerivations) == 0 {
		t.Fatal("the vector file publishes no service_id derivations")
	}
	for _, v := range f.ServiceIDDerivations {
		t.Run(v.ServiceName, func(t *testing.T) {
			if err := config.ValidateServiceName(v.ServiceName); err != nil {
				t.Fatalf("the vector file publishes a service name the grammar refuses: %v", err)
			}
			if got, want := []byte(v.ServiceName), decode(t, v.NameHex); !bytes.Equal(got, want) {
				t.Fatalf("name_hex decodes to %q, want %q", want, got)
			}
			svc := config.Service{Name: v.ServiceName}
			if got, want := svc.ID(), decode16(t, v.ServiceIDHex); got != want {
				t.Fatalf("ID() = %x, want the published %x", got, want)
			}
		})
	}
}

func bundleCriteria(t *testing.T, a vectors.BundleAccept) bundle.AcceptCriteria {
	t.Helper()
	return bundle.AcceptCriteria{
		FleetID:         decode16(t, a.FleetIDHex),
		HostID:          decode16(t, a.HostIDHex),
		CurrentVersion:  a.CurrentVersion,
		HasCurrent:      a.HasCurrent,
		EnrollmentFloor: a.EnrollmentFloor,
	}
}

// TestVectors_Bundle_OpensToThePublishedFields runs the whole hub-to-agent
// path over frozen bytes: unseal anonymously with the host's own keypair,
// establish the structure, check the signer against the trusted set, verify
// the signature, and apply the fleet, host, floor and ordering checks.
func TestVectors_Bundle_OpensToThePublishedFields(t *testing.T) {
	f := load(t)
	trusted := [][32]byte{decode32(t, f.Bundle.Fields.SignerKeyHex)}

	got, err := bundle.Open(decode(t, f.Bundle.SealedHex), vectors.Host(), trusted, bundleCriteria(t, f.Bundle.Accept))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if want := decode16(t, f.Bundle.Fields.FleetIDHex); got.FleetID != want {
		t.Errorf("FleetID = %x, want %x", got.FleetID, want)
	}
	if want := decode16(t, f.Bundle.Fields.HostIDHex); got.HostID != want {
		t.Errorf("HostID = %x, want %x", got.HostID, want)
	}
	if got.Version != f.Bundle.Fields.Version {
		t.Errorf("Version = %d, want %d", got.Version, f.Bundle.Fields.Version)
	}
	//nolint:gosec // G115: the published value is a checked-in millisecond timestamp.
	if want := time.UnixMilli(int64(f.Bundle.Fields.IssuedAtMS)).UTC(); !got.IssuedAt.Equal(want) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, want)
	}
	if want := decode(t, f.Bundle.Fields.PolicyHex); !bytes.Equal(got.Policy, want) {
		t.Errorf("Policy = %q, want %q", got.Policy, want)
	}
	if string(got.Policy) != f.Bundle.Fields.PolicyUTF8 {
		t.Errorf("policy_hex and policy_utf8 disagree: %q against %q", got.Policy, f.Bundle.Fields.PolicyUTF8)
	}
	if want := decode32(t, f.Bundle.Fields.SignerKeyHex); got.SignerKey != want {
		t.Errorf("SignerKey = %x, want %x", got.SignerKey, want)
	}
}

func bundleError(t *testing.T, id string) error {
	t.Helper()
	switch id {
	case "format":
		return bundle.ErrFormat
	case "untrusted_signer":
		return bundle.ErrUntrustedSigner
	case "bad_signature":
		return bundle.ErrBadSignature
	case "unseal":
		return bundle.ErrUnseal
	}
	t.Fatalf("the vector file names a bundle error class %q this package has no sentinel for", id)
	return nil
}

// TestVectors_BundleRejections_AreRefused walks the malformed records. Each is
// signed by the key its vector names and sealed to the same host, so the field
// the vector describes is the only reason to refuse it.
func TestVectors_BundleRejections_AreRefused(t *testing.T) {
	f := load(t)
	if len(f.BundleRejections) == 0 {
		t.Fatal("the vector file publishes no bundle rejection vectors")
	}
	trusted := [][32]byte{decode32(t, f.Bundle.Fields.SignerKeyHex)}
	criteria := bundleCriteria(t, f.Bundle.Accept)

	for _, v := range f.BundleRejections {
		t.Run(v.Name, func(t *testing.T) {
			want := bundleError(t, v.Expect)
			if _, err := bundle.Open(decode(t, v.SealedHex), vectors.Host(), trusted, criteria); !errors.Is(err, want) {
				t.Fatalf("Open = %v, want %v", err, want)
			}
		})
	}
}

func beatFromVector(t *testing.T, f *vectors.File) *attest.Beat {
	t.Helper()
	var body attest.Body
	if err := json.Unmarshal([]byte(f.Beat.Fields.BodyUTF8), &body); err != nil {
		t.Fatalf("the published beat body is not valid JSON for attest.Body: %v", err)
	}
	return &attest.Beat{
		FleetID:  decode16(t, f.Beat.Fields.FleetIDHex),
		HostID:   decode16(t, f.Beat.Fields.HostIDHex),
		Epoch:    f.Beat.Fields.Epoch,
		Sequence: f.Beat.Fields.Sequence,
		//nolint:gosec // G115: the published value is a checked-in millisecond timestamp.
		SentAt: time.UnixMilli(int64(f.Beat.Fields.SentAtMS)).UTC(),
		Body:   body,
	}
}

// TestVectors_Beat_EncodesToThePublishedRecord covers the encoder and the
// signature in one call, Ed25519 being deterministic: the published fields
// signed with the published host key must reproduce the published bytes.
func TestVectors_Beat_EncodesToThePublishedRecord(t *testing.T) {
	f := load(t)
	got, err := attest.Encode(beatFromVector(t, f), vectors.Host())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if want := decode(t, f.Beat.RecordHex); !bytes.Equal(got, want) {
		t.Fatalf("Encode() = %x, want the published record %x", got, want)
	}
}

// TestVectors_Beat_VerifiesToThePublishedFields is the hub side over the same
// frozen bytes.
func TestVectors_Beat_VerifiesToThePublishedFields(t *testing.T) {
	f := load(t)
	got, err := attest.Verify(decode(t, f.Beat.RecordHex), vectors.Host().Public().Signing)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := beatFromVector(t, f)
	if got.FleetID != want.FleetID {
		t.Errorf("FleetID = %x, want %x", got.FleetID, want.FleetID)
	}
	if got.HostID != want.HostID {
		t.Errorf("HostID = %x, want %x", got.HostID, want.HostID)
	}
	if got.Epoch != want.Epoch {
		t.Errorf("Epoch = %d, want %d", got.Epoch, want.Epoch)
	}
	if got.Sequence != want.Sequence {
		t.Errorf("Sequence = %d, want %d", got.Sequence, want.Sequence)
	}
	if !got.SentAt.Equal(want.SentAt) {
		t.Errorf("SentAt = %v, want %v", got.SentAt, want.SentAt)
	}
	if diff := cmpBody(got.Body, want.Body); diff != "" {
		t.Error(diff)
	}
}

func cmpBody(got, want attest.Body) string {
	g, _ := json.Marshal(&got)
	w, _ := json.Marshal(&want)
	if bytes.Equal(g, w) {
		return ""
	}
	return "Body = " + string(g) + ", want " + string(w)
}

func beatError(t *testing.T, id string) error {
	t.Helper()
	switch id {
	case "format":
		return attest.ErrFormat
	case "bad_signature":
		return attest.ErrBadSignature
	}
	t.Fatalf("the vector file names a beat error class %q this package has no sentinel for", id)
	return nil
}

// TestVectors_BeatRejections_AreRefused walks the malformed beats.
func TestVectors_BeatRejections_AreRefused(t *testing.T) {
	f := load(t)
	if len(f.BeatRejections) == 0 {
		t.Fatal("the vector file publishes no beat rejection vectors")
	}
	for _, v := range f.BeatRejections {
		t.Run(v.Name, func(t *testing.T) {
			want := beatError(t, v.Expect)
			if _, err := attest.Verify(decode(t, v.RecordHex), vectors.Host().Public().Signing); !errors.Is(err, want) {
				t.Fatalf("Verify = %v, want %v", err, want)
			}
		})
	}
}

// TestVectors_DomainTags_MatchTheFourSignedRecordTypes checks the tag table
// against the tags the four packages actually use, so the file cannot publish
// a tag postern does not sign with.
func TestVectors_DomainTags_MatchTheFourSignedRecordTypes(t *testing.T) {
	f := load(t)
	want := map[string]struct {
		tag         string
		transmitted bool
	}{
		"spa_request": {spaRequestDomain, false},
		"pong":        {spaPongDomain, false},
		"bundle":      {bundle.Magic, true},
		"beat":        {attest.Magic, true},
	}
	if len(f.DomainTags) != len(want) {
		t.Fatalf("the vector file publishes %d domain tags, want %d", len(f.DomainTags), len(want))
	}
	for _, v := range f.DomainTags {
		w, ok := want[v.Record]
		if !ok {
			t.Errorf("the vector file publishes a tag for an unknown record type %q", v.Record)
			continue
		}
		if got := string(decode(t, v.Hex)); got != w.tag {
			t.Errorf("%s tag = %q, want %q", v.Record, got, w.tag)
		}
		if v.Length != len(w.tag) {
			t.Errorf("%s tag length = %d, want %d", v.Record, v.Length, len(w.tag))
		}
		if v.Transmitted != w.transmitted {
			t.Errorf("%s transmitted = %v, want %v", v.Record, v.Transmitted, w.transmitted)
		}
	}
}

// The two SPA tags are named here rather than imported from internal/spa,
// which imports nothing from this package but which this package's other
// tests should not have to drag in to check a string. internal/spa's own
// vectors_test.go compares the published tag against spa.RequestDomain
// directly.
const (
	spaRequestDomain = "postern-spa-request\x00"
	spaPongDomain    = "postern-spa-pong\x00"
)

// TestVectors_File_PublishesThePromisedSet guards the file itself: every check
// above iterates a slice, so a deleted vector would quietly shrink the
// coverage instead of failing.
func TestVectors_File_PublishesThePromisedSet(t *testing.T) {
	f := load(t)

	if f.Schema != 1 {
		t.Errorf("schema = %d, want 1", f.Schema)
	}
	if f.Warning == "" {
		t.Error("the vector file publishes private keys with no warning attached to them")
	}

	names := func(get func() []string, want []string, what string) {
		got := get()
		if len(got) != len(want) {
			t.Errorf("published %s = %v, want %v", what, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("published %s = %v, want %v", what, got, want)
				return
			}
		}
	}

	names(func() []string {
		out := make([]string, 0, len(f.ServiceIDDerivations))
		for _, v := range f.ServiceIDDerivations {
			out = append(out, v.ServiceName)
		}
		return out
	}, []string{"ssh", "confirm", "disarm", "liveness", "postgres-primary"}, "service_id derivations")

	names(func() []string {
		out := make([]string, 0, len(f.BundleRejections))
		for _, v := range f.BundleRejections {
			out = append(out, v.Name)
		}
		return out
	}, []string{
		"wrong-magic",
		"unknown-format",
		"policy-len-disagrees-with-record-length",
		"policy-len-above-the-cap",
		"shorter-than-the-fixed-length",
		"untrusted-signer",
		"corrupted-signature",
	}, "bundle rejections")

	names(func() []string {
		out := make([]string, 0, len(f.BeatRejections))
		for _, v := range f.BeatRejections {
			out = append(out, v.Name)
		}
		return out
	}, []string{
		"wrong-magic",
		"unknown-format",
		"body-len-disagrees-with-record-length",
		"body-len-above-the-cap",
		"shorter-than-the-fixed-length",
		"signed-by-another-key",
		"corrupted-signature",
	}, "beat rejections")

	if len(f.KeyIDDerivations) != 4 {
		t.Errorf("published key_id derivations = %d, want one per key", len(f.KeyIDDerivations))
	}
}

// TestVectors_LoadFile_RefusesAnUnknownField keeps the file and the Go types
// that describe it from drifting. A published field nothing reads would be
// invisible to every check above, which is how a vector set grows a section
// that means nothing.
func TestVectors_LoadFile_RefusesAnUnknownField(t *testing.T) {
	path, err := vectors.Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	raw["a_field_no_type_here_declares"] = 1
	edited, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	copied := filepath.Join(t.TempDir(), "postern-v1.json")
	if err := os.WriteFile(copied, edited, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := vectors.LoadFile(copied); err == nil {
		t.Fatal("LoadFile accepted a vector file carrying a field no type declares")
	}
}

// TestVectors_Path_ReportsAFileItCannotFind pins the failure a test sees when
// the vectors are absent: an error naming what was looked for, rather than an
// empty File that would make every check above pass on nothing.
func TestVectors_Path_ReportsAFileItCannotFind(t *testing.T) {
	t.Chdir(t.TempDir())
	if got, err := vectors.Path(); err == nil {
		t.Fatalf("Path() = %q with no vector file above it, want an error", got)
	}
	if _, err := vectors.Load(); err == nil {
		t.Fatal("Load() succeeded with no vector file above the working directory")
	}
}

// TestVectors_Hex_RefusesNonHex keeps a mistyped fixture from decoding to
// something shorter and quietly comparing equal to a truncated expectation.
func TestVectors_Hex_RefusesNonHex(t *testing.T) {
	if _, err := vectors.Hex("00zz").Bytes(); err == nil {
		t.Fatal("Hex.Bytes accepted a string that is not hex")
	}
}

// TestVectors_Signer_StringRedactsPrivateKeyMaterial mirrors
// TestIdentity_String_RedactsPrivateKeyMaterial. That these keys are published
// is not a reason for a Signer to print itself as a struct dump: the habit is
// what matters, since the same formatting verb reaches a real signer.
func TestVectors_Signer_StringRedactsPrivateKeyMaterial(t *testing.T) {
	s := vectors.Operator()
	want := regexp.MustCompile(`^vectors\.Signer\{name:"vector-operator" key_id:[0-9a-f]{32}\}$`)
	for _, got := range []string{fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s)} {
		if !want.MatchString(got) {
			t.Fatalf("formatted Signer = %q, want match for %s", got, want)
		}
		if strings.Contains(got, "signing") || strings.Contains(got, "encrypt") {
			t.Fatalf("formatted Signer leaked an internal field name: %q", got)
		}
	}
}
