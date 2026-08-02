package spa_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

// This file holds the invariants that make a postern signature mean exactly
// one record type. It lives in internal/spa because that is the package that
// carries two of the four tags, and it reaches across to internal/bundle and
// internal/attest for the other two: neither imports internal/spa, so the
// test-only dependency runs one way and adds no cycle.

// signedRecordDomains is every byte string that can begin a postern signing
// input. RequestDomain and PongDomain are prefixes the signer prepends and
// the wire never carries; bundle.Magic and attest.Magic are the first field
// of their record and are transmitted. The distinction does not matter to
// the property below, which is about what an Ed25519 key commits to.
func signedRecordDomains() map[string]string {
	return map[string]string{
		"spa request":   spa.RequestDomain,
		"liveness pong": spa.PongDomain,
		"bundle":        bundle.Magic,
		"beat":          attest.Magic,
	}
}

// TestSPA_DomainTags_AreMutuallyNonPrefix is the property that replaces "the
// signed regions happen to be different lengths" as the reason a signature
// over one record type cannot be reinterpreted as a signature over another.
//
// Distinctness alone is not enough. If one tag were a prefix of another, a
// signing input under the shorter tag could still be a valid signing input
// under the longer one once the remaining bytes were chosen to suit, which is
// exactly the confusion the tags exist to remove. Equality is caught here too,
// since every string is a prefix of itself.
func TestSPA_DomainTags_AreMutuallyNonPrefix(t *testing.T) {
	domains := signedRecordDomains()
	for aName, a := range domains {
		for bName, b := range domains {
			if aName == bName {
				continue
			}
			if bytes.HasPrefix([]byte(a), []byte(b)) {
				t.Errorf("the %s tag %q begins with the %s tag %q: a signature over one "+
					"record type could be presented as a signature over the other",
					aName, a, bName, b)
			}
		}
	}
}

// TestSPA_SignedRegions_HaveDistinctLengths pins the first of the two
// properties that used to hold the SPA request and the pong apart on their
// own. It is no longer what the separation rests on, and it is asserted so
// that a v2 which equalises the two lengths says so out loud rather than
// silently spending a margin nobody wrote down.
func TestSPA_SignedRegions_HaveDistinctLengths(t *testing.T) {
	if spa.SignedLen == spa.PongSignedLen {
		t.Fatalf("the SPA request and the pong both sign %d bytes; that used to be "+
			"the whole of their separation, and equalising it is a decision to take "+
			"deliberately", spa.SignedLen)
	}
}

// TestSPA_SigningInput_CarriesOnlyItsOwnDomainTag checks the separation in
// the form that does not lean on the lengths: whatever the two records are
// made to contain, one signing input never begins with the other's tag, so
// the two sets of signable byte strings are disjoint even if SignedLen and
// PongSignedLen were ever made equal.
func TestSPA_SigningInput_CarriesOnlyItsOwnDomainTag(t *testing.T) {
	req := sampleGate()
	reqInput := req.SigningInput()

	pong := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_700_000_000_000}
	pongInput := spa.PongSigningInput(pong)

	if want := append([]byte(spa.RequestDomain), req.MarshalSigned()...); !bytes.Equal(reqInput, want) {
		t.Errorf("Request.SigningInput() = %x, want the domain tag followed by the signed region %x", reqInput, want)
	}
	if !bytes.HasPrefix(reqInput, []byte(spa.RequestDomain)) {
		t.Errorf("Request.SigningInput() does not begin with RequestDomain: %x", reqInput)
	}
	if bytes.HasPrefix(reqInput, []byte(spa.PongDomain)) {
		t.Errorf("Request.SigningInput() begins with PongDomain: %x", reqInput)
	}
	if !bytes.HasPrefix(pongInput, []byte(spa.PongDomain)) {
		t.Errorf("pong signing input does not begin with PongDomain: %x", pongInput)
	}
	if bytes.HasPrefix(pongInput, []byte(spa.RequestDomain)) {
		t.Errorf("pong signing input begins with RequestDomain: %x", pongInput)
	}
}

// TestSPA_TrialOpen_RejectsASignatureOverTheUntaggedRegion proves the tag is
// covered by the shipped verifier rather than only present in SigningInput.
// The untagged row is what a client from before this change emits: the
// datagram decrypts, parses, and key_id-matches, so the signature check is
// the only control that can reject it. The tagged row is the same
// construction with the tag restored, and it must be accepted, which is what
// stops the untagged row passing for some unrelated reason.
func TestSPA_TrialOpen_RejectsASignatureOverTheUntaggedRegion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signOver func(*spa.Request) []byte
		wantErr  error
	}{
		{"signed over the untagged region", func(r *spa.Request) []byte { return r.MarshalSigned() }, spa.ErrBadSignature},
		{"signed over the tagged region", func(r *spa.Request) []byte { return r.SigningInput() }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSealFixture(t)
			req := sampleGate()
			req.KeyID = f.operator.Public().KeyID()

			sig, err := f.operator.Sign(tc.signOver(req))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			copy(req.Signature[:], sig)

			dg, err := spa.SealPresigned(req, f.operator, f.host.Public().Encryption)
			if err != nil {
				t.Fatalf("SealPresigned: %v", err)
			}
			if _, _, err := f.opener.TrialOpen(dg); !errors.Is(err, tc.wantErr) {
				t.Fatalf("TrialOpen = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestSPA_PongVerify_RejectsASignatureOverTheUntaggedRegion is the pong's
// half of the same check. Every other field the verifier looks at is the one
// the fixture minted, so the signature is the only control in play, and the
// tagged row establishes that.
func TestSPA_PongVerify_RejectsASignatureOverTheUntaggedRegion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signOver func(*spa.Pong) []byte
		wantOK   bool
	}{
		{"signed over the untagged region", func(p *spa.Pong) []byte {
			return spa.MarshalPongUnsigned(p)[:spa.PongSignedLen]
		}, false},
		{"signed over the tagged region", spa.PongSigningInput, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, err := identity.Generate("web-01")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			p := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_700_000_000_000}
			for i := range p.HostID {
				p.HostID[i] = byte(i)
				p.RequestID[i] = byte(i + 40)
				p.Challenge[i] = byte(i + 80)
			}

			sig, err := host.Sign(tc.signOver(p))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			copy(p.Signature[:], sig)

			got, err := spa.ParsePong(spa.MarshalPongUnsigned(p))
			if err != nil {
				t.Fatalf("ParsePong: %v", err)
			}
			err = got.Verify(host.Public().Signing, p.HostID, p.RequestID, p.Challenge, p.TimestampMS, 60_000)
			if tc.wantOK && err != nil {
				t.Fatalf("Verify = %v, want nil", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("Verify accepted a pong whose signature covers the untagged region")
			}
		})
	}
}

// TestSPA_NewOpenerFromSigner_RejectsAnOperatorReusingTheHostSigningKey pins
// the agent's half of the second invariant: no key signs in both the operator
// and the host role. Building the trusted-operator set is where an agent has
// both halves of the pairing in hand, so it is where the invariant can be
// enforced rather than asserted. The operator's half is in internal/client,
// TestClient_Status_RefusesAHostWhoseSigningKeyIsTheOperatorsOwn.
//
// The two rows differ in the Signing field and nothing else: same name, same
// encryption key, same host. The accepted row is what makes the rejected row
// mean what it says: if the rejection came from anything but the signing key
// comparison, the accepted row would be refused too.
func TestSPA_NewOpenerFromSigner_RejectsAnOperatorReusingTheHostSigningKey(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hostsOwnKey bool
	}{
		{"the host's own signing key", true},
		{"a signing key of its own", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, err := identity.Generate("web-01")
			if err != nil {
				t.Fatalf("Generate host: %v", err)
			}
			op, err := identity.Generate("laptop-primary")
			if err != nil {
				t.Fatalf("Generate operator: %v", err)
			}

			entry := op.Public()
			if tc.hostsOwnKey {
				entry.Signing = host.Public().Signing
			}

			opener, rejected, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{entry})
			if !tc.hostsOwnKey {
				if err != nil {
					t.Fatalf("NewOpenerFromSigner: %v", err)
				}
				if len(rejected) != 0 {
					t.Fatalf("rejected = %v, want none for an operator with its own signing key", rejected)
				}
				req := sampleGate()
				req.KeyID = entry.KeyID()
				dg, err := spa.Seal(req, op, host.Public().Encryption)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				if _, _, err := opener.TrialOpen(dg); err != nil {
					t.Fatalf("TrialOpen = %v, want nil for the operator the opener was built for", err)
				}
				return
			}

			if len(rejected) != 1 || rejected[0] != "laptop-primary" {
				t.Fatalf("rejected = %v, want exactly [laptop-primary]: an operator holding the "+
					"host's own signing key would sign in both roles", rejected)
			}
			if opener != nil {
				t.Fatal("NewOpenerFromSigner returned an Opener built from a key that also signs pongs")
			}
			if err == nil {
				t.Fatal("NewOpenerFromSigner = nil error with no usable operator left")
			}
		})
	}
}
