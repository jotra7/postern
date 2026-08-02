package spa_test

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
	"github.com/jotra7/postern/internal/vectors"
)

// This file checks internal/spa against docs/vectors/postern-v1.json, the
// published v1 test vectors. The direction matters: the file is frozen bytes
// checked in beside the specification, and nothing here recomputes it. A
// vector regenerated at test time from the code it is meant to pin agrees
// with that code whatever the code does.
//
// internal/vectors/gen wrote the file, from the specification's offsets
// rather than from this package, and is run by hand.

func loadVectors(t *testing.T) *vectors.File {
	t.Helper()
	f, err := vectors.Load()
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	return f
}

func mustHex(t *testing.T, h vectors.Hex) []byte {
	t.Helper()
	b, err := h.Bytes()
	if err != nil {
		t.Fatalf("decode vector hex: %v", err)
	}
	return b
}

func mustID(t *testing.T, h vectors.Hex) [spa.IDSize]byte {
	t.Helper()
	b := mustHex(t, h)
	if len(b) != spa.IDSize {
		t.Fatalf("identifier is %d bytes, want %d", len(b), spa.IDSize)
	}
	return [spa.IDSize]byte(b)
}

// vectorOpener is the agent side of the published vectors: the host identity
// the datagrams are sealed to, trusting the one operator that signed them.
func vectorOpener(t *testing.T) *spa.Opener {
	t.Helper()
	opener, rejected, err := spa.NewOpenerFromSigner(vectors.Host(), []identity.PublicIdentity{vectors.Operator().Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("rejected = %v, want none", rejected)
	}
	return opener
}

// requestFromVector rebuilds the Request a vector describes from its published
// field values, not from its published bytes, so Marshal has something to
// reproduce.
func requestFromVector(t *testing.T, v vectors.SPARequestVector) *spa.Request {
	t.Helper()
	sig := mustHex(t, v.SignatureHex)
	if len(sig) != spa.SigLen {
		t.Fatalf("%s: signature is %d bytes, want %d", v.Name, len(sig), spa.SigLen)
	}
	payload := mustHex(t, v.Fields.PayloadHex)
	if len(payload) != spa.PayloadLen {
		t.Fatalf("%s: payload is %d bytes, want %d", v.Name, len(payload), spa.PayloadLen)
	}
	return &spa.Request{
		Version:     uint8(v.Fields.Version), //nolint:gosec // G115: the file is checked in and holds 1.
		Alg:         uint8(v.Fields.Alg),     //nolint:gosec // G115: as above.
		Kind:        spa.Kind(v.Fields.Kind), //nolint:gosec // G115: as above.
		KeyID:       mustID(t, v.Fields.KeyIDHex),
		HostID:      mustID(t, v.Fields.HostIDHex),
		RequestID:   mustID(t, v.Fields.RequestIDHex),
		ServiceID:   mustID(t, v.Fields.ServiceIDHex),
		Counter:     v.Fields.Counter,
		TimestampMS: v.Fields.TimestampMS,
		TTLSeconds:  v.Fields.TTLSeconds,
		Payload:     [spa.PayloadLen]byte(payload),
		Signature:   [spa.SigLen]byte(sig),
	}
}

// TestSPA_Vectors_MarshalProducesThePublishedRecord is the encoding
// direction: a Request built from a vector's decoded fields must render the
// exact bytes the vector publishes, signed region and signature both.
func TestSPA_Vectors_MarshalProducesThePublishedRecord(t *testing.T) {
	f := loadVectors(t)
	if len(f.SPARequests) == 0 {
		t.Fatal("the vector file publishes no SPA requests")
	}
	for _, v := range f.SPARequests {
		t.Run(v.Name, func(t *testing.T) {
			req := requestFromVector(t, v)
			if got, want := req.MarshalSigned(), mustHex(t, v.SignedRegionHex); !bytes.Equal(got, want) {
				t.Errorf("MarshalSigned() = %x, want the published signed region %x", got, want)
			}
			if got, want := req.Marshal(), mustHex(t, v.RecordHex); !bytes.Equal(got, want) {
				t.Errorf("Marshal() = %x, want the published record %x", got, want)
			}
		})
	}
}

// TestSPA_Vectors_SigningInputCarriesThePublishedDomainTag pins the byte
// string Ed25519 actually covers, which is the part of the construction the
// wire cannot show: the tag is never transmitted, so a vector that published
// only the record would leave an independent implementation guessing.
func TestSPA_Vectors_SigningInputCarriesThePublishedDomainTag(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.SPARequests {
		t.Run(v.Name, func(t *testing.T) {
			req := requestFromVector(t, v)
			want := mustHex(t, v.SigningInputHex)
			if got := req.SigningInput(); !bytes.Equal(got, want) {
				t.Fatalf("SigningInput() = %x, want the published signing input %x", got, want)
			}
			tag := mustHex(t, v.DomainTagHex)
			if string(tag) != spa.RequestDomain {
				t.Fatalf("published domain tag %q is not RequestDomain %q", tag, spa.RequestDomain)
			}
		})
	}
}

// TestSPA_Vectors_ParseProducesThePublishedFields is the decoding direction,
// field by field, from the frozen record bytes.
func TestSPA_Vectors_ParseProducesThePublishedFields(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.SPARequests {
		t.Run(v.Name, func(t *testing.T) {
			got, err := spa.Parse(mustHex(t, v.RecordHex))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := requestFromVector(t, v)
			if *got != *want {
				t.Fatalf("Parse() = %+v, want the published fields %+v", *got, *want)
			}
		})
	}
}

// TestSPA_Vectors_TrialOpenAcceptsThePublishedDatagram runs the whole agent
// side over the frozen 224 bytes: decrypt under the host's precomputed shared
// secret, parse, agree on key_id, and verify the signature over the tagged
// region. Nothing in the chain is recomputed from the datagram.
func TestSPA_Vectors_TrialOpenAcceptsThePublishedDatagram(t *testing.T) {
	f := loadVectors(t)
	opener := vectorOpener(t)
	wantKeyID := vectors.Operator().Public().KeyID()

	for _, v := range f.SPARequests {
		t.Run(v.Name, func(t *testing.T) {
			req, who, err := opener.TrialOpen(mustHex(t, v.DatagramHex))
			if err != nil {
				t.Fatalf("TrialOpen: %v", err)
			}
			if who.KeyID() != wantKeyID {
				t.Errorf("TrialOpen attributed the datagram to key_id %x, want %x", who.KeyID(), wantKeyID)
			}
			if got, want := req.Marshal(), mustHex(t, v.RecordHex); !bytes.Equal(got, want) {
				t.Errorf("opened record = %x, want the published record %x", got, want)
			}
		})
	}
}

// TestSPA_Vectors_DatagramIsTheSealOfThePublishedRecord reproduces the
// sealing direction, which opening the datagram does not cover: nonce first,
// then box.SealAfterPrecomputation over the whole 184-byte record. A datagram
// that only ever gets opened would leave a sealer free to frame it some other
// way, since box is symmetric about the framing this test asserts.
//
// The Signer here is internal/vectors' own, which is the only kind that can
// hold the published key material: internal/identity mints its keys from
// crypto/rand and offers no way to be handed one. So this fixes the sealing
// layout and the shared-secret derivation of that Signer, and the identity
// package's own tests are what cover internal/identity's.
func TestSPA_Vectors_DatagramIsTheSealOfThePublishedRecord(t *testing.T) {
	f := loadVectors(t)
	shared, err := vectors.Operator().Precompute(vectors.Host().Public().Encryption)
	if err != nil {
		t.Fatalf("Precompute: %v", err)
	}

	for _, v := range f.SPARequests {
		t.Run(v.Name, func(t *testing.T) {
			nonceBytes := mustHex(t, v.NonceHex)
			if len(nonceBytes) != spa.NonceSize {
				t.Fatalf("nonce is %d bytes, want %d", len(nonceBytes), spa.NonceSize)
			}
			nonce := [spa.NonceSize]byte(nonceBytes)

			out := make([]byte, 0, spa.DatagramSize)
			out = append(out, nonce[:]...)
			out = box.SealAfterPrecomputation(out, mustHex(t, v.RecordHex), &nonce, shared)

			if want := mustHex(t, v.DatagramHex); !bytes.Equal(out, want) {
				t.Fatalf("resealed datagram = %x, want the published datagram %x", out, want)
			}
		})
	}
}

func spaTrialOpenError(t *testing.T, id string) error {
	t.Helper()
	switch id {
	case "wrong_size":
		return spa.ErrWrongSize
	case "not_canonical":
		return spa.ErrNotCanonical
	case "unknown_kind":
		return spa.ErrUnknownKind
	case "unsupported_version":
		return spa.ErrUnsupportedVersion
	case "key_id_mismatch":
		return spa.ErrKeyIDMismatch
	case "bad_signature":
		return spa.ErrBadSignature
	case "no_operator":
		return spa.ErrNoOperator
	}
	t.Fatalf("the vector file names an error class %q this package has no sentinel for", id)
	return nil
}

// callPayload runs the variant accessor a rejection vector names. Which one
// applies is a property of the resolved service, not of the record, so the
// file names it rather than the parser inferring it.
func callPayload(t *testing.T, req *spa.Request, call string) error {
	t.Helper()
	switch call {
	case "gate":
		_, err := req.GatePayload()
		return err
	case "confirm":
		_, _, err := req.ConfirmPayload()
		return err
	case "disarm":
		return req.DisarmPayload()
	case "liveness":
		_, err := req.LivenessPayload()
		return err
	}
	t.Fatalf("the vector file names a payload accessor %q this package does not have", call)
	return nil
}

// TestSPA_Vectors_RejectionsAreRefused walks every published rejection class.
// Each datagram is correctly signed and correctly sealed except where the
// vector says otherwise, so the field the vector names is the only thing that
// can refuse it.
func TestSPA_Vectors_RejectionsAreRefused(t *testing.T) {
	f := loadVectors(t)
	if len(f.SPARejections) == 0 {
		t.Fatal("the vector file publishes no SPA rejection vectors")
	}
	opener := vectorOpener(t)

	for _, v := range f.SPARejections {
		t.Run(v.Name, func(t *testing.T) {
			req, _, err := opener.TrialOpen(mustHex(t, v.DatagramHex))

			if v.ExpectTrialOpen != "accept" {
				want := spaTrialOpenError(t, v.ExpectTrialOpen)
				if !errors.Is(err, want) {
					t.Fatalf("TrialOpen = %v, want %v", err, want)
				}
				if v.PayloadCall != "" {
					t.Fatalf("vector refuses at TrialOpen yet also names the %q accessor", v.PayloadCall)
				}
				return
			}

			if err != nil {
				t.Fatalf("TrialOpen = %v, want the wire layer to admit this record and the payload accessor to refuse it", err)
			}
			if v.PayloadCall == "" {
				t.Fatal("vector expects TrialOpen to accept but names no payload accessor to refuse it")
			}
			want := spaTrialOpenError(t, v.ExpectPayload)
			if got := callPayload(t, req, v.PayloadCall); !errors.Is(got, want) {
				t.Fatalf("%s payload = %v, want %v", v.PayloadCall, got, want)
			}
		})
	}
}

func pongFromVector(t *testing.T, v vectors.PongVector) *spa.Pong {
	t.Helper()
	sig := mustHex(t, v.SignatureHex)
	if len(sig) != spa.SigLen {
		t.Fatalf("pong signature is %d bytes, want %d", len(sig), spa.SigLen)
	}
	return &spa.Pong{
		Version:     uint8(v.Fields.Version), //nolint:gosec // G115: the file is checked in and holds 1.
		Alg:         uint8(v.Fields.Alg),     //nolint:gosec // G115: as above.
		HostID:      mustID(t, v.Fields.HostIDHex),
		RequestID:   mustID(t, v.Fields.RequestIDHex),
		Challenge:   mustID(t, v.Fields.ChallengeHex),
		TimestampMS: v.Fields.TimestampMS,
		Signature:   [spa.SigLen]byte(sig),
	}
}

// TestSPA_Vectors_SignPongProducesThePublishedRecord covers the pong's
// encoding and its signature in one call, since Ed25519 is deterministic:
// signing the published fields with the published host key must reproduce the
// published 122 bytes exactly.
func TestSPA_Vectors_SignPongProducesThePublishedRecord(t *testing.T) {
	f := loadVectors(t)
	p := pongFromVector(t, f.Pong)
	p.Signature = [spa.SigLen]byte{}

	got, err := spa.SignPong(p, vectors.Host())
	if err != nil {
		t.Fatalf("SignPong: %v", err)
	}
	if want := mustHex(t, f.Pong.RecordHex); !bytes.Equal(got, want) {
		t.Fatalf("SignPong() = %x, want the published pong %x", got, want)
	}
	if want := mustHex(t, f.Pong.SigningInputHex); !bytes.Equal(spa.PongSigningInput(p), want) {
		t.Fatalf("pong signing input = %x, want the published signing input %x", spa.PongSigningInput(p), want)
	}
}

// TestSPA_Vectors_VerifyAcceptsThePublishedPong is the client side over the
// frozen bytes: parse, then check host_id, request_id, challenge nonce,
// freshness and the signature over the tagged region.
func TestSPA_Vectors_VerifyAcceptsThePublishedPong(t *testing.T) {
	f := loadVectors(t)
	want := pongFromVector(t, f.Pong)

	got, err := spa.ParsePong(mustHex(t, f.Pong.RecordHex))
	if err != nil {
		t.Fatalf("ParsePong: %v", err)
	}
	if *got != *want {
		t.Fatalf("ParsePong() = %+v, want the published fields %+v", *got, *want)
	}
	err = got.Verify(vectors.Host().Public().Signing,
		want.HostID, want.RequestID, want.Challenge, f.Pong.VerifyNowMS, f.Pong.VerifyWindowMS)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSPA_Vectors_PongRejectionsAreRefused walks the replies a client must
// refuse. Each is signed correctly over the bytes it carries, unless the
// vector is about the signature, so the field its description names is the
// only reason to refuse it. The two stages are separate because only the
// second one has the ping in hand: ParsePong establishes version, algorithm
// and length, and everything else is Verify's.
func TestSPA_Vectors_PongRejectionsAreRefused(t *testing.T) {
	f := loadVectors(t)
	if len(f.PongRejections) == 0 {
		t.Fatal("the vector file publishes no pong rejection vectors")
	}
	sent := pongFromVector(t, f.Pong)

	for _, v := range f.PongRejections {
		t.Run(v.Name, func(t *testing.T) {
			p, err := spa.ParsePong(mustHex(t, v.RecordHex))

			if v.ExpectParse != "accept" {
				want := spaTrialOpenError(t, v.ExpectParse)
				if !errors.Is(err, want) {
					t.Fatalf("ParsePong = %v, want %v", err, want)
				}
				if v.ExpectVerify != "" {
					t.Fatalf("vector refuses at ParsePong yet also expects %q from Verify", v.ExpectVerify)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParsePong = %v, want the record to parse and Verify to refuse it", err)
			}
			if v.ExpectVerify != "pong_mismatch" {
				t.Fatalf("vector expects %q from Verify, want pong_mismatch", v.ExpectVerify)
			}
			err = p.Verify(vectors.Host().Public().Signing,
				sent.HostID, sent.RequestID, sent.Challenge, f.Pong.VerifyNowMS, f.Pong.VerifyWindowMS)
			if !errors.Is(err, spa.ErrPongMismatch) {
				t.Fatalf("Verify = %v, want %v", err, spa.ErrPongMismatch)
			}
		})
	}
}

// TestSPA_Vectors_CrossProtocolSignaturesAreRefused is what the domain tags
// exist for. Every signature in these vectors is genuine and made by the key
// the verifier checks against; the only thing wrong with it is which record
// type's signing input it covers. An implementation that verified over the
// untagged region would accept all four.
func TestSPA_Vectors_CrossProtocolSignaturesAreRefused(t *testing.T) {
	f := loadVectors(t)
	if len(f.CrossProtocolRejections) == 0 {
		t.Fatal("the vector file publishes no cross-protocol rejection vectors")
	}
	opener := vectorOpener(t)
	pongFields := pongFromVector(t, f.Pong)

	for _, v := range f.CrossProtocolRejections {
		t.Run(v.Name, func(t *testing.T) {
			switch v.Record {
			case "spa_request":
				want := spaTrialOpenError(t, v.Expect)
				if _, _, err := opener.TrialOpen(mustHex(t, v.DatagramHex)); !errors.Is(err, want) {
					t.Fatalf("TrialOpen = %v, want %v", err, want)
				}
			case "pong":
				if v.Expect != "pong_mismatch" {
					t.Fatalf("vector expects %q from a pong, want pong_mismatch", v.Expect)
				}
				p, err := spa.ParsePong(mustHex(t, v.RecordHex))
				if err != nil {
					t.Fatalf("ParsePong: %v", err)
				}
				err = p.Verify(vectors.Host().Public().Signing,
					pongFields.HostID, pongFields.RequestID, pongFields.Challenge,
					f.Pong.VerifyNowMS, f.Pong.VerifyWindowMS)
				if !errors.Is(err, spa.ErrPongMismatch) {
					t.Fatalf("Verify = %v, want %v", err, spa.ErrPongMismatch)
				}
			default:
				t.Fatalf("the vector file names a record type %q this test does not know", v.Record)
			}
		})
	}
}

// TestSPA_Vectors_PublishThePromisedSet is the guard on the file itself. Every
// check above iterates a slice, so deleting an entry would quietly reduce the
// coverage rather than fail; this names what section 13 of the specification
// promised, so a vector cannot go missing in silence.
func TestSPA_Vectors_PublishThePromisedSet(t *testing.T) {
	f := loadVectors(t)

	wantRequests := []string{"gate-observed", "gate-asserted-v4", "gate-asserted-v6", "confirm", "disarm", "liveness"}
	gotRequests := make([]string, 0, len(f.SPARequests))
	for _, v := range f.SPARequests {
		gotRequests = append(gotRequests, v.Name)
	}
	if !equalStrings(gotRequests, wantRequests) {
		t.Errorf("published SPA requests = %v, want %v", gotRequests, wantRequests)
	}

	wantRejections := []string{
		"datagram-shorter-than-the-record",
		"datagram-longer-than-max",
		"reserved-byte-at-offset-3",
		"reserved-byte-at-offset-118",
		"reserved-byte-at-offset-119",
		"unknown-version",
		"unknown-alg",
		"unknown-kind",
		"action-with-non-zero-counter",
		"action-with-non-zero-ttl",
		"gate-observed-payload-not-zero",
		"gate-asserted-unmasked-prefix",
		"gate-asserted-v4-padding-not-zero",
		"gate-asserted-prefix-bits-above-family-max",
		"gate-asserted-unknown-family",
		"gate-asserted-reserved-tail-not-zero",
		"confirm-reserved-tail-not-zero",
		"disarm-payload-not-zero",
		"liveness-reserved-tail-not-zero",
		"key-id-disagrees-with-decrypting-operator",
		"corrupted-signature",
		"sealed-by-an-untrusted-operator",
	}
	gotRejections := make([]string, 0, len(f.SPARejections))
	for _, v := range f.SPARejections {
		gotRejections = append(gotRejections, v.Name)
	}
	if !equalStrings(gotRejections, wantRejections) {
		t.Errorf("published SPA rejections = %v, want %v", gotRejections, wantRejections)
	}

	wantPongRejections := []string{
		"unknown-version",
		"unknown-alg",
		"shorter-than-the-record",
		"longer-than-max",
		"host-id-does-not-match-the-host-that-was-pinged",
		"request-id-does-not-match-the-ping",
		"challenge-nonce-does-not-match-the-ping",
		"timestamp-outside-the-freshness-window",
		"corrupted-signature",
	}
	gotPongRejections := make([]string, 0, len(f.PongRejections))
	for _, v := range f.PongRejections {
		gotPongRejections = append(gotPongRejections, v.Name)
	}
	if !equalStrings(gotPongRejections, wantPongRejections) {
		t.Errorf("published pong rejections = %v, want %v", gotPongRejections, wantPongRejections)
	}

	wantCross := []string{
		"spa-request-signed-over-the-untagged-region",
		"spa-request-signed-over-the-pong-signing-input",
		"pong-signed-over-the-untagged-region",
		"pong-signed-over-the-spa-request-signing-input",
	}
	gotCross := make([]string, 0, len(f.CrossProtocolRejections))
	for _, v := range f.CrossProtocolRejections {
		gotCross = append(gotCross, v.Name)
	}
	if !equalStrings(gotCross, wantCross) {
		t.Errorf("published cross-protocol rejections = %v, want %v", gotCross, wantCross)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
