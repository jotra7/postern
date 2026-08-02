package attest_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/identity"
)

// fixture holds one signer and the fleet/host identifiers a beat carries.
type fixture struct {
	t        *testing.T
	signer   identity.Signer
	attacker identity.Signer
	fleetID  [16]byte
	hostID   [16]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{
		t:        t,
		signer:   newSigner(t, "host-01"),
		attacker: newSigner(t, "attacker"),
		fleetID:  [16]byte{0xf1, 0xee, 0x70},
		hostID:   [16]byte{0xa0, 0x01},
	}
}

func newSigner(t *testing.T, name string) identity.Signer {
	t.Helper()
	s, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("identity.Generate(%q): %v", name, err)
	}
	return s
}

// beat builds a beat at the given sequence number, otherwise filled with
// representative telemetry.
func (f *fixture) beat(sequence uint64) *attest.Beat {
	return &attest.Beat{
		FleetID:  f.fleetID,
		HostID:   f.hostID,
		Epoch:    3,
		Sequence: sequence,
		SentAt:   time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		Body: attest.Body{
			AgentVersion:   "1.2.3",
			BundleVersion:  47,
			ConfigHash:     "deadbeef",
			ClockSkewMS:    -12,
			ListenerStatus: map[string]string{"udp/62201": "listening"},
			GateElements:   map[string]int{"ssh": 3},
			SPAAccepted:    9001,
			SPARejected:    3,
			AgentUpHealthy: true,
		},
	}
}

// encode signs with the fixture's signer.
func (f *fixture) encode(b *attest.Beat) []byte {
	f.t.Helper()
	return f.encodeWith(b, f.signer)
}

func (f *fixture) encodeWith(b *attest.Beat, signer identity.Signer) []byte {
	f.t.Helper()
	data, err := attest.Encode(b, signer)
	if err != nil {
		f.t.Fatalf("Encode: %v", err)
	}
	return data
}

func (f *fixture) pub() [32]byte { return f.signer.Public().Signing }

// buildRecord renders a record straight from the documented layout, without
// going through beat.go's own encoder, and signs it with signer. Tests use it
// for records Encode will not produce — an over-cap body, chiefly — and it
// doubles as a second opinion on the layout: a parser reading a field from
// the wrong offset would disagree with it.
func (f *fixture) buildRecord(b *attest.Beat, body []byte, signer identity.Signer) []byte {
	f.t.Helper()
	out := make([]byte, 0, attest.FixedLen+len(body))
	out = append(out, attest.Magic...)
	out = append(out, attest.FormatV1)
	out = append(out, b.FleetID[:]...)
	out = append(out, b.HostID[:]...)
	out = binary.BigEndian.AppendUint64(out, b.Epoch)
	out = binary.BigEndian.AppendUint64(out, b.Sequence)
	out = binary.BigEndian.AppendUint64(out, uint64(b.SentAt.UnixMilli())) //nolint:gosec // G115: a test's own fixed timestamp.
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))            //nolint:gosec // G115: a test's own body length.
	out = append(out, body...)
	sig, err := signer.Sign(out)
	if err != nil {
		f.t.Fatalf("Sign: %v", err)
	}
	return append(out, sig...)
}

// rawBodyRecord signs a record whose body is exactly the raw bytes given,
// bypassing the Body struct entirely — for asserting that an unrecognized
// key survives Verify.
func (f *fixture) rawBodyRecord(b *attest.Beat, rawBody string) []byte {
	f.t.Helper()
	return f.buildRecord(b, []byte(rawBody), f.signer)
}

func TestAttest_Verify_AcceptsWhatEncodeProduced(t *testing.T) {
	f := newFixture(t)
	want := f.beat(9)

	got, err := attest.Verify(f.encode(want), f.pub())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
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
		t.Errorf("SentAt = %s, want %s", got.SentAt, want.SentAt)
	}
	if diff := cmp.Diff(want.Body, got.Body); diff != "" {
		t.Errorf("Body (-want +got):\n%s", diff)
	}
}

// Section 8: an attacker replaying captured healthy heartbeats could mask a
// dead agent, defeating the most valuable signal the system produces. The
// signature alone does not stop that — it is the hub's sequence check that
// does — so this asserts the fields the hub needs survive the round trip
// intact and unforgeable.
func TestAttest_Verify_RejectsATamperedSequence(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(9))

	data[attest.OffSequence+7] ^= 0x01

	if _, err := attest.Verify(data, f.pub()); !errors.Is(err, attest.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A beat signed by a key other than the one the hub has on file for this
// host must be refused, even though the record is otherwise perfectly
// formed: the signature is the only thing that ties a beat to a host's
// identity, since (unlike a bundle) the record carries no signer key of its
// own to check membership against.
func TestAttest_Verify_RejectsAnotherHostsKey(t *testing.T) {
	f := newFixture(t)
	data := f.encodeWith(f.beat(1), f.attacker)

	if _, err := attest.Verify(data, f.pub()); !errors.Is(err, attest.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A single flipped bit anywhere in the signed region must fail verification,
// including inside the body where the interesting tampering would be. The
// expected error is asserted per region rather than "some error", which also
// pins the ordering: the four bytes of body_len must come back as ErrFormat
// (the record's own length no longer agrees with it), proving the length
// check runs before the signature is ever verified.
func TestAttest_Verify_RejectsEverySingleByteMutation(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(47))

	for i := range data {
		for _, bit := range []byte{0x01, 0x80} {
			mutated := slices.Clone(data)
			mutated[i] ^= bit

			want := attest.ErrBadSignature
			switch {
			case i < attest.MagicLen, i == attest.OffFormat:
				want = attest.ErrFormat
			case i >= attest.OffBodyLen && i < attest.BodyOff:
				// body_len no longer agrees with the record's length.
				want = attest.ErrFormat
			}

			_, err := attest.Verify(mutated, f.pub())
			if !errors.Is(err, want) {
				t.Fatalf("byte %d bit %#x: err = %v, want %v", i, bit, err, want)
			}
		}
	}
}

// An older hub must survive a newer agent's body, since hosts are upgraded
// before the hub in the common case and a hub that 400s every beat from an
// upgraded host turns a routine upgrade into a fleet-wide health blackout.
func TestAttest_Verify_ToleratesUnknownBodyFields(t *testing.T) {
	f := newFixture(t)
	data := f.rawBodyRecord(f.beat(1), `{"agent_version":"9.9.9","a_later_field":42}`)

	b, err := attest.Verify(data, f.pub())
	if err != nil {
		t.Fatalf("Verify with an unknown body field: %v", err)
	}
	if b.Body.AgentVersion != "9.9.9" {
		t.Errorf("AgentVersion = %q, want the field it did understand", b.Body.AgentVersion)
	}
}

func TestAttest_Encode_RejectsAnOversizedBody(t *testing.T) {
	f := newFixture(t)
	b := f.beat(1)
	b.Body.ConfigHash = string(make([]byte, attest.MaxBodyLen+1))

	if _, err := attest.Encode(b, f.signer); !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestAttest_Encode_PropagatesASignerFailure(t *testing.T) {
	f := newFixture(t)
	boom := errors.New("hsm unplugged")

	_, err := attest.Encode(f.beat(1), &stubSigner{Signer: f.signer, signErr: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the signer's own error", err)
	}
}

func TestAttest_Encode_RejectsASignatureOfTheWrongLength(t *testing.T) {
	f := newFixture(t)

	_, err := attest.Encode(f.beat(1), &stubSigner{Signer: f.signer, truncateSig: true})
	if err == nil {
		t.Fatal("Encode accepted a 63-byte signature")
	}
}

// The other direction: what Encode writes must land on the documented
// offsets, checked against the bytes rather than against this package's own
// decoder.
func TestAttest_Encode_EncodesTheDocumentedLayout(t *testing.T) {
	f := newFixture(t)
	b := f.beat(9)
	data := f.encode(b)
	body, err := json.Marshal(&b.Body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	if len(data) != attest.FixedLen+len(body) {
		t.Fatalf("record is %d bytes, want %d", len(data), attest.FixedLen+len(body))
	}
	if got := string(data[attest.OffMagic : attest.OffMagic+attest.MagicLen]); got != attest.Magic {
		t.Errorf("magic = %q, want %q", got, attest.Magic)
	}
	if data[attest.OffFormat] != attest.FormatV1 {
		t.Errorf("format = %d, want %d", data[attest.OffFormat], attest.FormatV1)
	}
	if got := data[attest.OffFleetID : attest.OffFleetID+attest.IDSize]; !bytes.Equal(got, b.FleetID[:]) {
		t.Errorf("fleet_id = %x, want %x", got, b.FleetID)
	}
	if got := data[attest.OffHostID : attest.OffHostID+attest.IDSize]; !bytes.Equal(got, b.HostID[:]) {
		t.Errorf("host_id = %x, want %x", got, b.HostID)
	}
	if got := binary.BigEndian.Uint64(data[attest.OffEpoch:]); got != b.Epoch {
		t.Errorf("epoch = %d, want %d", got, b.Epoch)
	}
	if got := binary.BigEndian.Uint64(data[attest.OffSequence:]); got != b.Sequence {
		t.Errorf("sequence = %d, want %d", got, b.Sequence)
	}
	if got := binary.BigEndian.Uint64(data[attest.OffSentAt:]); got != uint64(b.SentAt.UnixMilli()) { //nolint:gosec // G115: a test's own fixed timestamp.
		t.Errorf("sent_at = %d, want %d", got, b.SentAt.UnixMilli())
	}
	if got := binary.BigEndian.Uint32(data[attest.OffBodyLen:]); got != uint32(len(body)) { //nolint:gosec // G115: a test's own body length.
		t.Errorf("body_len = %d, want %d", got, len(body))
	}
	if got := data[attest.BodyOff : attest.BodyOff+len(body)]; !bytes.Equal(got, body) {
		t.Errorf("body = %q, want %q", got, body)
	}
	key := f.pub()
	if !ed25519.Verify(key[:], data[:attest.BodyOff+len(body)], data[attest.BodyOff+len(body):]) {
		t.Error("signature does not verify over [0, 74+N)")
	}
}

// A record assembled straight from the documented layout, by a test encoder
// that shares no code with Encode, must verify. Without this the tests that
// build records by hand could be passing because the hand-built record is
// malformed in some way nobody intended.
func TestAttest_Verify_AcceptsAHandBuiltRecordMatchingTheDocumentedLayout(t *testing.T) {
	f := newFixture(t)
	want := f.beat(47)
	body, err := json.Marshal(&want.Body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	got, err := attest.Verify(f.buildRecord(want, body, f.signer), f.pub())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Sequence != want.Sequence || got.FleetID != want.FleetID || got.HostID != want.HostID {
		t.Fatalf("got fleet %x host %x sequence %d, want %x / %x / %d",
			got.FleetID, got.HostID, got.Sequence, want.FleetID, want.HostID, want.Sequence)
	}
}

// A body that JSON-decodes to a zero-value Body is a legal record, and
// Verify must decode it correctly rather than tripping over a minimal
// payload. This is the two-byte object "{}", not body_len == 0: an empty
// byte slice is never valid JSON, so a record cannot legally carry a zero
// body at all — "{}" is the smallest one that can.
func TestAttest_Verify_AcceptsAnEmptyBody(t *testing.T) {
	f := newFixture(t)
	want := f.beat(1)

	got, err := attest.Verify(f.buildRecord(want, []byte("{}"), f.signer), f.pub())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Body.AgentVersion != "" {
		t.Errorf("AgentVersion = %q, want empty", got.Body.AgentVersion)
	}
}

// Attacker-controlled length prefix. body_len is read before the signature is
// checked, because the signature covers the body, so it must not be trusted
// to size an allocation.
//
// The body here is valid, parseable JSON — not garbage bytes — so that
// json.Unmarshal would happily succeed if it were ever reached. That is the
// point: only the cap can reject this record. A body of garbage bytes would
// also fail json.Unmarshal and come back as ErrFormat for the wrong reason,
// leaving the cap check itself untested.
func TestAttest_Verify_RejectsAnOversizedBodyLength(t *testing.T) {
	f := newFixture(t)
	// A record that is internally consistent and correctly signed, differing
	// from a valid beat only in being one byte over the cap. Nothing but the
	// bound rejects it.
	b := f.beat(1)
	b.Body.ConfigHash = strings.Repeat("a", attest.MaxBodyLen)
	body, err := json.Marshal(&b.Body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(body) <= attest.MaxBodyLen {
		t.Fatalf("test body is %d bytes, want more than the %d cap", len(body), attest.MaxBodyLen)
	}

	if _, err := attest.Verify(f.buildRecord(b, body, f.signer), f.pub()); !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// An absurd length prefix (0xFFFFFFFF) on an otherwise real, short record
// must never be used to size a slice: this asserts Verify returns ErrFormat
// rather than panicking.
//
// It does not isolate the cap from the exact-length check. In the shipped
// code the cap returns first, but this particular value is refused by either
// control on its own: no short record can ever satisfy
// len(data) == FixedLen + 0xFFFFFFFF, so the exact-length check would catch
// it independently were the cap ever removed. RejectsAnOversizedBodyLength
// isolates the cap; RejectsABodyLengthThatDisagreesWithARecordSize isolates
// the exact-length check. What this test pins down is the outcome — safe
// rejection, not a slice panic — for a value large enough that a naive
// implementation might index with it directly.
func TestAttest_Verify_RejectsAnAbsurdBodyLengthOnAShortRecord(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(1))
	binary.BigEndian.PutUint32(data[attest.OffBodyLen:], ^uint32(0))

	_, err := attest.Verify(data, f.pub())
	if !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// The exact-length check has to run even when the declared body_len sits
// comfortably inside the cap: a within-cap prefix that simply disagrees with
// how many bytes actually followed it must not be sliced past the end of the
// record. Deleting only the exact-length check (leaving the cap in place)
// would try to slice data[BodyOff:BodyOff+bodyLen] on a buffer shorter than
// that and panic — the cap alone cannot catch this, because bodyLen here is
// nowhere near it.
func TestAttest_Verify_RejectsABodyLengthThatDisagreesWithARecordSize(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(1))
	// Well within MaxBodyLen, but there is no such data following the header.
	binary.BigEndian.PutUint32(data[attest.OffBodyLen:], 1000)

	_, err := attest.Verify(data, f.pub())
	if !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestAttest_Verify_RejectsATruncatedRecord(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(1))

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"header only", attest.BodyOff},
		{"one byte short", len(data) - 1},
		{"missing the signature", len(data) - attest.SigLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := attest.Verify(data[:tc.n], f.pub())
			if !errors.Is(err, attest.ErrFormat) {
				t.Fatalf("err = %v, want ErrFormat", err)
			}
		})
	}
}

// Trailing bytes would give one meaning two encodings, and only one of them
// is under the signature.
func TestAttest_Verify_RejectsTrailingBytes(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(1))

	if _, err := attest.Verify(append(data, 0), f.pub()); !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestAttest_Verify_RejectsWrongMagic(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(1))
	copy(data, "postern-BEAT\x00")

	if _, err := attest.Verify(data, f.pub()); !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// A format the hub does not understand is refused outright rather than
// parsed as v1: the layout after byte 13 is only meaningful under a version
// this code knows.
func TestAttest_Verify_RejectsAnUnknownFormatVersion(t *testing.T) {
	f := newFixture(t)
	data := f.encode(f.beat(1))
	data[attest.OffFormat] = 2

	if _, err := attest.Verify(data, f.pub()); !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// A signature is verified over this record, not over some record: a valid
// signature lifted from another beat must not verify here.
func TestAttest_Verify_RejectsASignatureFromADifferentRecord(t *testing.T) {
	f := newFixture(t)
	victim := f.encode(f.beat(1))
	other := f.encode(f.beat(2))
	copy(victim[len(victim)-attest.SigLen:], other[len(other)-attest.SigLen:])

	if _, err := attest.Verify(victim, f.pub()); !errors.Is(err, attest.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A body that fails to decode as JSON at all — as opposed to one merely
// carrying fields Body does not know — is still a malformed record, not a
// tolerated one.
func TestAttest_Verify_RejectsABodyThatIsNotJSON(t *testing.T) {
	f := newFixture(t)
	data := f.rawBodyRecord(f.beat(1), "not json")

	if _, err := attest.Verify(data, f.pub()); !errors.Is(err, attest.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// Every sentinel this package returns has to be distinguishable from every
// other one, or a caller checking for a specific rejection silently matches
// the wrong thing.
func TestAttest_Errors_AreDistinct(t *testing.T) {
	all := []error{attest.ErrFormat, attest.ErrBadSignature}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("errors.Is(%v, %v) is true, but they are different rejections", a, b)
			}
		}
	}
}

// FuzzAttest_Verify asserts that Verify never panics on arbitrary bytes, and
// that anything it does accept parses back to a record with the shape Verify
// claims to guarantee. Verify runs on the hub, parsing bytes that arrived
// over the network from an agent it does not otherwise trust, which is what
// earns a fuzz target.
func FuzzAttest_Verify(f *testing.F) {
	signer, err := identity.Generate("fuzz-host")
	if err != nil {
		f.Fatalf("identity.Generate: %v", err)
	}
	pub := signer.Public().Signing

	valid, err := attest.Encode(&attest.Beat{
		FleetID:  [16]byte{1},
		HostID:   [16]byte{2},
		Epoch:    3,
		Sequence: 9,
		SentAt:   time.Unix(0, 0),
		Body: attest.Body{
			AgentVersion:   "1.0.0",
			ListenerStatus: map[string]string{"udp/62201": "listening"},
			GateElements:   map[string]int{"ssh": 1},
		},
	}, signer)
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}

	f.Add(valid)
	f.Add([]byte{})
	f.Add(valid[:attest.BodyOff])
	f.Add(valid[:len(valid)-1])
	oversize := slices.Clone(valid)
	binary.BigEndian.PutUint32(oversize[attest.OffBodyLen:], ^uint32(0))
	f.Add(oversize)

	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := attest.Verify(data, pub)
		if err != nil {
			if b != nil {
				t.Fatal("Verify returned both a beat and an error")
			}
			return
		}
		if len(b.FleetID) != 16 || len(b.HostID) != 16 {
			t.Fatal("Verify returned a beat with malformed ID fields")
		}
	})
}

// stubSigner wraps a real signer so a test can break exactly one thing about
// it. Everything not overridden is genuine, so a failure is attributable to
// the override.
type stubSigner struct {
	identity.Signer
	signErr     error
	truncateSig bool
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
