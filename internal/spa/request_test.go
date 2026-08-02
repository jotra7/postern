package spa_test

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/spa"
)

func sampleGate() *spa.Request {
	r := &spa.Request{
		Version:     1,
		Alg:         1,
		Kind:        spa.KindGate,
		Counter:     1_700_000_000_000,
		TimestampMS: 1_700_000_000_000,
		TTLSeconds:  120,
	}
	for i := range r.KeyID {
		r.KeyID[i] = byte(i)
		r.HostID[i] = byte(i + 100)
		r.RequestID[i] = byte(i + 200)
		r.ServiceID[i] = byte(i + 50)
	}
	pl, err := spa.EncodeGatePayload(spa.GatePayload{SourceKind: spa.SourceObserved})
	if err != nil {
		panic(err)
	}
	r.Payload = pl
	for i := range r.Signature {
		r.Signature[i] = byte(i)
	}
	return r
}

func TestSPA_Marshal_ProducesExactWireSizes(t *testing.T) {
	r := sampleGate()
	if got := len(r.MarshalSigned()); got != spa.SignedLen {
		t.Fatalf("signed region = %d bytes, want %d", got, spa.SignedLen)
	}
	if got := len(r.Marshal()); got != spa.InnerSize {
		t.Fatalf("inner record = %d bytes, want %d", got, spa.InnerSize)
	}
}

func TestSPA_ParseMarshal_RoundTrips(t *testing.T) {
	orig := sampleGate()
	got, err := spa.Parse(orig.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(got.Marshal(), orig.Marshal()) {
		t.Fatal("round trip changed the encoding")
	}
	// Every field, not just TTLSeconds and Counter: a layout bug that
	// corrupts one field by reading or writing another's bytes can still
	// leave Marshal() byte-identical (both sides use the same, possibly
	// wrong, offsets) while silently swapping content between fields. See
	// golden_test.go for the complementary check that pins expected bytes
	// independently of whatever offsets Parse/Marshal currently use.
	if got.Version != orig.Version {
		t.Errorf("Version = %v, want %v", got.Version, orig.Version)
	}
	if got.Alg != orig.Alg {
		t.Errorf("Alg = %v, want %v", got.Alg, orig.Alg)
	}
	if got.Kind != orig.Kind {
		t.Errorf("Kind = %v, want %v", got.Kind, orig.Kind)
	}
	if got.KeyID != orig.KeyID {
		t.Errorf("KeyID = %x, want %x", got.KeyID, orig.KeyID)
	}
	if got.HostID != orig.HostID {
		t.Errorf("HostID = %x, want %x", got.HostID, orig.HostID)
	}
	if got.RequestID != orig.RequestID {
		t.Errorf("RequestID = %x, want %x", got.RequestID, orig.RequestID)
	}
	if got.ServiceID != orig.ServiceID {
		t.Errorf("ServiceID = %x, want %x", got.ServiceID, orig.ServiceID)
	}
	if got.Counter != orig.Counter {
		t.Errorf("Counter = %d, want %d", got.Counter, orig.Counter)
	}
	if got.TimestampMS != orig.TimestampMS {
		t.Errorf("TimestampMS = %d, want %d", got.TimestampMS, orig.TimestampMS)
	}
	if got.TTLSeconds != orig.TTLSeconds {
		t.Errorf("TTLSeconds = %d, want %d", got.TTLSeconds, orig.TTLSeconds)
	}
	if got.Payload != orig.Payload {
		t.Errorf("Payload = %x, want %x", got.Payload, orig.Payload)
	}
	if got.Signature != orig.Signature {
		t.Errorf("Signature = %x, want %x", got.Signature, orig.Signature)
	}
}

func TestSPA_Parse_RejectsWrongSize(t *testing.T) {
	r := sampleGate().Marshal()
	for _, n := range []int{0, 1, spa.InnerSize - 1, spa.InnerSize + 1} {
		buf := make([]byte, n)
		copy(buf, r)
		if _, err := spa.Parse(buf); !errors.Is(err, spa.ErrWrongSize) {
			t.Errorf("Parse(%d bytes) = %v, want ErrWrongSize", n, err)
		}
	}
}

func TestSPA_Parse_RejectsEveryNonZeroReservedByte(t *testing.T) {
	// Canonical encoding is what makes a signature cover exactly one meaning.
	// These are the two record-level MUST-be-zero positions: the single
	// filler byte after kind, and the two-byte filler before the signature.
	// Reserved regions inside a payload variant are covered separately below
	// (TestSPA_Parse_RejectsEveryNonZeroReservedByteInPayloadVariants) — this
	// test's name only speaks to the top-level record.
	reserved := []int{3, 118, 119}
	for _, off := range reserved {
		buf := sampleGate().Marshal()
		buf[off] = 0x01
		if _, err := spa.Parse(buf); !errors.Is(err, spa.ErrNotCanonical) {
			t.Errorf("Parse with reserved byte %d set = %v, want ErrNotCanonical", off, err)
		}
	}
}

// TestSPA_Parse_RejectsEveryNonZeroReservedByteInPayloadVariants closes the
// gap the test above leaves open: every payload variant has its own
// MUST-be-zero bytes (observed source, the v4 address-slot gap, the asserted
// tail, confirm's tail, liveness's tail), and each one must be enforced
// independently or a signature could cover more than one meaning.
func TestSPA_Parse_RejectsEveryNonZeroReservedByteInPayloadVariants(t *testing.T) {
	observedPayload, err := spa.EncodeGatePayload(spa.GatePayload{SourceKind: spa.SourceObserved})
	if err != nil {
		t.Fatalf("EncodeGatePayload(observed): %v", err)
	}
	assertedV4Payload, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     netip.MustParsePrefix("198.51.100.0/24"),
	})
	if err != nil {
		t.Fatalf("EncodeGatePayload(asserted v4): %v", err)
	}
	confirmPayload, err := spa.EncodeConfirmPayload(1, [16]byte{})
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	var challenge [16]byte
	livenessPayload, err := spa.EncodeLivenessPayload(challenge)
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}

	cases := []struct {
		name           string
		kind           spa.Kind
		payload        [spa.PayloadLen]byte
		reservedOffset int // offset within the 32-byte payload
	}{
		{"observed byte 1", spa.KindGate, observedPayload, 1},
		{"observed byte 31", spa.KindGate, observedPayload, 31},
		{"asserted v4 gap byte 7", spa.KindGate, assertedV4Payload, 7},
		{"asserted v4 gap byte 18", spa.KindGate, assertedV4Payload, 18},
		{"asserted tail byte 19", spa.KindGate, assertedV4Payload, 19},
		{"asserted tail byte 31", spa.KindGate, assertedV4Payload, 31},
		{"confirm tail byte 24", spa.KindAction, confirmPayload, 24},
		{"confirm tail byte 31", spa.KindAction, confirmPayload, 31},
		{"liveness tail byte 16", spa.KindAction, livenessPayload, 16},
		{"liveness tail byte 31", spa.KindAction, livenessPayload, 31},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleGate()
			r.Kind = tc.kind
			if tc.kind == spa.KindAction {
				r.Counter = 0
				r.TTLSeconds = 0
			}
			r.Payload = tc.payload
			r.Payload[tc.reservedOffset] = 0xff

			_, err := spa.Parse(r.Marshal())
			if tc.kind == spa.KindGate {
				// Parse validates the gate payload itself.
				if !errors.Is(err, spa.ErrNotCanonical) {
					t.Fatalf("Parse = %v, want ErrNotCanonical", err)
				}
				return
			}
			// Parse cannot canonicalize an action's payload without knowing
			// the sub-type (that needs service_id from config, which this
			// package does not import), so it must succeed here and the
			// specific accessor rejects the tampered byte instead.
			if err != nil {
				t.Fatalf("Parse = %v, want success (action canonicalisation is deferred to the accessor)", err)
			}
		})
	}
}

func TestSPA_ConfirmPayload_RejectsNonZeroTailByte(t *testing.T) {
	pl, err := spa.EncodeConfirmPayload(1, [16]byte{})
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	r := sampleGate()
	r.Kind = spa.KindAction
	r.Counter = 0
	r.TTLSeconds = 0
	r.Payload = pl
	r.Payload[24] = 0xff

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, _, err := parsed.ConfirmPayload(); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("ConfirmPayload = %v, want ErrNotCanonical", err)
	}
}

func TestSPA_LivenessPayload_RejectsNonZeroTailByte(t *testing.T) {
	var challenge [16]byte
	pl, err := spa.EncodeLivenessPayload(challenge)
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}
	r := sampleGate()
	r.Kind = spa.KindAction
	r.Counter = 0
	r.TTLSeconds = 0
	r.Payload = pl
	r.Payload[16] = 0xff

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.LivenessPayload(); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("LivenessPayload = %v, want ErrNotCanonical", err)
	}
}

func TestSPA_DisarmPayload_RejectsNonZeroByte(t *testing.T) {
	r := sampleGate()
	r.Kind = spa.KindAction
	r.Counter = 0
	r.TTLSeconds = 0
	r.Payload = [32]byte{}
	r.Payload[0] = 0x01

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := parsed.DisarmPayload(); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("DisarmPayload = %v, want ErrNotCanonical", err)
	}
}

func TestSPA_Parse_RejectsActionWithNonZeroCounter(t *testing.T) {
	// An action with a free counter could raise the operator's high-water mark
	// and silently disable drift tolerance for later gate requests.
	r := sampleGate()
	r.Kind = spa.KindAction
	r.TTLSeconds = 0
	r.Counter = 12345
	r.Payload = [32]byte{} // disarm shape
	if _, err := spa.Parse(r.Marshal()); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("Parse = %v, want ErrNotCanonical for an action with a counter", err)
	}
}

func TestSPA_Parse_RejectsActionWithNonZeroTTL(t *testing.T) {
	r := sampleGate()
	r.Kind = spa.KindAction
	r.Counter = 0
	r.TTLSeconds = 30
	r.Payload = [32]byte{}
	if _, err := spa.Parse(r.Marshal()); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("Parse = %v, want ErrNotCanonical for an action with a TTL", err)
	}
}

func TestSPA_Parse_RejectsUnknownKind(t *testing.T) {
	buf := sampleGate().Marshal()
	buf[2] = 9
	if _, err := spa.Parse(buf); !errors.Is(err, spa.ErrUnknownKind) {
		t.Fatalf("Parse = %v, want ErrUnknownKind", err)
	}
}

// TestSPA_Parse_RejectsUnsupportedVersionOrAlg guards the branch that gates
// acceptance of every packet the agent will ever see: without it, a record
// with an unknown version or algorithm would parse as if it were v1.
func TestSPA_Parse_RejectsUnsupportedVersionOrAlg(t *testing.T) {
	cases := []struct {
		name    string
		version uint8
		alg     uint8
	}{
		{"unknown version", 2, 1},
		{"unknown alg", 1, 2},
		{"both zero", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleGate()
			r.Version = tc.version
			r.Alg = tc.alg
			if _, err := spa.Parse(r.Marshal()); !errors.Is(err, spa.ErrUnsupportedVersion) {
				t.Fatalf("Parse(version=%d, alg=%d) = %v, want ErrUnsupportedVersion", tc.version, tc.alg, err)
			}
		})
	}
}

func TestSPA_GatePayload_ObservedRequiresAllSourceBytesZero(t *testing.T) {
	r := sampleGate()
	r.Payload[3] = 0x0a // stray address byte with source_kind = observed
	if _, err := spa.Parse(r.Marshal()); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("Parse = %v, want ErrNotCanonical", err)
	}
}

func TestSPA_GatePayload_AssertedRoundTrips(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	pl, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     prefix,
	})
	if err != nil {
		t.Fatalf("EncodeGatePayload: %v", err)
	}
	r := sampleGate()
	r.Payload = pl

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gp, err := parsed.GatePayload()
	if err != nil {
		t.Fatalf("GatePayload: %v", err)
	}
	if gp.Prefix != prefix {
		t.Fatalf("prefix = %v, want %v", gp.Prefix, prefix)
	}
}

func TestSPA_GatePayload_AssertedIPv6RoundTrips(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/32")
	pl, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     prefix,
	})
	if err != nil {
		t.Fatalf("EncodeGatePayload: %v", err)
	}
	r := sampleGate()
	r.Payload = pl

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gp, err := parsed.GatePayload()
	if err != nil {
		t.Fatalf("GatePayload: %v", err)
	}
	if gp.Prefix != prefix {
		t.Fatalf("prefix = %v, want %v", gp.Prefix, prefix)
	}
}

func TestSPA_EncodeGatePayload_RejectsNonZeroHostBits(t *testing.T) {
	// One network must have exactly one signed encoding.
	_, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     netip.MustParsePrefix("198.51.100.7/24"),
	})
	if err == nil {
		t.Fatal("EncodeGatePayload accepted a prefix with non-zero host bits")
	}
}

// TestSPA_GatePayload_RejectsAssertedIPv4WithNonZeroHostBitsInAddress hand-
// builds the 32-byte payload directly rather than going through
// EncodeGatePayload, because an attacker never calls EncodeGatePayload — they
// craft the payload bytes and send them. The host bit is set inside the
// address bytes themselves (198.51.100.5 under a /24), not in the reserved
// gap that sits next to it, so this exercises the
// `pfx.Masked() != pfx` mask check in GatePayload and nothing else.
func TestSPA_GatePayload_RejectsAssertedIPv4WithNonZeroHostBitsInAddress(t *testing.T) {
	var payload [spa.PayloadLen]byte
	payload[0] = byte(spa.SourceAsserted)
	payload[1] = 4  // family
	payload[2] = 24 // prefix length
	addr := netip.MustParseAddr("198.51.100.5").As4()
	copy(payload[3:7], addr[:]) // .5 is a host bit under /24

	r := sampleGate()
	r.Payload = payload

	if _, err := spa.Parse(r.Marshal()); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("Parse = %v, want ErrNotCanonical for an asserted /24 whose address has a set host bit", err)
	}
}

// TestSPA_GatePayload_RejectsAssertedIPv6WithNonZeroHostBitsInAddress is the
// v6 equivalent of the test above: 2001:db8::1 under a /32 has its trailing
// host bit set inside the 16-byte address field, not in any reserved region.
func TestSPA_GatePayload_RejectsAssertedIPv6WithNonZeroHostBitsInAddress(t *testing.T) {
	var payload [spa.PayloadLen]byte
	payload[0] = byte(spa.SourceAsserted)
	payload[1] = 6  // family
	payload[2] = 32 // prefix length
	addr := netip.MustParseAddr("2001:db8::1").As16()
	copy(payload[3:19], addr[:])

	r := sampleGate()
	r.Payload = payload

	if _, err := spa.Parse(r.Marshal()); !errors.Is(err, spa.ErrNotCanonical) {
		t.Fatalf("Parse = %v, want ErrNotCanonical for an asserted /32 whose address has a set host bit", err)
	}
}

func TestSPA_ConfirmPayload_RoundTrips(t *testing.T) {
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i + 7)
	}
	pl, err := spa.EncodeConfirmPayload(42, nonce)
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}

	r := sampleGate()
	r.Kind = spa.KindAction
	r.Counter = 0
	r.TTLSeconds = 0
	r.Payload = pl

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rev, gotNonce, err := parsed.ConfirmPayload()
	if err != nil {
		t.Fatalf("ConfirmPayload: %v", err)
	}
	if rev != 42 || gotNonce != nonce {
		t.Fatalf("ConfirmPayload = (%d, %x), want (42, %x)", rev, gotNonce, nonce)
	}
}

func TestSPA_LivenessPayload_RoundTrips(t *testing.T) {
	var challenge [16]byte
	for i := range challenge {
		challenge[i] = byte(255 - i)
	}
	pl, err := spa.EncodeLivenessPayload(challenge)
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}

	r := sampleGate()
	r.Kind = spa.KindAction
	r.Counter = 0
	r.TTLSeconds = 0
	r.Payload = pl

	parsed, err := spa.Parse(r.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := parsed.LivenessPayload()
	if err != nil {
		t.Fatalf("LivenessPayload: %v", err)
	}
	if got != challenge {
		t.Fatalf("challenge = %x, want %x", got, challenge)
	}
}
