package spa_test

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/spa"
)

// This file anchors the wire layout to bytes that do not move when the code
// does. Every other test in this package compares against spa's own
// constants (spa.OffCounter, spa.OffTimestamp, spa.OffTTL, ...), so a change
// that swaps two offsets, or slides one by a byte, re-derives its own
// expectations from the same mutated constants and the suite stays green.
// These hex literals were generated once from the current implementation
// (see the git history of this file for the generator) and are then frozen:
// they are checked in as plain strings, not computed from spa.Marshal at
// test time, so a later layout bug has nothing consistent to compare itself
// against.
//
// Every field below is a distinct, non-overlapping byte pattern —
// KeyID = 01..10, HostID = 11..20, RequestID = 21..30, ServiceID = 31..40,
// Counter = 0102030405060708, TimestampMS = 1112131415161718,
// TTLSeconds = 2122, Signature = 41..80 — specifically so that a bug which
// corrupts one field by reading or writing another's bytes changes the
// decoded value rather than accidentally reproducing it. TestSPA_Golden_*
// verifies both directions: spa.Marshal(value) reproduces the frozen hex,
// and spa.Parse(frozen hex) reproduces the value field by field (not just
// the two scalars plus a byte-equal Marshal output the way
// TestSPA_ParseMarshal_RoundTrips used to).
func idPattern(start byte) [spa.IDSize]byte {
	var b [spa.IDSize]byte
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func sigPattern(start byte) [spa.SigLen]byte {
	var b [spa.SigLen]byte
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

var (
	goldenKeyID     = idPattern(0x01)
	goldenHostID    = idPattern(0x11)
	goldenRequestID = idPattern(0x21)
	goldenServiceID = idPattern(0x31)
	goldenSig       = sigPattern(0x41)
)

// goldenPongHex is the frozen liveness pong. It is a package-level constant
// rather than a local one because two tests read it: the layout check below
// and the cross-check against the published vectors.
const goldenPongHex = "01018182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"

func goldenConfirmNonce() [16]byte {
	var b [16]byte
	for i := range b {
		b[i] = 0x51 + byte(i)
	}
	return b
}

func goldenLivenessChallenge() [16]byte {
	var b [16]byte
	for i := range b {
		b[i] = 0x71 + byte(i)
	}
	return b
}

type goldenRequestCase struct {
	name string
	hex  string
	want *spa.Request
}

func goldenRequestCases(t *testing.T) []goldenRequestCase {
	t.Helper()

	mk := func(kind spa.Kind, counter, ts uint64, ttl uint16, payload [spa.PayloadLen]byte) *spa.Request {
		return &spa.Request{
			Version:     spa.Version1,
			Alg:         spa.AlgEd25519X25519,
			Kind:        kind,
			KeyID:       goldenKeyID,
			HostID:      goldenHostID,
			RequestID:   goldenRequestID,
			ServiceID:   goldenServiceID,
			Counter:     counter,
			TimestampMS: ts,
			TTLSeconds:  ttl,
			Payload:     payload,
			Signature:   goldenSig,
		}
	}

	observedPl, err := spa.EncodeGatePayload(spa.GatePayload{SourceKind: spa.SourceObserved})
	if err != nil {
		t.Fatalf("EncodeGatePayload(observed): %v", err)
	}
	v4Pl, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     netip.MustParsePrefix("198.51.100.0/24"),
	})
	if err != nil {
		t.Fatalf("EncodeGatePayload(asserted v4): %v", err)
	}
	v6Pl, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     netip.MustParsePrefix("2001:db8::/32"),
	})
	if err != nil {
		t.Fatalf("EncodeGatePayload(asserted v6): %v", err)
	}
	confirmPl, err := spa.EncodeConfirmPayload(0x6162636465666768, goldenConfirmNonce())
	if err != nil {
		t.Fatalf("EncodeConfirmPayload: %v", err)
	}
	disarmPl, err := spa.EncodeDisarmPayload()
	if err != nil {
		t.Fatalf("EncodeDisarmPayload: %v", err)
	}
	livenessPl, err := spa.EncodeLivenessPayload(goldenLivenessChallenge())
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}

	const (
		gateCounter = 0x0102030405060708
		gateTS      = 0x1112131415161718
		gateTTL     = 0x2122
	)

	return []goldenRequestCase{
		{
			name: "gate-observed",
			hex:  "010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30010203040506070811121314151617183132333435363738393a3b3c3d3e3f402122000000000000000000000000000000000000000000000000000000000000000000004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
			want: mk(spa.KindGate, gateCounter, gateTS, gateTTL, observedPl),
		},
		{
			name: "gate-asserted-v4",
			hex:  "010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30010203040506070811121314151617183132333435363738393a3b3c3d3e3f402122010418c63364000000000000000000000000000000000000000000000000000000004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
			want: mk(spa.KindGate, gateCounter, gateTS, gateTTL, v4Pl),
		},
		{
			name: "gate-asserted-v6",
			hex:  "010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30010203040506070811121314151617183132333435363738393a3b3c3d3e3f40212201062020010db80000000000000000000000000000000000000000000000000000004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
			want: mk(spa.KindGate, gateCounter, gateTS, gateTTL, v6Pl),
		},
		{
			name: "confirm",
			hex:  "010102000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30000000000000000011121314151617183132333435363738393a3b3c3d3e3f40000061626364656667685152535455565758595a5b5c5d5e5f60000000000000000000004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
			want: mk(spa.KindAction, 0, gateTS, 0, confirmPl),
		},
		{
			name: "disarm",
			hex:  "010102000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30000000000000000011121314151617183132333435363738393a3b3c3d3e3f400000000000000000000000000000000000000000000000000000000000000000000000004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
			want: mk(spa.KindAction, 0, gateTS, 0, disarmPl),
		},
		{
			name: "liveness",
			hex:  "010102000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30000000000000000011121314151617183132333435363738393a3b3c3d3e3f4000007172737475767778797a7b7c7d7e7f800000000000000000000000000000000000004142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
			want: mk(spa.KindAction, 0, gateTS, 0, livenessPl),
		},
	}
}

// TestSPA_Golden_MarshalProducesFrozenBytes is direction one: encoding a
// fully-specified value must reproduce the exact frozen wire bytes. Unlike
// TestSPA_Marshal_ProducesExactWireSizes, this pins actual content, not just
// length, so a field written at the wrong offset changes the output even
// though the length stays correct.
func TestSPA_Golden_MarshalProducesFrozenBytes(t *testing.T) {
	for _, tc := range goldenRequestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("bad golden hex fixture: %v", err)
			}
			got := tc.want.Marshal()
			if !bytes.Equal(got, want) {
				t.Fatalf("Marshal() = %x, want frozen golden %x", got, want)
			}
		})
	}
}

// TestSPA_Golden_ParseProducesFrozenValue is direction two: parsing the
// frozen bytes must reproduce the fixture value, field by field — KeyID,
// HostID, RequestID, ServiceID, Counter, TimestampMS, TTLSeconds, Payload,
// and Signature are all compared individually, not just the two scalars
// TestSPA_ParseMarshal_RoundTrips checked before this. A layout bug that
// swaps two field offsets, or shifts one into another's territory, corrupts
// exactly the fields whose bytes moved while leaving Parse(Marshal(x))=x
// (self-consistent round trip) intact — this test is what catches that,
// because the "expected" side comes from a frozen literal rather than from
// the same (possibly mutated) offsets used to encode it.
func TestSPA_Golden_ParseProducesFrozenValue(t *testing.T) {
	for _, tc := range goldenRequestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("bad golden hex fixture: %v", err)
			}
			got, err := spa.Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := tc.want

			if got.Version != want.Version {
				t.Errorf("Version = %v, want %v", got.Version, want.Version)
			}
			if got.Alg != want.Alg {
				t.Errorf("Alg = %v, want %v", got.Alg, want.Alg)
			}
			if got.Kind != want.Kind {
				t.Errorf("Kind = %v, want %v", got.Kind, want.Kind)
			}
			if got.KeyID != want.KeyID {
				t.Errorf("KeyID = %x, want %x", got.KeyID, want.KeyID)
			}
			if got.HostID != want.HostID {
				t.Errorf("HostID = %x, want %x", got.HostID, want.HostID)
			}
			if got.RequestID != want.RequestID {
				t.Errorf("RequestID = %x, want %x", got.RequestID, want.RequestID)
			}
			if got.ServiceID != want.ServiceID {
				t.Errorf("ServiceID = %x, want %x", got.ServiceID, want.ServiceID)
			}
			if got.Counter != want.Counter {
				t.Errorf("Counter = %d, want %d", got.Counter, want.Counter)
			}
			if got.TimestampMS != want.TimestampMS {
				t.Errorf("TimestampMS = %d, want %d", got.TimestampMS, want.TimestampMS)
			}
			if got.TTLSeconds != want.TTLSeconds {
				t.Errorf("TTLSeconds = %d, want %d", got.TTLSeconds, want.TTLSeconds)
			}
			if got.Payload != want.Payload {
				t.Errorf("Payload = %x, want %x", got.Payload, want.Payload)
			}
			if got.Signature != want.Signature {
				t.Errorf("Signature = %x, want %x", got.Signature, want.Signature)
			}
		})
	}
}

// TestSPA_Golden_AgreeWithThePublishedVectors keeps the two sets of frozen
// bytes in this repository from drifting apart. The fixtures above and
// docs/vectors/postern-v1.json describe the same six records and the same
// pong, and section 13 of the specification asks that neither can move
// without the other going red.
//
// They are not byte-identical, and the one place they differ is the point.
// goldenKeyID is the pattern 01..10, chosen so that a bug copying another
// field over key_id changes the decoded value; a published vector's key_id
// has to be the real truncated SHA-256 of the operator signing key it
// publishes, or the datagram would not survive the agent's key_id check. So
// the comparison is over the signed region with those 16 bytes lifted out,
// which still covers every offset, every length and every payload encoding.
func TestSPA_Golden_AgreeWithThePublishedVectors(t *testing.T) {
	f := loadVectors(t)

	published := map[string][]byte{}
	for _, v := range f.SPARequests {
		published[v.Name] = mustHex(t, v.SignedRegionHex)
	}

	for _, tc := range goldenRequestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			want, ok := published[tc.name]
			if !ok {
				t.Fatalf("the vector file publishes no request named %q", tc.name)
			}
			golden, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("bad golden hex fixture: %v", err)
			}
			got := golden[:spa.SignedLen]

			if len(got) != len(want) {
				t.Fatalf("signed region is %d bytes here and %d in the vector file", len(got), len(want))
			}
			if !bytes.Equal(got[:spa.OffKeyID], want[:spa.OffKeyID]) {
				t.Errorf("bytes before key_id: %x here, %x in the vector file", got[:spa.OffKeyID], want[:spa.OffKeyID])
			}
			after := spa.OffKeyID + spa.IDSize
			if !bytes.Equal(got[after:], want[after:]) {
				t.Errorf("bytes after key_id: %x here, %x in the vector file", got[after:], want[after:])
			}
			if bytes.Equal(got[spa.OffKeyID:after], want[spa.OffKeyID:after]) {
				t.Errorf("key_id is %x in both, so one of them is no longer what it was chosen to be: "+
					"the fixture's is a byte pattern and the vector's is a derived key_id", got[spa.OffKeyID:after])
			}
		})
	}

	t.Run("pong", func(t *testing.T) {
		golden, err := hex.DecodeString(goldenPongHex)
		if err != nil {
			t.Fatalf("bad golden hex fixture: %v", err)
		}
		want := mustHex(t, f.Pong.SignedRegionHex)
		if got := golden[:spa.PongSignedLen]; !bytes.Equal(got, want) {
			t.Fatalf("pong signed region = %x here, %x in the vector file", got, want)
		}
	})
}

// TestSPA_Golden_Pong is the liveness pong's golden vector: one
// fully-specified record, its frozen wire bytes, and both directions.
// MarshalPongUnsigned (export_test.go) renders the signed region plus
// whatever the fixture set in Signature, without invoking Ed25519 signing —
// this test is about the record's byte layout, not signature validity,
// which pong_test.go already covers.
func TestSPA_Golden_Pong(t *testing.T) {
	p := &spa.Pong{
		Version:     spa.Version1,
		Alg:         spa.AlgEd25519X25519,
		HostID:      idPattern(0x81),
		RequestID:   idPattern(0x91),
		Challenge:   idPattern(0xA1),
		TimestampMS: 0xB1B2B3B4B5B6B7B8,
		Signature:   sigPattern(0xC1),
	}

	want, err := hex.DecodeString(goldenPongHex)
	if err != nil {
		t.Fatalf("bad golden hex fixture: %v", err)
	}

	got := spa.MarshalPongUnsigned(p)
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalPongUnsigned() = %x, want frozen golden %x", got, want)
	}

	parsed, err := spa.ParsePong(want)
	if err != nil {
		t.Fatalf("ParsePong: %v", err)
	}
	if parsed.Version != p.Version {
		t.Errorf("Version = %v, want %v", parsed.Version, p.Version)
	}
	if parsed.Alg != p.Alg {
		t.Errorf("Alg = %v, want %v", parsed.Alg, p.Alg)
	}
	if parsed.HostID != p.HostID {
		t.Errorf("HostID = %x, want %x", parsed.HostID, p.HostID)
	}
	if parsed.RequestID != p.RequestID {
		t.Errorf("RequestID = %x, want %x", parsed.RequestID, p.RequestID)
	}
	if parsed.Challenge != p.Challenge {
		t.Errorf("Challenge = %x, want %x", parsed.Challenge, p.Challenge)
	}
	if parsed.TimestampMS != p.TimestampMS {
		t.Errorf("TimestampMS = %d, want %d", parsed.TimestampMS, p.TimestampMS)
	}
	if parsed.Signature != p.Signature {
		t.Errorf("Signature = %x, want %x", parsed.Signature, p.Signature)
	}
}
