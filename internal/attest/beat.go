package attest

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jotra7/postern/internal/identity"
)

const (
	// Magic is the fixed 13-byte prefix of every beat record.
	Magic = "postern-beat\x00"
	// FormatV1 is the only record format v1 understands.
	FormatV1 = uint8(1)
	// MaxBodyLen bounds body_len. The prefix is read out of a record whose
	// signature has not been checked yet — the signature covers the body, so
	// the body has to be located before it can be verified — which makes it
	// attacker-controlled input used to size a slice. A beat's body is small,
	// fixed-shape telemetry rather than an arbitrary policy document, so the
	// cap is far tighter than a bundle's: 64 KiB comfortably covers even a
	// host gating a few hundred services without giving an attacker room to
	// force a large allocation.
	MaxBodyLen = 1 << 16
)

// Field offsets and sizes for the signed record. These are the protocol; do
// not derive them from struct layout.
const (
	OffMagic    = 0
	OffFormat   = 13
	OffFleetID  = 14
	OffHostID   = 30
	OffEpoch    = 46
	OffSequence = 54
	OffSentAt   = 62
	OffBodyLen  = 70
	// BodyOff is where the length-prefixed body begins, and so is also the
	// size of the fixed header.
	BodyOff = 74

	MagicLen = 13
	IDSize   = 16
	SigLen   = 64

	// FixedLen is every byte of a record other than the body: the header and
	// the trailing signature. Unlike a bundle record, there is no signer key
	// field here — Verify is handed the one host key a beat must be checked
	// against, rather than a trusted set to search, so there is nothing to
	// re-attribute and nothing to carry.
	FixedLen = BodyOff + SigLen // 138
)

var (
	// ErrFormat means the bytes are not a v1 beat record: wrong length, wrong
	// magic, an unknown format version, a body_len that exceeds MaxBodyLen or
	// disagrees with the record's own length, or a body that is not valid
	// JSON for Body.
	ErrFormat = errors.New("attest: malformed beat")
	// ErrBadSignature means the Ed25519 signature failed verification.
	ErrBadSignature = errors.New("attest: signature verification failed")
)

// Beat is one signed heartbeat: a host asserting, at (Epoch, Sequence), that
// it is alive and reporting what it can see of its own health.
type Beat struct {
	FleetID  [16]byte
	HostID   [16]byte
	Epoch    uint64
	Sequence uint64
	SentAt   time.Time
	Body     Body
}

// Body carries only what the agent can compute today. It is JSON and
// additive: Phase B adds ruleset hashes and the liveness result, and an older
// hub reading a newer body ignores what it does not know. See doc.go for why
// that is deliberate, unlike a bundle's policy.
type Body struct {
	AgentVersion   string            `json:"agent_version"`
	BundleVersion  uint64            `json:"bundle_version"`
	ConfigHash     string            `json:"config_hash"`
	ClockSkewMS    int64             `json:"clock_skew_ms"`
	ListenerStatus map[string]string `json:"listener_status"`
	GateElements   map[string]int    `json:"gate_elements"`
	SPAAccepted    uint64            `json:"spa_accepted"`
	SPARejected    uint64            `json:"spa_rejected"`
	AgentUpHealthy bool              `json:"agent_up_healthy"`
}

// Encode signs b with signer and returns the wire record.
func Encode(b *Beat, signer identity.Signer) ([]byte, error) {
	body, err := json.Marshal(&b.Body)
	if err != nil {
		return nil, fmt.Errorf("attest: marshal body: %w", err)
	}
	if len(body) > MaxBodyLen {
		return nil, fmt.Errorf("%w: body is %d bytes, limit %d", ErrFormat, len(body), MaxBodyLen)
	}

	signed := marshalSigned(b, body)
	sig, err := signer.Sign(signed)
	if err != nil {
		return nil, fmt.Errorf("attest: sign beat: %w", err)
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("attest: signer produced a %d byte signature, want %d", len(sig), SigLen)
	}
	return append(signed, sig...), nil
}

// marshalSigned renders the region the signature covers: the fixed header and
// the body.
func marshalSigned(b *Beat, body []byte) []byte {
	out := make([]byte, BodyOff+len(body))
	copy(out[OffMagic:], Magic)
	out[OffFormat] = FormatV1
	copy(out[OffFleetID:], b.FleetID[:])
	copy(out[OffHostID:], b.HostID[:])
	binary.BigEndian.PutUint64(out[OffEpoch:], b.Epoch)
	binary.BigEndian.PutUint64(out[OffSequence:], b.Sequence)
	//nolint:gosec // G115: UnixMilli is int64 and the record field is 64 bits
	// wide, so this conversion round-trips through time.UnixMilli exactly.
	binary.BigEndian.PutUint64(out[OffSentAt:], uint64(b.SentAt.UnixMilli()))
	//nolint:gosec // G115: the body is bounded by MaxBodyLen (64 KiB) above.
	binary.BigEndian.PutUint32(out[OffBodyLen:], uint32(len(body)))
	copy(out[BodyOff:], body)
	return out
}

// Verify checks data against hostSigningPub — the signing key already on file
// for the host named in the record's HostID, established when that host
// enrolled — and returns the beat it carries.
//
// The order below is the security property, not a style choice: structure is
// established before anything is trusted, and the signature is checked
// before the body is parsed as JSON, so a hostile body can only ever reach
// encoding/json once it is already known to have come from that host's key.
func Verify(data []byte, hostSigningPub [32]byte) (*Beat, error) {
	// 1. Structure. Nothing here is trusted yet; these checks only establish
	//    that the bytes can be indexed as a record at all.
	if len(data) < FixedLen {
		return nil, fmt.Errorf("%w: %d bytes, minimum %d", ErrFormat, len(data), FixedLen)
	}
	if string(data[OffMagic:OffMagic+MagicLen]) != Magic {
		return nil, fmt.Errorf("%w: wrong magic", ErrFormat)
	}
	if data[OffFormat] != FormatV1 {
		return nil, fmt.Errorf("%w: format version %d", ErrFormat, data[OffFormat])
	}
	bodyLen := binary.BigEndian.Uint32(data[OffBodyLen:])
	// The bound is checked before the length prefix is used for anything,
	// including as a slice index, so an absurd prefix can never size an
	// allocation or an index computation.
	if bodyLen > MaxBodyLen {
		return nil, fmt.Errorf("%w: body_len %d exceeds %d", ErrFormat, bodyLen, MaxBodyLen)
	}
	// Exact, not "at least": a record with trailing bytes would give one
	// meaning two encodings, and only one of them is covered by the
	// signature.
	if len(data) != FixedLen+int(bodyLen) {
		return nil, fmt.Errorf("%w: %d bytes, body_len %d implies %d", ErrFormat, len(data), bodyLen, FixedLen+int(bodyLen))
	}
	signedLen := BodyOff + int(bodyLen)

	// 2. Signature, against the one key the caller says this host holds.
	if !ed25519.Verify(hostSigningPub[:], data[:signedLen], data[signedLen:]) {
		return nil, ErrBadSignature
	}

	// 3. Only now are the fields worth reading: everything below this line is
	//    a claim that key made.
	b := &Beat{
		Epoch:    binary.BigEndian.Uint64(data[OffEpoch:]),
		Sequence: binary.BigEndian.Uint64(data[OffSequence:]),
		//nolint:gosec // G115: the field is the exact 64 bits UnixMilli
		// produced, so this restores the original instant.
		SentAt: time.UnixMilli(int64(binary.BigEndian.Uint64(data[OffSentAt:]))).UTC(),
	}
	copy(b.FleetID[:], data[OffFleetID:OffFleetID+IDSize])
	copy(b.HostID[:], data[OffHostID:OffHostID+IDSize])

	// Deliberately encoding/json.Unmarshal, not a decoder with
	// DisallowUnknownFields: see doc.go for why a beat tolerates fields it
	// does not recognize where a bundle's policy must not.
	if err := json.Unmarshal(data[BodyOff:BodyOff+bodyLen], &b.Body); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrFormat, err)
	}
	return b, nil
}
