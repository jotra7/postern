package spa

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jotra7/postern/internal/identity"
)

// Pong offsets. The record is unencrypted: it travels only over the
// always-allow path, after that path has already been proven trusted by a
// fully authenticated liveness ping, and carries no secret.
const (
	PongOffVersion   = 0
	PongOffAlg       = 1
	PongOffHostID    = 2
	PongOffRequestID = 18
	PongOffChallenge = 34
	PongOffTimestamp = 50
	PongOffSignature = 58

	// PongSignedLen is the region the signature covers.
	PongSignedLen = 58
	// PongSize is the full record.
	PongSize = PongSignedLen + SigLen // 122
)

// ErrPongMismatch means a field did not match what the client sent, or the
// signature or freshness check failed.
var ErrPongMismatch = errors.New("spa: pong did not match the ping it answers")

// Pong is the one reply postern ever emits, and only on the always-allow path
// after full authentication of the corresponding liveness ping. It is signed
// with the host's signing key — the same key that signs health heartbeats —
// rather than encrypted, since the path it travels is already trusted and it
// carries nothing an eavesdropper could use.
//
// What that key signs is PongDomain followed by the record's signed region,
// so a pong signature is not a signature over any other postern record.
type Pong struct {
	Version     uint8
	Alg         uint8
	HostID      [IDSize]byte
	RequestID   [IDSize]byte
	Challenge   [IDSize]byte
	TimestampMS uint64
	Signature   [SigLen]byte
}

func (p *Pong) marshalSigned() []byte {
	b := make([]byte, PongSignedLen)
	b[PongOffVersion] = p.Version
	b[PongOffAlg] = p.Alg
	copy(b[PongOffHostID:], p.HostID[:])
	copy(b[PongOffRequestID:], p.RequestID[:])
	copy(b[PongOffChallenge:], p.Challenge[:])
	binary.BigEndian.PutUint64(b[PongOffTimestamp:], p.TimestampMS)
	return b
}

// signingInput returns the byte string Ed25519 covers: PongDomain followed by
// the signed region. The tag never reaches the wire, so the pong stays
// PongSize bytes.
func (p *Pong) signingInput() []byte {
	b := make([]byte, 0, len(PongDomain)+PongSignedLen)
	b = append(b, PongDomain...)
	return append(b, p.marshalSigned()...)
}

// SignPong signs and renders a pong with the host's signing key.
//
// This takes identity.Signer rather than a narrower ad hoc interface.
// internal/spa already imports internal/identity for Seal and TrialOpen, so
// a smaller interface here would not decouple this package from anything it
// isn't already coupled to — it would just be a second, redundant way to say
// "something that can sign," with no caller ever needing to satisfy it with
// a type that isn't already an identity.Signer. The pong is signed by the
// host's own identity, the same identity.Signer a caller already holds to
// open and reply to the datagram that produced this pong, so asking for that
// concrete interface is both simpler and more precise about who is expected
// to call this.
func SignPong(p *Pong, host identity.Signer) ([]byte, error) {
	sig, err := host.Sign(p.signingInput())
	if err != nil {
		return nil, fmt.Errorf("sign pong: %w", err)
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("spa: pong signature is %d bytes, want %d", len(sig), SigLen)
	}
	copy(p.Signature[:], sig)

	out := make([]byte, PongSize)
	copy(out, p.marshalSigned())
	copy(out[PongOffSignature:], p.Signature[:])
	return out, nil
}

// ParsePong decodes a pong record without verifying it. Call Verify on the
// result before trusting any field.
func ParsePong(b []byte) (*Pong, error) {
	// The pong is the PongSize record followed by a random amount of padding
	// (see Pad), so a length in [PongSize, MaxDatagram] is acceptable and the
	// trailing bytes are discarded; anything shorter or longer is rejected.
	if len(b) < PongSize || len(b) > MaxDatagram {
		return nil, ErrWrongSize
	}
	b = b[:PongSize]
	p := &Pong{
		Version:     b[PongOffVersion],
		Alg:         b[PongOffAlg],
		TimestampMS: binary.BigEndian.Uint64(b[PongOffTimestamp:]),
	}
	copy(p.HostID[:], b[PongOffHostID:PongOffHostID+IDSize])
	copy(p.RequestID[:], b[PongOffRequestID:PongOffRequestID+IDSize])
	copy(p.Challenge[:], b[PongOffChallenge:PongOffChallenge+IDSize])
	copy(p.Signature[:], b[PongOffSignature:PongOffSignature+SigLen])

	if p.Version != Version1 || p.Alg != AlgEd25519X25519 {
		return nil, ErrUnsupportedVersion
	}
	return p, nil
}

// Verify checks every field the client is entitled to expect: that the host
// answering is the host that was pinged, that this pong answers the specific
// ping the client sent — not a captured pong replayed against a later ping —
// that it is fresh, and that it is genuinely signed by that host's key.
//
// Echoing both request_id and challenge_nonce is what closes the replay
// hole: either check alone would let a captured pong answer a different
// later ping that happened to share the other value.
func (p *Pong) Verify(hostSigning [32]byte, wantHostID, wantRequestID, wantChallenge [IDSize]byte, nowMS, windowMS uint64) error {
	if subtle.ConstantTimeCompare(p.HostID[:], wantHostID[:]) != 1 {
		return fmt.Errorf("%w: host_id", ErrPongMismatch)
	}
	if subtle.ConstantTimeCompare(p.RequestID[:], wantRequestID[:]) != 1 {
		return fmt.Errorf("%w: request_id", ErrPongMismatch)
	}
	if subtle.ConstantTimeCompare(p.Challenge[:], wantChallenge[:]) != 1 {
		return fmt.Errorf("%w: challenge nonce", ErrPongMismatch)
	}
	if absDiffUint64(nowMS, p.TimestampMS) > windowMS {
		return fmt.Errorf("%w: timestamp outside the freshness window", ErrPongMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(hostSigning[:]), p.signingInput(), p.Signature[:]) {
		return fmt.Errorf("%w: signature", ErrPongMismatch)
	}
	return nil
}

func absDiffUint64(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
