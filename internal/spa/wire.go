// Package spa implements the single-packet-authorization wire format.
//
// This package performs no I/O and reads no clock: it is the code that parses
// attacker-controlled bytes as root, so it must be fuzzable without a network,
// a host, or a firewall. Callers supply time and keys. seal.go and pong.go
// import internal/identity for Signer, but the fuzz target only exercises
// Parse, which — together with payload.go and fuzz_test.go — imports
// nothing beyond the standard library, so fuzzability holds without a
// network, a host, or a firewall, even though the package as a whole is no
// longer decoupled from internal/identity.
package spa

import "errors"

// Field offsets and sizes for the inner record. These are the protocol; do
// not derive them from struct layout.
const (
	OffVersion   = 0
	OffAlg       = 1
	OffKind      = 2
	OffReserved1 = 3
	OffKeyID     = 4
	OffHostID    = 20
	OffRequestID = 36
	OffCounter   = 52
	OffTimestamp = 60
	OffServiceID = 68
	OffTTL       = 84
	// PayloadOff is where the 32-byte payload union begins.
	PayloadOff   = 86
	OffReserved2 = 118
	OffSignature = 120

	IDSize     = 16
	PayloadLen = 32
	SigLen     = 64

	// SignedLen is the region covered by the signature.
	SignedLen = 120
	// InnerSize is the full plaintext record: the signed region plus the
	// signature itself.
	InnerSize = SignedLen + SigLen // 184
	// NonceSize is the nacl/box nonce prepended to the datagram.
	NonceSize = 24
	// TagSize is the Poly1305 authentication tag box.Seal appends.
	TagSize = 16
	// DatagramSize is the sealed record: the fixed core every datagram begins
	// with, and the only part a receiver parses. The bytes that cross the wire
	// are this core followed by a random amount of padding (see Pad), so the
	// on-wire length varies and is no longer a fingerprint.
	DatagramSize = NonceSize + InnerSize + TagSize // 224
	// MaxDatagram bounds the padded datagram. It keeps the datagram plus a
	// 28-byte IPv4/UDP header under a 1500-byte MTU, so a padded packet never
	// fragments; fragmentation is its own fingerprint and hurts delivery, so it
	// is never allowed. A receiver rejects anything longer in silence.
	MaxDatagram = 1400
)

// Version and Alg values understood by v1.
const (
	Version1         uint8 = 1
	AlgEd25519X25519 uint8 = 1
)

// Domain separation tags. Each is prepended to the bytes handed to Ed25519
// and is never transmitted: the sealed record stays exactly DatagramSize bytes
// and the pong exactly PongSize (the padding appended by Pad is outside the
// record and carries no signature), so nothing an observer can attribute to
// the tag changed. A signer therefore commits to which record type it meant,
// the way the bundle and the beat do with the magic strings they carry on the
// wire.
//
// The two tags here and the two magic strings in internal/bundle and
// internal/attest are checked against each other by
// TestSPA_DomainTags_AreMutuallyNonPrefix, which is what makes "no signature
// over one record type is a signature over another" hold rather than
// depending on the four signed regions happening to differ some other way.
const (
	// RequestDomain prefixes the SPA request's signed region.
	RequestDomain = "postern-spa-request\x00"
	// PongDomain prefixes the liveness pong's signed region.
	PongDomain = "postern-spa-pong\x00"
)

// Kind discriminates the record and its payload variant.
type Kind uint8

const (
	KindGate   Kind = 1
	KindAction Kind = 2
)

// SourceKind selects observed or asserted source semantics for a gate.
type SourceKind uint8

const (
	SourceObserved SourceKind = 0
	SourceAsserted SourceKind = 1
)

var (
	// ErrWrongSize means the buffer is not exactly InnerSize bytes.
	ErrWrongSize = errors.New("spa: record is not the expected size")
	// ErrNotCanonical means a MUST-be-zero byte was set, or a payload did not
	// match the variant its kind selects. A signature must cover exactly one
	// meaning, so a non-canonical encoding is a rejection rather than a
	// tolerated alternative form.
	ErrNotCanonical = errors.New("spa: record is not canonically encoded")
	// ErrUnknownKind means the kind byte is neither gate nor action.
	ErrUnknownKind = errors.New("spa: unknown record kind")
	// ErrUnsupportedVersion means version or alg is not understood.
	ErrUnsupportedVersion = errors.New("spa: unsupported version or algorithm")
)
