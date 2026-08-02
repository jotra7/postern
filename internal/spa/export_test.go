package spa

import "github.com/jotra7/postern/internal/identity"

// SealPresigned exposes sealRecord to the external spa_test package so a
// test can build a datagram whose encryption is valid but whose signature is
// not (Sign, corrupt r.Signature, then encrypt exactly what's there).
//
// This file has the _test.go suffix, so the Go toolchain compiles it only
// into the test binary. SealPresigned never exists in a production build:
// it is a test seam, not a second public entry point alongside Seal.
func SealPresigned(r *Request, signer identity.Signer, hostEncryptionPub [32]byte) ([]byte, error) {
	return sealRecord(r, signer, hostEncryptionPub)
}

// MarshalPongUnsigned renders a pong's signed region plus whatever is
// currently in its Signature field, without invoking Sign. This lets a
// golden-vector test pin an arbitrary Signature byte pattern to check the
// Pong record's wire shape, decoupled from Ed25519 signing itself (already
// covered by pong_test.go). Test-only, same rationale as SealPresigned above.
func MarshalPongUnsigned(p *Pong) []byte {
	out := make([]byte, PongSize)
	copy(out, p.marshalSigned())
	copy(out[PongOffSignature:], p.Signature[:])
	return out
}

// PongSigningInput exposes the bytes Ed25519 covers for a pong: PongDomain
// followed by the signed region. The Request half of this pair is exported
// for real (Request.SigningInput), because a client builds and seals requests
// through this package; nothing outside the package builds a pong, so the
// pong's half stays a test seam. Test-only, same rationale as the two above.
func PongSigningInput(p *Pong) []byte { return p.signingInput() }
