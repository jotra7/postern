// Package identity holds operator and host key material.
//
// An identity carries two keypairs: Ed25519 for signing (SPA authorship,
// heartbeats, bundle signatures) and X25519 for encryption (sealing SPA
// packets to a host). The algorithm is tagged rather than assumed, because
// hardware-backed keys are constrained to other curves — Apple's Secure
// Enclave offers P-256 and neither Ed25519 nor X25519 — and a format that
// assumes the algorithm cannot accept one later without a protocol break.
package identity

import (
	"crypto/sha256"
)

// Algorithm names a key suite.
type Algorithm string

// AlgEd25519X25519 is the only suite in v1.
const AlgEd25519X25519 Algorithm = "ed25519+x25519"

// KeyIDSize is the on-the-wire length of a key identifier.
const KeyIDSize = 16

// PublicIdentity is the public half of an identity, safe to publish in
// configuration and bundles.
type PublicIdentity struct {
	Name       string
	Alg        Algorithm
	Signing    [32]byte
	Encryption [32]byte
}

// KeyID is the identifier carried in the SPA packet: the first 16 bytes of
// SHA-256 over the signing public key.
func (p PublicIdentity) KeyID() [KeyIDSize]byte {
	sum := sha256.Sum256(p.Signing[:])
	var id [KeyIDSize]byte
	copy(id[:], sum[:KeyIDSize])
	return id
}
