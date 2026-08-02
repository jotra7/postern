package vectors

import (
	"crypto/ed25519"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/identity"
)

// The key material behind every published vector.
//
// Test vectors need fixed keys, and a fixed key checked into a public
// repository has to be impossible to mistake for one that protects something.
// These are readable ASCII: each constant below is the private key, byte for
// byte, and each one spells out what it is. An Ed25519 seed and an X25519
// scalar are both 32 arbitrary bytes, so a sentence of exactly the right
// length is as valid a key as any other, and a hex dump of one of these keys
// in a log, a packet capture, or a key file reads "postern v1 TEST VECTOR"
// rather than looking like entropy.
//
// The corresponding public keys and the derived key_id values are published
// too, in docs/vectors/postern-v1.json, so anyone can rebuild every vector
// from these seven strings alone.
const (
	// SeedPrefix begins every key below. It is 23 bytes, leaving a 9-byte
	// role tag in a 32-byte key and a 1-byte tag in a 24-byte SPA nonce.
	SeedPrefix = "postern v1 TEST VECTOR "

	// OperatorSigningSeed is the Ed25519 seed of the operator whose key
	// signs the SPA request vectors.
	OperatorSigningSeed = SeedPrefix + "sign-oper"
	// OperatorEncryptionPrivate is that operator's X25519 private key, which
	// seals the datagram vectors to the host.
	OperatorEncryptionPrivate = SeedPrefix + "encr-oper"

	// HostSigningSeed is the Ed25519 seed of the host whose key signs the
	// pong and the beat.
	HostSigningSeed = SeedPrefix + "sign-host"
	// HostEncryptionPrivate is that host's X25519 private key, which opens
	// the datagram and bundle vectors.
	HostEncryptionPrivate = SeedPrefix + "encr-host"

	// SignerSigningSeed is the Ed25519 seed of the bundle signer.
	SignerSigningSeed = SeedPrefix + "sign-bndl"
	// SignerEncryptionPrivate completes that identity. No vector uses it: a
	// bundle is sealed anonymously, so a bundle signer needs no encryption
	// key at all, and it is here only because an identity carries both.
	SignerEncryptionPrivate = SeedPrefix + "encr-bndl"

	// UntrustedSigningSeed and UntrustedEncryptionPrivate belong to a party
	// no vector's verifier trusts. They exist for the rejection vectors that
	// need a genuine signature from the wrong key.
	UntrustedSigningSeed       = SeedPrefix + "sign-strn"
	UntrustedEncryptionPrivate = SeedPrefix + "encr-strn"
)

func seed32(s string) [32]byte {
	if len(s) != 32 {
		panic(fmt.Sprintf("vectors: seed %q is %d bytes, want 32", s, len(s)))
	}
	return [32]byte([]byte(s))
}

// Operator is the identity that signs and seals the SPA request vectors.
func Operator() identity.Signer {
	return newSigner("vector-operator", OperatorSigningSeed, OperatorEncryptionPrivate)
}

// Host is the identity the datagram and bundle vectors are sealed to, and
// whose key signs the pong and the beat.
func Host() identity.Signer {
	return newSigner("vector-host", HostSigningSeed, HostEncryptionPrivate)
}

// BundleSigner is the identity whose key signs the bundle vector.
func BundleSigner() identity.Signer {
	return newSigner("vector-bundle-signer", SignerSigningSeed, SignerEncryptionPrivate)
}

// Untrusted is a party outside every trusted set in the vectors.
func Untrusted() identity.Signer {
	return newSigner("vector-untrusted", UntrustedSigningSeed, UntrustedEncryptionPrivate)
}

// fixedSigner is an identity.Signer over published key material.
//
// It does not reuse identity.Generate, which draws from crypto/rand and has
// no way to be told which key to produce. Repeating the four method bodies
// here is the price of that, and it buys something as well: the vectors are
// checked against an implementation of the Signer contract that is not the
// one under test, so a vector cannot agree with internal/identity merely by
// having come from it.
type fixedSigner struct {
	pub     identity.PublicIdentity
	signing ed25519.PrivateKey
	encrypt [32]byte
}

func newSigner(name, signingSeed, encryptionPrivate string) identity.Signer {
	seed := seed32(signingSeed)
	priv := ed25519.NewKeyFromSeed(seed[:])
	enc := seed32(encryptionPrivate)

	pub, err := curve25519.X25519(enc[:], curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("vectors: X25519 public key for %q: %v", name, err))
	}

	s := &fixedSigner{
		pub: identity.PublicIdentity{
			Name: name,
			Alg:  identity.AlgEd25519X25519,
		},
		signing: priv,
		encrypt: enc,
	}
	copy(s.pub.Signing[:], priv[32:])
	copy(s.pub.Encryption[:], pub)
	return s
}

func (s *fixedSigner) Public() identity.PublicIdentity { return s.pub }

func (s *fixedSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.signing, msg), nil }

func (s *fixedSigner) Precompute(peer [32]byte) (*[32]byte, error) {
	if _, err := curve25519.X25519(s.encrypt[:], peer[:]); err != nil {
		return nil, fmt.Errorf("vectors: invalid peer encryption key: %w", err)
	}
	var shared [32]byte
	box.Precompute(&shared, &peer, &s.encrypt)
	return &shared, nil
}

func (s *fixedSigner) OpenAnonymous(sealed []byte) ([]byte, bool, error) {
	plaintext, ok := box.OpenAnonymous(nil, sealed, &s.pub.Encryption, &s.encrypt)
	return plaintext, ok, nil
}

// String and GoString keep a fixedSigner out of a log line in the shape of a
// struct dump, for the same reason identity's own signer does. That the key
// is published here is not a reason to print it by accident.
func (s *fixedSigner) String() string {
	id := s.pub.KeyID()
	return fmt.Sprintf("vectors.Signer{name:%q key_id:%x}", s.pub.Name, id)
}

func (s *fixedSigner) GoString() string { return s.String() }
