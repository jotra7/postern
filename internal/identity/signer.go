package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Signer is the seam that lets a hardware-backed key land later without
// touching callers. Private key material never leaves an implementation.
type Signer interface {
	// Public returns the publishable half of this identity.
	Public() PublicIdentity
	// Sign returns a 64-byte Ed25519 signature over msg.
	Sign(msg []byte) ([]byte, error)
	// Precompute derives the shared secret used to seal to, or open from,
	// a peer's encryption key. Callers cache this per peer at startup. It
	// returns an error if peerEncryption is a low-order point: box.Precompute
	// (which calls the deprecated curve25519.ScalarMult) silently writes an
	// all-zero intermediate for such inputs, producing a fixed, publicly
	// computable "shared" secret with no error signal. curve25519.X25519
	// rejects those inputs outright, so this seam can only ever hand callers
	// a value derived from a genuine Diffie-Hellman exchange.
	Precompute(peerEncryption [32]byte) (*[32]byte, error)
	// OpenAnonymous opens a box.SealAnonymous ciphertext sealed to this
	// identity's encryption key. It sits on this seam for the same reason
	// Precompute does: the operation needs the private encryption key, and
	// private key material never leaves an implementation.
	//
	// An anonymous box carries an ephemeral sender key that authenticates
	// nobody, so a successful open means "this was sealed to me" and never
	// "this came from someone I trust". Anyone holding this identity's public
	// encryption key can produce a ciphertext that opens here. Callers that
	// need authenticity establish it separately — internal/bundle verifies an
	// Ed25519 signature over the plaintext against a trusted signer set.
	//
	// The two failure modes are reported separately and must stay that way.
	// ok is false with a nil error when the ciphertext simply did not open,
	// which is the case a caller must not explain to anyone: "sealed to
	// another identity" and "corrupted" are indistinguishable by
	// construction. A non-nil error means the key itself could not be used —
	// a hardware token removed, a device locked, a PIN not supplied — which
	// has nothing to do with the ciphertext and must not be reported to an
	// operator as a key mismatch they will then go looking for.
	OpenAnonymous(sealed []byte) (plaintext []byte, ok bool, err error)
}

type memorySigner struct {
	pub     PublicIdentity
	signing ed25519.PrivateKey
	encrypt [32]byte
}

// Generate creates a fresh identity held in process memory.
func Generate(name string) (Signer, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	encPub, encPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	s := &memorySigner{
		pub: PublicIdentity{
			Name:       name,
			Alg:        AlgEd25519X25519,
			Encryption: *encPub,
		},
		signing: signPriv,
		encrypt: *encPriv,
	}
	copy(s.pub.Signing[:], signPub)
	return s, nil
}

func (s *memorySigner) Public() PublicIdentity { return s.pub }

func (s *memorySigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.signing, msg), nil
}

// Precompute validates the peer key, then delegates the actual derivation to
// box.Precompute rather than replicating it. box.Precompute internally calls
// the deprecated curve25519.ScalarMult, which silently maps a low-order peer
// point to an all-zero intermediate instead of erroring, producing a fixed,
// publicly computable "shared" secret with no error signal. curve25519.X25519
// performs the same scalar multiplication but rejects low-order input, so
// it's used here purely for that validation — its result is discarded, and
// box.Precompute computes the actual returned key. That keeps the derivation
// itself owned by golang.org/x/crypto rather than hand-copied into this
// package, where it would silently drift if box's internals ever changed.
func (s *memorySigner) Precompute(peer [32]byte) (*[32]byte, error) {
	if _, err := curve25519.X25519(s.encrypt[:], peer[:]); err != nil {
		return nil, fmt.Errorf("identity: invalid peer encryption key: %w", err)
	}
	var shared [32]byte
	box.Precompute(&shared, &peer, &s.encrypt)
	return &shared, nil
}

// OpenAnonymous delegates to box.OpenAnonymous, which needs both halves of
// this identity's encryption keypair: the public half to reconstruct the
// nonce the sender derived from it, and the private half for the exchange
// with the ephemeral key the ciphertext carries.
//
// An in-memory key cannot fail to be available, so this implementation never
// returns an error. The error exists for the implementations this seam was
// built for: a key held in hardware fails for reasons that are not "wrong
// ciphertext".
func (s *memorySigner) OpenAnonymous(sealed []byte) ([]byte, bool, error) {
	plaintext, ok := box.OpenAnonymous(nil, sealed, &s.pub.Encryption, &s.encrypt)
	return plaintext, ok, nil
}

// String returns a redacted description safe to pass to fmt or a logger.
// Unexported struct fields are not a defense against reflection: fmt's %v
// and %+v verbs happily print private key bytes held in unexported fields.
// A Signer is exactly the kind of value that ends up in a log line or a
// panic message by accident, so it gets an explicit, deliberately narrow
// Stringer instead of the default struct dump.
func (s *memorySigner) String() string {
	id := s.pub.KeyID()
	return fmt.Sprintf("identity.Signer{name:%q key_id:%x}", s.pub.Name, id)
}

// GoString mirrors String so %#v is equally safe.
func (s *memorySigner) GoString() string {
	return s.String()
}
