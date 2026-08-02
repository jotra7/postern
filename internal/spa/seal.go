package spa

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/identity"
)

var (
	// ErrNoOperator means no trusted operator's shared secret opened the
	// datagram. This is the common case for garbage and for forged packets,
	// and it is also what a corrupted ciphertext or authentication tag
	// produces: Poly1305 rejection looks identical to "not one of ours" by
	// design, so a remote party learns nothing about which stage failed.
	ErrNoOperator = errors.New("spa: no trusted operator opened this datagram")
	// ErrKeyIDMismatch means the payload claims an operator other than the
	// one whose shared secret decrypted it.
	ErrKeyIDMismatch = errors.New("spa: key_id does not match the decrypting operator")
	// ErrBadSignature means the Ed25519 signature failed verification.
	ErrBadSignature = errors.New("spa: signature verification failed")
)

// Opener holds precomputed shared secrets, one per trusted operator, so a
// trial decrypt costs a Poly1305 verification rather than a scalar multiply.
type Opener struct {
	operators []identity.PublicIdentity
	shared    []*[32]byte
}

// NewOpenerFromSigner builds an Opener from the host's own signer, which owns
// the private encryption key, and the set of trusted operators.
//
// An operator whose encryption key is rejected — a low-order point, which
// identity.Signer.Precompute refuses rather than silently deriving a fixed,
// publicly computable shared secret (see that method's doc comment) — is
// skipped rather than fatal: one bad key in a fleet must not stop the agent
// from opening packets for every other operator.
//
// Partial success is reported through the rejected return value, a slice of
// the names of operators whose key was rejected, rather than through the
// error. This is deliberate: partial success and total failure are not the
// same outcome, and folding both into "check err" makes them indistinguishable
// to a caller. The universal Go idiom
//
//	opener, err := spa.NewOpenerFromSigner(host, ops)
//	if err != nil { return err }
//
// must not refuse to start an agent merely because one operator in the
// bundle has a bad key — that is an availability failure in a tool whose
// whole purpose is break-glass access. err is non-nil only when the returned
// Opener is unusable (nil), i.e. when every operator was rejected; a caller
// that wants to surface individually-rejected operators (to fix a key, or
// just to log it) inspects the rejected slice, which is populated whenever
// it is non-empty regardless of whether err is nil.
//
// An operator whose signing key is this host's own signing key is rejected
// the same way. That key would sign in the operator role, over SPA requests,
// and in the host role, over pongs and heartbeats. RequestDomain and
// PongDomain are what stop either signature standing in for the other; this
// refusal is what keeps the roles disjoint in the first place, and it belongs
// here because both halves of the pairing arrive here as arguments.
func NewOpenerFromSigner(host identity.Signer, operators []identity.PublicIdentity) (opener *Opener, rejected []string, err error) {
	o := &Opener{}
	hostSigning := host.Public().Signing
	for _, op := range operators {
		if op.Signing == hostSigning {
			rejected = append(rejected, op.Name)
			continue
		}
		shared, perr := host.Precompute(op.Encryption)
		if perr != nil {
			rejected = append(rejected, op.Name)
			continue
		}
		o.operators = append(o.operators, op)
		o.shared = append(o.shared, shared)
	}
	if len(o.operators) == 0 {
		return nil, rejected, fmt.Errorf("spa: no usable operator keys (%d rejected: %v)", len(rejected), rejected)
	}
	return o, rejected, nil
}

// TrialOpen decrypts, identifies the sender, parses, and verifies the
// signature.
//
// Rejections are ordered cheapest-first because every datagram is
// attacker-controlled input handled as root: exact length, then trial
// decrypt against each trusted operator, then the claimed key_id against the
// key that actually decrypted the packet, and only then the signature. The
// function never explains itself to a caller that might relay the reason
// back onto the wire — every failure path returns one of a small set of
// sentinel errors and nothing about the plaintext leaks on a rejection.
func (o *Opener) TrialOpen(datagram []byte) (*Request, identity.PublicIdentity, error) {
	var none identity.PublicIdentity

	// 1. Bounded length. The datagram is the DatagramSize sealed record
	//    followed by a random amount of padding (see Pad), so a length in
	//    [DatagramSize, MaxDatagram] is the only shape worth a key operation;
	//    anything shorter or longer is garbage rejected without touching key
	//    material. The padding beyond the record is discarded here and never
	//    parsed, allocated against, or logged.
	if len(datagram) < DatagramSize || len(datagram) > MaxDatagram {
		return nil, none, ErrWrongSize
	}
	datagram = datagram[:DatagramSize]

	var nonce [NonceSize]byte
	copy(nonce[:], datagram[:NonceSize])
	ct := datagram[NonceSize:]

	// 2. Trial decrypt. Poly1305 rejects a non-matching operator's shared
	//    secret without revealing anything about the plaintext, and with a
	//    bounded operator count this stays cheap relative to a scalar
	//    multiply per attempt.
	for i, shared := range o.shared {
		plain, ok := box.OpenAfterPrecomputation(nil, ct, &nonce, shared)
		if !ok {
			continue
		}
		who := o.operators[i]

		// A successful authenticated decryption under this operator's shared
		// secret is what identifies the sender: only someone holding that
		// operator's private key could have produced a tag that verifies
		// here. Every later rejection is therefore specific to this sender
		// and must not fall through to trying the remaining operators.

		// 3. Structure and canonical encoding.
		req, err := Parse(plain)
		if err != nil {
			return nil, none, err
		}

		// 4. The claimed key_id must match the key that actually opened it.
		//    Without this check, anyone holding any trusted key could forge
		//    audit attribution to a different trusted operator.
		if req.KeyID != who.KeyID() {
			return nil, none, ErrKeyIDMismatch
		}

		// 5. Signature over RequestDomain and the signed region, the most
		//    expensive check and so the last one run. The tag is not in the
		//    datagram: it is reconstructed here from the fact that this is an
		//    SPA request, which is what keeps the wire at DatagramSize.
		if !ed25519.Verify(ed25519.PublicKey(who.Signing[:]), req.SigningInput(), req.Signature[:]) {
			return nil, none, ErrBadSignature
		}
		return req, who, nil
	}

	return nil, none, ErrNoOperator
}

// Seal signs the request with the operator's signing key and seals it to the
// host's encryption key. The request's Signature field is overwritten with
// the freshly computed signature before encryption, so the ciphertext always
// carries a signature consistent with the plaintext it wraps.
func Seal(r *Request, signer identity.Signer, hostEncryptionPub [32]byte) ([]byte, error) {
	sig, err := signer.Sign(r.SigningInput())
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("spa: signer produced a %d byte signature, want %d", len(sig), SigLen)
	}
	copy(r.Signature[:], sig)
	return sealRecord(r, signer, hostEncryptionPub)
}

// sealRecord encrypts r as-is: it does not sign, so the caller controls
// exactly what ends up in r.Signature before the record is sealed. Seal is
// the only production caller and always signs first. This split exists so a
// test can build a datagram whose encryption is valid but whose signature is
// not — see export_test.go, which is compiled only into the test binary and
// carries no exported test-only seam into the shipped package.
func sealRecord(r *Request, signer identity.Signer, hostEncryptionPub [32]byte) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	shared, err := signer.Precompute(hostEncryptionPub)
	if err != nil {
		return nil, fmt.Errorf("spa: host encryption key rejected: %w", err)
	}

	out := make([]byte, 0, DatagramSize)
	out = append(out, nonce[:]...)
	out = box.SealAfterPrecomputation(out, r.Marshal(), &nonce, shared)
	if len(out) != DatagramSize {
		return nil, fmt.Errorf("spa: sealed datagram is %d bytes, want %d", len(out), DatagramSize)
	}
	return out, nil
}
