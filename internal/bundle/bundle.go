package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/identity"
)

const (
	// Magic is the fixed 15-byte prefix of every bundle record.
	Magic = "postern-bundle\x00"
	// FormatV1 is the only record format v1 understands.
	FormatV1 = uint8(1)
	// MaxPolicyLen bounds policy_len. The prefix is read out of a record
	// whose signature has not been checked yet — the signature covers the
	// policy, so the policy has to be located before it can be verified —
	// which makes it attacker-controlled input used to size a slice.
	MaxPolicyLen = 1 << 20
)

// Field offsets and sizes for the signed record. These are the protocol; do
// not derive them from struct layout.
const (
	OffMagic     = 0
	OffFormat    = 15
	OffFleetID   = 16
	OffHostID    = 32
	OffVersion   = 48
	OffIssuedAt  = 56
	OffPolicyLen = 64
	// PolicyOff is where the length-prefixed policy begins, and so is also
	// the size of the fixed header.
	PolicyOff = 68

	MagicLen     = 15
	IDSize       = 16
	SignerKeyLen = 32
	SigLen       = 64

	// FixedLen is every byte of a record other than the policy: the header,
	// the trailing signer key, and the signature.
	FixedLen = PolicyOff + SignerKeyLen + SigLen // 164
)

var (
	// ErrFormat means the unsealed bytes are not a v1 bundle record: wrong
	// length, wrong magic, an unknown format version, or a policy_len that
	// exceeds MaxPolicyLen or disagrees with the record's own length.
	ErrFormat = errors.New("bundle: malformed record")
	// ErrUnseal means the ciphertext did not open under this host's
	// encryption key. As with any AEAD, "sealed to another host" and
	// "corrupted in transit" are indistinguishable here by construction.
	ErrUnseal = errors.New("bundle: cannot unseal for this host")
	// ErrRecipientKey means the host encryption key a bundle was to be sealed
	// to is not a usable X25519 point. Sealing to a low-order point derives a
	// fixed, publicly computable shared secret, so the ciphertext would be
	// readable by anyone who fetched it — the seal's entire job, silently not
	// done, with the target host unable to open its own bundle as the only
	// symptom.
	ErrRecipientKey = errors.New("bundle: host encryption key rejected")
	// ErrUntrustedSigner means the record's signer key is not in the trusted
	// set. Sealing is anonymous, so anyone holding a host's public encryption
	// key can produce ciphertext that host can open: this check, not the
	// seal, is what makes a bundle authentic.
	ErrUntrustedSigner = errors.New("bundle: signed by a key outside the trusted set")
	// ErrBadSignature means the Ed25519 signature failed verification.
	ErrBadSignature = errors.New("bundle: signature verification failed")
	// ErrWrongFleet means fleet_id does not match the criteria.
	ErrWrongFleet = errors.New("bundle: fleet_id does not match")
	// ErrWrongHost means host_id does not match the criteria.
	ErrWrongHost = errors.New("bundle: host_id does not match")
	// ErrNotNewer means the version is not strictly greater than the version
	// already accepted.
	ErrNotNewer = errors.New("bundle: version is not newer than the accepted one")
	// ErrBelowFloor means the version is below the floor stamped at
	// enrollment.
	ErrBelowFloor = errors.New("bundle: version is below the enrollment floor")
)

// Sealed is what the hub stores and serves: opaque ciphertext.
type Sealed []byte

// Contents is a verified, unsealed bundle.
type Contents struct {
	FleetID  [IDSize]byte
	HostID   [IDSize]byte
	Version  uint64
	IssuedAt time.Time
	// Policy is standalone YAML, deliberately not parsed here. Nothing on the
	// Seal/Open path touches internal/config — compile.go, in this same
	// package, is what imports it — so a malformed policy is the caller's
	// error to handle and the cryptographic layer stays fuzzable on its own,
	// with no YAML parser reachable from openInner.
	Policy []byte
	// SignerKey is an output of Open: the trusted key whose signature this
	// record carried. Seal ignores whatever is here and always writes the key
	// that produced the signature.
	SignerKey [SignerKeyLen]byte
}

// AcceptCriteria is what the agent already knows about itself, and is the
// only thing that makes a well-formed, correctly-signed bundle acceptable or
// not.
type AcceptCriteria struct {
	FleetID [IDSize]byte
	HostID  [IDSize]byte
	// CurrentVersion is the version already applied; it is meaningful only
	// when HasCurrent is set, because version zero is a legal bundle version
	// and "none accepted yet" has to be distinguishable from it.
	CurrentVersion uint64
	HasCurrent     bool
	// EnrollmentFloor is the version stamped at enrollment. A freshly
	// enrolled agent holds no current version, so without a floor an old but
	// validly-signed bundle — one still naming a since-removed operator —
	// would replay against it cleanly.
	EnrollmentFloor uint64
}

// Seal signs the policy with signer and seals the result to
// hostEncryptionPub.
//
// c.SignerKey is ignored: the key written into the record is always the one
// that produced the signature, so the two can never disagree, and Open is
// what populates the field on the way back.
func Seal(c *Contents, signer identity.Signer, hostEncryptionPub [32]byte) (Sealed, error) {
	if len(c.Policy) > MaxPolicyLen {
		return nil, fmt.Errorf("%w: policy is %d bytes, limit %d", ErrFormat, len(c.Policy), MaxPolicyLen)
	}
	if err := checkRecipient(hostEncryptionPub); err != nil {
		return nil, err
	}
	signerKey := signer.Public().Signing
	signed := marshalSigned(c, signerKey)

	sig, err := signer.Sign(signed)
	if err != nil {
		return nil, fmt.Errorf("sign bundle: %w", err)
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("bundle: signer produced a %d byte signature, want %d", len(sig), SigLen)
	}

	sealed, err := box.SealAnonymous(nil, append(signed, sig...), &hostEncryptionPub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("seal bundle: %w", err)
	}
	return Sealed(sealed), nil
}

// checkRecipient refuses a host encryption key that box.SealAnonymous would
// accept and quietly seal to nothing. A low-order point drives the X25519
// exchange to an all-zero output, and since the anonymous nonce derives from
// public values only, the resulting ciphertext is readable by anyone who
// fetches it from the hub. Nothing downstream notices: the signature is
// unaffected, and the target host simply cannot open its bundle, which reads
// as a delivery fault rather than a key problem.
//
// curve25519.X25519 rejects those inputs, which is the same validation
// identity.Signer.Precompute performs and documents for the same reason.
// Seal cannot borrow Precompute for it, because that would derive a shared
// secret from the signer's own private X25519 key — the coupling that sealing
// anonymously exists to avoid, and the reason a bundle signer needs no
// encryption key at all.
//
// The scalar is ephemeral and discarded. Clamping makes every X25519 scalar a
// multiple of the cofactor, so the rejection depends on the peer point alone
// and not on which scalar happens to be drawn.
func checkRecipient(hostEncryptionPub [32]byte) error {
	var scalar [32]byte
	if _, err := rand.Read(scalar[:]); err != nil {
		return fmt.Errorf("bundle: read scalar: %w", err)
	}
	if _, err := curve25519.X25519(scalar[:], hostEncryptionPub[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrRecipientKey, err)
	}
	return nil
}

// marshalSigned renders the region the signature covers: the fixed header,
// the policy, and the signer's own public key. Including the signer key under
// the signature means a record cannot be re-attributed to a different trusted
// signer by rewriting those 32 bytes.
func marshalSigned(c *Contents, signerKey [SignerKeyLen]byte) []byte {
	b := make([]byte, PolicyOff+len(c.Policy)+SignerKeyLen)
	copy(b[OffMagic:], Magic)
	b[OffFormat] = FormatV1
	copy(b[OffFleetID:], c.FleetID[:])
	copy(b[OffHostID:], c.HostID[:])
	binary.BigEndian.PutUint64(b[OffVersion:], c.Version)
	//nolint:gosec // G115: UnixMilli is int64 and the record field is 64 bits
	// wide, so this conversion round-trips through time.UnixMilli exactly.
	binary.BigEndian.PutUint64(b[OffIssuedAt:], uint64(c.IssuedAt.UnixMilli()))
	//nolint:gosec // G115: the caller's policy length is bounded by
	// MaxPolicyLen (1 MiB) above.
	binary.BigEndian.PutUint32(b[OffPolicyLen:], uint32(len(c.Policy)))
	copy(b[PolicyOff:], c.Policy)
	copy(b[PolicyOff+len(c.Policy):], signerKey[:])
	return b
}

// Open unseals with the host's own key pair, verifies the signature against
// the trusted signer set, and applies the fleet, host, floor, and version
// checks.
//
// The order below is the security property, not a style choice, so each stage
// only ever runs on input the stage before it accepted.
func Open(s Sealed, host identity.Signer, trustedSigners [][32]byte, want AcceptCriteria) (*Contents, error) {
	// 1. Unseal. A ciphertext that does not open reveals nothing: the seal
	//    names no recipient, so "not for this host" and "corrupted" are the
	//    same outcome. A key that cannot be used at all is a different
	//    problem, and it is reported as itself rather than as ErrUnseal — an
	//    operator sent looking for a key mismatch that does not exist is an
	//    operator not getting through a door.
	//
	//    There is no equivalent of Seal's checkRecipient here, and the reason
	//    is that the check would be redundant rather than that it would be
	//    expensive. Seal's check protects the RECIPIENT key, which comes out
	//    of a hand-edited inventory and, if it is low-order, silently produces
	//    ciphertext anyone can read. The ephemeral key inside a ciphertext is
	//    a different thing: a low-order one only yields a shared secret the
	//    attacker already knows, and whatever they wrap in it still has to
	//    carry a signature from a trusted signer to get past step 4. Rejecting
	//    it here would refuse nothing that step does not already refuse.
	inner, ok, err := host.OpenAnonymous(s)
	if err != nil {
		return nil, fmt.Errorf("bundle: unseal: %w", err)
	}
	if !ok {
		return nil, ErrUnseal
	}
	return openInner(inner, trustedSigners, want)
}

// openInner runs every check after the seal. It is separate from Open so a
// fuzz target can reach the parser directly, without a scalar multiplication
// per execution and without crypto/rand making the target non-deterministic.
func openInner(inner []byte, trustedSigners [][32]byte, want AcceptCriteria) (*Contents, error) {
	// 2. Structure. Nothing here is trusted yet; these checks only establish
	//    that the bytes can be indexed as a record at all.
	if len(inner) < FixedLen {
		return nil, fmt.Errorf("%w: %d bytes, minimum %d", ErrFormat, len(inner), FixedLen)
	}
	if string(inner[OffMagic:OffMagic+MagicLen]) != Magic {
		return nil, fmt.Errorf("%w: wrong magic", ErrFormat)
	}
	if inner[OffFormat] != FormatV1 {
		return nil, fmt.Errorf("%w: format version %d", ErrFormat, inner[OffFormat])
	}
	policyLen := binary.BigEndian.Uint32(inner[OffPolicyLen:])
	// The bound is checked before the length prefix is used for anything,
	// including as a slice index, so an absurd prefix can never size an
	// allocation or an index computation.
	if policyLen > MaxPolicyLen {
		return nil, fmt.Errorf("%w: policy_len %d exceeds %d", ErrFormat, policyLen, MaxPolicyLen)
	}
	// Exact, not "at least": a record with trailing bytes would give one
	// meaning two encodings, and only one of them is covered by the
	// signature.
	if len(inner) != FixedLen+int(policyLen) {
		return nil, fmt.Errorf("%w: %d bytes, policy_len %d implies %d", ErrFormat, len(inner), policyLen, FixedLen+int(policyLen))
	}
	signedLen := PolicyOff + int(policyLen) + SignerKeyLen

	// 3. Trusted-signer membership, before any signature verification, so an
	//    attacker's signature is never even verified.
	var signerKey [SignerKeyLen]byte
	copy(signerKey[:], inner[PolicyOff+int(policyLen):signedLen])
	if !slices.Contains(trustedSigners, signerKey) {
		return nil, ErrUntrustedSigner
	}

	// 4. Signature. Membership alone would accept any record naming a trusted
	//    key, so both checks run and neither substitutes for the other.
	if !ed25519.Verify(ed25519.PublicKey(signerKey[:]), inner[:signedLen], inner[signedLen:]) {
		return nil, ErrBadSignature
	}

	// 5. Only now are the fields worth reading: everything below this line is
	//    a claim a trusted signer made.
	c := &Contents{
		Version: binary.BigEndian.Uint64(inner[OffVersion:]),
		//nolint:gosec // G115: the field is the exact 64 bits UnixMilli
		// produced, so this restores the original instant.
		IssuedAt: time.UnixMilli(int64(binary.BigEndian.Uint64(inner[OffIssuedAt:]))).UTC(),
		// Copied into an exactly-sized allocation rather than aliased: a
		// caller appending to a subslice of the record would otherwise write
		// over the signer key and signature sitting right behind it.
		Policy:    copyOf(inner[PolicyOff : PolicyOff+int(policyLen)]),
		SignerKey: signerKey,
	}
	copy(c.FleetID[:], inner[OffFleetID:OffFleetID+IDSize])
	copy(c.HostID[:], inner[OffHostID:OffHostID+IDSize])

	if c.FleetID != want.FleetID {
		return nil, ErrWrongFleet
	}
	if c.HostID != want.HostID {
		return nil, ErrWrongHost
	}
	// The floor is checked before the ordering because it is the check that
	// still applies when there is no current version to order against.
	if c.Version < want.EnrollmentFloor {
		return nil, ErrBelowFloor
	}
	// Equal is not newer. An agent that re-applied its current version on
	// every pull would re-arm and re-enter the confirm window on a schedule.
	if want.HasCurrent && c.Version <= want.CurrentVersion {
		return nil, ErrNotNewer
	}
	return c, nil
}

// copyOf returns b in an allocation of exactly its own length. slices.Clone
// would be as safe, but it is free to over-allocate, and the spare capacity
// makes the copy indistinguishable from a subslice of the record from the
// outside — cap == len is the only handle a test has on which one it got.
func copyOf(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
