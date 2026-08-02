package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// Key derivation parameters. N is deliberately expensive: this file holds the
// key that opens every door in a fleet, and it is unlocked interactively.
const (
	scryptN      = 1 << 17
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// Sentinel errors, so a caller (typically a CLI prompting for a passphrase)
// can tell these failure modes apart instead of pattern-matching an error
// string:
//   - ErrIncorrectPassphrase: retry makes sense — ask again. Note this is
//     also what a corrupted ciphertext produces: a symmetric AEAD's
//     authentication failure cannot distinguish "wrong key" from "altered
//     ciphertext" by construction, so a caller that keeps failing here
//     after a correct passphrase should suspect file corruption rather
//     than user error.
//   - ErrMalformedKeyFile: the file's structure itself is invalid (bad
//     JSON, wrong field lengths, unsupported algorithm). No passphrase
//     fixes this.
//   - ErrTamperedKeyFile: the passphrase was right and the ciphertext
//     authenticated, but the file's plaintext public-key/name fields don't
//     match what was inside the sealed private material. Someone edited
//     the file without the passphrase; this is a security event, not a
//     typo, and must never be retried silently.
var (
	ErrIncorrectPassphrase = errors.New("identity: incorrect passphrase or corrupt ciphertext")
	ErrMalformedKeyFile    = errors.New("identity: malformed key file")
	ErrTamperedKeyFile     = errors.New("identity: key file public fields do not match its sealed private key")
)

// keyFile is the on-disk envelope. Name, Signing, and Encryption are
// plaintext JSON and therefore unauthenticated on their own — anyone with
// write access to the file (a restored backup, a synced directory, a wrong
// ACL) can edit them without the passphrase. LoadFile treats them as a
// claim to be checked, not a fact: the authoritative copies of all three
// live inside sealedSecret, and LoadFile rejects the file outright if they
// disagree rather than trusting either one.
type keyFile struct {
	Name       string `json:"name"`
	Alg        string `json:"alg"`
	Signing    string `json:"signing_public"`
	Encryption string `json:"encryption_public"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Sealed     string `json:"sealed"`
}

// sealedSecret is the authenticated plaintext inside secretbox: everything
// an attacker with write-but-not-read access must not be able to change
// undetected. encoding/json base64-encodes []byte fields automatically.
//
// Alg lives here, not only in keyFile, so the algorithm tag is covered by
// the same AEAD as Name/SigningPriv/EncryptPriv. Sitting outside the seal
// was harmless while ed25519+x25519 is the only suite in v1 — LoadFile's
// early structural check already rejects any other value in kf.Alg before
// the expensive KDF runs — but the moment a second suite lands, an
// unauthenticated Alg field is a downgrade vector: someone with
// write-but-not-read access to the file could relabel a victim's key under
// a weaker algorithm the code trusts unchecked. No key files exist in the
// wild yet, so moving it costs nothing now and avoids a migration later.
type sealedSecret struct {
	Name        string `json:"name"`
	Alg         string `json:"alg"`
	SigningPriv []byte `json:"signing_priv"`
	EncryptPriv []byte `json:"encrypt_priv"`
}

// SaveFile writes an identity to disk, encrypting the private halves (and
// the name, so it's authenticated too) under a passphrase. The write is
// atomic and the resulting file is always exactly 0600, even when
// overwriting a pre-existing file with wider permissions: os.WriteFile only
// applies its mode argument at creation, so writing over an existing 0644
// path would silently leave it 0644. SaveFile instead writes a fresh 0600
// temp file in the same directory and renames it into place, which also
// means a crash mid-write leaves the original key file untouched rather
// than truncated.
func SaveFile(path string, s Signer, passphrase []byte) error {
	ms, ok := s.(*memorySigner)
	if !ok {
		return errors.New("identity: only in-memory signers can be written to a key file")
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("read salt: %w", err)
	}
	dk, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	var secret [32]byte
	copy(secret[:], dk)

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	inner, err := json.Marshal(sealedSecret{
		Name:        ms.pub.Name,
		Alg:         string(ms.pub.Alg),
		SigningPriv: ms.signing,
		EncryptPriv: ms.encrypt[:],
	})
	if err != nil {
		return fmt.Errorf("marshal sealed secret: %w", err)
	}
	sealed := secretbox.Seal(nil, inner, &nonce, &secret)

	kf := keyFile{
		Name:       ms.pub.Name,
		Alg:        string(ms.pub.Alg),
		Signing:    base64.StdEncoding.EncodeToString(ms.pub.Signing[:]),
		Encryption: base64.StdEncoding.EncodeToString(ms.pub.Encryption[:]),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce[:]),
		Sealed:     base64.StdEncoding.EncodeToString(sealed),
	}
	body, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key file: %w", err)
	}

	return writeFileAtomic0600(path, body)
}

// closeAndJoin closes f and joins any close error onto err. A failed close
// can mean data never actually made it to disk, so on a write path that
// error is never just discarded; it's surfaced alongside whatever error
// triggered the close in the first place.
func closeAndJoin(f *os.File, err error) error {
	if cerr := f.Close(); cerr != nil {
		return errors.Join(err, fmt.Errorf("close temp key file: %w", cerr))
	}
	return err
}

// writeFileAtomic0600 writes body to a fresh 0600 temp file in path's
// directory, verifies the mode actually landed, and renames it over path.
// The rename is what makes both the permission guarantee and the crash
// safety hold: it replaces path's directory entry wholesale rather than
// reusing (and inheriting the mode bits of) whatever inode was already
// there.
func writeFileAtomic0600(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// Best-effort cleanup of the temp file on any early return. A
		// rename that already succeeded has moved it out from under this
		// path, so Remove failing at that point is expected, not an error
		// worth surfacing; and on any other exit path the caller already
		// has the real failure reason from further down.
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return closeAndJoin(tmp, fmt.Errorf("chmod temp key file: %w", err))
	}
	if _, err := tmp.Write(body); err != nil {
		return closeAndJoin(tmp, fmt.Errorf("write temp key file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return closeAndJoin(tmp, fmt.Errorf("sync temp key file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp key file: %w", err)
	}

	info, err := os.Stat(tmpPath)
	if err != nil {
		return fmt.Errorf("stat temp key file: %w", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("identity: temp key file mode = %o, want 600", perm)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename key file into place: %w", err)
	}
	return nil
}

// LoadFile reads and decrypts an identity written by SaveFile. Structural
// checks (JSON shape, field lengths, algorithm tag) run before the scrypt
// derivation so a malformed file fails fast rather than paying the
// deliberately expensive KDF first. Once decrypted, both public keys are
// re-derived from the private material that just came out of the seal and
// compared against the file's plaintext claims; any disagreement is treated
// as tampering and rejected outright rather than resolved by preferring one
// side.
func LoadFile(path string, passphrase []byte) (Signer, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var kf keyFile
	if err := json.Unmarshal(body, &kf); err != nil {
		return nil, fmt.Errorf("%w: parse json: %v", ErrMalformedKeyFile, err)
	}
	if Algorithm(kf.Alg) != AlgEd25519X25519 {
		return nil, fmt.Errorf("%w: unsupported key algorithm %q", ErrMalformedKeyFile, kf.Alg)
	}

	salt, err := base64.StdEncoding.DecodeString(kf.Salt)
	if err != nil || len(salt) != saltLen {
		return nil, fmt.Errorf("%w: salt", ErrMalformedKeyFile)
	}
	nonceRaw, err := base64.StdEncoding.DecodeString(kf.Nonce)
	if err != nil || len(nonceRaw) != 24 {
		return nil, fmt.Errorf("%w: nonce", ErrMalformedKeyFile)
	}
	sealed, err := base64.StdEncoding.DecodeString(kf.Sealed)
	if err != nil || len(sealed) <= secretbox.Overhead {
		return nil, fmt.Errorf("%w: sealed ciphertext", ErrMalformedKeyFile)
	}
	claimedSignPub, err := base64.StdEncoding.DecodeString(kf.Signing)
	if err != nil || len(claimedSignPub) != 32 {
		return nil, fmt.Errorf("%w: signing_public", ErrMalformedKeyFile)
	}
	claimedEncPub, err := base64.StdEncoding.DecodeString(kf.Encryption)
	if err != nil || len(claimedEncPub) != 32 {
		return nil, fmt.Errorf("%w: encryption_public", ErrMalformedKeyFile)
	}

	// Structural checks passed; only now pay for the expensive KDF.
	dk, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	var secret [32]byte
	copy(secret[:], dk)
	var nonce [24]byte
	copy(nonce[:], nonceRaw)

	plain, ok := secretbox.Open(nil, sealed, &nonce, &secret)
	if !ok {
		return nil, ErrIncorrectPassphrase
	}

	var inner sealedSecret
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, fmt.Errorf("%w: sealed payload: %v", ErrMalformedKeyFile, err)
	}
	if len(inner.SigningPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: sealed signing key length", ErrMalformedKeyFile)
	}
	if len(inner.EncryptPriv) != 32 {
		return nil, fmt.Errorf("%w: sealed encryption key length", ErrMalformedKeyFile)
	}

	signPriv := ed25519.PrivateKey(inner.SigningPriv)
	var xpriv [32]byte
	copy(xpriv[:], inner.EncryptPriv)

	// Derive both public halves from the private material that was just
	// authenticated by the seal — never trust the plaintext fields on their
	// own (this is the fix for the C1 finding: an attacker with write-only
	// access could otherwise swap in their own public keys and name while
	// leaving the victim's sealed private keys untouched, and LoadFile would
	// hand back a Signer whose Public() lied about which key signs for it).
	derivedSignPub, ok := signPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: could not derive signing public key", ErrMalformedKeyFile)
	}
	derivedEncPubRaw, err := curve25519.X25519(xpriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("%w: derive encryption public key: %v", ErrMalformedKeyFile, err)
	}

	if !bytes.Equal(derivedSignPub, claimedSignPub) ||
		!bytes.Equal(derivedEncPubRaw, claimedEncPub) ||
		inner.Name != kf.Name ||
		inner.Alg != kf.Alg {
		return nil, ErrTamperedKeyFile
	}

	ms := &memorySigner{
		pub:     PublicIdentity{Name: inner.Name, Alg: AlgEd25519X25519},
		signing: append(ed25519.PrivateKey(nil), signPriv...),
	}
	copy(ms.pub.Signing[:], derivedSignPub)
	copy(ms.pub.Encryption[:], derivedEncPubRaw)
	copy(ms.encrypt[:], xpriv[:])

	return ms, nil
}
