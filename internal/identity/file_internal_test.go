package identity

// This file is package identity (not identity_test), deliberately: proving
// Alg is now covered by the sealed AEAD requires constructing a keyFile
// whose outer, plaintext Alg matches the one value LoadFile's early
// structural gate accepts, while the AUTHENTICATED Alg inside the seal
// disagrees with it — a scenario only reachable by hand-building the sealed
// payload with raw private key material, which Signer intentionally has no
// public accessor for. See precompute_internal_test.go for the same
// rationale applied to a different property.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// TestIdentity_LoadFile_RejectsAlgOutsideAuthenticatedRegion proves Alg is
// now covered by the same AEAD as Name/SigningPriv/EncryptPriv: a sealed
// payload whose own Alg disagrees with the outer plaintext claim must be
// rejected as tampered, even though the outer claim alone still passes
// LoadFile's early "is this an algorithm we support" gate on its own.
//
// With only one algorithm in v1, an attacker who lacks the passphrase
// cannot produce this scenario today — kf.Alg can only ever legitimately be
// "ed25519+x25519", so there is nothing to downgrade TO yet. That is
// exactly the point: this test exercises the cross-check mechanism now,
// while it is still cheap to add, rather than leaving it unexercised until
// a second algorithm makes the gap attacker-reachable.
func TestIdentity_LoadFile_RejectsAlgOutsideAuthenticatedRegion(t *testing.T) {
	s, err := Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ms := s.(*memorySigner)

	pass := []byte("pass")
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("read salt: %v", err)
	}
	dk, err := scrypt.Key(pass, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		t.Fatalf("scrypt.Key: %v", err)
	}
	var secret [32]byte
	copy(secret[:], dk)

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("read nonce: %v", err)
	}

	// The AUTHENTICATED payload legitimately claims a different algorithm
	// than the outer plaintext will. The private-key fields still match ms's
	// real Ed25519/X25519 keys, so the derived-public-key cross-check that
	// guards C1 stays satisfied — this test isolates Alg specifically.
	inner, err := json.Marshal(sealedSecret{
		Name:        ms.pub.Name,
		Alg:         "future-hypothetical-alg",
		SigningPriv: ms.signing,
		EncryptPriv: ms.encrypt[:],
	})
	if err != nil {
		t.Fatalf("marshal sealed secret: %v", err)
	}
	sealed := secretbox.Seal(nil, inner, &nonce, &secret)

	kf := keyFile{
		Name: ms.pub.Name,
		// The outer plaintext claim: the one algorithm LoadFile's early
		// structural gate accepts today, deliberately different from the
		// sealed payload's Alg above.
		Alg:        string(AlgEd25519X25519),
		Signing:    base64.StdEncoding.EncodeToString(ms.pub.Signing[:]),
		Encryption: base64.StdEncoding.EncodeToString(ms.pub.Encryption[:]),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce[:]),
		Sealed:     base64.StdEncoding.EncodeToString(sealed),
	}
	body, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err = LoadFile(path, pass)
	if err == nil {
		t.Fatal("LoadFile accepted a sealed Alg that disagrees with the outer plaintext claim")
	}
	if !errors.Is(err, ErrTamperedKeyFile) {
		t.Fatalf("LoadFile err = %v, want errors.Is(err, ErrTamperedKeyFile)", err)
	}
}
