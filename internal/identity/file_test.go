package identity_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jotra7/postern/internal/identity"
)

func TestIdentityFile_RoundTrip_PreservesKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")
	pass := []byte("correct horse battery staple")

	orig, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.SaveFile(path, orig, pass); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	loaded, err := identity.LoadFile(path, pass)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if loaded.Public() != orig.Public() {
		t.Fatal("public identity changed across save/load")
	}

	msg := []byte("canary")
	sigA, _ := orig.Sign(msg)
	sigB, _ := loaded.Sign(msg)
	if !bytes.Equal(sigA, sigB) {
		t.Fatal("loaded signer produced a different signature; private key not preserved")
	}

	// Sign and Public() only exercise the Ed25519 half. The X25519 private
	// half has no public-facing accessor at all, so the only way to prove
	// it survived the round trip is to derive a shared secret with it and
	// compare it against the same derivation from the pre-save signer. This
	// was verified to actually catch a dropped X25519 key — see the fix
	// report's I3 mutation evidence.
	peer, err := identity.Generate("peer")
	if err != nil {
		t.Fatalf("Generate peer: %v", err)
	}
	wantShared, err := orig.Precompute(peer.Public().Encryption)
	if err != nil {
		t.Fatalf("orig.Precompute: %v", err)
	}
	gotShared, err := loaded.Precompute(peer.Public().Encryption)
	if err != nil {
		t.Fatalf("loaded.Precompute: %v", err)
	}
	if !bytes.Equal(wantShared[:], gotShared[:]) {
		t.Fatal("loaded signer derived a different shared secret; X25519 private key not preserved")
	}
}

func TestIdentityFile_LoadFile_RejectsWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.SaveFile(path, s, []byte("right")); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	if _, err := identity.LoadFile(path, []byte("wrong")); err == nil {
		t.Fatal("LoadFile accepted a wrong passphrase")
	}
}

func TestIdentityFile_SaveFile_IsOwnerReadableOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	s, _ := identity.Generate("laptop-primary")
	if err := identity.SaveFile(path, s, []byte("pass")); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 600", perm)
	}
}

// TestIdentityFile_SaveFile_NarrowsExistingWorldReadablePermissions guards
// I4: os.WriteFile's mode argument only applies at file creation, so
// SaveFile writing over a pre-existing wider-mode path (a restored backup,
// a bad umask, a re-key operation) must not silently leave it readable by
// other local users. This was verified to fail against the prior
// implementation (a plain os.WriteFile(path, body, 0o600) call, which does
// not narrow an existing file's mode) — see the fix report's I4 mutation
// evidence — because the tests above only ever write into a fresh
// t.TempDir() path and could never observe this.
func TestIdentityFile_SaveFile_NarrowsExistingWorldReadablePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	//nolint:gosec // G306: the wide 0644 mode is the point of this test — it
	// stands in for a restored backup, a bad umask, or a re-key operation,
	// and SaveFile must narrow it, not preserve it.
	if err := os.WriteFile(path, []byte("stale placeholder"), 0o644); err != nil {
		t.Fatalf("pre-create world-readable file: %v", err)
	}

	s, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.SaveFile(path, s, []byte("pass")); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode after overwriting a 0644 path = %o, want 600", perm)
	}
}

// rawKeyFile mirrors the on-disk field names identity.SaveFile writes. It's
// declared here, independent of the unexported keyFile type, so these tests
// tamper the wire format rather than package internals.
type rawKeyFile struct {
	Name       string `json:"name"`
	Alg        string `json:"alg"`
	Signing    string `json:"signing_public"`
	Encryption string `json:"encryption_public"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Sealed     string `json:"sealed"`
}

func readRawKeyFile(t *testing.T, path string) rawKeyFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var kf rawKeyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return kf
}

func writeRawKeyFile(t *testing.T, path string, kf rawKeyFile) {
	t.Helper()
	body, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestIdentityFile_LoadFile_RejectsTamperedCiphertext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")
	pass := []byte("pass")

	s, _ := identity.Generate("laptop-primary")
	if err := identity.SaveFile(path, s, pass); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	kf := readRawKeyFile(t, path)

	// Decode the structured file, flip a byte inside the decoded ciphertext
	// itself (not the base64 text), and re-encode. This guarantees the
	// mutation lands inside the sealed private-key material rather than
	// risking an offset that happens to fall in the salt, nonce, or a
	// base64 boundary and fails for an unrelated (decode) reason.
	sealed, err := base64.StdEncoding.DecodeString(kf.Sealed)
	if err != nil {
		t.Fatalf("decode sealed field: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealed ciphertext is empty; nothing to tamper")
	}
	sealed[len(sealed)/2] ^= 0x01
	kf.Sealed = base64.StdEncoding.EncodeToString(sealed)
	writeRawKeyFile(t, path, kf)

	_, err = identity.LoadFile(path, pass)
	if err == nil {
		t.Fatal("LoadFile accepted tampered ciphertext")
	}
	// Confirm this is the secretbox authentication failure, not an
	// unrelated JSON or base64 decode error, so the test actually proves
	// the tamper was detected where it's supposed to be: in the ciphertext.
	// A sentinel comparison (rather than string-matching the error text) is
	// itself part of the M1 fix: a caller needs to make this distinction
	// programmatically.
	if !errors.Is(err, identity.ErrIncorrectPassphrase) {
		t.Fatalf("LoadFile err = %v, want errors.Is(err, identity.ErrIncorrectPassphrase)", err)
	}
}

// TestIdentityFile_LoadFile_RejectsTamperedPublicFields guards C1: the
// plaintext name/signing_public/encryption_public fields sit outside the
// AEAD, so anyone with write-but-not-read access to the file can edit them
// without the passphrase. LoadFile must re-derive both public keys (and the
// name) from the decrypted private material and reject the file if they
// disagree, rather than trusting the plaintext claims. This was verified to
// fail against the prior implementation, which copied these fields straight
// from JSON into the returned Signer with no cross-check — see the fix
// report's C1 mutation evidence.
func TestIdentityFile_LoadFile_RejectsTamperedPublicFields(t *testing.T) {
	pass := []byte("pass")

	attacker, err := identity.Generate("attacker")
	if err != nil {
		t.Fatalf("Generate attacker: %v", err)
	}
	attackerPub := attacker.Public()
	attackerSignB64 := base64.StdEncoding.EncodeToString(attackerPub.Signing[:])
	attackerEncB64 := base64.StdEncoding.EncodeToString(attackerPub.Encryption[:])

	cases := []struct {
		name   string
		tamper func(kf rawKeyFile) rawKeyFile
	}{
		{
			name: "signing_public",
			tamper: func(kf rawKeyFile) rawKeyFile {
				kf.Signing = attackerSignB64
				return kf
			},
		},
		{
			name: "encryption_public",
			tamper: func(kf rawKeyFile) rawKeyFile {
				kf.Encryption = attackerEncB64
				return kf
			},
		},
		{
			name: "name",
			tamper: func(kf rawKeyFile) rawKeyFile {
				kf.Name = "spoofed-name"
				return kf
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "operator.key")

			victim, err := identity.Generate("victim")
			if err != nil {
				t.Fatalf("Generate victim: %v", err)
			}
			if err := identity.SaveFile(path, victim, pass); err != nil {
				t.Fatalf("SaveFile: %v", err)
			}

			kf := readRawKeyFile(t, path)
			kf = tc.tamper(kf)
			writeRawKeyFile(t, path, kf)

			loaded, err := identity.LoadFile(path, pass)
			if err == nil {
				t.Fatalf("LoadFile accepted a tampered %s field; got Signer with Public() = %+v", tc.name, loaded.Public())
			}
			if !errors.Is(err, identity.ErrTamperedKeyFile) {
				t.Fatalf("LoadFile err = %v, want errors.Is(err, identity.ErrTamperedKeyFile)", err)
			}
		})
	}
}
