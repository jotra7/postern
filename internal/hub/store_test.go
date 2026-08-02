package hub

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var storeTestHostID = [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

// writeStore builds a store directory holding one bundle and one index.json
// entry for storeTestHostID.
func writeStore(t *testing.T, sealed []byte, signingKey [32]byte) string {
	t.Helper()
	dir := t.TempDir()
	idHex := hex.EncodeToString(storeTestHostID[:])
	if err := os.WriteFile(filepath.Join(dir, idHex+".bundle"), sealed, 0o600); err != nil {
		t.Fatalf("write bundle fixture: %v", err)
	}
	index := `{"hosts":{"` + idHex + `":{"signing":"` + base64.StdEncoding.EncodeToString(signingKey[:]) + `","version":1}}}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o600); err != nil {
		t.Fatalf("write index.json fixture: %v", err)
	}
	return dir
}

func randomSigningKey(t *testing.T) [32]byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	var key [32]byte
	copy(key[:], pub)
	return key
}

func TestHub_OpenStore_RejectsAMissingDirectory(t *testing.T) {
	if _, err := OpenStore(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("OpenStore accepted a directory that does not exist")
	}
}

func TestHub_OpenStore_RejectsAPathThatIsAFileNotADirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := OpenStore(path); err == nil {
		t.Fatal("OpenStore accepted a plain file as a store directory")
	}
}

func TestHub_Store_Bundle_ReturnsWhatWasWritten(t *testing.T) {
	sealed := []byte("opaque ciphertext, not a policy")
	dir := writeStore(t, sealed, randomSigningKey(t))
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	got, err := s.Bundle(storeTestHostID)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if string(got) != string(sealed) {
		t.Errorf("Bundle = %q, want %q", got, sealed)
	}
}

func TestHub_Store_Bundle_ReturnsErrNoBundleForAnAbsentHost(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	var otherHost [16]byte
	otherHost[0] = 0x01
	if _, err := s.Bundle(otherHost); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("err = %v, want ErrNoBundle", err)
	}
}

func TestHub_Store_HostKey_ReturnsWhatIndexRecords(t *testing.T) {
	key := randomSigningKey(t)
	dir := writeStore(t, []byte("x"), key)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	got, err := s.HostKey(storeTestHostID)
	if err != nil {
		t.Fatalf("HostKey: %v", err)
	}
	if got != key {
		t.Errorf("HostKey = %x, want %x", got, key)
	}
}

func TestHub_Store_HostKey_ReturnsErrNoHostKeyForAnAbsentHost(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	var otherHost [16]byte
	otherHost[0] = 0x01
	if _, err := s.HostKey(otherHost); !errors.Is(err, ErrNoHostKey) {
		t.Fatalf("err = %v, want ErrNoHostKey", err)
	}
}

// A store directory with no index.json at all (a bundle written by a
// version of `sign` from before Task 7, or a directory an operator built by
// hand) must not make HostKey panic or misbehave; it is the same "nothing on
// file for this host" fact as an entry-less index.
func TestHub_Store_HostKey_MissingIndexFileIsErrNoHostKeyNotAPanic(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.HostKey(storeTestHostID); !errors.Is(err, ErrNoHostKey) {
		t.Fatalf("err = %v, want ErrNoHostKey", err)
	}
}

// A redeploy replaces index.json and the bundle files under a running hub.
// Nothing in Store caches either, so the very next call sees the new
// content without a restart.
func TestHub_Store_RereadsFilesOnEveryCall(t *testing.T) {
	firstKey := randomSigningKey(t)
	dir := writeStore(t, []byte("v1"), firstKey)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if got, err := s.Bundle(storeTestHostID); err != nil || string(got) != "v1" {
		t.Fatalf("Bundle before redeploy = %q, %v", got, err)
	}

	secondKey := randomSigningKey(t)
	idHex := hex.EncodeToString(storeTestHostID[:])
	if err := os.WriteFile(filepath.Join(dir, idHex+".bundle"), []byte("v2"), 0o600); err != nil {
		t.Fatalf("rewrite bundle: %v", err)
	}
	index := `{"hosts":{"` + idHex + `":{"signing":"` + base64.StdEncoding.EncodeToString(secondKey[:]) + `","version":2}}}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o600); err != nil {
		t.Fatalf("rewrite index.json: %v", err)
	}

	got, err := s.Bundle(storeTestHostID)
	if err != nil || string(got) != "v2" {
		t.Fatalf("Bundle after redeploy = %q, %v; the same *Store did not pick up the new file", got, err)
	}
	key, err := s.HostKey(storeTestHostID)
	if err != nil || key != secondKey {
		t.Fatalf("HostKey after redeploy = %x, %v; want %x", key, err, secondKey)
	}
}

// --- ParseHostID: the path-traversal defense, and the two-controls trap ---

// The literal adversarial input named in the task brief. It is rejected —
// but, as the isolating tests below prove, it is rejected by hex-validity
// alone ('.' and '/' are not hex digits), never reaching the length check.
// This test alone does not prove the length check does anything; see
// RejectsWrongLengthValidHex and RejectsInvalidHexCharactersAtTheRightLength
// for the tests that isolate each control from the other.
func TestHub_Store_RejectsAHostIDThatIsNotHex(t *testing.T) {
	if _, err := ParseHostID("../../etc/passwd"); !errors.Is(err, ErrInvalidHostID) {
		t.Fatalf("err = %v, want ErrInvalidHostID", err)
	}
}

// Isolates the exact-length control: valid hex characters, even length (so
// hex.DecodeString itself succeeds), but not 16 bytes' worth. Deleting the
// length check alone — while hex.DecodeString's own error check stays in
// place — would make this input pass.
func TestHub_Store_ParseHostID_RejectsWrongLengthValidHex(t *testing.T) {
	tests := map[string]string{
		"too short": strings.Repeat("ab", 8),  // 16 chars, 8 bytes
		"too long":  strings.Repeat("ab", 20), // 40 chars, 20 bytes
	}
	for name, s := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHostID(s); !errors.Is(err, ErrInvalidHostID) {
				t.Fatalf("ParseHostID(%q): err = %v, want ErrInvalidHostID", s, err)
			}
		})
	}
}

// Isolates the hex-validity control from the length control — genuinely,
// not just apparently.
//
// A first attempt at this test used 32 copies of a non-hex character
// ("gggg...g"). That construction does NOT isolate anything: hex.Decode
// stops at the first invalid byte and returns only the bytes it decoded
// before that point, so an all-invalid 32-character string decodes to 0
// bytes, not 16 — meaning the length check (0 != 16) would independently
// reject it even with the hex-validity check deleted. Deleting the
// hex-validity check alone and re-running proved this empirically: the test
// still passed, for the wrong reason, exactly the "test that could not
// fail" shape this task warns about.
//
// The construction below is what actually isolates the two: 32 valid hex
// characters (which decode cleanly to the full 16 bytes) followed by two
// invalid ones. hex.Decode has already produced all 16 bytes by the time it
// reaches the bad trailing pair, so the decoded length equals exactly 16
// AND an error is returned — the one shape where the length check cannot
// substitute for the hex-validity check, because the length is already
// correct.
func TestHub_Store_ParseHostID_RejectsInvalidHexCharactersAtTheRightLength(t *testing.T) {
	s := strings.Repeat("ab", 16) + "zz" // 32 valid hex chars (=16 bytes), then 2 invalid ones
	if _, err := ParseHostID(s); !errors.Is(err, ErrInvalidHostID) {
		t.Fatalf("ParseHostID(%q): err = %v, want ErrInvalidHostID", s, err)
	}
}

func TestHub_Store_ParseHostID_AcceptsAWellFormedHostID(t *testing.T) {
	want := storeTestHostID
	got, err := ParseHostID(hex.EncodeToString(want[:]))
	if err != nil {
		t.Fatalf("ParseHostID: %v", err)
	}
	if got != want {
		t.Errorf("ParseHostID round trip = %x, want %x", got, want)
	}
}

func TestHub_Store_ParseHostID_RejectsAnEmptyString(t *testing.T) {
	if _, err := ParseHostID(""); !errors.Is(err, ErrInvalidHostID) {
		t.Fatalf("err = %v, want ErrInvalidHostID", err)
	}
}

// writeIndex overwrites a store directory's index.json with raw JSON, so a
// test can put entries in it that `postern sign` would never write.
func writeIndex(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write index.json fixture: %v", err)
	}
}

// Hosts is the fleet the hub knows before anyone reports, which is what makes
// a host that has never beaten distinguishable from one that does not exist.
func TestHub_Store_Hosts_ReturnsEveryHostTheIndexNames(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	second := [16]byte{0x01}
	writeIndex(t, dir, `{"hosts":{`+
		`"`+hex.EncodeToString(storeTestHostID[:])+`":{"signing":"AA==","version":1},`+
		`"`+hex.EncodeToString(second[:])+`":{"signing":"AA==","version":1}}}`)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	got, err := store.Hosts()
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	want := map[[16]byte]bool{storeTestHostID: true, second: true}
	if len(got) != len(want) {
		t.Fatalf("Hosts returned %d hosts, want %d: %x", len(got), len(want), got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("Hosts returned %x, which index.json does not name", id)
		}
	}
}

// An entry whose key is not a host_id names nothing this Store can serve a
// bundle for or verify a beat from, so it is not a fleet member and must not
// deny a caller the entries that are.
func TestHub_Store_Hosts_SkipsAnEntryThatIsNotAHostID(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	writeIndex(t, dir, `{"hosts":{`+
		`"`+hex.EncodeToString(storeTestHostID[:])+`":{"signing":"AA==","version":1},`+
		`"../../etc/passwd":{"signing":"AA==","version":1},`+
		`"aabbcc":{"signing":"AA==","version":1}}}`)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	got, err := store.Hosts()
	if err != nil {
		t.Fatalf("Hosts on an index with unusable keys: %v", err)
	}
	if len(got) != 1 || got[0] != storeTestHostID {
		t.Fatalf("Hosts = %x, want exactly [%x]", got, storeTestHostID)
	}
}

// A file that does not parse at all is not one bad entry, and returning an
// empty fleet for it would read as "nobody is enrolled".
func TestHub_Store_Hosts_FailsOnAnUnparseableIndex(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	writeIndex(t, dir, `{"hosts": [ this is not json`)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if got, err := store.Hosts(); err == nil {
		t.Fatalf("Hosts on an unparseable index.json returned %x and no error", got)
	}
}

// A store directory `postern sign` has never written to has no index.json at
// all. That is an empty fleet, not a failure, which is the same reading
// HostKey already gives it.
func TestHub_Store_Hosts_ReturnsNoHostsWhenTheIndexIsAbsent(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	got, err := store.Hosts()
	if err != nil {
		t.Fatalf("Hosts with no index.json: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Hosts = %x, want none", got)
	}
}
