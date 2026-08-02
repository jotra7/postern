package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/identity"
)

// webID and dbID are the fixture's two hosts' host_ids, hex-encoded — the
// filenames `sign` must write into --out.
const (
	webID = "1112131415161718191a1b1c1d1e1f20"
	dbID  = "2122232425262728292a2b2c2d2e2f30"
)

// signFixture is the cast every sign test draws from: laptop is the fleet's
// sole bundle signer, outsider is a real, declared operator who is
// deliberately not one, and web/db are the two hosts' own identities — held
// here (not just their public halves) so a test can OpenAnonymous a written
// bundle and inspect what is actually inside it.
type signFixture struct {
	laptop, outsider, web, db identity.Signer
}

func newSignFixture(t *testing.T) *signFixture {
	t.Helper()
	gen := func(name string) identity.Signer {
		s, err := identity.Generate(name)
		if err != nil {
			t.Fatalf("identity.Generate(%q): %v", name, err)
		}
		return s
	}
	return &signFixture{
		laptop:   gen("laptop-primary"),
		outsider: gen("outsider"),
		web:      gen("web-01"),
		db:       gen("db-01"),
	}
}

func b64Pub(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

// inventoryYAML renders a two host, two operator fleet inventory naming this
// fixture's identities. Only laptop-primary is a bundle_signer; outsider is
// a real, declared operator so a test can prove `sign` checks bundle_signers
// membership rather than merely "does this operator name exist".
func (f *signFixture) inventoryYAML(version int) string {
	return fmt.Sprintf(`
fleet_id: "0102030405060708090a0b0c0d0e0f10"
version: %d

bundle_signers: [laptop-primary]

operators:
  - name: laptop-primary
    alg: ed25519+x25519
    signing:    %q
    encryption: %q
    grants:
      - hosts: ["*"]
        services: [ssh, confirm, disarm, liveness]
        max_ttl: 300s
  - name: outsider
    alg: ed25519+x25519
    signing:    %q
    encryption: %q
    grants:
      - hosts: ["*"]
        services: [ssh]
        max_ttl: 60s

breakglass_services: [ssh]

services:
  ssh:      { kind: gate, proto: tcp, ports: [22], default_ttl: 120s, max_ttl: 300s, listener_expectation: present }
  confirm:  { kind: action }
  disarm:   { kind: action }
  liveness: { kind: action }

defaults:
  spa_port: 62201
  always_allow_iface: tailscale0
  recovery_service: ssh
  freshness_window: 45s
  freshness_window_max: 12h

hosts:
  - name: web-01
    host_id: %q
    knock_addr: 203.0.113.9
    ssh: { host: web-01.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    %q
      encryption: %q
    services: [ssh]
  - name: db-01
    host_id: %q
    knock_addr: 203.0.113.10
    ssh: { host: db-01.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    %q
      encryption: %q
    services: [ssh]
`,
		version,
		b64Pub(f.laptop.Public().Signing), b64Pub(f.laptop.Public().Encryption),
		b64Pub(f.outsider.Public().Signing), b64Pub(f.outsider.Public().Encryption),
		webID,
		b64Pub(f.web.Public().Signing), b64Pub(f.web.Public().Encryption),
		dbID,
		b64Pub(f.db.Public().Signing), b64Pub(f.db.Public().Encryption),
	)
}

// inventoryYAMLTwoSigners is inventoryYAML with a second bundle_signers
// entry, for tests about --as ambiguity.
func (f *signFixture) inventoryYAMLTwoSigners(version int) string {
	return strings.Replace(f.inventoryYAML(version),
		"bundle_signers: [laptop-primary]", "bundle_signers: [laptop-primary, outsider]", 1)
}

// writeInventory writes yaml to a fresh temp file and returns its path.
func writeInventory(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return path
}

// keyFile writes s's private key, unencrypted, to a temp file and returns
// its path — paired with --no-passphrase on the command line.
func keyFile(t *testing.T, s identity.Signer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := identity.SaveFile(path, s, nil); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	return path
}

// trySign runs the sign subcommand through the real dispatcher without
// asserting on the outcome, for tests that expect a refusal.
func trySign(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	e, out, errBuf := testEnv()
	code = runCLI(t, e, append([]string{"sign"}, args...)...)
	return code, out.String(), errBuf.String()
}

// signCLI runs the sign subcommand and fails the test unless it succeeds,
// returning what it printed to stdout.
func signCLI(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errBuf := trySign(t, args...)
	if code != exitOK {
		t.Fatalf("sign %v exited %d, want %d\nstderr:\n%s", args, code, exitOK, errBuf)
	}
	return out
}

// openBundle reads path and opens it with host's own key, failing the test
// if it does not open — every test here seals to a host whose key it also
// holds, so a failure to open means the bundle itself is broken, not that it
// was sealed to someone else.
func openBundle(t *testing.T, host identity.Signer, path string) []byte {
	t.Helper()
	sealed, err := os.ReadFile(path) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	inner, ok, err := host.OpenAnonymous(sealed)
	if err != nil || !ok {
		t.Fatalf("OpenAnonymous(%s): ok=%v err=%v", path, ok, err)
	}
	return inner
}

func readIndex(t *testing.T, dir string) map[string]struct {
	Signing string `json:"signing"`
	Version uint64 `json:"version"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "index.json")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var idx struct {
		Hosts map[string]struct {
			Signing string `json:"signing"`
			Version uint64 `json:"version"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("parse index.json: %v", err)
	}
	return idx.Hosts
}

// The output has to be servable without the hub knowing anything secret: one
// opaque file per host, plus (elsewhere, in index.json) the host signing
// keys the hub needs to verify heartbeats. Nothing in a .bundle file may
// contain a private key or a readable policy.
func TestMain_Sign_WritesOneOpaqueBundlePerHost(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	// --as omitted: laptop-primary is the inventory's only bundle signer.
	signCLI(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")

	for _, h := range []string{webID, dbID} {
		raw, err := os.ReadFile(filepath.Join(dir, h+".bundle")) //nolint:gosec // a test reading a file it just generated
		if err != nil {
			t.Fatalf("bundle for %s: %v", h, err)
		}
		if bytes.Contains(raw, []byte("ssh")) || bytes.Contains(raw, []byte("operators")) {
			t.Errorf("bundle for %s is not sealed; policy text is readable on disk", h)
		}
	}
}

// Signing with a key that is not in bundle_signers produces bundles every
// agent will reject. Catching it here costs a second; catching it at
// rollout costs a fleet that will not take a deploy.
func TestMain_Sign_RefusesAKeyOutsideTheSignerSet(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.outsider)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--as", "outsider", "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage)\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "bundle_signers") {
		t.Fatalf("stderr does not name bundle_signers:\n%s", stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("sign wrote %d files despite refusing the signer", len(entries))
	}
}

// A key file whose identity name does not match --as is refused before
// anything is signed: --as says who the operator claims to be, and the key
// file is the only proof of that.
func TestMain_Sign_RefusesWhenTheLoadedKeyNameDoesNotMatchAs(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.outsider) // named "outsider", but --as claims laptop-primary

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--as", "laptop-primary", "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "outsider") || !strings.Contains(stderr, "laptop-primary") {
		t.Fatalf("stderr does not name both the loaded key's identity and --as:\n%s", stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("sign wrote %d files despite the identity mismatch", len(entries))
	}
}

// A key file whose name matches --as but whose actual key bytes disagree
// with what the inventory records for that operator must also be refused:
// the agent's trusted-signer set is built from the inventory's recorded
// bytes, not from a name, so a name match alone is not enough to trust.
func TestMain_Sign_RefusesWhenTheLoadedKeyBytesDoNotMatchTheInventory(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))

	rogue, err := identity.Generate("laptop-primary") // same name, different key material
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	key := keyFile(t, rogue)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--as", "laptop-primary", "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "laptop-primary") {
		t.Fatalf("stderr does not name laptop-primary:\n%s", stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("sign wrote %d files despite the key/inventory mismatch", len(entries))
	}
}

// Determinism: an unchanged inventory must produce byte-identical bundles,
// or a config hash means nothing and every pull looks like a change. The
// seal is randomised, so this asserts on the signed inner record instead —
// recovered with the host's own key, which is the only way to see it.
func TestMain_Sign_IsDeterministicForAnUnchangedInventory(t *testing.T) {
	f := newSignFixture(t)
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	dirA, dirB := t.TempDir(), t.TempDir()
	signCLI(t, "--inventory", inv, "--out", dirA, "--key-file", key, "--no-passphrase")
	signCLI(t, "--inventory", inv, "--out", dirB, "--key-file", key, "--no-passphrase")

	innerA := openBundle(t, f.web, filepath.Join(dirA, webID+".bundle"))
	innerB := openBundle(t, f.web, filepath.Join(dirB, webID+".bundle"))
	if !bytes.Equal(innerA, innerB) {
		t.Fatalf("signed inner record differs between two sign runs of an unchanged inventory")
	}

	// The seal itself is randomised (anonymous box, fresh ephemeral key and
	// nonce each call) — a control confirming the two on-disk files are not
	// byte-identical outright, so the inner-record comparison above is
	// actually exercising unsealing rather than a coincidence.
	rawA, _ := os.ReadFile(filepath.Join(dirA, webID+".bundle")) //nolint:gosec // a test reading a file it just generated
	rawB, _ := os.ReadFile(filepath.Join(dirB, webID+".bundle")) //nolint:gosec // a test reading a file it just generated
	if bytes.Equal(rawA, rawB) {
		t.Fatalf("sealed bytes are identical across two runs; the seal is supposed to be randomised")
	}
}

// --host limits output to one host, for a targeted re-sign.
func TestMain_Sign_HostFlagLimitsOutputToOneHost(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	signCLI(t, "--inventory", inv, "--out", dir, "--host", "web-01", "--key-file", key, "--no-passphrase")

	if _, err := os.Stat(filepath.Join(dir, webID+".bundle")); err != nil {
		t.Fatalf("web-01 bundle missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, dbID+".bundle")); !os.IsNotExist(err) {
		t.Fatalf("db-01 bundle exists despite --host web-01: err=%v", err)
	}
}

// A --host naming a host the inventory does not declare is a usage error,
// not a silent no-op.
func TestMain_Sign_RefusesAnUnknownHostFilter(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--host", "no-such-host", "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "no-such-host") {
		t.Fatalf("stderr does not name the unknown host:\n%s", stderr)
	}
}

// --as is required when bundle_signers holds more than one entry, and the
// refusal names the candidates so the operator knows what to pass.
func TestMain_Sign_AsRequiredWhenMultipleBundleSigners(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAMLTwoSigners(1))
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "laptop-primary") || !strings.Contains(stderr, "outsider") {
		t.Fatalf("stderr does not name both signers:\n%s", stderr)
	}
}

// With --as given explicitly, signing as either of two bundle_signers works.
func TestMain_Sign_AsSelectsAmongMultipleBundleSigners(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAMLTwoSigners(1))
	key := keyFile(t, f.outsider)

	signCLI(t, "--inventory", inv, "--out", dir, "--as", "outsider", "--key-file", key, "--no-passphrase")

	if _, err := os.Stat(filepath.Join(dir, webID+".bundle")); err != nil {
		t.Fatalf("bundle missing: %v", err)
	}
}

// postern sign must refuse an inventory whose version is not greater than
// the highest version already present in --out. Re-signing at the same
// version produces bundles every agent rejects as not-newer, and the
// operator's next symptom is a deploy that appears to do nothing.
func TestMain_Sign_RefusesToResignAtAVersionNotNewerThanWhatsInOut(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	key := keyFile(t, f.laptop)

	signCLI(t, "--inventory", writeInventory(t, f.inventoryYAML(5)), "--out", dir, "--key-file", key, "--no-passphrase")
	before, err := os.ReadFile(filepath.Join(dir, webID+".bundle")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read initial bundle: %v", err)
	}

	// Same version again: refused.
	code, _, stderr := trySign(t, "--inventory", writeInventory(t, f.inventoryYAML(5)), "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("re-signing at the same version exited %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "not newer") {
		t.Fatalf("stderr does not explain the version floor:\n%s", stderr)
	}

	// A lower version: also refused.
	code, _, stderr = trySign(t, "--inventory", writeInventory(t, f.inventoryYAML(3)), "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("re-signing at a lower version exited %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}

	after, err := os.ReadFile(filepath.Join(dir, webID+".bundle")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read bundle after refused re-signs: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("a refused re-sign modified the existing bundle on disk")
	}

	// A higher version succeeds.
	signCLI(t, "--inventory", writeInventory(t, f.inventoryYAML(6)), "--out", dir, "--key-file", key, "--no-passphrase")
}

// --host limits which bundle is rewritten, but the version floor check still
// looks at the whole directory: a stale inventory checkout must be caught
// even when --host targets a host the floor's own high-water mark did not
// come from.
func TestMain_Sign_HostFilterStillRefusesAStaleVersionAgainstTheWholeDirectory(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	key := keyFile(t, f.laptop)

	// Sign the whole fleet at version 5, then bump web-01 alone to 6.
	signCLI(t, "--inventory", writeInventory(t, f.inventoryYAML(5)), "--out", dir, "--key-file", key, "--no-passphrase")
	signCLI(t, "--inventory", writeInventory(t, f.inventoryYAML(6)), "--out", dir, "--host", "web-01", "--key-file", key, "--no-passphrase")

	// db-01's own recorded version is still 5, so a floor scoped to only the
	// host being signed would accept version 6 for db-01 (6 > 5). The
	// directory's highest is 6 (from web-01), and version 6 is not *newer*
	// than that, so the whole-directory floor this command actually uses
	// must refuse it even though db-01 itself never held version 6.
	code, _, stderr := trySign(t, "--inventory", writeInventory(t, f.inventoryYAML(6)), "--out", dir, "--host", "db-01", "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
}

// A --host resign must not disturb the other hosts already in --out: their
// bundle files are untouched, and their index.json entries keep their own
// recorded versions rather than being overwritten by this run's version.
func TestMain_Sign_HostFilterPreservesOtherHostsBundlesAndIndexEntries(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	key := keyFile(t, f.laptop)

	signCLI(t, "--inventory", writeInventory(t, f.inventoryYAML(1)), "--out", dir, "--key-file", key, "--no-passphrase")
	dbBefore, err := os.ReadFile(filepath.Join(dir, dbID+".bundle")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read db-01 bundle: %v", err)
	}

	signCLI(t, "--inventory", writeInventory(t, f.inventoryYAML(2)), "--out", dir, "--host", "web-01", "--key-file", key, "--no-passphrase")

	dbAfter, err := os.ReadFile(filepath.Join(dir, dbID+".bundle")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read db-01 bundle after targeted resign: %v", err)
	}
	if !bytes.Equal(dbBefore, dbAfter) {
		t.Fatalf("a --host web-01 resign modified db-01's bundle")
	}

	entries := readIndex(t, dir)
	if entries[dbID].Version != 1 {
		t.Errorf("db-01's index entry = version %d, want it to stay at 1", entries[dbID].Version)
	}
	if entries[webID].Version != 2 {
		t.Errorf("web-01's index entry = version %d, want 2", entries[webID].Version)
	}
}

// index.json maps host_id to the host's signing public key (and the version
// last signed for it), which is what Task 9's ingest needs to verify
// heartbeats without the hub holding anything it could leak.
func TestMain_Sign_WritesIndexJSONMappingHostIDToSigningKey(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	signCLI(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")

	raw, err := os.ReadFile(filepath.Join(dir, "index.json")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	entries := readIndex(t, dir)

	web, ok := entries[webID]
	if !ok {
		t.Fatalf("index.json has no entry for %s", webID)
	}
	if web.Signing != b64Pub(f.web.Public().Signing) {
		t.Errorf("index.json signing key for web-01 = %s, want %s", web.Signing, b64Pub(f.web.Public().Signing))
	}
	if web.Version != 1 {
		t.Errorf("index.json version for web-01 = %d, want 1", web.Version)
	}

	db, ok := entries[dbID]
	if !ok {
		t.Fatalf("index.json has no entry for %s", dbID)
	}
	if db.Signing != b64Pub(f.db.Public().Signing) {
		t.Errorf("index.json signing key for db-01 = %s, want %s", db.Signing, b64Pub(f.db.Public().Signing))
	}

	// index.json is cleartext by necessity (the hub has to read it), so it
	// is held to the same minimality index.json's own doc comment claims:
	// host names are not in it, only host_id and the signing key the hub
	// already needs.
	if strings.Contains(string(raw), "web-01") || strings.Contains(string(raw), "db-01") {
		t.Errorf("index.json names hosts by name rather than only by host_id:\n%s", raw)
	}
}

// --inventory and --out are both required; sign is unusable without either.
func TestMain_Sign_RequiresInventoryAndOutAndKeyFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing --inventory", []string{"--out", "x", "--key-file", "y"}},
		{"missing --out", []string{"--inventory", "x.yaml", "--key-file", "y"}},
		{"missing --key-file", []string{"--inventory", "x.yaml", "--out", "y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := trySign(t, tc.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
			}
		})
	}
}

// The command prints one line per host with its version, then the reminder
// that signing is not deploying.
func TestMain_Sign_PrintsOneLinePerHostAndTheDeployReminder(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(9))
	key := keyFile(t, f.laptop)

	out := signCLI(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")

	if !strings.Contains(out, "web-01") || !strings.Contains(out, "version 9") {
		t.Fatalf("stdout does not report web-01's version:\n%s", out)
	}
	if !strings.Contains(out, "db-01") {
		t.Fatalf("stdout does not report db-01:\n%s", out)
	}
	if !strings.Contains(out, "2 bundles written") {
		t.Fatalf("stdout does not report the bundle count:\n%s", out)
	}
	if !strings.Contains(out, "nothing is deployed until an agent pulls") {
		t.Fatalf("stdout is missing the deploy reminder:\n%s", out)
	}
}

// sign takes no positional arguments; everything is a flag.
func TestMain_Sign_RejectsPositionalArguments(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase", "web-01")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "positional") {
		t.Fatalf("stderr does not explain the positional argument refusal:\n%s", stderr)
	}
}

// An inventory with no hosts at all is not rejected by Inventory.Validate()
// (nothing requires at least one host), so this refusal has to be sign's
// own.
func TestMain_Sign_RefusesAnInventoryWithNoHosts(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	yaml := f.inventoryYAML(1)
	i := strings.Index(yaml, "hosts:")
	if i < 0 {
		t.Fatal("fixture precondition: no \"hosts:\" block found")
	}
	yaml = yaml[:i] + "hosts: []\n"
	inv := writeInventory(t, yaml)
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "no hosts") {
		t.Fatalf("stderr does not say the inventory has no hosts:\n%s", stderr)
	}
}

// Inventory.Validate() has no rule against two of a host's own services
// claiming the same port — that collision is Policy.Validate's
// validatePortOwnership, reached only from inside bundle.Compile, after
// Inventory.Validate() has already passed. This is the one case that
// exercises Compile's error return through the CLI.
//
// The failing host is db-01, the second host in document order, and web-01
// (the first) compiles cleanly — deliberately, so that "nothing was
// written" is not true merely because the failure happened to be first.
// A sequential implementation that wrote each host's bundle as soon as it
// was sealed, rather than compiling and sealing every host before writing
// any of them, would have already written web-01's bundle by the time
// db-01 fails.
func TestMain_Sign_RefusesWhenCompileFailsAndWritesNothing(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	yaml := f.inventoryYAML(1)
	yaml = strings.Replace(yaml, "  confirm:  { kind: action }",
		"  mgmt:     { kind: gate, proto: tcp, ports: [22], default_ttl: 60s, max_ttl: 120s, listener_expectation: present }\n"+
			"  confirm:  { kind: action }", 1)
	marker := "    services: [ssh]"
	last := strings.LastIndex(yaml, marker) // db-01's services line, not web-01's
	if last < 0 {
		t.Fatal("fixture precondition: no services: [ssh] line found")
	}
	yaml = yaml[:last] + "    services: [ssh, mgmt]" + yaml[last+len(marker):]
	inv := writeInventory(t, yaml)
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "db-01") {
		t.Fatalf("stderr does not name the host that failed to compile:\n%s", stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("sign wrote %d files despite a compile failure on the second host", len(entries))
	}
}

// A directory that cannot be created must fail loudly, not silently report
// success.
func TestMain_Sign_ReturnsAnErrorWhenOutCannotBeCreated(t *testing.T) {
	f := newSignFixture(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	dir := filepath.Join(blocker, "bundles") // blocker is a plain file, not a directory
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code == exitOK {
		t.Fatalf("sign exited 0 despite --out being unusable\nstderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "bundles written") {
		t.Fatalf("stderr falsely reports bundles written:\n%s", stderr)
	}
}

// --key-file naming a file that does not exist is a usage error naming the
// path, not a bare "file not found".
func TestMain_Sign_RefusesWhenKeyFileDoesNotExist(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	missing := filepath.Join(t.TempDir(), "no-such-key.json")

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", missing, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, missing) {
		t.Fatalf("stderr does not name the missing key file:\n%s", stderr)
	}
}

// The wrong passphrase against a real, encrypted key file is a usage error
// naming the passphrase, not the identity package's bare sentinel.
func TestMain_Sign_RefusesTheWrongPassphrase(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, f.inventoryYAML(1))
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := identity.SaveFile(path, f.laptop, []byte("correct horse battery staple")); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	e, _, errBuf := testEnv()
	e.getenv = func(k string) string {
		if k == "POSTERN_PASSPHRASE" {
			return "the wrong passphrase"
		}
		return ""
	}
	code := runCLI(t, e, "sign", "--inventory", inv, "--out", dir, "--key-file", path)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "passphrase") {
		t.Fatalf("stderr does not name the passphrase problem:\n%s", errBuf.String())
	}
}

// Malformed inventory YAML is a usage error from ParseInventory, surfaced
// through sign rather than swallowed or turned into a bare panic.
func TestMain_Sign_RefusesMalformedInventoryYAML(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	inv := writeInventory(t, `fleet_id: "unterminated`)
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
}

// --inventory naming a file that does not exist is a usage error, not a bare
// stat failure.
func TestMain_Sign_RefusesWhenInventoryFileDoesNotExist(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	key := keyFile(t, f.laptop)
	missing := filepath.Join(t.TempDir(), "no-such-inventory.yaml")

	code, _, stderr := trySign(t, "--inventory", missing, "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
}

// An inventory that parses but fails Inventory.Validate() (here, a
// bundle_signers entry naming no declared operator) must be refused by
// sign's own call to Validate(), not merely by ParseInventory.
func TestMain_Sign_RefusesAnInventoryThatFailsValidate(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	yaml := strings.Replace(f.inventoryYAML(1),
		"bundle_signers: [laptop-primary]", "bundle_signers: [laptop-primary, nobody-by-that-name]", 1)
	inv := writeInventory(t, yaml)
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "nobody-by-that-name") {
		t.Fatalf("stderr does not name the invalid bundle signer:\n%s", stderr)
	}
}

// index.json is the one file sign both reads and writes; if something else
// has corrupted it, sign must fail rather than silently discard the
// existing entries (which is what an unchecked overwrite would do).
func TestMain_Sign_ReturnsAnErrorWhenIndexJSONIsCorrupt(t *testing.T) {
	f := newSignFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt index.json: %v", err)
	}
	inv := writeInventory(t, f.inventoryYAML(1))
	key := keyFile(t, f.laptop)

	code, _, stderr := trySign(t, "--inventory", inv, "--out", dir, "--key-file", key, "--no-passphrase")
	if code == exitOK {
		t.Fatalf("sign exited 0 despite a corrupt index.json\nstderr:\n%s", stderr)
	}
}

func TestMain_Registry_CarriesSign(t *testing.T) {
	if _, ok := registry["sign"]; !ok {
		t.Fatal(`subcommand "sign" is not registered`)
	}
}
