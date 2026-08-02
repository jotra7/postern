package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

func init() {
	register(&command{
		name:    "sign",
		usage:   "sign --inventory FILE --out DIR --key-file FILE [--as NAME] [--host NAME] [flags]",
		summary: "compile a fleet inventory into sealed, signed bundles for a hub to serve",
		run:     runSign,
	})
}

// signedIssuedAt is the fixed instant recorded in every bundle's issued_at
// field. Real wall-clock time there would make two signing runs of the same
// unchanged inventory produce different bytes, and the whole point of a
// deterministic bundle (this command's own determinism test) is that an
// unchanged inventory hashes the same — a hub, or an operator diffing a
// redeploy, has to be able to tell "nothing changed" from the bytes, not
// from trusting the clock. Nothing in the wire format's history reads this
// field yet; it is here for a future consumer this task does not need to
// satisfy, so a fixed sentinel costs nothing today.
var signedIssuedAt = time.Unix(0, 0).UTC()

// runSign compiles a fleet inventory into one signed, sealed bundle per host
// (design section 6) and writes them, plus index.json, to --out for a hub to
// serve.
//
// Unlike enroll and open, this never touches a local client config: the
// machine running `sign` may hold a key for a fleet operator distinct from
// whatever `postern operator init` set up here, or may be a CI signing box
// with no client config at all. --key-file is therefore required rather than
// defaulted, and the operator identity it names is checked two ways before
// anything is signed: its name must match --as, and its actual public key
// bytes must match what the inventory records for that operator — a name
// match alone would let a stale or mistyped local key produce bundles every
// agent rejects as coming from an untrusted signer.
func runSign(ctx context.Context, e *env, args []string) error {
	usage := "sign --inventory FILE --out DIR --key-file FILE [--as NAME] [--host NAME] [flags]"
	fs := newFlagSet(e, "sign", usage)
	inventoryPath := fs.String("inventory", "", "path to the fleet inventory YAML (required)")
	outDir := fs.String("out", "", "directory to write sealed bundles and index.json into (required)")
	keyFile := fs.String("key-file", "", "the signing operator's private key file (required)")
	passphraseFile := fs.String("passphrase-file", "",
		"read the key file passphrase from this path (\"-\" for stdin); default $POSTERN_PASSPHRASE, else prompt")
	noPassphrase := fs.Bool("no-passphrase", false, "the key file is stored unencrypted; skip the passphrase prompt")
	as := fs.String("as", "", "operator name to sign as (default: the inventory's one bundle_signers entry)")
	hostName := fs.String("host", "", "sign only this host, for a targeted re-sign")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		fs.Usage()
		return usagef("sign takes no positional arguments")
	}
	if *inventoryPath == "" {
		return usagef("--inventory is required")
	}
	if *outDir == "" {
		return usagef("--out is required")
	}
	if *keyFile == "" {
		return usagef("--key-file is required: sign does not consult any local client config for it")
	}

	data, err := os.ReadFile(*inventoryPath) //nolint:gosec // the operator named this path
	if err != nil {
		return usageError{fmt.Errorf("read inventory: %w", err)}
	}
	inv, err := config.ParseInventory(data)
	if err != nil {
		return usageError{err}
	}
	if err := inv.Validate(); err != nil {
		return usageError{err}
	}

	asName, err := resolveSigningOperator(inv, *as)
	if err != nil {
		return usageError{err}
	}
	op, err := findInventoryOperator(inv, asName)
	if err != nil {
		return usageError{err}
	}

	cf := clientFlags{keyFile: *keyFile, passphraseFile: *passphraseFile, noPassphrase: *noPassphrase}
	signer, err := loadSignOperatorKey(e, &cf)
	if err != nil {
		return err
	}
	if signer.Public().Name != asName {
		return usagef("the key at %s is named %q, but --as is %q; pass --key-file for the right key",
			*keyFile, signer.Public().Name, asName)
	}
	if signer.Public().Signing != op.Identity.Signing {
		return usagef("the key at %s does not match the signing key %s records for operator %q; "+
			"bundles it signs would be rejected by every agent as coming from an untrusted signer",
			*keyFile, *inventoryPath, asName)
	}

	hosts := inv.Hosts
	if *hostName != "" {
		h, err := inv.Host(*hostName)
		if err != nil {
			return usageError{err}
		}
		hosts = []config.InventoryHost{*h}
	}
	if len(hosts) == 0 {
		return usagef("the inventory declares no hosts")
	}

	idx, err := loadBundleIndex(*outDir)
	if err != nil {
		return err
	}
	if floor, ok := idx.maxVersion(); ok && inv.Version <= floor {
		return usagef("inventory version %d is not newer than %d, the highest version already present in %s; "+
			"re-signing at a version that is not newer produces bundles every agent rejects as not-newer — "+
			"bump the inventory's version field before signing again", inv.Version, floor, *outDir)
	}

	// Compile and seal every host before writing anything: a failure partway
	// through must not leave --out holding some bundles at the new version
	// and some stale, which is exactly the half-deployed state the version
	// floor above exists to prevent an operator from creating by hand.
	type signedHost struct {
		host   config.InventoryHost
		sealed bundle.Sealed
	}
	signed := make([]signedHost, 0, len(hosts))
	for _, h := range hosts {
		policy, err := bundle.Compile(inv, h.Name)
		if err != nil {
			return usageError{err}
		}
		policyBytes, err := config.MarshalStandalone(policy)
		if err != nil {
			return fmt.Errorf("host %q: marshal policy: %w", h.Name, err)
		}
		contents := &bundle.Contents{
			FleetID:  inv.FleetID,
			HostID:   h.HostID,
			Version:  inv.Version,
			IssuedAt: signedIssuedAt,
			Policy:   policyBytes,
		}
		sealed, err := bundle.Seal(contents, signer, h.HostIdentity.Encryption)
		if err != nil {
			if errors.Is(err, bundle.ErrRecipientKey) {
				// Inventory.Validate already rejects a low-order
				// host_identity encryption key, so this should be
				// unreachable in practice — but Seal has callers other than
				// this command, and a silent "seal: bundle: host encryption
				// key rejected" is exactly the opaque failure the task that
				// added this check exists to prevent.
				return fmt.Errorf("host %q: encryption key is not a usable X25519 point (%w); "+
					"this should have been caught by inventory validation — check host_identity.encryption for %q",
					h.Name, err, h.Name)
			}
			return fmt.Errorf("host %q: seal: %w", h.Name, err)
		}
		signed = append(signed, signedHost{host: h, sealed: sealed})
	}

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", *outDir, err)
	}
	for _, s := range signed {
		path := filepath.Join(*outDir, hex.EncodeToString(s.host.HostID[:])+".bundle")
		// A bundle is sealed ciphertext — doc.go is explicit that this is the
		// entire reason bundles are sealed rather than merely signed — so it
		// is safe to be world-readable, and it must be, because whatever
		// serves it to a hub may run as a different user than the one that
		// signed it.
		if err := os.WriteFile(path, s.sealed, 0o644); err != nil { //nolint:gosec // sealed ciphertext, meant to be served
			return fmt.Errorf("write %s: %w", path, err)
		}
		idx.set(s.host.HostID, s.host.HostIdentity.Signing, inv.Version)
		outf(e.stdout, "✓ %-7s version %d\n", s.host.Name, inv.Version)
	}
	if err := idx.writeTo(*outDir); err != nil {
		return err
	}

	outf(e.stdout, "%d bundles written to %s — nothing is deployed until an agent pulls\n", len(signed), *outDir)
	return nil
}

// resolveSigningOperator applies the --as default: the inventory's one
// bundle_signers entry when there is exactly one, required otherwise. It
// also refuses an --as that names a real, declared operator who simply is
// not a bundle signer — Inventory.Validate already guarantees every
// bundle_signers entry resolves to a declared operator, but says nothing
// about the reverse, and signing with a non-signer's key produces bundles
// every agent rejects.
func resolveSigningOperator(inv *config.Inventory, as string) (string, error) {
	if as != "" {
		for _, name := range inv.BundleSigners {
			if name == as {
				return as, nil
			}
		}
		return "", fmt.Errorf("--as %q is not in the inventory's bundle_signers %v", as, inv.BundleSigners)
	}
	switch len(inv.BundleSigners) {
	case 1:
		return inv.BundleSigners[0], nil
	case 0:
		// Unreachable: inv.Validate() already refuses an empty
		// bundle_signers before this function is ever called.
		return "", fmt.Errorf("the inventory has no bundle signers")
	default:
		return "", fmt.Errorf("the inventory names %d bundle signers %v; pass --as to say which one is signing",
			len(inv.BundleSigners), inv.BundleSigners)
	}
}

// findInventoryOperator resolves name to its declared operator record.
func findInventoryOperator(inv *config.Inventory, name string) (*config.InventoryOperator, error) {
	for i := range inv.Operators {
		if inv.Operators[i].Identity.Name == name {
			return &inv.Operators[i], nil
		}
	}
	return nil, fmt.Errorf("operator %q is not declared in the inventory", name)
}

// loadSignOperatorKey opens the key file that will sign bundles. It mirrors
// clientFlags.signer's passphrase handling and error messages, but does not
// check the loaded identity's name against anything here — runSign checks it
// against --as and against the inventory's own record instead, which is the
// pair of checks that actually matters for a bundle signer.
func loadSignOperatorKey(e *env, cf *clientFlags) (identity.Signer, error) {
	pass, err := cf.passphrase(e)
	if err != nil {
		return nil, err
	}
	s, err := identity.LoadFile(cf.keyFile, pass)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usagef("no key file at %s", cf.keyFile)
		}
		if errors.Is(err, identity.ErrIncorrectPassphrase) {
			return nil, usagef("the passphrase for %s is wrong (or the file is corrupt): %v", cf.keyFile, err)
		}
		return nil, err
	}
	return s, nil
}

// bundleIndex is index.json: the one piece of cleartext state `sign` keeps
// in --out. It exists for two reasons. First, it is what Task 9's ingest
// needs to verify a heartbeat's signature — the hub holds bundles it cannot
// open (sealing is anonymous), so it has nowhere else to learn a host's
// signing key. Second, it is what lets `sign` itself compute the re-sign
// floor: the signer holds no host's private key either, so it cannot open a
// bundle it already wrote to recover the version inside it, and this is the
// only record of that version it can consult.
//
// It is deliberately minimal: host_id and a signing key the hub already
// needs to do its job, and the version, and nothing else — no host name, no
// fleet structure beyond what serving bundles at all already requires. A
// hub is not sealed the way a bundle is, so anything more here is exactly
// the kind of leak the bundle's own opacity exists to prevent.
type bundleIndex struct {
	Hosts map[string]bundleIndexEntry `json:"hosts"`
}

type bundleIndexEntry struct {
	// Signing is the host's own Ed25519 public key, base64: what the hub
	// verifies a heartbeat's signature against.
	Signing string `json:"signing"`
	// Version is the bundle version last signed for this host.
	Version uint64 `json:"version"`
}

func bundleIndexPath(dir string) string { return filepath.Join(dir, "index.json") }

// loadBundleIndex reads dir's index.json, or returns an empty index if the
// directory has never been signed into.
func loadBundleIndex(dir string) (*bundleIndex, error) {
	path := bundleIndexPath(dir)
	data, err := os.ReadFile(path) //nolint:gosec // dir is operator-supplied, same as --out generally
	if err != nil {
		if os.IsNotExist(err) {
			return &bundleIndex{Hosts: map[string]bundleIndexEntry{}}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var idx bundleIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if idx.Hosts == nil {
		idx.Hosts = map[string]bundleIndexEntry{}
	}
	return &idx, nil
}

// maxVersion is the highest version recorded across every host currently in
// the index, which is the floor a re-sign must clear — regardless of which
// host --host is targeting, since a single inventory names one version for
// every bundle it produces, and a stale inventory checkout must be caught
// even when it is only being used to re-sign a host that floor does not
// itself mention yet.
func (idx *bundleIndex) maxVersion() (version uint64, ok bool) {
	for _, entry := range idx.Hosts {
		if !ok || entry.Version > version {
			version = entry.Version
			ok = true
		}
	}
	return version, ok
}

// set records (or replaces) one host's entry. Hosts not touched by this run
// — because --host named a different one — are left exactly as they were,
// which is what lets a targeted re-sign share a directory with hosts it did
// not resign.
func (idx *bundleIndex) set(hostID [16]byte, signing [32]byte, version uint64) {
	idx.Hosts[hex.EncodeToString(hostID[:])] = bundleIndexEntry{
		Signing: base64.StdEncoding.EncodeToString(signing[:]),
		Version: version,
	}
}

func (idx *bundleIndex) writeTo(dir string) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("encode index.json: %w", err)
	}
	data = append(data, '\n')
	path := bundleIndexPath(dir)
	// index.json holds no secret — only host_id, a public signing key, and a
	// version number (see bundleIndex's own doc comment) — and it must be
	// readable by whatever serves it to a hub.
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // no secret in this file; meant to be served
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
