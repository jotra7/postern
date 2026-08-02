package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
)

// This file is the machinery `operator init`, `host add`, and the deprecated
// `enroll` alias all share. It used to live entirely inside `enroll`, back
// when that one command did everything these now split between them (#28) —
// see cmd_enroll.go, cmd_operator.go, and cmd_host.go for what each does
// with it.

// noteAssertedSource says, at enrollment, that this host will refuse an
// asserted source prefix.
//
// Enrollment is the last moment an operator reliably has working access, and
// it is the only moment at which the fix — re-running init-standalone on the
// host — costs nothing. Every other moment it could be said is after the
// lockout, from a client that cannot reach the host to apply it.
//
// It fires only on an entry that records the refusal, never on one that says
// nothing. A default-generated entry does record it, so a default enrollment
// prints this line; entries that predate the field, and hand-written ones,
// stay silent rather than being warned about on a guess. That split is the
// whole reason the field is a tri-state: a note that fired on silence would
// fire on every enrollment postern has ever done, and be ignored by the time
// it mattered.
func noteAssertedSource(e *env, entry *client.Host, operator string) {
	if entry.AssertedSourceGrant() != client.AssertedSourceNotGranted {
		return
	}
	outf(e.stderr, "note: %s permits no asserted source prefix, so `postern open --source-cidr` against "+
		"it is refused — silently, as every SPA refusal is. If you knock from behind a carrier NAT that "+
		"egresses UDP and TCP from different addresses, re-run init-standalone on the host now with "+
		"--allow-source-cidr %s, while you still have a way in.\n", entry.Name, operator)
}

// loadOrCreateConfig returns the operator's config and whether it had to be
// invented, which the caller needs in order to decide whether a name
// disagreeing with the key file is a fresh config to correct or an existing
// one to refuse.
func loadOrCreateConfig(path, operator string, e *env) (*client.Config, bool, error) {
	cfg, err := client.LoadConfig(path)
	if err == nil {
		if operator != "" && operator != cfg.Operator {
			return nil, false, usagef("%s already names operator %q; --operator cannot rename an existing identity", path, cfg.Operator)
		}
		return cfg, false, nil
	}
	if !os.IsNotExist(errUnwrapPath(err)) {
		return nil, false, err
	}
	name := operator
	if name == "" {
		name = e.getenv("USER")
	}
	if name == "" {
		name = "operator"
	}
	// A config with no hosts does not pass ParseConfig, and should not: an
	// operator config that cannot knock anything is not a valid one. So the
	// in-memory value is built directly here and only written once a host
	// entry has joined it.
	cfg = &client.Config{Operator: name}
	cfg.SetDir(filepath.Dir(path))
	return cfg, true, nil
}

// errUnwrapPath finds the os error under LoadConfig's wrapping.
func errUnwrapPath(err error) error {
	for err != nil {
		if os.IsNotExist(err) {
			return err
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
	return nil
}

// loadOrCreateIdentity opens the operator key, or mints one.
//
// Which passphrase resolver runs depends on which of those two happens, and
// that split is the whole point: reading a key with the wrong passphrase
// produces an error the operator sees, while writing one under a passphrase
// nobody chose produces a file that works perfectly and is recoverable by
// anything running as this user. So the mint path refuses where the load
// path guesses.
//
// The existence check is a stat rather than a failed LoadFile because the
// passphrase has to be resolved differently before the call, not after it.
//
// Only `operator init` and the deprecated `enroll` alias call this. `host
// add` calls loadOperatorIdentity instead, which never mints: registering a
// host under an identity that does not exist yet should say so, not choose a
// name and a passphrase policy on the operator's behalf.
func loadOrCreateIdentity(e *env, cf *clientFlags, path, name string) (identity.Signer, bool, error) {
	if _, statErr := os.Stat(path); statErr == nil {
		pass, err := cf.passphrase(e)
		if err != nil {
			return nil, false, err
		}
		s, err := identity.LoadFile(path, pass)
		if err != nil {
			if errors.Is(err, identity.ErrIncorrectPassphrase) {
				return nil, false, usagef("the passphrase for %s is wrong (or the file is corrupt)", path)
			}
			return nil, false, err
		}
		return s, false, nil
	} else if !os.IsNotExist(statErr) {
		return nil, false, fmt.Errorf("stat %s: %w", path, statErr)
	}

	pass, err := cf.newKeyPassphrase(e)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create key directory: %w", err)
	}
	s, err := identity.Generate(name)
	if err != nil {
		return nil, false, fmt.Errorf("generate operator identity: %w", err)
	}
	if err := identity.SaveFile(path, s, pass); err != nil {
		return nil, false, fmt.Errorf("write operator key: %w", err)
	}
	return s, true, nil
}

// loadOperatorIdentity opens the operator identity `operator init` already
// created. Unlike loadOrCreateIdentity, it never mints one.
//
// `host add` registers a host under an identity that is supposed to already
// exist. Minting one silently here — the way the old combined `enroll` did —
// would let the first `host add` invocation choose an operator name and a
// passphrase policy by accident, instead of `operator init` choosing them on
// purpose. So a missing key is a refusal that names the command which
// creates one.
func loadOperatorIdentity(e *env, cf *clientFlags, path string) (identity.Signer, error) {
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, usagef("no operator identity at %s yet; run `postern operator init` first", path)
		}
		return nil, fmt.Errorf("stat %s: %w", path, statErr)
	}
	pass, err := cf.passphrase(e)
	if err != nil {
		return nil, err
	}
	s, err := identity.LoadFile(path, pass)
	if err != nil {
		if errors.Is(err, identity.ErrIncorrectPassphrase) {
			return nil, usagef("the passphrase for %s is wrong (or the file is corrupt)", path)
		}
		return nil, err
	}
	return s, nil
}

// loadOperatorContext is what `host add` needs before it can register
// anything: the config path, the config itself (invented in memory if this
// is the first host), and the identity that will sign every knock built
// from it.
//
// The name-reconciliation here mirrors what the old combined `enroll` did
// across its two calls: a freshly invented config defaults its operator name
// to $USER, and if that guess disagrees with the key actually sitting at
// keyPath, the key is the fact — see the comment this replaced in
// cmd_enroll.go's history for why the alternative silently produces a config
// every later command refuses.
func loadOperatorContext(e *env, cf *clientFlags) (path string, cfg *client.Config, signer identity.Signer, err error) {
	path = cf.config
	if path == "" {
		if path, err = defaultConfigPath(e); err != nil {
			return "", nil, nil, usageError{err}
		}
	}
	cfg, configIsNew, err := loadOrCreateConfig(path, "", e)
	if err != nil {
		return "", nil, nil, err
	}

	keyPath := cf.keyFile
	if keyPath == "" {
		keyPath = cfg.KeyFilePath()
	}
	signer, err = loadOperatorIdentity(e, cf, keyPath)
	if err != nil {
		return "", nil, nil, err
	}
	if configIsNew && signer.Public().Name != cfg.Operator {
		cfg.Operator = signer.Public().Name
	}
	if signer.Public().Name != cfg.Operator {
		return "", nil, nil, usagef("key file %s holds identity %q but %s names operator %q; this will not "+
			"write a config whose every later command would be refused", keyPath, signer.Public().Name, path, cfg.Operator)
	}
	return path, cfg, signer, nil
}

func printEnrollInstructions(e *env, operator string, pub identity.PublicIdentity, hostName string) {
	if hostName == "" {
		hostName = "<host>"
	}
	sign := base64.StdEncoding.EncodeToString(pub.Signing[:])
	enc := base64.StdEncoding.EncodeToString(pub.Encryption[:])
	outf(e.stdout, "operator %s\n", operator)
	outf(e.stdout, "  signing:    %s\n", sign)
	outf(e.stdout, "  encryption: %s\n", enc)
	outln(e.stdout)
	outf(e.stdout, "run this on %s as root, over ordinary SSH:\n", hostName)
	outf(e.stdout, "  postern init-standalone --host-name %s \\\n", hostName)
	outf(e.stdout, "    --knock-addr <the address you will knock> \\\n")
	outf(e.stdout, "    --always-allow-iface <your mesh interface> \\\n")
	outf(e.stdout, "    --operator '%s=%s,%s' --go-live > entry.yaml\n", operator, sign, enc)
	outln(e.stdout)
	outln(e.stdout, "--go-live arms the host and prints a confirm line once it comes up.")
	outln(e.stdout)
	outf(e.stdout, "then bring entry.yaml back and run:\n")
	outf(e.stdout, "  postern host add %s --from entry.yaml\n", hostName)
	outln(e.stdout)
	outln(e.stdout, "then run the confirm line the host printed.")
}

func readEntryBytes(e *env, from string) ([]byte, error) {
	var data []byte
	var err error
	if from == "-" {
		data, err = readAll(e.stdin)
	} else {
		data, err = os.ReadFile(from) //nolint:gosec // the operator named this path
	}
	if err != nil {
		return nil, fmt.Errorf("read host entry: %w", err)
	}
	return data, nil
}

// parseHostEntry decodes the entry.yaml a host printed at enrollment.
//
// Unknown keys are reported and then ignored, which is the same posture
// client.ParseConfig takes and for the same reason: this file is written by
// the host, and a key the laptop does not recognise means the host is newer
// than the laptop. Refusing it turns that into an operator who cannot enroll,
// and the moment they find out is the outage the laptop was kept for. The
// host's own config keeps KnownFields(true), where a misspelled key costs no
// feature but silently inverts a fail posture.
//
// They are reported rather than swallowed because the other thing an unknown
// key can mean is a typo in a file someone hand-edited, and that costs a
// capability quietly. The caller decides where the notice goes; nothing here
// writes to a stream it was not handed.
func parseHostEntry(data []byte) (*client.Host, []string, error) {
	var h client.Host
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&h); err != nil {
		return nil, nil, fmt.Errorf("parse host entry: %w", err)
	}
	if h.Name == "" {
		return nil, nil, usagef("the host entry has no name")
	}
	return &h, unknownEntryKeys(data), nil
}

// unknownEntryKeys re-decodes strictly and reads the keys back out of the
// error, so the list comes from the same decoder that produced the value
// rather than from a second model of the schema that could drift from it.
func unknownEntryKeys(data []byte) []string {
	var probe client.Host
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(&probe)
	if err == nil {
		return nil
	}
	var keys []string
	for _, line := range strings.Split(err.Error(), "\n") {
		const marker = "field "
		i := strings.Index(line, marker)
		if i < 0 || !strings.Contains(line, " not found in type ") {
			continue
		}
		rest := line[i+len(marker):]
		if j := strings.Index(rest, " not found in type "); j >= 0 {
			keys = append(keys, rest[:j])
		}
	}
	return keys
}

// upsertHost adds or replaces a host, then re-validates the whole config
// through the same parser `open` will use. Writing a config that the next
// command refuses to load is a worse outcome than refusing to write it.
func upsertHost(cfg *client.Config, entry *client.Host) error {
	replaced := false
	for i := range cfg.Hosts {
		if cfg.Hosts[i].Name == entry.Name {
			cfg.Hosts[i] = *entry
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.Hosts = append(cfg.Hosts, *entry)
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode client config: %w", err)
	}
	if _, err := client.ParseConfig(body); err != nil {
		return fmt.Errorf("the host entry does not produce a usable config: %w", err)
	}
	return nil
}

func writeClientConfig(path string, cfg *client.Config) error {
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode client config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return os.Chmod(path, 0o600)
}

// warnUnknownEntryKeys prints the notice parseHostEntry's caller owes an
// operator when a host entry carried keys this build does not know.
func warnUnknownEntryKeys(e *env, keys []string) {
	if len(keys) == 0 {
		return
	}
	outf(e.stderr, "note: this host entry carries %d key(s) this postern does not know: %s. "+
		"They were ignored. That is expected when the host is newer than this laptop, and it is a typo "+
		"when it is not.\n", len(keys), strings.Join(keys, ", "))
}
