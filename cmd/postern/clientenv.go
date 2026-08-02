package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
)

// clientFlags are the three things every client subcommand needs to find:
// the config, the key file, and the passphrase that unlocks it. They are
// flags rather than constants so nothing in the logic hardcodes
// ~/.config/postern, which is also what makes these commands testable
// against a temp directory.
type clientFlags struct {
	config         string
	keyFile        string
	passphraseFile string
	noPassphrase   bool
}

func (c *clientFlags) bind(fs *flag.FlagSet) {
	c.bindForExistingKey(fs)
	fs.BoolVar(&c.noPassphrase, "no-passphrase", false,
		"store the operator key unencrypted; only meaningful when minting one, and it must be said out loud")
}

// bindForExistingKey binds the subset of clientFlags relevant to opening a
// key that must already exist: --no-passphrase only ever matters when
// minting one, and `host add` never does — see loadOperatorIdentity. Binding
// it there anyway would be the same defect this package's own comments call
// out elsewhere: a flag that is accepted and silently does nothing.
func (c *clientFlags) bindForExistingKey(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "config", "", "client config path (default $POSTERN_CONFIG, else the user config dir)")
	fs.StringVar(&c.keyFile, "key-file", "", "operator key file (default: from the config, else identity.json beside it)")
	fs.StringVar(&c.passphraseFile, "passphrase-file", "",
		"read the key file passphrase from this path (\"-\" for stdin); default $POSTERN_PASSPHRASE, else prompt")
}

// defaultConfigPath is where an operator's config lives when they have not
// said otherwise. It is resolved here, once, and passed down — no package
// under internal/ knows this path exists.
func defaultConfigPath(e *env) (string, error) {
	if p := e.getenv("POSTERN_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate the user config directory: %w", err)
	}
	return filepath.Join(dir, "postern", "config.yaml"), nil
}

func (c *clientFlags) load(e *env) (*client.Config, error) {
	path := c.config
	if path == "" {
		var err error
		if path, err = defaultConfigPath(e); err != nil {
			return nil, usageError{err}
		}
	}
	cfg, err := client.LoadConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usagef("no client config at %s — run `postern operator init` then `postern host add` to create one", path)
		}
		return nil, usageError{err}
	}
	return cfg, nil
}

// signer unlocks the operator's identity.
func (c *clientFlags) signer(e *env, cfg *client.Config) (identity.Signer, error) {
	path := c.keyFile
	if path == "" {
		path = cfg.KeyFilePath()
	}
	pass, err := c.passphrase(e)
	if err != nil {
		return nil, err
	}
	s, err := identity.LoadFile(path, pass)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usagef("no operator key at %s — run `postern operator init` to create one", path)
		}
		if errors.Is(err, identity.ErrIncorrectPassphrase) {
			return nil, usagef("the passphrase for %s is wrong (or the file is corrupt): %v", path, err)
		}
		return nil, err
	}
	if s.Public().Name != cfg.Operator {
		// A mismatch here means the packets would be signed by a key the host
		// may not know, and the host's rejection is silent. Better to refuse
		// now, with a name in the message.
		return nil, usagef("key file %s holds identity %q but the config names operator %q",
			path, s.Public().Name, cfg.Operator)
	}
	return s, nil
}

// ErrNoPassphraseSource means no passphrase could be obtained: none was
// configured, and there is no terminal to ask at.
var ErrNoPassphraseSource = errors.New("no passphrase source is available")

// nonInteractivePassphrase resolves the sources that need no terminal, in
// precedence order. It returns ErrNoPassphraseSource when there are none, so
// the two callers can differ on what that means.
func (c *clientFlags) nonInteractivePassphrase(e *env) ([]byte, error) {
	if c.noPassphrase {
		return nil, nil
	}
	if c.passphraseFile == "-" {
		data, err := readAll(e.stdin)
		if err != nil {
			return nil, fmt.Errorf("read passphrase from stdin: %w", err)
		}
		return trimNewline(data), nil
	}
	if c.passphraseFile != "" {
		data, err := os.ReadFile(c.passphraseFile) //nolint:gosec // the operator named this path
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		return trimNewline(data), nil
	}
	if v := e.getenv("POSTERN_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	return nil, ErrNoPassphraseSource
}

// passphrase resolves the passphrase for a key file that already exists.
//
// An unattended run with no configured source falls through to the empty
// passphrase rather than failing: a key may legitimately have been minted
// with --no-passphrase, and if it was not, identity.LoadFile returns
// ErrIncorrectPassphrase, which signer() turns into a message naming the
// file. Guessing wrong here costs a clear error; refusing would break every
// scripted open against a deliberately unencrypted key.
func (c *clientFlags) passphrase(e *env) ([]byte, error) {
	pass, err := c.nonInteractivePassphrase(e)
	if err == nil {
		return pass, nil
	}
	if !errors.Is(err, ErrNoPassphraseSource) {
		return nil, err
	}
	if e.isTerminal != nil && e.isTerminal() {
		return e.readPassword("passphrase for the postern operator key: ")
	}
	return nil, nil
}

// newKeyPassphrase resolves the passphrase for a key about to be minted, and
// refuses rather than defaulting to the empty one.
//
// This is the asymmetry that matters. Reading a key with the wrong
// passphrase produces an error the operator sees. *Writing* one with a
// passphrase nobody chose produces a file that works perfectly — design
// section 5's "the key that opens every door in a fleet", sealed under
// scrypt of the empty string, recoverable by anything running as that user,
// with no symptom until it is someone else's. So an unattended mint with no
// configured source is refused, and the refusal names the flag that makes
// the choice explicit.
//
// The interactive path asks twice. A mistyped passphrase on a key that is
// only ever unlocked during an outage is discovered at the worst possible
// moment.
func (c *clientFlags) newKeyPassphrase(e *env) ([]byte, error) {
	pass, err := c.nonInteractivePassphrase(e)
	if err == nil {
		if !c.noPassphrase && len(pass) == 0 {
			return nil, usagef("the configured passphrase source is empty. To store the operator key " +
				"unencrypted, say so with --no-passphrase.")
		}
		return pass, nil
	}
	if !errors.Is(err, ErrNoPassphraseSource) {
		return nil, err
	}

	if e.isTerminal == nil || !e.isTerminal() {
		return nil, usagef("refusing to mint an operator key with no passphrase. stdin is not a " +
			"terminal, so there is nothing to prompt, and $POSTERN_PASSPHRASE and --passphrase-file " +
			"are both unset. This key signs every knock you will ever send; an empty passphrase makes " +
			"it recoverable by anything running as this user. Set $POSTERN_PASSPHRASE, pass " +
			"--passphrase-file, or pass --no-passphrase if you genuinely want it stored unencrypted.")
	}

	first, err := e.readPassword("new passphrase for the postern operator key: ")
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, usagef("an empty passphrase leaves the operator key recoverable by anything " +
			"running as this user. Pass --no-passphrase if that is what you want.")
	}
	second, err := e.readPassword("repeat it: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, usagef("the two passphrases do not match")
	}
	return first, nil
}

// flagWasSet reports whether the operator actually passed a flag, as opposed
// to it holding its zero default. flag.FlagSet.Parse does not clear the set
// of visited flags between calls, so this stays correct across parseFlags'
// permutation loop.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func trimNewline(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), "\r\n"))
}

// newFlagSet builds a FlagSet that reports to the command's own stderr and
// never calls os.Exit, so run() owns every exit path.
func newFlagSet(e *env, name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.Usage = func() {
		outf(e.stderr, "usage: postern %s\n\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args and returns the positional arguments, permitting
// flags to appear before or after them.
//
// stdlib flag stops at the first non-flag argument, so `postern open web-01
// --ttl 5m` would otherwise treat "--ttl" and "5m" as positionals and refuse
// the command. Every other tool an operator uses accepts that order, and a
// break-glass command that rejects it on a technicality — while the host is
// unreachable — is the kind of friction that gets a tool abandoned. The loop
// takes one positional at a time and re-parses the remainder; values already
// set survive, because Parse resets only the argument list.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageError{err}
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func readAll(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errors.New("no stdin")
	}
	return io.ReadAll(r)
}
