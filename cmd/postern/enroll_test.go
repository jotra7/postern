package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

var keyLine = regexp.MustCompile(`(?m)^\s+(signing|encryption):\s+(\S+)$`)

// The two halves of enrollment have to fit: what `enroll` prints is what
// `init-standalone` consumes, and what `init-standalone` prints is what
// `enroll --from` consumes. Neither half is useful alone, and a mismatch
// between them is invisible until an operator is locked out.
//
// The test then carries the result all the way to the agent's own
// validation pipeline against the generated host config and host key — so
// what is asserted is not "the files look right" but "a packet built from
// the client config is accepted by a host built from the host config".
// Everything between them is real: identity files, YAML, the seal, the
// signature, the replay store.
func TestMain_Enroll_ProducesAClientConfigWhoseKnockTheGeneratedHostAccepts(t *testing.T) {
	home := t.TempDir()
	etc := filepath.Join(home, "etc")
	configPath := filepath.Join(home, "config.yaml")

	// 1. The operator's side, with no host yet: mint the identity and print
	//    the public halves.
	e, out, _ := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, out.String())
	}
	keys := keyLine.FindAllStringSubmatch(out.String(), -1)
	if len(keys) != 2 {
		t.Fatalf("enroll printed %d key lines, want 2:\n%s", len(keys), out.String())
	}
	signing, encryption := keys[0][2], keys[1][2]

	// 2. The host's side: generate its config, identity, ruleset and units,
	//    trusting that operator.
	e2, entry, _ := envWithHome(t, home)
	if code := runCLI(t, e2,
		"init-standalone", "--no-nft-check",
		"--dir", etc,
		"--state-dir", filepath.Join(home, "var"),
		"--unit-dir", filepath.Join(home, "units"),
		"--host-name", "web-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--ssh-host", "web-01.example.com",
		"--ssh-user", "ops",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", "laptop-primary="+signing+","+encryption,
	); code != exitOK {
		t.Fatalf("init-standalone failed")
	}

	// 3. Back on the operator's side: consume the host entry.
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry.String()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e3, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e3, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll --from exited %d: %s", code, errBuf.String())
	}

	// The client config the operator now holds.
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("the written client config does not load: %v", err)
	}
	host, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if host.KnockAddrPort().String() != "203.0.113.9:62201" {
		t.Fatalf("knock address = %s", host.KnockAddrPort())
	}
	if host.SSH.Host != "web-01.example.com" {
		t.Fatalf("ssh host = %q; the entry lost it", host.SSH.Host)
	}

	// 4. Build the host exactly as `postern agent` would.
	policyBody, err := os.ReadFile(filepath.Join(etc, "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("read host config: %v", err)
	}
	policy, err := config.ParseStandalone(policyBody)
	if err != nil {
		t.Fatalf("parse host config: %v", err)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("validate host config: %v", err)
	}
	hostSigner, err := identity.LoadFile(filepath.Join(etc, "host.key"), nil)
	if err != nil {
		t.Fatalf("load host key: %v", err)
	}
	ops := make([]identity.PublicIdentity, 0, len(policy.Operators))
	for _, op := range policy.Operators {
		ops = append(ops, op.Identity)
	}
	opener, rejected, err := spa.NewOpenerFromSigner(hostSigner, ops)
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("the generated config carries operator keys the host rejects: %v", rejected)
	}
	store, err := replay.Open(filepath.Join(t.TempDir(), "replay.db"), replay.Options{})
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	// 5. The operator knocks. Everything on the wire is real.
	signer, err := identity.LoadFile(cfg.KeyFilePath(), nil)
	if err != nil {
		t.Fatalf("load operator key: %v", err)
	}
	var sent [][]byte
	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: signer},
		Host:    host,
		Service: "ssh",
		Counter: client.NewCounter(cfg.CounterFilePath()),
		Send: func(_ context.Context, _ netip.AddrPort, payload []byte) error {
			sent = append(sent, payload)
			return nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent %d datagrams, want one", len(sent))
	}
	if rep.Result.Outcome != client.Connected {
		t.Fatalf("outcome = %q", rep.Result.Outcome)
	}

	dec, err := agent.Validate(sent[0], netip.MustParseAddr("198.51.100.7"), policy, opener, store,
		agent.PendingTransaction{}, false, time.Now())
	if err != nil {
		t.Fatalf("the host rejected a knock built from the config enrollment produced: %v", err)
	}
	if dec.Service != "ssh" || dec.ServiceKind != config.KindGate {
		t.Fatalf("decision = %+v, want an ssh gate", dec)
	}
	if dec.Source.Prefix.Addr().String() != "198.51.100.7" {
		t.Fatalf("the gate would open for %s, not the observed source", dec.Source.Prefix)
	}
	if dec.TTL != 120*time.Second {
		t.Fatalf("ttl = %s, want the configured default of 120s", dec.TTL)
	}
}

// Re-enrolling a host replaces its entry rather than appending a second one:
// a config with two `web-01` blocks is refused by the parser, so an append
// would leave an operator with a config that no longer loads at all.
func TestMain_Enroll_ReplacesAnExistingHostEntry(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 203.0.113.9\n" +
		"knock_port: 62201\n" +
		"host_encryption: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"services:\n" +
		"  ssh: { port: 22 }\n"
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for i := 0; i < 2; i++ {
		e, _, errBuf := envWithHome(t, home)
		if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
			t.Fatalf("enroll #%d exited %d: %s", i, code, errBuf.String())
		}
	}
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("the config after two enrolls does not load: %v", err)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("%d host entries after re-enrolling one host, want 1", len(cfg.Hosts))
	}
}

// #28: enroll is deprecated but must keep working exactly as before, so that
// nobody's runbook breaks silently — that guarantee is the whole reason
// splitting the verb is cheap to do now. This drives it through --from
// exactly like the pre-split behaviour and checks both halves: the notice
// fires, and the command still does its job.
//
// Mutation verified: removing the notice print in runEnroll fails this on
// the "postern operator init" assertion while the registration assertions
// below it keep passing — which is the point, the alias's behaviour must
// not change even though its output gains a line.
func TestMain_Enroll_PrintsADeprecationNoticeAndStillWorks(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(""+
		"name: web-01\n"+
		"host_id: 3a713a713a713a713a713a713a713a71\n"+
		"knock_addr: 203.0.113.9\n"+
		"knock_port: 62201\n"+
		"host_encryption: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"+
		"services:\n"+
		"  ssh: { port: 22 }\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath,
		"--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}
	said := errBuf.String()
	for _, want := range []string{"deprecated", "postern operator init", "postern host add", "init-standalone --force --go-live"} {
		if !strings.Contains(said, want) {
			t.Errorf("the deprecation notice does not mention %q:\n%s", want, said)
		}
	}
	// And the command still did exactly what it always did.
	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("the written client config does not load: %v", err)
	}
	if _, err := cfg.Host("web-01"); err != nil {
		t.Fatalf("Host: %v", err)
	}
}

func TestMain_Enroll_RefusesAnEntryThatNamesADifferentHost(t *testing.T) {
	home := t.TempDir()
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte("name: db-01\nknock_addr: 203.0.113.9\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "db-01") {
		t.Fatalf("the refusal does not name the mismatch:\n%s", errBuf.String())
	}
}

// A host entry that cannot produce a loadable config must not be written.
// Writing one leaves the operator with a config every later command
// refuses — discovered at the moment they need it, with the original entry
// long gone.
func TestMain_Enroll_RefusesAnEntryThatWouldProduceAnUnloadableConfig(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	// No services: `open` would have nothing to knock, and ParseConfig says so.
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 203.0.113.9\n" +
		"host_encryption: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code == exitOK {
		t.Fatal("an entry that produces an unloadable config was accepted")
	}
	if !strings.Contains(errBuf.String(), "services") {
		t.Fatalf("the refusal does not name the problem:\n%s", errBuf.String())
	}
	if _, err := os.Stat(configPath); err == nil {
		t.Fatal("the unusable config was written anyway")
	}
}

// terminalEnv gives a test env an interactive stdin and a scripted
// passphrase reader, so the prompt path can be exercised without a tty.
func terminalEnv(t *testing.T, home string, answers ...string) (*env, *strings.Builder, *strings.Builder, *[]string) {
	t.Helper()
	e, out, errBuf := envWithHome(t, home)
	prompts := new([]string)
	i := 0
	e.isTerminal = func() bool { return true }
	e.readPassword = func(prompt string) ([]byte, error) {
		*prompts = append(*prompts, prompt)
		if i >= len(answers) {
			return nil, errors.New("the command asked for more passphrases than the test supplied")
		}
		a := answers[i]
		i++
		return []byte(a), nil
	}
	return e, out, errBuf, prompts
}

// The Critical. `postern enroll` mints the key design section 5 calls "the
// key that opens every door in a fleet". Writing it under scrypt of the
// empty string produces a file that works perfectly and is recoverable by
// anything running as this user, with no symptom until it is someone else's.
//
// Unattended is the case the prompt cannot cover, so it is a refusal. The
// prompt covers the interactive one. Both are asserted here because either
// alone leaves the hole open on half the paths an operator takes.
//
// Mutation verified: returning nil instead of the refusal from
// newKeyPassphrase's non-terminal branch fails the first subtest, and it
// fails on the "no key was written" assertion rather than only the exit
// code — the key existing is the actual harm.
func TestMain_Enroll_RefusesToMintAnUnprotectedKeyWhenItCannotAsk(t *testing.T) {
	home := t.TempDir()
	// envWithHome leaves isTerminal nil, which is the unattended case: a CI
	// runner, a script, a pipe.
	e, _, errBuf := envWithHome(t, home)

	code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary")
	if code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(home, "identity.json")); err == nil {
		t.Fatal("an operator key was minted with no passphrase and no prompt; anything running as " +
			"this user could sign knocks against every host enrolled with it")
	}
	for _, want := range []string{"--no-passphrase", "POSTERN_PASSPHRASE", "not a terminal"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("the refusal does not mention %q, so an operator cannot act on it:\n%s", want, errBuf.String())
		}
	}
}

func TestMain_Enroll_PromptsForAPassphraseWhenStdinIsATerminal(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf, prompts := terminalEnv(t, home, "correct horse battery", "correct horse battery")

	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary"); code != exitOK {
		t.Fatalf("exit = %d: %s", code, errBuf.String())
	}
	if len(*prompts) != 2 {
		t.Fatalf("the operator was prompted %d times, want 2 — a mistyped passphrase on a key that is "+
			"only ever unlocked during an outage is discovered at the worst possible moment", len(*prompts))
	}

	keyPath := filepath.Join(home, "identity.json")
	if _, err := identity.LoadFile(keyPath, []byte("correct horse battery")); err != nil {
		t.Fatalf("the key does not open with the passphrase that was typed: %v", err)
	}
	if _, err := identity.LoadFile(keyPath, nil); err == nil {
		t.Fatal("the key opens with an empty passphrase, so the prompt protected nothing")
	}
}

func TestMain_Enroll_RefusesMismatchedPassphraseConfirmation(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf, _ := terminalEnv(t, home, "one thing", "another thing")

	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "do not match") {
		t.Fatalf("the refusal does not say what happened:\n%s", errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(home, "identity.json")); err == nil {
		t.Fatal("a key was written despite the mismatch, sealed under whichever of the two was typed first")
	}
}

// --no-passphrase is a real choice with a real cost, so it works and it is
// said out loud. An operator will not open this file again until an outage.
func TestMain_Enroll_MintsUnprotectedOnlyWhenSaidOutLoudAndWarns(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)

	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("exit = %d: %s", code, errBuf.String())
	}
	if _, err := identity.LoadFile(filepath.Join(home, "identity.json"), nil); err != nil {
		t.Fatalf("--no-passphrase did not produce an unencrypted key: %v", err)
	}
	if !strings.Contains(errBuf.String(), "WARNING") || !strings.Contains(errBuf.String(), "unencrypted") {
		t.Fatalf("minting an unprotected key printed no warning:\n%s", errBuf.String())
	}
}

// An environment variable is a passphrase source and must be used, including
// on a terminal — a scripted run that happens to have a tty must not start
// prompting.
func TestMain_Enroll_PrefersAConfiguredPassphraseOverPrompting(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf, prompts := terminalEnv(t, home)
	base := e.getenv
	e.getenv = func(k string) string {
		if k == "POSTERN_PASSPHRASE" {
			return "from the environment"
		}
		return base(k)
	}

	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary"); code != exitOK {
		t.Fatalf("exit = %d: %s", code, errBuf.String())
	}
	if len(*prompts) != 0 {
		t.Fatalf("prompted despite a configured passphrase source: %v", *prompts)
	}
	if _, err := identity.LoadFile(filepath.Join(home, "identity.json"), []byte("from the environment")); err != nil {
		t.Fatalf("the key was not sealed under $POSTERN_PASSPHRASE: %v", err)
	}
}

// An empty $POSTERN_PASSPHRASE is a misconfiguration that reads as a
// configured source, so it produces the same unprotected key the refusal
// exists to prevent. It is refused rather than honoured.
func TestMain_Enroll_RefusesAnEmptyConfiguredPassphraseFile(t *testing.T) {
	home := t.TempDir()
	empty := filepath.Join(home, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)

	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary", "--passphrase-file", empty); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "--no-passphrase") {
		t.Fatalf("the refusal does not name the explicit alternative:\n%s", errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(home, "identity.json")); err == nil {
		t.Fatal("an unprotected key was written from an empty passphrase file")
	}
}

// The client config carries the whole knockable inventory — every host_id,
// origin address, and gated port an operator holds. Design section 6 says a
// public bundle must never leak that; leaving it world-readable publishes it
// to every local account instead.
func TestMain_Enroll_WritesTheClientConfigOwnerReadableOnly(t *testing.T) {
	home := enrolledHome(t)
	info, err := os.Stat(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("client config mode = %o, want 600 — it lists every host this operator can knock, "+
			"their origin addresses, and their gated ports", perm)
	}
}

// C-1 again, through the one path the fix's own tests drove but did not
// assert on. An operator pressing enter at "new passphrase" would, without
// this check, be prompted a second time, match themselves, and get the
// unencrypted fleet key the refusal exists to prevent — this time with the
// prompt supplying the appearance of having chosen something.
//
// Two empty answers are supplied deliberately: with the check disabled the
// command runs to completion and writes the key, so the assertion that
// fails is "no key was written", which is the actual harm, rather than an
// exit code.
//
// Mutation verified: disabling `if len(first) == 0` in newKeyPassphrase
// fails this test on the key-file assertion.
func TestMain_Enroll_RefusesAnEmptyPassphraseTypedAtThePrompt(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf, prompts := terminalEnv(t, home, "", "")

	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(home, "identity.json")); err == nil {
		t.Fatal("pressing enter at the passphrase prompt produced an unencrypted operator key — the " +
			"same outcome the unattended refusal exists to prevent, with the prompt supplying the " +
			"appearance of a choice")
	}
	if len(*prompts) != 1 {
		t.Errorf("an empty first answer was followed by %d more prompts; it should be refused at once",
			len(*prompts)-1)
	}
	if !strings.Contains(errBuf.String(), "--no-passphrase") {
		t.Fatalf("the refusal does not name the explicit alternative:\n%s", errBuf.String())
	}
}

// The two halves of enrollment are two commands, and only the second one
// writes the config: the first mints the key, and a config with no hosts is
// not a valid config so there is nothing to write yet. That leaves a window
// in which the key exists and the config does not, and the second command
// used to re-derive the operator name from $USER (or the literal "operator")
// instead of from the key sitting next to it. The result was a config naming
// an operator whose key was not the key on disk, and every later command
// refused with "key file holds identity X but the config names operator Y" —
// discovered, in this project's own end-to-end run, three phases after the
// enrollment that caused it.
func TestMain_Enroll_AdoptsTheOperatorNameFromTheKeyWhenTheConfigIsNew(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	entryPath := filepath.Join(home, "entry.yaml")
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 203.0.113.9\n" +
		"knock_port: 62201\n" +
		"host_encryption: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"services:\n" +
		"  ssh: { port: 22 }\n"
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Step one: mint the identity under an explicit name. No config yet.
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("the minting enroll exited %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("a config was written before any host was registered (%v); this test no longer covers the window it is about", err)
	}

	// Step two: register the host, without repeating --operator, which is
	// what the printed instructions tell an operator to do.
	e2, _, errBuf2 := envWithHome(t, home)
	if code := runCLI(t, e2, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("the registering enroll exited %d: %s", code, errBuf2.String())
	}

	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("the written config does not load: %v", err)
	}
	if cfg.Operator != "laptop-primary" {
		t.Fatalf("the config names operator %q but the key file holds %q; every command against this "+
			"config is refused", cfg.Operator, "laptop-primary")
	}

	// And the pairing actually works: this is the check every client command
	// makes before it signs anything.
	var cf clientFlags
	if _, err := cf.signer(e2, cfg); err != nil {
		t.Fatalf("the config and the key it sits beside do not pair: %v", err)
	}
}
