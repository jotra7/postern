package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/identity"
)

// operator init is #28's split of the identity-minting half of the old
// combined enroll. These tests mirror the equivalent enroll_test.go cases,
// but only the ones that are actually operator init's job: enroll's own
// tests already cover the deprecated alias end to end.

func TestMain_OperatorInit_MintsAnIdentityAndPrintsHostAddNext(t *testing.T) {
	home := t.TempDir()
	e, out, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "operator", "init", "--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("operator init exited %d: %s", code, errBuf.String())
	}
	if _, err := identity.LoadFile(filepath.Join(home, "identity.json"), nil); err != nil {
		t.Fatalf("no operator identity was minted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("a client config was written before any host was registered (%v); operator init "+
			"must not write one, because a config with no hosts is not a valid one", err)
	}
	if !strings.Contains(out.String(), "postern host add") {
		t.Fatalf("operator init does not point at `host add` as the next step:\n%s", out.String())
	}
}

// Positional arguments are host add's business, not operator init's — the
// whole point of the split is that this command never touches a host.
func TestMain_OperatorInit_RefusesAPositionalArgument(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "operator", "init", "some-host"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
}

// The unattended, no-passphrase-source refusal is C-1 (see enroll_test.go's
// identical case): a key minted with no passphrase and nothing to prompt is
// recoverable by anything running as this user. operator init is the only
// command that mints, so it is the one that must refuse this, not merely
// inherit it by accident.
//
// Mutation verified: returning nil instead of the refusal from
// newKeyPassphrase's non-terminal branch fails this on the "no key was
// written" assertion, same as enroll_test.go's version of this test.
func TestMain_OperatorInit_RefusesToMintAnUnprotectedKeyWhenItCannotAsk(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "operator", "init", "--operator", "laptop-primary"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(home, "identity.json")); err == nil {
		t.Fatal("an operator key was minted with no passphrase and no prompt")
	}
	if !strings.Contains(errBuf.String(), "--no-passphrase") {
		t.Fatalf("the refusal does not name the explicit alternative:\n%s", errBuf.String())
	}
}

// Re-running operator init is the ordinary path once a key already exists —
// checking status, or re-reading the public keys to enrol a second host —
// and must be a no-op that reports the identity rather than an error or a
// second mint.
func TestMain_OperatorInit_IsIdempotent(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "operator", "init", "--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("first operator init exited %d: %s", code, errBuf.String())
	}
	before, err := os.ReadFile(filepath.Join(home, "identity.json")) //nolint:gosec // this test's own temp path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	e2, _, errBuf2 := envWithHome(t, home)
	if code := runCLI(t, e2, "operator", "init"); code != exitOK {
		t.Fatalf("second operator init exited %d: %s", code, errBuf2.String())
	}
	after, err := os.ReadFile(filepath.Join(home, "identity.json")) //nolint:gosec // this test's own temp path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("re-running operator init minted a new key over the existing one")
	}
	if !strings.Contains(errBuf2.String(), "already exists") {
		t.Fatalf("the second run does not say the identity already existed:\n%s", errBuf2.String())
	}
}

// `operator init -h` and an unknown verb both have to work through the
// `operator` dispatcher, which is hand-written rather than a library's — see
// cmd_operator.go.
func TestMain_Operator_UnknownVerbIsAUsageError(t *testing.T) {
	home := t.TempDir()
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "operator", "bogus"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal:\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "unknown verb") {
		t.Fatalf("the refusal does not say the verb is unknown:\n%s", errBuf.String())
	}
}
