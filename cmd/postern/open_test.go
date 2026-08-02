package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
)

// enrolledHome builds a client config and operator key on disk, the state an
// operator is in when they type `postern open`. The knock address is
// unroutable documentation space (RFC 5737), so the confirmation connect
// fails without touching anything real.
func enrolledHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 203.0.113.9\n" +
		"knock_port: 62201\n" +
		"host_encryption: " + testHostEncryptionB64 + "\n" +
		"recovery_service: ssh\n" +
		"ssh: { host: web-01.example.com, user: ops, port: 22 }\n" +
		"services:\n" +
		"  ssh: { port: 22, ttl: 120s }\n"
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}
	return home
}

// A real X25519 public key, so the seal succeeds. Its private half is
// nobody's: nothing in these tests opens the datagram.
const testHostEncryptionB64 = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr06H5F9wKgcHU="

// The diagnosis has to reach the terminal, not just the struct. Advise is
// tested in internal/client; this asserts printOpenReport prints all of what
// Advise produced, and prints the paste-ready retry command.
//
// Driven from a synthesized report rather than from a real connect: which
// error an unroutable address produces depends on the machine's routing
// table (a host with no default route gets ENETUNREACH where a laptop gets a
// timeout), and a test that quietly changed which branch it exercised would
// stop covering the one that matters.
//
// Mutation verified: dropping the Advice.Hint line from printOpenReport
// leaves the summary intact and fails this test — the hint is the
// deliverable, not the outcome word.
func TestMain_Open_PrintsTheDiagnosisAndTheSourceCIDRRetry(t *testing.T) {
	host := testOpenHost(t)

	sent := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      netip.MustParseAddrPort("203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}
	res := client.Result{Outcome: client.TimedOut, Attempts: 2}
	rep := client.OpenReport{
		KnockAddr: host.KnockAddrPort(),
		Sent:      sent,
		Result:    res,
		Advice:    client.Advise(res, sent),
	}

	e, out, _ := testEnv()
	printOpenReport(e, host, rep)
	got := out.String()
	for _, want := range []string{
		"knock sent to 203.0.113.9:62201",
		"timeout",
		"--source-cidr",
		"carrier NAT",
		"postern open web-01 ssh",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the open report does not contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "web-01.example.com:") {
		t.Errorf("the report shows a connect to the SSH hostname:\n%s", got)
	}
}

// The whole command, end to end, against an address nothing answers on. What
// outcome the connect produces depends on the machine, so this asserts only
// what does not: the knock line names knock_addr, and an open that did not
// confirm is a non-zero exit.
func TestMain_Open_RunsEndToEndAndFailsWhenNothingConfirms(t *testing.T) {
	home := enrolledHome(t)
	e, out, _ := envWithHome(t, home)

	code := runCLI(t, e, "open", "web-01", "ssh", "--timeout", "50ms", "--attempts", "1")
	if code == exitOK {
		t.Fatalf("an open that never confirmed exited 0:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "203.0.113.9:62201") {
		t.Fatalf("the report does not name the knock address:\n%s", out.String())
	}
}

// Flags after the positional arguments. stdlib flag stops at the first
// non-flag argument, and a break-glass command that refuses the argument
// order every other tool accepts — while the host is unreachable — is how a
// tool gets abandoned mid-incident.
func TestMain_Open_AcceptsFlagsAfterThePositionalArguments(t *testing.T) {
	home := enrolledHome(t)
	e, out, errBuf := envWithHome(t, home)

	code := runCLI(t, e, "open", "web-01", "ssh", "--ttl", "45s", "--timeout", "50ms", "--attempts", "1")
	if code == exitUsage {
		t.Fatalf("flags after the host were rejected as a usage error:\n%s", errBuf.String())
	}
	if !strings.Contains(out.String(), "ttl 45s") {
		t.Fatalf("--ttl after the positional arguments was not applied:\n%s", out.String())
	}
}

func TestMain_Open_DefaultsToTheHostsRecoveryService(t *testing.T) {
	home := enrolledHome(t)
	e, out, _ := envWithHome(t, home)

	runCLI(t, e, "open", "web-01", "--timeout", "50ms", "--attempts", "1")
	if !strings.Contains(out.String(), "web-01/ssh") {
		t.Fatalf("`open web-01` with no service did not use recovery_service:\n%s", out.String())
	}
}

func TestMain_Open_RefusesAnUnparseableSourceCIDR(t *testing.T) {
	home := enrolledHome(t)
	e, _, errBuf := envWithHome(t, home)

	if code := runCLI(t, e, "open", "web-01", "ssh", "--source-cidr", "203.0.113.0"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "source-cidr") {
		t.Fatalf("the refusal does not name the flag:\n%s", errBuf.String())
	}
}

func TestMain_Open_RefusesAHostThatIsNotInTheConfig(t *testing.T) {
	home := enrolledHome(t)
	e, _, errBuf := envWithHome(t, home)

	if code := runCLI(t, e, "open", "db-01"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "db-01") {
		t.Fatalf("the refusal does not name the host:\n%s", errBuf.String())
	}
}

// An unbound confirm ratifies whatever happens to be pending when it lands,
// which is the wrong thing by construction. The agent refuses one; the
// client must not be able to send one by omission either.
func TestMain_Confirm_RefusesWithoutADeploymentNonce(t *testing.T) {
	home := enrolledHome(t)
	e, _, errBuf := envWithHome(t, home)

	if code := runCLI(t, e, "confirm", "web-01", "--revision", "47"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "--nonce is required") {
		t.Fatalf("the refusal does not name the missing binding:\n%s", errBuf.String())
	}
}

func TestMain_Confirm_RefusesANonceOfTheWrongLength(t *testing.T) {
	home := enrolledHome(t)
	e, _, errBuf := envWithHome(t, home)

	if code := runCLI(t, e, "confirm", "web-01", "--revision", "47", "--nonce", "deadbeef"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "16") {
		t.Fatalf("the refusal does not say what length is wanted:\n%s", errBuf.String())
	}
}

// disarm --local takes no host: it disarms the machine it runs on. Accepting
// a host name there would read as "disarm that host" and silently disarm
// this one.
func TestMain_Disarm_LocalRefusesAHostArgument(t *testing.T) {
	e, _, errBuf := testEnv()
	if code := runCLI(t, e, "disarm", "--local", "web-01"); code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal", code)
	}
	if !strings.Contains(errBuf.String(), "takes no host argument") {
		t.Fatalf("the refusal does not explain itself:\n%s", errBuf.String())
	}
}

// Both halves of the confirm binding are required and neither has a default.
// The nonce is the unguessable half, so the security property rests on it —
// but a silently-defaulted revision produces a confirm the agent refuses for
// a reason the operator can never observe, because the SPA path never
// replies. The command's own doc comment claimed both were required while
// only one was; that claim is now true.
//
// Mutation verified: removing the flagWasSet check fails this test.
func TestMain_Confirm_RefusesWithoutAPendingRevision(t *testing.T) {
	home := enrolledHome(t)
	e, _, errBuf := envWithHome(t, home)

	code := runCLI(t, e, "confirm", "web-01", "--nonce", "000102030405060708090a0b0c0d0e0f")
	if code != exitUsage {
		t.Fatalf("exit = %d, want a usage refusal: a confirm went out carrying revision 0", code)
	}
	if !strings.Contains(errBuf.String(), "--revision is required") {
		t.Fatalf("the refusal does not name the missing half:\n%s", errBuf.String())
	}
}

// Revision 0 is a legitimate value — a host's first configuration — so it
// must be settable explicitly. Requiring the flag is not the same as
// forbidding its zero value.
func TestMain_Confirm_AcceptsAnExplicitRevisionZero(t *testing.T) {
	home := enrolledHome(t)
	e, _, errBuf := envWithHome(t, home)

	code := runCLI(t, e, "confirm", "web-01", "--revision", "0", "--nonce", "000102030405060708090a0b0c0d0e0f")
	if code == exitUsage {
		t.Fatalf("an explicit --revision 0 was refused as a usage error:\n%s", errBuf.String())
	}
}

// testOpenHost is the host entry these report tests print against: knock_addr
// and SSH hostname deliberately different, as everywhere else in this package.
func testOpenHost(t *testing.T) *client.Host {
	t.Helper()
	cfg, err := client.ParseConfig([]byte("" +
		"operator: laptop-primary\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: 3a713a713a713a713a713a713a713a71\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    host_encryption: " + testHostEncryptionB64 + "\n" +
		"    ssh: { host: web-01.example.com, user: ops, port: 22 }\n" +
		"    services:\n" +
		"      ssh: { port: 22 }\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	host, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return host
}

// The line about the connect made before the knock has to reach the terminal,
// and has to come first: an operator who reads three lines in the order the
// events happened can see the change for themselves rather than taking a
// verdict on trust.
//
// Both findings are exercised, because a report that printed the same line
// whatever the pre-knock connect found would tell an operator nothing and
// would pass a test that only looked at one of them.
//
// Mutation verified: dropping the beforeLine call from printOpenReport fails
// both rows, and printing it after the knock line fails the ordering check.
func TestMain_Open_PrintsWhatTheConnectBeforeTheKnockFound(t *testing.T) {
	host := testOpenHost(t)
	sent := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      netip.MustParseAddrPort("203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}

	for _, tc := range []struct {
		name   string
		before client.Result
		want   string
	}{
		{
			name:   "shut before the knock",
			before: client.Result{Outcome: client.TimedOut, Attempts: 1},
			want:   "before the knock, 203.0.113.9:22 did not answer",
		},
		{
			name:   "already answering before the knock",
			before: client.Result{Outcome: client.Connected, Attempts: 1},
			want:   "before the knock, 203.0.113.9:22 already answered (connected)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sent
			s.Prior = tc.before.Prior()
			res := client.Result{Outcome: client.Connected, Attempts: 1}
			rep := client.OpenReport{
				KnockAddr: host.KnockAddrPort(),
				Before:    tc.before,
				Sent:      s,
				Result:    res,
				Advice:    client.Advise(res, s),
			}

			e, out, _ := testEnv()
			printOpenReport(e, host, rep)
			got := out.String()
			if !strings.Contains(got, tc.want) {
				t.Fatalf("the report does not contain %q:\n%s", tc.want, got)
			}
			if strings.Index(got, tc.want) > strings.Index(got, "knock sent to") {
				t.Fatalf("the pre-knock connect is reported after the knock it preceded:\n%s", got)
			}
		})
	}
}

// A pre-knock connect that found silence licenses the one strong claim `open`
// makes, and that claim has to survive the trip to the terminal. The
// qualification the unmeasured case carries must not survive it, because
// printing both would leave an operator no better off than before.
//
// Mutation verified: leaving Before out of the report so Advise takes its
// unmeasured branch fails every check here.
func TestMain_Open_PrintsTheStrongerClaimWhenThePortWasShutFirst(t *testing.T) {
	host := testOpenHost(t)
	before := client.Result{Outcome: client.TimedOut, Attempts: 1}
	sent := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      netip.MustParseAddrPort("203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
		Prior: before.Prior(),
	}
	res := client.Result{Outcome: client.Connected, Attempts: 1}

	e, out, _ := testEnv()
	printOpenReport(e, host, client.OpenReport{
		KnockAddr: host.KnockAddrPort(),
		Before:    before,
		Sent:      sent,
		Result:    res,
		Advice:    client.Advise(res, sent),
	})
	got := out.String()

	if !strings.Contains(got, "did not answer before the knock and answers now") {
		t.Errorf("a shut-then-open report does not say so, so the pre-knock connect bought "+
			"nothing an operator can read:\n%s", got)
	}
	if strings.Contains(got, "does not establish that") {
		t.Errorf("a shut-then-open report still carries the qualification that applies when nothing "+
			"was measured first:\n%s", got)
	}
	if strings.Contains(got, "verify: ") {
		t.Errorf("a shut-then-open report still sends the operator to `status` for something this "+
			"already established:\n%s", got)
	}
}

// --pre-timeout 0 is the escape hatch for an operator who wants the knock on
// the wire without waiting to establish the port was shut first. What outcome
// either connect produces depends on the machine's routing table, so this
// asserts only on whether a pre-knock connect was reported at all.
//
// Mutation verified: passing the flag's zero through to OpenOptions unchanged
// makes it select the default instead of skipping, and the line reappears.
func TestMain_Open_SkipsTheConnectBeforeTheKnockWhenPreTimeoutIsZero(t *testing.T) {
	home := enrolledHome(t)

	e, out, _ := envWithHome(t, home)
	runCLI(t, e, "open", "web-01", "ssh", "--timeout", "50ms", "--attempts", "1")
	if !strings.Contains(out.String(), "before the knock") {
		t.Fatalf("open did not connect before the knock by default:\n%s", out.String())
	}

	e, out, _ = envWithHome(t, home)
	runCLI(t, e, "open", "web-01", "ssh", "--timeout", "50ms", "--attempts", "1", "--pre-timeout", "0")
	if strings.Contains(out.String(), "before the knock") {
		t.Fatalf("--pre-timeout 0 still connected before the knock:\n%s", out.String())
	}
}

// The outcome that looks most like success is the one that establishes
// least, so the qualification and the pointer to `status` have to reach the
// terminal — not merely exist on the Advice struct. internal/client tests
// the wording; this tests that `open` prints it.
//
// Mutation verified: dropping the Verify line from printOpenReport fails
// this test, and dropping the Detail line fails it independently.
func TestMain_Open_ConnectedDoesNotClaimTheGateActedAndPointsAtStatus(t *testing.T) {
	host := testOpenHost(t)

	sent := client.Sent{
		Host: "web-01", Service: "ssh",
		Addr:      netip.MustParseAddrPort("203.0.113.9:22"),
		Delivered: true, TTL: 2 * time.Minute,
	}
	res := client.Result{Outcome: client.Connected, Attempts: 1}
	rep := client.OpenReport{
		KnockAddr: host.KnockAddrPort(),
		Sent:      sent,
		Result:    res,
		Advice:    client.Advise(res, sent),
	}

	e, out, _ := testEnv()
	printOpenReport(e, host, rep)
	got := out.String()

	if !strings.Contains(got, "verify: postern status web-01") {
		t.Errorf("a successful open does not point at the one instrument that establishes the agent "+
			"is alive:\n%s", got)
	}
	if !strings.Contains(got, "does not establish") {
		t.Errorf("a successful open reports no qualification, so an operator reads it as proof the "+
			"gate worked — which on a fail-open service with a dead agent is exactly backwards:\n%s", got)
	}
	for _, forbidden := range []string{"the gate admitted", "is open on"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the report claims %q:\n%s", forbidden, got)
		}
	}
}
