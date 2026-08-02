package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/agent"
)

// Every return Daemon.Run can produce, mapped to the exit status systemd
// reads. The mapping is an interface, and a comment claiming it is a claim
// nothing checks — this project has shipped that comment wrong twice.
//
// The wrapped rows are the ones that matter: Run wraps both sentinels with
// context, so a == comparison compiles, passes a naive test built on bare
// sentinels, and silently reports a self-incapacitated agent as an ordinary
// failure. Mutation verified: replacing errors.Is with == fails both wrapped
// rows and neither bare one.
func TestMain_ExitCode_MapsEveryDaemonRunReturn(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"clean shutdown", nil, exitOK},
		{"inert", agent.ErrInert, exitInert},
		{"inert, wrapped as Run wraps it", fmt.Errorf("%w: pre-arm: nft missing", agent.ErrInert), exitInert},
		{"incapacitated", agent.ErrIncapacitated, exitIncapacitated},
		{"incapacitated, wrapped", errors.Join(agent.ErrIncapacitated, errors.New("teardown")), exitIncapacitated},
		{"the socket failed", errors.New("agent: receive: use of closed connection"), exitFailed},
		{"a usage problem", usagef("no such host"), exitUsage},
		{"a failed operation", failedError{errors.New("timeout")}, exitFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.want {
				t.Fatalf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// exitInert and exitIncapacitated must stay distinct from each other and
// from a plain failure: systemd retries the first and an operator must not
// have the second buried among ordinary errors.
func TestMain_ExitCode_TheAgentStatusesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ok":            exitOK,
		"usage":         exitUsage,
		"failed":        exitFailed,
		"inert":         exitInert,
		"incapacitated": exitIncapacitated,
	} {
		if prev, dup := seen[code]; dup {
			t.Fatalf("%q and %q share exit code %d", name, prev, code)
		}
		seen[code] = name
	}
}

func TestMain_Run_UnknownSubcommandIsAUsageError(t *testing.T) {
	e, _, errBuf := testEnv()
	if got := run(context.Background(), e, []string{"deploy"}); got != exitUsage {
		t.Fatalf("exit = %d, want %d", got, exitUsage)
	}
	if !strings.Contains(errBuf.String(), "unknown subcommand") {
		t.Fatalf("stderr does not name the problem:\n%s", errBuf.String())
	}
}

func TestMain_Run_NoArgumentsPrintsUsage(t *testing.T) {
	e, _, errBuf := testEnv()
	if got := run(context.Background(), e, nil); got != exitUsage {
		t.Fatalf("exit = %d, want %d", got, exitUsage)
	}
	for _, want := range []string{
		"open", "status", "confirm", "disarm", "agent", "init-standalone", "enroll", "operator", "host",
	} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("usage does not list %q:\n%s", want, errBuf.String())
		}
	}
}

// Every subcommand the brief names must exist on every platform this binary
// builds for. On a laptop the host-side ones refuse with a reason; "unknown
// subcommand" would read like a broken build.
func TestMain_Registry_CarriesEverySubcommandTheBriefNames(t *testing.T) {
	for _, name := range []string{
		"init-standalone", "enroll", "operator", "host", "open", "status", "confirm", "disarm", "agent",
		"gate-flush", "gate-teardown",
	} {
		if _, ok := registry[name]; !ok {
			t.Errorf("subcommand %q is not registered", name)
		}
	}
}

func TestMain_Help_ExitsZero(t *testing.T) {
	e, out, _ := testEnv()
	if got := run(context.Background(), e, []string{"help"}); got != exitOK {
		t.Fatalf("exit = %d, want 0", got)
	}
	if !strings.Contains(out.String(), "usage: postern") {
		t.Fatalf("help printed nothing useful:\n%s", out.String())
	}
}

func TestMain_Wrap_BreaksLongDiagnosesAtWordBoundaries(t *testing.T) {
	long := strings.Repeat("word ", 40)
	got := wrap(strings.TrimSpace(long), 40)
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 40 {
			t.Fatalf("line is %d characters, over the 40 requested: %q", len(line), line)
		}
	}
	if strings.ReplaceAll(got, "\n", " ") != strings.TrimSpace(long) {
		t.Fatal("wrapping changed the text")
	}
}
