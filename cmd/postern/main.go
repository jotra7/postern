// Command postern is the single binary: subcommands select the role.
//
// The client half — open, status, confirm, disarm, enroll, sign — and the
// hub build and run on macOS, because an operator knocks from a laptop and a
// hub is a plain HTTP server with no nftables dependency of its own. Only
// agent, gate-flush, and gate-teardown are Linux-only, and they live in
// files this package builds only under //go:build linux.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/jotra7/postern/internal/agent"
)

// Exit codes. These are an interface: systemd reads them, and so does the
// operator's shell.
//
// Each one is asserted by a test rather than only described here — a comment
// claiming a mapping is a claim nothing checks, and this project has shipped
// one of those wrong twice.
const (
	exitOK = 0
	// exitUsage: the command was wrong, or its configuration was. Nothing
	// was attempted.
	exitUsage = 1
	// exitFailed: the operation ran and did not achieve its purpose — the
	// knock was not confirmed, the pong did not come back.
	exitFailed = 2
	// exitInert: agent only. Nothing was armed and the agent never became
	// reachable, from a cause that may clear on its own. systemd's RestartSec
	// should retry.
	exitInert = 3
	// exitIncapacitated: agent only. The replay store proved unusable
	// mid-run; agent_up is already silenced and the tables torn down.
	// Retrying blindly will not help.
	exitIncapacitated = 4
)

// env is everything a command touches outside its own arguments, so a test
// can supply all of it.
type env struct {
	stdout io.Writer
	stderr io.Writer
	stdin  io.Reader
	// getenv is os.Getenv in production.
	getenv func(string) string
	// isTerminal reports whether stdin is an interactive terminal. A nil
	// value means "not a terminal", so a test that does not care about
	// prompting gets the unattended path.
	isTerminal func() bool
	// readPassword writes prompt to stderr and reads one line from the
	// terminal without echoing it.
	readPassword func(prompt string) ([]byte, error)
}

type command struct {
	name    string
	usage   string
	summary string
	// run returns nil for success. A returned error is printed and mapped to
	// an exit code by exitCode.
	run func(ctx context.Context, e *env, args []string) error
}

// registry is populated by each cmd_*.go file's init. The Linux-only files
// add their commands the same way, so the dispatch table needs no build tags
// of its own.
var registry = map[string]*command{}

func register(c *command) {
	if _, dup := registry[c.name]; dup {
		panic("postern: duplicate subcommand " + c.name)
	}
	registry[c.name] = c
}

// usageError marks a problem with what the operator typed or configured, as
// opposed to a failure of the operation itself. The distinction is the
// difference between exit 1 and exit 2.
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }
func (u usageError) Unwrap() error { return u.err }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// failedError marks an operation that ran and did not achieve its purpose.
// It carries no extra text: the command has already printed the diagnosis,
// which for a failed open is several lines long and is the actual product.
type failedError struct{ err error }

func (f failedError) Error() string { return f.err.Error() }
func (f failedError) Unwrap() error { return f.err }

func main() {
	e := &env{
		stdout:       os.Stdout,
		stderr:       os.Stderr,
		stdin:        os.Stdin,
		getenv:       os.Getenv,
		isTerminal:   func() bool { return term.IsTerminal(stdinFd()) },
		readPassword: readPasswordFromTerminal,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, e, os.Args[1:]))
}

func run(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		printUsage(e.stderr)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		printUsage(e.stdout)
		return exitOK
	}

	cmd, ok := registry[args[0]]
	if !ok {
		outf(e.stderr, "postern: unknown subcommand %q\n\n", args[0])
		printUsage(e.stderr)
		return exitUsage
	}

	err := cmd.run(ctx, e, args[1:])
	if err == nil {
		return exitOK
	}
	code := exitCode(err)
	// A failed operation has already printed its own diagnosis; repeating the
	// error would bury it. Everything else gets one line.
	var failed failedError
	if !errors.As(err, &failed) {
		outf(e.stderr, "postern %s: %v\n", cmd.name, err)
	}
	return code
}

// exitCode maps an error to the process's exit status.
func exitCode(err error) int {
	switch {
	case err == nil:
		return exitOK
	case isUsage(err):
		return exitUsage
	// The two agent sentinels are checked with errors.Is, which is the
	// supported check: Run wraps both with context, so a == comparison would
	// silently fall through to exitFailed and systemd would treat a
	// self-incapacitated agent exactly like a failed knock.
	case errors.Is(err, agent.ErrInert):
		return exitInert
	case errors.Is(err, agent.ErrIncapacitated):
		return exitIncapacitated
	default:
		return exitFailed
	}
}

func isUsage(err error) bool {
	var u usageError
	return errors.As(err, &u)
}

func printUsage(w io.Writer) {
	outln(w, "postern — single-packet authorization")
	outln(w)
	outln(w, "usage: postern <command> [flags]")
	outln(w)
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		outf(w, "  %-16s %s\n", name, registry[name].summary)
	}
	outln(w)
	outln(w, "run `postern <command> -h` for a command's flags")
}

// indent wraps a diagnosis so the advice lines read as belonging to the
// result above them.
func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

// outf, outln, and outs are fmt.Fprint* with the error dropped explicitly.
//
// A write to a terminal that fails has nowhere to be reported — the report
// itself is what failed — and threading an unused error through every print
// in this package would bury the one place an I/O error does matter (writing
// a config file) among fifty places it does not.
func outf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func outln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

func outs(w io.Writer, args ...any) {
	_, _ = fmt.Fprint(w, args...)
}

// readPasswordFromTerminal prompts on stderr and reads without echo.
//
// stderr, not stdout, so a command whose stdout is being piped somewhere —
// `postern init-standalone … > entry.yaml` is the documented flow — does not
// put the prompt into the file.
func readPasswordFromTerminal(prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}
	pass, err := term.ReadPassword(stdinFd())
	// The terminal swallowed the operator's newline along with the echo, so
	// the next thing written would land on the prompt line.
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return pass, nil
}

// stdinFd narrows os.Stdin's file descriptor for x/term, which takes an int.
// The conversion is safe for the reason the narrowing check cannot see: fd 0
// is a constant on every platform this builds for, and os.Stdin is never
// reopened.
func stdinFd() int {
	return int(os.Stdin.Fd()) //nolint:gosec // os.Stdin's descriptor is 0
}
