package agent_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/gate"
)

// fakeSystemctl writes an executable stand-in for systemctl that echoes a
// fixed state and exits with a fixed code, so the parsing below is tested
// against the shapes systemctl actually produces rather than against a
// hand-written mock of what it was assumed to produce.
func fakeSystemctl(t *testing.T, state string, exitCode int) string {
	path, _ := fakeSystemctlRecording(t, state, exitCode)
	return path
}

// fakeSystemctlRecording returns the stub's path and the path of the file it
// appends its argv to, so a test can assert what was actually invoked rather
// than only what came back.
func fakeSystemctlRecording(t *testing.T, state string, exitCode int) (stub, argvLog string) {
	t.Helper()
	dir := t.TempDir()
	stub = filepath.Join(dir, "systemctl")
	argvLog = filepath.Join(dir, "argv.log")
	script := fmt.Sprintf(
		"#!/bin/sh\necho \"$@\" >> %q\nif [ \"$1\" = \"is-enabled\" ]; then echo %s; exit %d; fi\nexit 0\n",
		argvLog, state, exitCode)
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil { //nolint:gosec // an executable stub is the point
		t.Fatalf("write stub: %v", err)
	}
	return stub, argvLog
}

func readArgvLog(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // this test's own temp path
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// `systemctl is-enabled` exits NON-ZERO for "disabled" — that is an answer,
// not a failure. A reader that treated the exit code as the error signal
// would report an error instead of "disabled", and a revert would then fail
// rather than restore the state it snapshotted.
//
// The mutation this catches: returning early on a non-nil err before looking
// at stdout. Every disabled case below then fails.
func TestAgent_SystemdUnit_ReadsEnabledStateFromStdoutNotTheExitCode(t *testing.T) {
	cases := []struct {
		state string
		exit  int
		want  bool
	}{
		{"enabled", 0, true},
		{"enabled-runtime", 0, true},
		{"static", 0, true},
		{"indirect", 0, true},
		// The cases that matter: systemctl reports these on a non-zero exit.
		{"disabled", 1, false},
		{"masked", 1, false},
		{"not-found", 1, false},
	}

	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: fakeSystemctl(t, tc.state, tc.exit)}
			got, err := u.Enabled(context.Background())
			if err != nil {
				t.Fatalf("Enabled(%q, exit %d) errored: %v", tc.state, tc.exit, err)
			}
			if got != tc.want {
				t.Fatalf("Enabled(%q) = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

// An output nobody has seen before must be an error rather than a silent
// "disabled": guessing here would let a revert disable a boot unit that was
// enabled, which is the direction that opens a host rather than locks it,
// but is still not what was snapshotted.
func TestAgent_SystemdUnit_UnrecognizedOutputIsAnError(t *testing.T) {
	u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: fakeSystemctl(t, "transmogrified", 0)}
	if _, err := u.Enabled(context.Background()); err == nil {
		t.Fatal("Enabled accepted an output it does not understand; a revert would act on a guess")
	}
}

// I1. SetEnabled had no coverage at all, and inverting its verb left the
// whole suite green — a revert would then ENABLE a boot unit it was supposed
// to disable, which is precisely the "looks successful, re-locks the host at
// the next reboot" failure confirm-or-revert exists to prevent. Nothing
// about it is untestable: the stub harness above already existed for
// Enabled, and asserting the argv is the whole check.
//
// The mutation this catches: swapping "enable" and "disable" in SetEnabled.
func TestAgent_SystemdUnit_SetEnabledInvokesTheCorrectVerbAndUnit(t *testing.T) {
	cases := []struct {
		enabled bool
		want    string
	}{
		{true, "enable postern-boot.service"},
		{false, "disable postern-boot.service"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			stub, argvLog := fakeSystemctlRecording(t, "enabled", 0)
			u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: stub}

			if err := u.SetEnabled(context.Background(), tc.enabled); err != nil {
				t.Fatalf("SetEnabled(%v): %v", tc.enabled, err)
			}

			argv := readArgvLog(t, argvLog)
			if len(argv) != 1 {
				t.Fatalf("systemctl was invoked %d times, want once: %v", len(argv), argv)
			}
			if argv[0] != tc.want {
				t.Fatalf("systemctl was invoked as %q, want %q; a revert that runs the wrong verb "+
					"leaves the boot unit in the opposite state from the one it snapshotted", argv[0], tc.want)
			}
		})
	}
}

// SystemdUnit drives two different units now, so a zero Name must be a
// refusal rather than a default.
//
// The mutation this catches: restoring the old `if u.Name == "" { return
// gate.BootUnitName }`. Both subtests then pass, and the argv log holds an
// operation on postern-boot.service that the caller meant for posternd —
// which is the shipped defect (the boot unit enabled, the agent not) arriving
// as a forgotten struct field.
func TestAgent_SystemdUnit_AnEmptyNameIsARefusalNotADefault(t *testing.T) {
	stub, argvLog := fakeSystemctlRecording(t, "enabled", 0)
	u := agent.SystemdUnit{Systemctl: stub}

	t.Run("SetEnabled", func(t *testing.T) {
		if err := u.SetEnabled(context.Background(), true); err == nil {
			t.Fatal("SetEnabled acted on a unit with no name; a forgotten Name field would silently " +
				"enable postern-boot.service a second time instead of enabling posternd.service")
		}
	})
	t.Run("Enabled", func(t *testing.T) {
		if _, err := u.Enabled(context.Background()); err == nil {
			t.Fatal("Enabled answered about a unit with no name")
		}
	})

	if _, err := os.Stat(argvLog); !os.IsNotExist(err) {
		t.Fatalf("systemctl was invoked despite the missing unit name: %v", readArgvLog(t, argvLog))
	}
}

// A custom unit name must reach systemctl too, or a host with a non-default
// layout silently has a different unit enabled and disabled from the one
// postern is managing.
func TestAgent_SystemdUnit_HonoursACustomUnitName(t *testing.T) {
	stub, argvLog := fakeSystemctlRecording(t, "enabled", 0)
	u := agent.SystemdUnit{Name: "custom-boot.service", Systemctl: stub}

	if err := u.SetEnabled(context.Background(), true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if argv := readArgvLog(t, argvLog); argv[0] != "enable custom-boot.service" {
		t.Fatalf("systemctl was invoked as %q, want the configured unit name", argv[0])
	}
}

// A failed SetEnabled must be reported, not swallowed: Revert joins its
// errors and a silent failure here is a boot unit left in the wrong state
// with a successful-looking revert.
func TestAgent_SystemdUnit_SetEnabledReportsFailure(t *testing.T) {
	u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: "/nonexistent/systemctl"}
	if err := u.SetEnabled(context.Background(), false); err == nil {
		t.Fatal("SetEnabled reported success with no systemctl to run")
	}
}

// I3. `systemctl is-enabled` exits non-zero for "disabled", so the exit code
// is an answer rather than a failure — but that cannot be stretched to cover
// an empty stdout, which is also what a systemctl that could not run at all
// produces. Listing "" among the disabled states mapped "I could not ask" to
// "the answer is no": a genuinely enabled boot unit was snapshotted as
// disabled, and Revert would then disable it, so the fail-closed drop rules
// stop loading at the next boot. Silent, and in the direction that opens
// ports.
//
// The mutation this catches: putting "" back in the disabled case list.
func TestAgent_SystemdUnit_AnUnrunnableSystemctlIsAnErrorNotADisabledUnit(t *testing.T) {
	u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: "/nonexistent/systemctl"}

	enabled, err := u.Enabled(context.Background())
	if err == nil {
		t.Fatalf("Enabled reported (%v, nil) when systemctl could not be run at all; a genuinely "+
			"enabled boot unit is snapshotted as disabled and the revert then disables it", enabled)
	}
	if enabled {
		t.Fatal("Enabled reported true alongside an error")
	}
}

// The case that must NOT become an error: systemctl ran, exited non-zero,
// and named no state. That is an uninstalled unit, which for this question
// is a genuine "not enabled" — and a revert on a freshly enrolled host
// depends on it.
func TestAgent_SystemdUnit_AnUninstalledUnitIsNotEnabledRatherThanAnError(t *testing.T) {
	stub, _ := fakeSystemctlRecording(t, "", 1) // ran, exit 1, empty stdout
	u := agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: stub}

	enabled, err := u.Enabled(context.Background())
	if err != nil {
		t.Fatalf("Enabled errored on an uninstalled unit: %v", err)
	}
	if enabled {
		t.Fatal("an uninstalled unit reported as enabled")
	}
}
