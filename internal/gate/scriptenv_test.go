package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The script backend hands root to an executable postern does not control, so
// what it hands down alongside is part of the contract. NOTIFY_SOCKET is not:
// systemd sets it so posternd can send sd_notify(3) state strings, systemd
// reads the sender's PID off it, and posternd.service is rendered with
// NotifyAccess=main precisely so a descendant cannot pet the watchdog for a
// packet loop that has wedged. A script holding the socket is a script that
// could try.
//
// The environment is otherwise inherited on purpose, since Environment= and
// EnvironmentFile= on the unit are how an operator configures a script, so
// this asserts both halves. An invoke that passed an empty environment would
// satisfy the first and break every script that reads PATH; POSTERN_TEST_ENV
// arriving is what rules that out, and the script writes nothing at all
// without it.
//
// The mutation this catches: dropping childenv.Sanitize from invoke.
func TestGate_ScriptInvoke_DoesNotPassNotifySocketToTheScript(t *testing.T) {
	script := installScript(t, "env.sh", 0o700)
	envPath := filepath.Join(t.TempDir(), "env.log")
	t.Setenv("POSTERN_TEST_ENV", envPath)
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 90*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return len(childEnvLines(t, envPath)) > 0 }, "the open invocation")

	sawCanary := false
	for _, line := range childEnvLines(t, envPath) {
		if strings.HasPrefix(line, "NOTIFY_SOCKET=") {
			t.Errorf("the gate script was handed %q; an operator's executable can then send sd_notify "+
				"state strings that systemd attributes to posternd", line)
		}
		if line == "POSTERN_TEST_ENV="+envPath {
			sawCanary = true
		}
	}
	if !sawCanary {
		t.Fatal("the script's environment reached it stripped rather than filtered; Environment= and " +
			"EnvironmentFile= on the unit are how a script is configured and would stop working")
	}
}

// childEnvLines reads back the NAME=VALUE lines testdata/env.sh records.
func childEnvLines(t *testing.T, path string) []string {
	t.Helper()

	body, err := os.ReadFile(path) //nolint:gosec // a path this test created
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read child environment log: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
