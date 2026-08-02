package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// installScript copies one of testdata's real gate scripts into a temporary
// directory and applies mode.
//
// The copy is not tidiness. git records only 0755 or 0644, so a world-
// writable script — the exact input CheckScriptPath exists to refuse — cannot
// be committed with the mode under test; it has to be applied here. Copying
// every script the same way keeps one code path rather than a special case
// for the one file that needs it.
func installScript(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()

	src := filepath.Join("testdata", name)
	body, err := os.ReadFile(src) //nolint:gosec // a fixed path under testdata
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), name)
	//nolint:gosec // G306,G703: the mode is the input under test, and dst is under t.TempDir()
	if err := os.WriteFile(dst, body, mode); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	// WriteFile applies mode through the process umask, which on most hosts
	// strips exactly the group and world bits this fixture sometimes needs to
	// keep. Chmod is not subject to it.
	if err := os.Chmod(dst, mode); err != nil {
		t.Fatalf("chmod %s: %v", dst, err)
	}
	return dst
}

// scriptPolicy builds the smallest policy that resolves and validates, with
// one script-backed gate service per entry in paths.
func scriptPolicy(t *testing.T, paths map[string]string, timeout time.Duration) *config.Policy {
	t.Helper()

	p := &config.Policy{
		SPAPort:            62201,
		AlwaysAllowIface:   "tailscale0",
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 24 * time.Hour,
		MaxOperators:       config.DefaultMaxOperators,
		Services:           map[string]config.Service{},
	}
	port := uint16(9000)
	for name, path := range paths {
		p.Services[name] = config.Service{
			Name:                name,
			Kind:                config.KindGate,
			Proto:               "tcp",
			Ports:               []uint16{port},
			DefaultTTL:          30 * time.Second,
			MaxTTL:              60 * time.Second,
			FailPosture:         config.PostureOpen,
			ListenerExpectation: config.ListenerUnchecked,
			Backend:             config.BackendScript,
			ScriptPath:          path,
			ScriptTimeout:       timeout,
		}
		port++
	}
	return p
}

// newTestScript builds a Script whose path checks pass under the test user
// rather than under root, so the suite does not have to run as root to
// exercise anything but CheckScriptPath's ownership rule itself.
func newTestScript(t *testing.T, p *config.Policy, mutate func(*ScriptOptions)) *Script {
	t.Helper()

	opts := ScriptOptions{
		LeasePath: filepath.Join(t.TempDir(), "gate-leases.db"),
		OwnerUID:  os.Getuid(),
		// Fast enough that a test does not wait on the production cadence,
		// slow enough that it is not a busy loop.
		ReapInterval:   20 * time.Millisecond,
		HealthInterval: 20 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := NewScript(p, opts)
	if err != nil {
		t.Fatalf("NewScript: %v", err)
	}
	t.Cleanup(func() {
		// Bounded, so a test that leaves a hung script running still finishes.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

// inflight reports whether a service's single invocation slot is held. It is
// the only deterministic "the subprocess has finished and the backend has
// finished acting on it" signal available: the slot is released after the open
// path has decided what to do with the lease, whereas testdata's scripts write
// their log line before they exit.
func inflight(s *Script, service string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state[service]
	return ok && st.inflight
}

// invocationLog reads back the argv lines testdata's scripts record.
func invocationLog(t *testing.T, path string) []string {
	t.Helper()

	body, err := os.ReadFile(path) //nolint:gosec // a path this test created
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read invocation log: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// waitFor polls cond until it holds or the deadline passes. Everything this
// backend does off the caller's goroutine has to be observed this way; a test
// that slept a fixed interval instead would be a test that passes on a fast
// machine and flakes on a loaded one.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, describe string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, describe)
}
