package gate

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

func observed(t *testing.T, s string) Source {
	t.Helper()
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return Source{Kind: SourceObserved, Prefix: pfx}
}

func asserted(t *testing.T, s string) Source {
	t.Helper()
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return Source{Kind: SourceAsserted, Prefix: pfx}
}

// The argument vector is the contract, and every field of it is load-bearing:
// a script that receives the ttl where it expects the kind admits a source
// for the wrong duration and says nothing. This asserts the whole line rather
// than that the script merely ran.
func TestGate_ScriptOpen_PassesTheContractsArgumentVector(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 90*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return len(invocationLog(t, logPath)) > 0 }, "the open invocation")

	want := "open perimeter 203.0.113.5/32 90 observed"
	if got := invocationLog(t, logPath)[0]; got != want {
		t.Errorf("argv\n got: %q\nwant: %q", got, want)
	}
}

// An asserted CIDR reaches the script as the prefix the operator signed for,
// tagged as asserted, so a script can apply a different policy to a range
// than to a single address.
func TestGate_ScriptOpen_MarksAnAssertedPrefixAsAsserted(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", asserted(t, "198.51.100.0/24"), 60*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return len(invocationLog(t, logPath)) > 0 }, "the open invocation")

	want := "open perimeter 198.51.100.0/24 60 asserted"
	if got := invocationLog(t, logPath)[0]; got != want {
		t.Errorf("argv\n got: %q\nwant: %q", got, want)
	}
}

// The whole reason this backend has its own goroutines. The agent calls Open
// from the packet loop, and that same loop renews agent_up — so an Open that
// waited on a subprocess could take the SPA port away by taking the renewal
// with it. Against a script that never returns, Open must come back at once.
func TestGate_ScriptOpen_ReturnsWithoutWaitingForAHungScript(t *testing.T) {
	script := installScript(t, "hang.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 30*time.Second), nil)

	start := time.Now()
	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 60*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	elapsed := time.Since(start)

	// Generous by two orders of magnitude against the script's 30s timeout:
	// this is asserting "did not wait for the subprocess at all", not a
	// latency budget.
	if elapsed > 2*time.Second {
		t.Errorf("Open took %s against a script that never returns; it waited for the subprocess", elapsed)
	}
}

// A hung script degrades its own service and nothing else. The second service
// keeps working while the first is wedged, which is the per-service isolation
// the whole design rests on.
func TestGate_ScriptOpen_HungServiceDoesNotBlockAnotherService(t *testing.T) {
	hang := installScript(t, "hang.sh", 0o700)
	ok := installScript(t, "ok.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"wedged": hang, "healthy": ok}, 30*time.Second), nil)

	if err := s.Open(context.Background(), "wedged", observed(t, "203.0.113.5/32"), 60*time.Second); err != nil {
		t.Fatalf("Open wedged: %v", err)
	}
	if err := s.Open(context.Background(), "healthy", observed(t, "203.0.113.6/32"), 60*time.Second); err != nil {
		t.Fatalf("Open healthy: %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		for _, line := range invocationLog(t, logPath) {
			if strings.HasPrefix(line, "open healthy ") {
				return true
			}
		}
		return false
	}, "the healthy service's open to complete while the wedged one is still running")
}

// The second knock for a wedged service is refused, on that service, with a
// sentinel the agent can report. Queueing it instead would build a backlog
// that fires all at once when the script finally clears, re-opening sources
// whose grants have lapsed.
func TestGate_ScriptOpen_SecondKnockForAWedgedServiceIsBusy(t *testing.T) {
	script := installScript(t, "hang.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 30*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 60*time.Second); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.6/32"), 60*time.Second)
	if !errors.Is(err, ErrScriptBusy) {
		t.Fatalf("second Open error = %v, want ErrScriptBusy", err)
	}
}

// The timeout has to actually free the slot, or "degrades its own service"
// would mean "disables its own service until the agent restarts". The hung
// script spawns a child that outlives its shell, so a backend that killed
// only the direct child would still be waiting here.
func TestGate_ScriptOpen_SlotIsFreedAfterTheTimeoutKillsTheScript(t *testing.T) {
	script := installScript(t, "hang.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 300*time.Millisecond), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 60*time.Second); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		return !errors.Is(s.Open(context.Background(), "perimeter", observed(t, "203.0.113.6/32"), 60*time.Second), ErrScriptBusy)
	}, "the timed-out invocation to release the service's slot")
}

// A refused open admitted nothing, so nothing is owed a close. Keeping the
// lease would have the reaper later issue a withdrawal for an admission that
// never existed — harmless against an idempotent script, and a line in the
// operator's audit log describing something that did not happen.
func TestGate_ScriptOpen_RefusalDropsTheLease(t *testing.T) {
	script := installScript(t, "refuse.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 300*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return len(s.leases.Live()) == 0 }, "the refused open's lease to be dropped")
}

// A failed open may have applied partially: a provider that accepted the call
// and then timed out on the reply is indistinguishable from one that never
// saw it. The close still owed is the safe assumption, so the lease survives.
func TestGate_ScriptOpen_FailureKeepsTheLease(t *testing.T) {
	script := installScript(t, "fail.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), func(o *ScriptOptions) {
		o.ReapInterval = time.Hour // so nothing but the open path can touch the lease
	})

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 300*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// The invocation slot being released is the signal, not the log line: the
	// script records its argv before it exits, so a test waiting on the log
	// would read the lease store before the open path had decided what to do
	// with the lease, and would pass whichever way that decision went.
	waitFor(t, 5*time.Second, func() bool { return !inflight(s, "perimeter") },
		"the failed open invocation to run to completion")

	if got := len(s.leases.Live()); got != 1 {
		t.Errorf("live leases after a failed open = %d, want 1: a partially applied open still owes a close", got)
	}
}

// The reaper is the whole of this backend's expiry story. nftables gets it
// from the kernel; here a goroutine has to notice the deadline and act.
func TestGate_ScriptReaper_ClosesALapsedAdmission(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 100*time.Millisecond); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// The lease going away is the condition, not the log line: the script
	// records its argv before it does anything, so a test that waited on the
	// log would race the backend's own bookkeeping and fail intermittently
	// with the work already done.
	waitFor(t, 5*time.Second, func() bool { return len(s.leases.Live()) == 0 },
		"the reaper to close the lapsed admission and drop its lease")

	var closed bool
	for _, line := range invocationLog(t, logPath) {
		if line == "close perimeter 203.0.113.5/32" {
			closed = true
		}
	}
	if !closed {
		t.Errorf("the lease was dropped without the close verb running; log was %v", invocationLog(t, logPath))
	}
}

// Recovering the schedule from disk is what makes a crash survivable at all.
// The first Script is abandoned without closing its admissions — a SIGKILL
// with extra steps — and the second one must find the lease and withdraw it
// rather than leaving a hole nothing remembers.
func TestGate_ScriptReaper_RecoversTheScheduleFromDiskAfterARestart(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)
	leasePath := filepath.Join(t.TempDir(), "gate-leases.db")
	policy := scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second)

	first, err := NewScript(policy, ScriptOptions{
		LeasePath: leasePath, OwnerUID: os.Getuid(),
		ReapInterval: time.Hour, HealthInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScript: %v", err)
	}
	if err := first.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 100*time.Millisecond); err != nil {
		t.Fatalf("Open: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return len(invocationLog(t, logPath)) > 0 }, "the open invocation")
	// Release the file lock without withdrawing anything: the reaper interval
	// is an hour, so nothing here has swept, and Close is never called.
	first.stopOnce.Do(func() { close(first.stopReap); first.stopBase() })
	first.wg.Wait()
	if err := first.leases.Close(); err != nil {
		t.Fatalf("close the first lease store: %v", err)
	}

	second := newTestScript(t, policy, func(o *ScriptOptions) { o.LeasePath = leasePath })
	waitFor(t, 5*time.Second, func() bool { return len(second.leases.Live()) == 0 },
		"the restarted backend's reaper to withdraw the recovered admission")

	var closed bool
	for _, line := range invocationLog(t, logPath) {
		if line == "close perimeter 203.0.113.5/32" {
			closed = true
		}
	}
	if !closed {
		t.Errorf("the recovered lease was dropped without the close verb running; log was %v", invocationLog(t, logPath))
	}
}

// State is a readback, not a mirror of what this process believes it did.
func TestGate_ScriptState_ReportsWhatTheScriptPrints(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	statePath := filepath.Join(t.TempDir(), "state.txt")
	if err := os.WriteFile(statePath, []byte(
		"postern-state-v1\n# a comment\n\n203.0.113.5/32 observed 84\n198.51.100.0/24 asserted -\n"), 0o600); err != nil {
		t.Fatalf("write state fixture: %v", err)
	}
	t.Setenv("POSTERN_TEST_STATE", statePath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	// The first call schedules the readback and reports that it has nothing
	// truthful to say yet.
	if _, err := s.State(context.Background(), "perimeter"); !errors.Is(err, ErrScriptNoState) {
		t.Fatalf("first State error = %v, want ErrScriptNoState", err)
	}

	var st ServiceState
	waitFor(t, 5*time.Second, func() bool {
		got, err := s.State(context.Background(), "perimeter")
		if err != nil {
			return false
		}
		st = got
		return true
	}, "the first successful state readback")

	if len(st.Elements) != 2 {
		t.Fatalf("elements = %d, want 2: %+v", len(st.Elements), st.Elements)
	}
	if got, want := st.Elements[0].Source.Prefix.String(), "203.0.113.5/32"; got != want {
		t.Errorf("element 0 prefix = %q, want %q", got, want)
	}
	if got, want := st.Elements[0].Expires, 84*time.Second; got != want {
		t.Errorf("element 0 expires = %s, want %s", got, want)
	}
	if got, want := st.Elements[1].Source.Kind, SourceAsserted; got != want {
		t.Errorf("element 1 kind = %s, want %s", got, want)
	}
}

// Most targets have no per-entry TTL to report, so the script prints "-" and
// the lease store supplies the remaining lifetime. Without this an operator
// reading `status` sees every perimeter admission as expiring immediately.
func TestGate_ScriptState_FillsAnUnknownExpiryFromTheLeaseStore(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	statePath := filepath.Join(t.TempDir(), "state.txt")
	if err := os.WriteFile(statePath, []byte("postern-state-v1\n203.0.113.5/32 observed -\n"), 0o600); err != nil {
		t.Fatalf("write state fixture: %v", err)
	}
	t.Setenv("POSTERN_TEST_STATE", statePath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)
	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 300*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}

	var st ServiceState
	waitFor(t, 5*time.Second, func() bool {
		got, err := s.State(context.Background(), "perimeter")
		if err != nil || len(got.Elements) == 0 {
			return false
		}
		st = got
		return true
	}, "the state readback")

	if got := st.Elements[0].Expires; got <= 0 || got > 300*time.Second {
		t.Errorf("expires = %s, want a positive value no greater than the 300s lease", got)
	}
}

// Unparseable output must never read as "this gate is admitting nothing".
// That is the one answer that turns a live hole invisible, and it is what a
// parser that skipped the lines it did not understand would produce.
func TestGate_ScriptState_MalformedOutputIsNotAdopted(t *testing.T) {
	script := installScript(t, "bad-state.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	// Drive at least one readback to completion, so this is asserting that a
	// parse failure was rejected rather than that nothing ran.
	waitFor(t, 5*time.Second, func() bool {
		_, _ = s.State(context.Background(), "perimeter")
		for _, line := range invocationLog(t, logPath) {
			if line == "state perimeter" {
				return true
			}
		}
		return false
	}, "the state invocation")

	if _, err := s.State(context.Background(), "perimeter"); !errors.Is(err, ErrScriptNoState) {
		t.Errorf("State after unparseable output returned %v, want ErrScriptNoState", err)
	}
}

// A clean shutdown withdraws what it admitted. This is the half of the story
// the honest caveat is measured against: Close does close the holes, and the
// gap is a stop that never reaches it.
func TestGate_ScriptClose_WithdrawsOutstandingAdmissions(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("POSTERN_TEST_LOG", logPath)

	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), func(o *ScriptOptions) {
		o.ReapInterval = time.Hour // so the reaper cannot be what closed it
	})
	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 300*time.Second); err != nil {
		t.Fatalf("Open: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return len(invocationLog(t, logPath)) > 0 }, "the open invocation")

	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var closed bool
	for _, line := range invocationLog(t, logPath) {
		if line == "close perimeter 203.0.113.5/32" {
			closed = true
		}
	}
	if !closed {
		t.Errorf("Close did not invoke the close verb; log was %v", invocationLog(t, logPath))
	}
}

// The agent reaches Close twice on the disarm path — once from the action,
// once from shutdown — and a teardown that errored the second time would
// report a failure for work already done.
func TestGate_ScriptClose_IsIdempotent(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// A closed backend refuses further admissions rather than recording leases
// nothing will ever act on: the reaper is stopped and the lease file is shut.
func TestGate_ScriptOpen_AfterCloseIsRefused(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 60*time.Second); err == nil {
		t.Error("Open after Close returned nil; a closed backend has no reaper to withdraw what it admits")
	}
}

func TestGate_ScriptOpen_UnknownServiceIsRefused(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "ssh", observed(t, "203.0.113.5/32"), 60*time.Second); err == nil {
		t.Error("Open for a service this backend does not own returned nil")
	}
}

func TestGate_ScriptOpen_NonPositiveTTLIsRefused(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	if err := s.Open(context.Background(), "perimeter", observed(t, "203.0.113.5/32"), 0); err == nil {
		t.Error("Open with a zero ttl returned nil")
	}
}

// The health verb's verdict is per service and never global; see
// Dispatcher.Health for why it must not reach pre-arm's inert decision.
func TestGate_ScriptServiceHealth_ReportsTheHealthVerbsVerdict(t *testing.T) {
	good := installScript(t, "ok.sh", 0o700)
	bad := installScript(t, "fail.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"good": good, "bad": bad}, 2*time.Second), nil)

	waitFor(t, 5*time.Second, func() bool {
		h, err := s.ServiceHealth("good")
		return err == nil && h.Healthy
	}, "the healthy service's health verb to report healthy")

	h, err := s.ServiceHealth("bad")
	if err != nil {
		t.Fatalf("ServiceHealth(bad): %v", err)
	}
	if h.Healthy {
		t.Error("a service whose health verb exits non-zero reported healthy")
	}
}

// Refusing at load, not at first knock, is the point: the operator finds out
// while they still have another way in.
func TestGate_NewScript_RefusesAWorldWritableScriptAtLoad(t *testing.T) {
	script := installScript(t, "world-writable.sh", 0o777)
	_, err := NewScript(scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), ScriptOptions{
		LeasePath: filepath.Join(t.TempDir(), "gate-leases.db"),
		OwnerUID:  os.Getuid(),
	})
	if !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("NewScript error = %v, want ErrScriptPathUnsafe", err)
	}
	if !strings.Contains(err.Error(), "perimeter") {
		t.Errorf("error does not name the offending service: %v", err)
	}
}

func TestGate_NewScript_RequiresALeasePath(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	_, err := NewScript(scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), ScriptOptions{
		OwnerUID: os.Getuid(),
	})
	if err == nil {
		t.Fatal("NewScript with no LeasePath returned nil; the schedule would live only in memory")
	}
}

// A fetched bundle can repoint a service at a different executable, so the
// path checks have to run again on the way in rather than only at boot.
func TestGate_ScriptSetPolicy_RefusesAnUnsafePathFromANewPolicy(t *testing.T) {
	good := installScript(t, "ok.sh", 0o700)
	bad := installScript(t, "world-writable.sh", 0o777)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": good}, 2*time.Second), nil)

	if err := s.SetPolicy(scriptPolicy(t, map[string]string{"perimeter": bad}, 2*time.Second)); !errors.Is(err, ErrScriptPathUnsafe) {
		t.Fatalf("SetPolicy error = %v, want ErrScriptPathUnsafe", err)
	}
	// And the refusal left the previous catalogue standing, rather than a
	// backend that half-adopted a policy.
	if got := s.Services(); len(got) != 1 || got[0] != "perimeter" {
		t.Errorf("services after a refused SetPolicy = %v, want [perimeter]", got)
	}
	if got := s.services["perimeter"].path; got != good {
		t.Errorf("script path after a refused SetPolicy = %q, want %q", got, good)
	}
}

func TestGate_ScriptSetPolicy_AdoptsANewService(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	s := newTestScript(t, scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second), nil)

	next := scriptPolicy(t, map[string]string{"perimeter": script, "edge": script}, 2*time.Second)
	if err := s.SetPolicy(next); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if got := strings.Join(s.Services(), ","); got != "edge,perimeter" {
		t.Errorf("services = %q, want %q", got, "edge,perimeter")
	}
}

// A service whose backend is nftables must never be picked up here, or the
// same admission would be applied twice through two different mechanisms.
func TestGate_NewScript_IgnoresNFTablesBackedServices(t *testing.T) {
	script := installScript(t, "ok.sh", 0o700)
	p := scriptPolicy(t, map[string]string{"perimeter": script}, 2*time.Second)
	p.Services["ssh"] = config.Service{
		Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
		DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
		FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
		Backend: config.BackendNFTables,
	}
	s := newTestScript(t, p, nil)

	if got := strings.Join(s.Services(), ","); got != "perimeter" {
		t.Errorf("services = %q, want %q", got, "perimeter")
	}
}
