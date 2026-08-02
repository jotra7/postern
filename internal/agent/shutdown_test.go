package agent_test

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
)

// --- helpers ----------------------------------------------------------------

// lockedBuffer is an io.Writer a slog handler can share with the goroutine
// reading it back. The daemon logs from its own goroutines, so an unguarded
// bytes.Buffer here is a data race the race detector would find rather than a
// test that occasionally reads a short line.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// parkedPullHarness is a running daemon whose bundle puller is parked inside
// applyBundlePolicy, holding no lock the shutdown path needs.
//
// The park point is Ruleset.Snapshot, reached through the arm the puller
// performs on a bundle it has already fetched and verified. That is the one
// hold in this package that behaves the way a real slow apply does: it is on
// the pull loop's own goroutine, and it is unaffected by Run's context,
// because the context applyBundlePolicy runs under is deliberately detached
// from Run's (see New, where applyFn is built). A park that a cancelled
// context released would prove nothing about a shutdown that has to wait.
type parkedPullHarness struct {
	*bundleHarness
	statePath string
	logs      *lockedBuffer
	release   chan struct{}
}

// newParkedPullHarness starts a daemon, serves it one valid bundle, and
// returns once its puller has reached the park inside the arm.
func newParkedPullHarness(t *testing.T) *parkedPullHarness {
	t.Helper()
	srv, set := newBundleServer(t)
	logs := &lockedBuffer{}

	var statePath string
	h := newBundleHarnessTuned(t, srv.URL, 0, func(cfg *agent.PullConfig) {
		// Short enough that the puller retries on its own after the bundle
		// below is published, which is what lets the park be armed first.
		// The alternative, publishing before Run starts, races the puller's
		// immediate first pull against arming the park.
		cfg.Interval = 20 * time.Millisecond
		statePath = cfg.StatePath
	}, func(o *agent.Options) {
		// The daemon's own logger, not the puller's: the line a shutdown
		// writes about a loop that did not stop belongs to the shutdown.
		o.Logger = slog.New(slog.NewTextHandler(logs, nil))
	})
	h.start(t)

	// Armed after start, so the daemon's own startup arm is not the Snapshot
	// that gets parked.
	entered, release := h.txn.ruleset.blockNextSnapshot()
	set(h.sealValid(t, txnHarnessRecordedRevision+1, nil))

	p := &parkedPullHarness{bundleHarness: h, statePath: statePath, logs: logs, release: release}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the bundle puller never reached the park inside the arm, so nothing below is " +
			"observing a shutdown that has a running loop to wait for")
	}
	return p
}

// releaseOnce unparks the puller, and is safe to call from both a test body
// and its cleanup.
func (p *parkedPullHarness) releaseOnce() {
	select {
	case <-p.release:
	default:
		close(p.release)
	}
}

// releaseAndDrain unparks the puller and waits for it to finish the work the
// park was holding.
//
// A test that deliberately lets the shutdown give up on this loop would
// otherwise race its own temp directory removal against the writes the loop
// resumes, which is the very failure that started this, reproduced by the
// test for it. Everything the arm writes lands before the applied count
// moves, and the version record is the last write of all, so the record
// appearing is the loop having gone quiet. It gives up silently after a
// deadline of its own:
// this runs as a cleanup, where a failure would report a second problem on
// top of whatever the test already found.
func (p *parkedPullHarness) releaseAndDrain() {
	p.releaseOnce()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p.statePath); err == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --- tests ------------------------------------------------------------------

// Run returning must mean the agent has stopped writing. Before this, Run
// returned when its own select saw the cancelled context and the three
// background loops were left to notice on their own, so the bundle puller
// went on writing the file that records the version this host has installed
// after the process had, as far as every caller could tell, stopped.
//
// That record is what lets a restart recognise an older but validly signed
// bundle as a rollback, so losing it is a security property degrading with no
// signal. The write is atomic, so nothing is corrupted and nothing is
// visibly wrong, which is exactly why nothing would have caught it.
//
// Asserted in both directions. Run must not return while the loop is parked,
// which is the property; and the version file must be complete and the state
// directory free of the write's temporary file once Run has returned, which
// is the consequence the flake in
// TestAgent_Puller_ABundleThatDegradesPreArmStandsRatherThanTearsDown was
// reporting as a temp directory that would not delete.
func TestAgent_Daemon_RunWaitsForTheBundlePullerBeforeReturning(t *testing.T) {
	p := newParkedPullHarness(t)
	t.Cleanup(p.releaseAndDrain)

	p.cancel()

	select {
	case <-p.done:
		t.Fatal("Run returned while the bundle puller was still inside an arm; a caller that has " +
			"seen Run return must be able to treat the agent as no longer writing anything")
	case <-time.After(300 * time.Millisecond):
	}

	p.releaseOnce()

	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the bundle puller was released")
	}
	if err := <-p.runErr; err != nil {
		t.Fatalf("Run() = %v, want nil: a cancelled context is a clean stop", err)
	}

	if _, err := os.Stat(p.statePath); err != nil {
		t.Fatalf("stat the applied-version record after Run returned: %v: the puller applied a "+
			"bundle, so the record that makes an older one a rollback must be on disk", err)
	}
	entries, err := os.ReadDir(filepath.Dir(p.statePath))
	if err != nil {
		t.Fatalf("read the state directory: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("the state directory still holds %q after Run returned: the write-then-rename "+
				"was cut off partway, which is the same race under another name", e.Name())
		}
	}
}

// The wait is bounded, and the bound is the daemon's own rather than
// systemd's. A loop that will not stop must not hold the process open until
// TimeoutStopSec kills it, because being killed says nothing: the whole
// value of stopping on a bound of our own is the line that names which loop
// did not stop.
//
// Run still returns nil. The three non-nil returns each describe a host that
// is unprotected or unreachable, and by the time this wait runs agent_up is
// silenced and the tables are down, so a failed stop would describe a host
// that is in exactly the state a clean stop leaves.
func TestAgent_Daemon_RunStopsOnItsOwnBoundWhenALoopWillNotStop(t *testing.T) {
	p := newParkedPullHarness(t)
	t.Cleanup(p.releaseAndDrain)

	start := time.Now()
	p.cancel()

	select {
	case <-p.done:
	case <-time.After(agent.LoopStopTimeoutForTest + 5*time.Second):
		t.Fatal("Run never returned with a loop parked; an unbounded wait hands shutdown to " +
			"whichever loop is slowest, and on a wedge that is never")
	}
	elapsed := time.Since(start)
	if elapsed < agent.LoopStopTimeoutForTest {
		t.Fatalf("Run returned after %s, before the %s bound had elapsed: it gave up on a loop it "+
			"had not yet waited for", elapsed, agent.LoopStopTimeoutForTest)
	}

	if err := <-p.runErr; err != nil {
		t.Fatalf("Run() = %v, want nil: a loop that did not stop is logged, not returned; changing "+
			"the exit status would report a failed stop for a host the teardown already left clean", err)
	}
	// The line, not the buffer. The daemon's logger is the puller's too, so
	// this buffer already holds the pull loop's own rejections and a search
	// for "pull" anywhere in it passes whatever the shutdown wrote, which is
	// how an earlier version of this assertion survived renaming the loop.
	var line string
	for _, l := range strings.Split(p.logs.String(), "\n") {
		if strings.Contains(l, "did not stop") {
			line = l
			break
		}
	}
	if line == "" {
		t.Errorf("no line about a loop that did not stop, in:\n%s", p.logs.String())
	} else if !strings.Contains(line, "loops="+agent.PullLoopNameForTest) {
		t.Errorf("the shutdown logged %q, want it to name %q as the loop that did not stop: a line "+
			"that cannot say which loop wedged is a line nobody can act on",
			line, agent.PullLoopNameForTest)
	}
}

// The split-plane invariant, at shutdown. The bundle puller and the
// heartbeat emitter are the management plane and the SPA port is the knock
// path, and the management plane must never be able to affect it, including
// by being slow to stop.
//
// So every step that touches the knock path runs before anything waits.
// Asserted while a management-plane loop is still parked and Run has
// therefore not returned: if agent_up has already been silenced and the gate
// already closed at that instant, no amount of waiting on that loop can have
// delayed either.
//
// Moving the wait ahead of the teardown fails this, which is the mutation
// that matters: it is the arrangement a plain "Wait before Run returns"
// produces, and on a real host it is worse than slow, because udpReceiver's
// Receive does not observe a cancelled context and only the socket's own
// Close ends it.
func TestAgent_Daemon_ShutdownSilencesTheSPAPortBeforeWaitingOnAnyLoop(t *testing.T) {
	p := newParkedPullHarness(t)
	t.Cleanup(p.releaseAndDrain)

	p.cancel()

	// The teardown is not instantaneous, so this waits for it rather than
	// sampling once. What it must never do is wait past the point where the
	// park is released, which is why nothing releases until after.
	deadline := time.Now().Add(agent.LoopStopTimeoutForTest / 2)
	var silences, closes int
	for time.Now().Before(deadline) {
		_, silences, closes, _ = p.gate.counts()
		if silences > 0 && closes > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	select {
	case <-p.done:
		t.Fatal("Run returned before the parked loop was released, so this test never observed the " +
			"teardown and the wait overlapping at all")
	default:
	}
	if silences == 0 || closes == 0 {
		t.Fatalf("with a management-plane loop parked and Run still waiting on it, agent_up was "+
			"silenced %d times and the gate closed %d; both must already have happened, or a slow "+
			"pull is delaying the instant the SPA port stops being reachable", silences, closes)
	}
}

// The bound covers the set of loops, not each loop in turn, and the line
// names all of them.
//
// A bound applied per loop would be a bound that grows with how many loops
// the daemon happens to start: three wedged loops would hold a stop for three
// times as long as one, for no reason an operator could predict from the
// number they were told. With one loop parked the two arrangements are
// indistinguishable, which is why this parks two.
//
// The parks are the two management-plane loops, held by different mechanisms
// on purpose: the puller inside an arm, the heartbeat emitter inside its
// state file's fsync. Both survive the cancelled context, and neither holds
// anything the other needs.
func TestAgent_Daemon_TheShutdownBoundCoversAllLoopsTogether(t *testing.T) {
	srv, set := newBundleServer(t)
	logs := &lockedBuffer{}

	var statePath string
	h := newBundleHarnessTuned(t, srv.URL, 0, func(cfg *agent.PullConfig) {
		cfg.Interval = 20 * time.Millisecond
		statePath = cfg.StatePath
	}, func(o *agent.Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, nil))
		_, hub := newBeatServer(t, o.Host.Public().Signing)
		o.Beat = &agent.BeatConfig{
			HubURL:    hub.URL,
			HostID:    o.Policy.HostID,
			Signer:    o.Host,
			StatePath: filepath.Join(t.TempDir(), "beat.state"),
			Interval:  time.Hour,
			Timeout:   150 * time.Millisecond,
		}
	})

	beatEntered := make(chan struct{})
	beatRelease := make(chan struct{})
	releaseBeat := func() {
		select {
		case <-beatRelease:
		default:
			close(beatRelease)
		}
	}
	// After construction, before start: NewBeater's own header write goes
	// through this same checkpoint, and parking there would hang inside
	// agent.New with no loop to wait for.
	t.Cleanup(func() { agent.SetBeatDurableCheckpoint(nil) })
	t.Cleanup(releaseBeat)
	var once sync.Once
	agent.SetBeatDurableCheckpoint(func(string) {
		once.Do(func() {
			close(beatEntered)
			<-beatRelease
		})
	})

	h.start(t)

	pullEntered, pullRelease := h.txn.ruleset.blockNextSnapshot()
	releasePull := func() {
		select {
		case <-pullRelease:
		default:
			close(pullRelease)
		}
	}
	t.Cleanup(func() {
		releasePull()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(statePath); err == nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	})
	set(h.sealValid(t, txnHarnessRecordedRevision+1, nil))

	for _, w := range []struct {
		name string
		ch   chan struct{}
	}{{"pull", pullEntered}, {"beat", beatEntered}} {
		select {
		case <-w.ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("the %s loop never reached its park, so this test is not observing two "+
				"loops wedged at once", w.name)
		}
	}

	start := time.Now()
	h.cancel()

	select {
	case <-h.done:
	case <-time.After(4 * agent.LoopStopTimeoutForTest):
		t.Fatal("Run never returned with two loops parked")
	}
	elapsed := time.Since(start)
	if elapsed >= 2*agent.LoopStopTimeoutForTest {
		t.Errorf("two parked loops held the shutdown for %s, at or beyond twice the %s bound: the "+
			"bound is being spent once per loop, so what a stop costs depends on how many loops "+
			"the daemon started rather than on the number anyone was told",
			elapsed, agent.LoopStopTimeoutForTest)
	}

	var line string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "did not stop") {
			line = l
			break
		}
	}
	for _, want := range []string{agent.PullLoopNameForTest, agent.BeatLoopNameForTest} {
		if !strings.Contains(line, want) {
			t.Errorf("the shutdown logged %q, want it to name %q: both loops were parked, and a "+
				"line that names only one sends an operator after half the problem", line, want)
		}
	}
	// Start order, which is the order waitLoops documents. Nothing depends on
	// it being this order rather than another; what an operator reading two
	// journals side by side depends on is that it is the same order twice.
	if pull, beat := strings.Index(line, agent.PullLoopNameForTest),
		strings.Index(line, agent.BeatLoopNameForTest); pull >= 0 && beat >= 0 && pull > beat {
		t.Errorf("the shutdown logged %q, naming the loops out of the order they were started", line)
	}
}

// Run stops its loops on every return, not only on a cancelled context.
//
// Two of Run's three non-nil returns leave the caller's context live: a
// receive error and an unusable replay store are the agent deciding to stop,
// not the caller asking it to. Loops selecting on that context would never be
// told anything, so every such exit would spend the whole shutdown bound
// waiting for loops that had no reason to stop, and would then log an error
// about loops that were working exactly as intended. Run gives them a context
// of its own and cancels it on the way out.
//
// Measured as the shutdown being prompt rather than by observing the context,
// because prompt is the whole of what the loop-scoped context buys here: the
// pull loop's sleep between attempts is an hour in this harness, so under a
// context nobody cancels it is still asleep when the bound expires.
func TestAgent_Daemon_RunStopsItsLoopsOnAnExitTheCallerDidNotAskFor(t *testing.T) {
	srv, _ := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)
	h.start(t)

	// A healthy packet first, so the exit below is demonstrably a transition
	// rather than a daemon that never worked.
	h.send(t, h.seal(h.gateRequest()), false)
	waitFor(t, "the first packet to open a gate", func() bool { return len(h.gate.openCalls()) == 1 })

	// The replay store fails, which is Run deciding to stop with the caller's
	// context untouched. Nothing in this test cancels anything.
	h.store.startFailing(errors.New("write record: no space left on device"))
	start := time.Now()
	h.send(t, h.seal(h.gateRequest()), false)

	select {
	case err := <-h.runErr:
		if !errors.Is(err, agent.ErrIncapacitated) {
			t.Fatalf("Run() = %v, want ErrIncapacitated", err)
		}
	case <-time.After(agent.LoopStopTimeoutForTest + 5*time.Second):
		t.Fatal("Run never returned after the replay store failed")
	}
	if elapsed := time.Since(start); elapsed >= agent.LoopStopTimeoutForTest {
		t.Errorf("Run took %s to return on an exit the caller did not ask for, at or beyond the %s "+
			"shutdown bound: the background loops were never told to stop, so the shutdown waited "+
			"out its whole timeout on loops that were doing nothing wrong",
			elapsed, agent.LoopStopTimeoutForTest)
	}
}

// The heartbeat emitter's state file is closed only once its loop has
// stopped, and not at all when that loop is the one that did not stop.
//
// Close syncs and closes the file under the same mutex the loop holds across
// its own fsync, so a shutdown that closed underneath a running loop would
// block for as long as that fsync did, with no bound at all, spending the
// shutdown timeout and then hanging anyway, which is the one outcome a bound
// exists to rule out.
//
// The park here is that fsync, held open for the whole shutdown, so the beat
// loop is still inside the mutex when the bound expires.
func TestAgent_Daemon_ShutdownSkipsTheBeatStateCloseWhenTheBeatLoopIsStuck(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}
	h := newDaemonHarness(t, func(o *agent.Options) {
		_, srv := newBeatServer(t, o.Host.Public().Signing)
		o.Beat = &agent.BeatConfig{
			HubURL:    srv.URL,
			HostID:    o.Policy.HostID,
			Signer:    o.Host,
			StatePath: filepath.Join(t.TempDir(), "beat.state"),
			Interval:  time.Hour,
			Timeout:   150 * time.Millisecond,
		}
	})

	// Installed after the daemon is built and before it is started, which is
	// the only window that parks the loop rather than the construction:
	// NewBeater opens the state file and writes its header, and that write is
	// fsynced through the same checkpoint. Parking there would hang inside
	// agent.New, with no loop running and nothing to shut down.
	//
	// Both cleanups are registered before start's, and therefore run after
	// it: the checkpoint stays installed for the whole of the shutdown under
	// test, and the parked goroutine is let go only once Run has returned.
	t.Cleanup(func() { agent.SetBeatDurableCheckpoint(nil) })
	t.Cleanup(releaseOnce)

	var once sync.Once
	agent.SetBeatDurableCheckpoint(func(string) {
		once.Do(func() {
			close(entered)
			<-release
		})
	})

	h.start(t)

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the heartbeat emitter never reached a durable checkpoint")
	}

	h.cancel()

	select {
	case <-h.done:
	case <-time.After(agent.LoopStopTimeoutForTest + 5*time.Second):
		t.Fatal("Run never returned with the beat loop parked inside its state file's mutex: the " +
			"shutdown is blocked on a Close that cannot proceed until the loop it is closing " +
			"underneath lets go")
	}
	if err := <-h.runErr; err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
}
