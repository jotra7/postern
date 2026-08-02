package agent_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/metrics"
)

// --- recording hub ----------------------------------------------------------

// beatRecorder is a POST /heartbeat handler that verifies every beat against
// one host's signing key and keeps every one it accepted, in arrival order.
type beatRecorder struct {
	mu    sync.Mutex
	beats []*attest.Beat
}

func (r *beatRecorder) add(b *attest.Beat) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.beats = append(r.beats, b)
}

func (r *beatRecorder) all() []*attest.Beat {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*attest.Beat(nil), r.beats...)
}

// newBeatServer answers every POST /heartbeat with 204 after verifying the
// beat against hostSigningPub, mirroring what internal/hub's own handler
// checks (signature before anything else is trusted) closely enough to be a
// meaningful stand-in without importing internal/hub, which internal/agent
// must not do.
func newBeatServer(t *testing.T, hostSigningPub [32]byte) (*beatRecorder, *httptest.Server) {
	t.Helper()
	rec := &beatRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		beat, err := attest.Verify(data, hostSigningPub)
		if err != nil {
			http.Error(w, "bad beat: "+err.Error(), http.StatusBadRequest)
			return
		}
		rec.add(beat)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return rec, srv
}

func waitForBeatFailure(t *testing.T, h *daemonHarness) {
	t.Helper()
	waitFor(t, "the heartbeat loop to record a rejection", func() bool {
		return h.daemon.Beater().Stats().Rejections >= 1
	})
}

// newBeatSlowServer answers after delay, which the caller sets comfortably
// longer than the client's own Timeout, so the client always gives up first
// — exercising the identical "hub accepts a connection and never answers in
// time" case pull_test.go's newSlowLorisServer covers for a bodyless GET.
//
// It is deliberately NOT built the way newSlowLorisServer is (blocking on
// <-r.Context().Done()). A POST carries a body, and — reproduced directly
// against the standard library, independent of anything in this package —
// net/http's Client.Timeout firing while a request-with-a-body is awaiting
// headers does not reliably close the underlying connection promptly: the
// server-side handler can be left blocked on that request's context for
// minutes after the client has already given up and moved on, and
// httptest.Server.Close (which this test's cleanup calls) waits for exactly
// that connection to finish. A handler that instead returns on its own after
// a bounded sleep lets the connection close normally regardless of what the
// client did, so the test's own cleanup is never held hostage by a Go
// standard library timing quirk that has nothing to do with the property
// under test here — which is that BeatOnce returns an error promptly, not
// that this test server torn down instantly.
func newBeatSlowServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- TestAgent_Beater_SequenceIncreasesAndSurvivesRestart -------------------

// Sequence is monotonic across the process's life, and epoch comes from
// enrollment (here: whatever this Beater's very first beat established,
// since Phase A builds no signed-reset mechanism to change it). A restart
// that reset sequence to zero would be rejected by the hub forever, which is
// the failure epoch exists to make recoverable — but only if the agent
// genuinely persists one and increments the other. This drives three beats,
// closes the Beater (releasing the state file's flock, exactly like a
// process exiting), opens a second Beater over the same StatePath — a
// restart, from the state file's point of view — and requires the next
// sequence to continue upward rather than repeat or reset.
func TestAgent_Beater_SequenceIncreasesAndSurvivesRestart(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	rec, srv := newBeatServer(t, host.Public().Signing)
	statePath := filepath.Join(t.TempDir(), "beat.state")
	noopCollect := func() attest.Body { return attest.Body{} }

	cfg := agent.BeatConfig{
		HubURL:    srv.URL,
		Signer:    host,
		StatePath: statePath,
		Interval:  time.Hour, // this test drives BeatOnce directly
	}

	b1, err := agent.NewBeater(cfg, noopCollect)
	if err != nil {
		t.Fatalf("NewBeater: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := b1.BeatOnce(context.Background()); err != nil {
			t.Fatalf("BeatOnce #%d: %v", i+1, err)
		}
	}
	if err := b1.Close(); err != nil {
		t.Fatalf("Close (simulating process exit): %v", err)
	}

	before := rec.all()
	if len(before) != 3 {
		t.Fatalf("hub recorded %d beats before the restart, want 3", len(before))
	}
	for i, b := range before {
		if want := uint64(i + 1); b.Sequence != want {
			t.Fatalf("beat %d sequence = %d, want %d", i, b.Sequence, want)
		}
	}
	epoch := before[0].Epoch

	// The restart: a fresh Beater over the identical StatePath, the same way
	// a fresh process would open it after posternd restarts.
	b2, err := agent.NewBeater(cfg, noopCollect)
	if err != nil {
		t.Fatalf("NewBeater after restart: %v", err)
	}
	t.Cleanup(func() { _ = b2.Close() })
	if err := b2.BeatOnce(context.Background()); err != nil {
		t.Fatalf("BeatOnce after restart: %v", err)
	}

	after := rec.all()
	last := after[len(after)-1]
	if last.Sequence <= before[len(before)-1].Sequence {
		t.Fatalf("sequence after restart = %d, want strictly greater than %d (the pre-restart high "+
			"water mark) — a restart that reset to zero, or replayed an already-used sequence, is "+
			"exactly what the hub rejects forever", last.Sequence, before[len(before)-1].Sequence)
	}
	if last.Epoch != epoch {
		t.Fatalf("epoch changed across a restart with no signed reset: got %d, want %d", last.Epoch, epoch)
	}
}

// --- TestAgent_Beater_KeepsServingKnocksWhenTheHubRejectsEveryBeat ----------

// A failing heartbeat is not a reason to stop gating. The hub being down
// must look like a hub being down, not like a host going quiet — the same
// split-plane invariant TestAgent_Puller_AKnockSucceedsWhileTheHubIsUnreachable
// asserts for the pull direction, asserted here for the push direction,
// against a hub that is refused, black-holed, or answering wrong.
func TestAgent_Beater_KeepsServingKnocksWhenTheHubRejectsEveryBeat(t *testing.T) {
	garbage := newGarbageServer(t)
	slow := newBeatSlowServer(t, time.Second)

	hubs := map[string]string{
		"connection_refused": "http://127.0.0.1:1",
		"black_hole":         "http://240.0.0.1:9",
		"garbage_200":        garbage.URL,
		"slow_server":        slow.URL,
	}

	for name, hubURL := range hubs {
		t.Run(name, func(t *testing.T) {
			h := newDaemonHarness(t, func(o *agent.Options) {
				o.Beat = &agent.BeatConfig{
					HubURL:    hubURL,
					HostID:    o.Policy.HostID,
					Signer:    o.Host,
					StatePath: filepath.Join(t.TempDir(), "beat.state"),
					Interval:  time.Hour, // this test drives the schedule itself
					Timeout:   150 * time.Millisecond,
				}
			})
			h.start(t)

			// Do not wait for the beat to fail first: the point is that the
			// two are independent, so knock immediately and knock again
			// after the beat has definitely errored.
			assertKnockOpensGate(t, h, 1)
			waitForBeatFailure(t, h)
			assertKnockOpensGate(t, h, 2)
		})
	}
}

// --- TestAgent_Beater_ReportsAgentUpFailureOnTheNextBeat --------------------

// Section 8: a failed agent_up renewal is its own immediate health
// transition. The agent holds that signal the instant it happens rather than
// waiting for drift comparison or the probe to notice on their own cadences.
// This forces the daemon's next agent_up renewal to fail through the same
// tick the packet loop's own beat() runs on, then drives the heartbeat
// emitter directly and requires the very next beat — not some later one —
// to carry AgentUpHealthy=false.
func TestAgent_Beater_ReportsAgentUpFailureOnTheNextBeat(t *testing.T) {
	var rec *beatRecorder
	var srv *httptest.Server
	h := newDaemonHarness(t, func(o *agent.Options) {
		rec, srv = newBeatServer(t, o.Host.Public().Signing)
		o.Beat = &agent.BeatConfig{
			HubURL:    srv.URL,
			HostID:    o.Policy.HostID,
			Signer:    o.Host,
			StatePath: filepath.Join(t.TempDir(), "beat.state"),
			Interval:  time.Hour, // this test drives BeatOnce directly
		}
	})
	h.start(t)

	// Run starts the heartbeat emitter's own goroutine, which beats
	// immediately (see Beater.Run) — racing this test's own explicit call
	// below, harmlessly, since both happen before the injected failure and
	// both must report the daemon healthy. Waiting for at least one here,
	// rather than assuming there is exactly one, is what keeps this
	// deterministic without depending on which of the two happened first.
	waitFor(t, "an initial heartbeat", func() bool { return len(rec.all()) >= 1 })
	for _, b := range rec.all() {
		if !b.Body.AgentUpHealthy {
			t.Fatal("a beat sent while agent_up is renewing cleanly reports AgentUpHealthy = false")
		}
	}

	// Force the next agent_up renewal to fail, then drive the exact tick the
	// daemon's own steady-state loop uses to renew it (see Daemon.beat) —
	// not a call to any lower-level method a beat itself would not have
	// observed through the running daemon.
	h.gate.setRefreshErr(errors.New("netlink: no such file or directory"))
	h.tick(t, true)

	// From here on nothing else will beat on its own — Interval is an hour —
	// so this explicit call is unambiguously the next beat sent, and it must
	// be the one that sees the failure above.
	before := len(rec.all())
	if err := h.daemon.Beater().BeatOnce(context.Background()); err != nil {
		t.Fatalf("BeatOnce (after a failed renewal): %v", err)
	}
	after := rec.all()
	if len(after) != before+1 {
		t.Fatalf("hub recorded %d beats after the explicit call, want %d", len(after), before+1)
	}
	last := after[len(after)-1]
	if last.Body.AgentUpHealthy {
		t.Fatal("the beat sent immediately after a failed agent_up renewal still reports " +
			"AgentUpHealthy = true; the daemon's live health signal did not reach the heartbeat body")
	}
}

// --- construction guards -----------------------------------------------

// Every one of NewBeater's construction-time refusals, isolated the same way
// TestAgent_Puller_NewPuller_RejectsIncompleteConfig isolates Puller's: only
// the field under test is broken, everything else stays legitimate, so a
// mutation deleting one guard cannot hide behind another.
func TestAgent_Beater_NewBeater_RejectsIncompleteConfig(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	validConfig := func(t *testing.T) agent.BeatConfig {
		t.Helper()
		return agent.BeatConfig{
			HubURL:    "https://hub.example.com",
			Signer:    host,
			StatePath: filepath.Join(t.TempDir(), "beat.state"),
		}
	}
	noopCollect := func() attest.Body { return attest.Body{} }

	t.Run("empty HubURL", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.HubURL = ""
		if _, err := agent.NewBeater(cfg, noopCollect); err == nil {
			t.Fatal("NewBeater accepted an empty HubURL")
		}
	})
	t.Run("nil Signer", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Signer = nil
		if _, err := agent.NewBeater(cfg, noopCollect); err == nil {
			t.Fatal("NewBeater accepted a nil Signer")
		}
	})
	t.Run("empty StatePath", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.StatePath = ""
		if _, err := agent.NewBeater(cfg, noopCollect); err == nil {
			t.Fatal("NewBeater accepted an empty StatePath; a restart would then reset sequence to " +
				"zero, which the hub rejects forever")
		}
	})
	t.Run("nil collect", func(t *testing.T) {
		if _, err := agent.NewBeater(validConfig(t), nil); err == nil {
			t.Fatal("NewBeater accepted a nil collect")
		}
	})
	t.Run("Jitter at 1 (exclusive upper bound)", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Jitter = 1
		if _, err := agent.NewBeater(cfg, noopCollect); err == nil {
			t.Fatal("NewBeater accepted Jitter = 1; a factor of 1 + 1*(-1) can reach 0, collapsing the interval")
		}
	})
	t.Run("negative Jitter", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Jitter = -0.1
		if _, err := agent.NewBeater(cfg, noopCollect); err == nil {
			t.Fatal("NewBeater accepted a negative Jitter")
		}
	})
	t.Run("every field legitimate", func(t *testing.T) {
		b, err := agent.NewBeater(validConfig(t), noopCollect)
		if err != nil {
			t.Fatalf("NewBeater rejected a legitimate config: %v", err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

// --- durable state file discipline --------------------------------------

// The wire layout reproduced here from beat.go's own doc comment, the same
// way pull_test.go's sealMalformed builds a record by hand from bundle's
// exported constants rather than through Seal: this package cannot see
// beat.go's unexported beatState constants from agent_test, and the point of
// these two tests is to prove the ON-DISK FORMAT behaves as documented, not
// to exercise it through a seam built just for testing.
const (
	testBeatStateHeaderLen = 8
	testBeatStateRecordLen = 16
)

var testBeatStateMagic = [4]byte{'P', 'B', 'S', 'T'}

func beatStateHeaderBytes() []byte {
	buf := make([]byte, testBeatStateHeaderLen)
	copy(buf[0:4], testBeatStateMagic[:])
	buf[4] = 1
	return buf
}

func appendBeatStateRecord(buf []byte, epoch, sequence uint64) []byte {
	rec := make([]byte, testBeatStateRecordLen)
	binary.BigEndian.PutUint64(rec[0:8], epoch)
	binary.BigEndian.PutUint64(rec[8:16], sequence)
	return append(buf, rec...)
}

// TestAgent_Beater_RejectsACorruptStateFileOutright is the property this
// file's own doc comment names: a file that exists but does not start with
// the expected magic must be refused, never silently treated as an empty
// store — treating it as empty is exactly the sequence-reset-to-zero failure
// this whole mechanism exists to prevent.
func TestAgent_Beater_RejectsACorruptStateFileOutright(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "beat.state")
	if err := os.WriteFile(statePath, []byte("not a beat state file, just garbage bytes"), 0o600); err != nil {
		t.Fatalf("write corrupt state file: %v", err)
	}

	_, err = agent.NewBeater(agent.BeatConfig{
		HubURL:    "https://hub.example.com",
		Signer:    host,
		StatePath: statePath,
	}, func() attest.Body { return attest.Body{} })
	if err == nil {
		t.Fatal("NewBeater accepted a corrupt state file; treating it as an empty store would reset " +
			"sequence to zero, which the hub rejects forever")
	}
}

// TestAgent_Beater_RecoversFromATornTailRecord mirrors
// internal/replay/log_test.go's identical property for the identical reason:
// a crash mid-write leaves a torn record at the end of the file, and
// everything before it is intact and must survive.
func TestAgent_Beater_RecoversFromATornTailRecord(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "beat.state")

	data := beatStateHeaderBytes()
	data = appendBeatStateRecord(data, 0, 5) // one whole, intact record: epoch 0, sequence 5
	data = append(data, 0x01, 0x02, 0x03)    // a torn tail: fewer than 16 bytes
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatalf("write state file with a torn tail record: %v", err)
	}

	rec, srv := newBeatServer(t, host.Public().Signing)
	b, err := agent.NewBeater(agent.BeatConfig{
		HubURL:    srv.URL,
		Signer:    host,
		StatePath: statePath,
		Interval:  time.Hour,
	}, func() attest.Body { return attest.Body{} })
	if err != nil {
		t.Fatalf("NewBeater over a file with a torn tail record: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.BeatOnce(context.Background()); err != nil {
		t.Fatalf("BeatOnce: %v", err)
	}
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("hub recorded %d beats, want 1", len(got))
	}
	if got[0].Sequence != 6 {
		t.Fatalf("sequence = %d, want 6 (continuing from the last WHOLE record, sequence 5, "+
			"ignoring the torn tail rather than being confused by it)", got[0].Sequence)
	}
}

// TestAgent_Beater_CompactionNeverLosesTheSequence is the crash-safety
// property compactLocked's shape exists for.
//
// The old compaction did Truncate(0), then writeHeader, then wrote the
// record. A crash anywhere between the truncate and the final sync left a
// header-only file: load found no records, haveRecord stayed false, and next
// returned sequence 1 — while hub.Beats.Accept goes on rejecting every
// sequence at or below the high-water mark for the life of the epoch, and the
// signed epoch bump is Phase B. The host's heartbeat would be permanently
// dead while looking identical to an unreachable hub, and the window opened
// once every beatStateCompactThreshold beats: about every six hours, per
// host.
//
// The defect lived only BETWEEN two durable states, so this test looks at
// every one of them. SetBeatDurableCheckpoint fires after each fsync; each
// snapshot is copied aside and reopened as a fresh process would, and the
// sequence it yields must be strictly greater than the one the beat that
// triggered the compaction already used. A test that only compared the file
// before and after would have found nothing wrong with either.
//
// Mutation verified: restoring the truncate-then-rewrite compaction fails
// this with "checkpoint 0 (8 bytes) hands out sequence 1, at or below the 361
// already sent" — the header-only file, caught at the one instant it exists.
func TestAgent_Beater_CompactionNeverLosesTheSequence(t *testing.T) {
	host, err := identity.Generate("host")
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}
	dir := t.TempDir()
	statePath := filepath.Join(dir, "beat.state")

	// Exactly at the threshold, so the very next beat compacts — under the
	// ordering this file uses now (append, then compact) and under the
	// truncate-first ordering it replaced, which is what makes the mutation
	// below reach the same code path rather than a different one.
	const staged = agent.BeatStateCompactThreshold
	const beatSequence = staged + 1
	data := beatStateHeaderBytes()
	for i := uint64(1); i <= staged; i++ {
		data = appendBeatStateRecord(data, 0, i)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatalf("stage a nearly-full beat state: %v", err)
	}

	rec, srv := newBeatServer(t, host.Public().Signing)
	cfg := agent.BeatConfig{
		HubURL:    srv.URL,
		Signer:    host,
		StatePath: statePath,
		Interval:  time.Hour,
	}
	b, err := agent.NewBeater(cfg, func() attest.Body { return attest.Body{} })
	if err != nil {
		t.Fatalf("NewBeater: %v", err)
	}

	// Every state the file is fsynced into during the beat below.
	var snapshots [][]byte
	agent.SetBeatDurableCheckpoint(func(path string) {
		raw, rerr := os.ReadFile(path) //nolint:gosec // the path is this test's own temp file
		if rerr != nil {
			t.Errorf("read the state file at a durable checkpoint: %v", rerr)
			return
		}
		snapshots = append(snapshots, raw)
	})
	t.Cleanup(func() { agent.SetBeatDurableCheckpoint(nil) })

	if err := b.BeatOnce(context.Background()); err != nil {
		t.Fatalf("the compacting beat: %v", err)
	}
	agent.SetBeatDurableCheckpoint(nil)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sent := rec.all()
	if len(sent) != 1 || sent[0].Sequence != beatSequence {
		t.Fatalf("the compacting beat carried %+v, want one beat at sequence %d", sent, beatSequence)
	}
	if len(snapshots) < 2 {
		t.Fatalf("compaction produced %d durable checkpoints; with fewer than two, this test cannot "+
			"be observing an intermediate state at all", len(snapshots))
	}
	// And it really did compact, or the intermediate states below are not the
	// ones a compaction passes through.
	final, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat the compacted state: %v", err)
	}
	if want := int64(testBeatStateHeaderLen + testBeatStateRecordLen); final.Size() != want {
		t.Fatalf("state file is %d bytes after the threshold beat, want %d: it was not compacted",
			final.Size(), want)
	}

	for i, snap := range snapshots {
		path := filepath.Join(t.TempDir(), "crashed.state")
		if err := os.WriteFile(path, snap, 0o600); err != nil {
			t.Fatalf("stage checkpoint %d: %v", i, err)
		}
		crashCfg := cfg
		crashCfg.StatePath = path
		resumed, err := agent.NewBeater(crashCfg, func() attest.Body { return attest.Body{} })
		if err != nil {
			t.Fatalf("checkpoint %d (%d bytes) cannot be reopened at all: %v", i, len(snap), err)
		}
		if err := resumed.BeatOnce(context.Background()); err != nil {
			_ = resumed.Close()
			t.Fatalf("checkpoint %d: the beat after reopening failed: %v", i, err)
		}
		all := rec.all()
		got := all[len(all)-1].Sequence
		_ = resumed.Close()
		if got <= beatSequence {
			t.Fatalf("checkpoint %d (%d bytes) hands out sequence %d, at or below the %d already "+
				"sent. The hub refuses every sequence at or below its high-water mark for the life "+
				"of the epoch, and the signed epoch bump is Phase B — so this host's heartbeat is "+
				"dead until someone notices, and it looks exactly like an unreachable hub",
				i, len(snap), got, beatSequence)
		}
	}
}

// A hub that is unreachable and a hub that answers and refuses are two
// different faults, and an operator acts on them differently: the first is a
// network or a stopped service, the second is a beat the hub will not take —
// which within an epoch means a sequence at or below its high-water mark,
// exactly the condition the durable state file exists to prevent and the one
// an operator has to be able to see when it happens anyway.
//
// internal/metrics documented "rejected" as a distinct reason and nothing
// emitted it; every failure came out as "send_failed".
//
// Both rows run against the SAME Beater code path with only the hub's
// behaviour differing, so the label is the only thing that can distinguish
// them here.
//
// Mutation verified: dropping the errHubRefused branch from BeatOnce turns the
// refusing row back into send_failed and fails it.
func TestAgent_Beater_DistinguishesARefusingHubFromAnUnreachableOne(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rejected", http.StatusBadRequest)
	}))
	t.Cleanup(refusing.Close)

	for _, tc := range []struct {
		name   string
		hubURL string
		want   string
	}{
		{"hub is not listening", "http://127.0.0.1:1", "send_failed"},
		{"hub answers and refuses", refusing.URL, "rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, err := identity.Generate("host")
			if err != nil {
				t.Fatalf("generate host signer: %v", err)
			}
			rec := metrics.New()
			b, err := agent.NewBeater(agent.BeatConfig{
				HubURL:    tc.hubURL,
				Signer:    host,
				StatePath: filepath.Join(t.TempDir(), "beat.state"),
				Interval:  time.Hour,
				Metrics:   rec,
			}, func() attest.Body { return attest.Body{} })
			if err != nil {
				t.Fatalf("NewBeater: %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })

			if err := b.BeatOnce(context.Background()); err == nil {
				t.Fatal("BeatOnce() = nil against a hub that cannot accept this beat")
			}

			body := scrapeRecorder(t, rec)
			want := `postern_heartbeat_rejections_total{reason="` + tc.want + `"} 1`
			if !strings.Contains(body, want) {
				t.Fatalf("no %s in the exposition; an operator cannot tell a hub that is down from one "+
					"that is refusing this host's beats\n--- scrape ---\n%s", want, body)
			}
		})
	}
}

// scrapeRecorder renders a Recorder's exposition text.
func scrapeRecorder(t *testing.T, r *metrics.Recorder) string {
	t.Helper()
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("scrape returned %d, want 200", w.Code)
	}
	return w.Body.String()
}
