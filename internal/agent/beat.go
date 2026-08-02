//go:build unix

package agent

// This file is the agent's other half of M2's fleet plane: emit this host's
// own signed heartbeat to the hub on an interval. It is Puller's sibling —
// same shape, own goroutine, own timeout, no lock held across a request,
// rate-limited error logging — because the split-plane invariant runs both
// directions. Section 1's promise is that the hub is a management
// convenience, never a dependency the packet path can be made to wait on; a
// beat that stalls, or a hub that never answers one, must never be able to
// slow or stop a knock any more than a stalled bundle fetch can. So: Run owns
// its own goroutine, shares no lock with the packet loop, and this file never
// imports internal/gate — the same reasoning pull.go's own doc comment gives,
// and for the same reason: a package that cannot reach the gate layer cannot
// be the one holding it hostage.
//
// Sequence must survive a process restart. internal/hub/beats.go rejects any
// (epoch, sequence) that is not strictly newer than the last one it recorded
// for this host_id, and within an epoch that means sequence must never go
// backwards. A Beater that started counting from zero on every restart would
// look, to the hub, exactly like a replay of an already-accepted beat —
// rejected for the entire remaining life of that epoch, which is the one
// failure epoch exists to make recoverable, and only because a real reset is
// a signed action a bundle signer takes (Phase B; not built here). So the
// state kept beside the replay store is not an optimisation: without it,
// the ordinary act of restarting posternd would reproduce the exact failure
// this mechanism exists to survive.
//
// This file carries //go:build unix for the same reason internal/replay does:
// the durable state file below takes an exclusive advisory lock (flock) so a
// systemd restart race — or a second process pointed at the same state file —
// fails loudly rather than silently maintaining two independent sequence
// counters against one host identity. Both platforms this project ships for,
// Linux (the agent) and macOS (the client binary that merely links this
// package), satisfy "unix", so this is not a narrowing of what actually ships.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/metrics"
)

// DefaultBeatInterval is how often a Beater sends when BeatConfig.Interval is
// zero. Design section 8: "every 60 seconds".
const DefaultBeatInterval = 60 * time.Second

// DefaultBeatTimeout bounds one send — connect, headers, and body — when
// BeatConfig.Timeout is zero. Short for the same reason DefaultPullTimeout
// is: a hub that cannot answer a POST within a few seconds is not a hub a
// longer timeout will fix, and every second this does not cover is a second
// a slow-loris hub can hold this goroutine's connection open for instead.
const DefaultBeatTimeout = 10 * time.Second

// maxBeatResponseBytes bounds what one send will read out of the hub's
// response body. A successful heartbeat answers 204 with an empty body; this
// exists only so a hostile or merely confused hub cannot make this goroutine
// buffer an unbounded reply.
const maxBeatResponseBytes = 4096

// BeatConfig configures a Beater. Every field is read once, at NewBeater, and
// never mutated afterward.
type BeatConfig struct {
	// HubURL is the hub's base address. The heartbeat path (design section 6:
	// POST /heartbeat) is appended by NewBeater itself.
	HubURL string
	// FleetID and HostID are this host's own identity, exactly as recorded in
	// its local standalone configuration — the same values PullConfig carries
	// them under, and for the same reason: neither can be learned from
	// anything the hub sends, because nothing sent by the hub is trusted
	// enough to name this host to itself.
	FleetID [16]byte
	HostID  [16]byte

	// Interval is how often to beat. Zero selects DefaultBeatInterval.
	Interval time.Duration
	// Jitter is a fraction of Interval, 0.1 meaning +/-10%, applied to every
	// sleep so a fleet restarted together does not synchronise into a
	// thundering herd against the one component with a public address. Zero
	// disables jitter entirely, which is what a test wants for a deterministic
	// cadence and is never the production default.
	Jitter float64
	// Timeout bounds one send's connect, header read, and body read combined.
	// Zero selects DefaultBeatTimeout.
	Timeout time.Duration

	// Signer signs every beat: this host's own signing identity, established
	// at enrollment. attest.Verify on the hub checks against exactly this
	// key, read out of index.json — the file `postern sign` writes alongside
	// every bundle.
	Signer identity.Signer

	// StatePath is where this Beater's (epoch, sequence) persists, so a
	// restart resumes counting rather than resetting to zero. See this
	// file's own doc comment. Required.
	StatePath string

	// Metrics receives every rejection and every accepted send. Nil means no
	// metrics are recorded; every Recorder method is nil-safe.
	Metrics *metrics.Recorder
	// Logger receives at most one line per rejection per Interval — see
	// reject — and one line per accepted send at Debug. Nil selects a text
	// handler on os.Stderr.
	Logger *slog.Logger
	// Now defaults to time.Now. Tests use it to make the log-throttling
	// window and the jitter band deterministic.
	Now func() time.Time
}

// Beater emits this host's signed heartbeat to the hub on an interval. It
// never touches the running policy and is never in a position to: everything
// it sends comes from the collect closure NewBeater is given, which the
// daemon supplies as a read of its own state, taken under lock for no longer
// than the read itself.
type Beater struct {
	cfg      BeatConfig
	collect  func() attest.Body
	interval time.Duration
	// logWindow is how long one rejection log line suppresses the next, a
	// multiple of interval rather than interval itself. See
	// rejectLogWindowFactor in pull.go.
	logWindow time.Duration
	timeout   time.Duration
	url       string
	client    *http.Client
	now       func() time.Time
	log       *slog.Logger
	state     *beatState

	// logMu serialises the log-throttling state below, separate from
	// anything the daemon owns because this package must not share a lock
	// with the packet path.
	logMu     sync.Mutex
	lastLogAt time.Time

	attempts   atomic.Uint64
	rejections atomic.Uint64
	sent       atomic.Uint64
}

// BeatStats are the counters an operator or a test can read without depending
// on log lines, which are throttled (see reject).
type BeatStats struct {
	Attempts   uint64
	Rejections uint64
	Sent       uint64
}

// NewBeater builds a Beater. collect is called fresh on every BeatOnce, with
// no lock held across the call by this package — the daemon's own closure
// takes whatever lock it needs only for the instant of the read, the same
// discipline pull.go's injected apply follows for the opposite direction.
// NewBeater does not call collect or send anything; the first send happens
// from Run or from an explicit BeatOnce.
func NewBeater(cfg BeatConfig, collect func() attest.Body) (*Beater, error) {
	if cfg.HubURL == "" {
		return nil, errors.New("agent: BeatConfig.HubURL is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("agent: BeatConfig.Signer is required")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("agent: BeatConfig.StatePath is required; without it a restart " +
			"would reset sequence to zero, which the hub would reject forever")
	}
	if collect == nil {
		return nil, errors.New("agent: collect is required")
	}
	if cfg.Jitter < 0 || cfg.Jitter >= 1 {
		return nil, fmt.Errorf("agent: BeatConfig.Jitter must be in [0, 1), got %v", cfg.Jitter)
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultBeatInterval
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultBeatTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	state, err := openBeatState(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("agent: open beat state: %w", err)
	}

	return &Beater{
		cfg:       cfg,
		collect:   collect,
		interval:  interval,
		logWindow: interval * rejectLogWindowFactor,
		timeout:   timeout,
		url:       strings.TrimRight(cfg.HubURL, "/") + "/heartbeat",
		// DisableKeepAlives: unlike a bundle fetch, a beat carries a request
		// body, and a persistent connection abandoned mid-request by
		// Client.Timeout is not a connection worth pooling for reuse — this
		// also gives every Beater its own connection, rather than sharing
		// http.DefaultTransport's pool with anything else the process builds
		// one of.
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}},
		now:    now,
		log:    log,
		state:  state,
	}, nil
}

// Run beats immediately, then sleeps a jittered Interval between further
// attempts until ctx is done. Like Puller.Run, it never returns a value:
// every outcome is already recorded through Metrics and logged through
// reject.
func (b *Beater) Run(ctx context.Context) {
	for {
		_ = b.BeatOnce(ctx)

		select {
		case <-ctx.Done():
			return
		case <-time.After(b.jitteredInterval()):
		}
	}
}

// BeatOnce sends one heartbeat: it advances and durably persists this
// process's (epoch, sequence) BEFORE building the record, so a crash between
// persisting and sending never reuses a sequence a restart could resend —
// the same "commit before the caller applies any effect" discipline
// internal/replay's Reserve follows, applied here to a send instead of a
// firewall write.
func (b *Beater) BeatOnce(ctx context.Context) error {
	b.attempts.Add(1)

	epoch, sequence, err := b.state.next()
	if err != nil {
		return b.reject("state_failed", fmt.Errorf("agent: advance beat sequence: %w", err))
	}

	beat := &attest.Beat{
		FleetID:  b.cfg.FleetID,
		HostID:   b.cfg.HostID,
		Epoch:    epoch,
		Sequence: sequence,
		SentAt:   b.now(),
		Body:     b.collect(),
	}
	data, err := attest.Encode(beat, b.cfg.Signer)
	if err != nil {
		return b.reject("send_failed", fmt.Errorf("agent: encode beat: %w", err))
	}
	if err := b.send(ctx, data); err != nil {
		// Two different conditions, two different labels, and an operator
		// cannot act on them the same way: send_failed is the hub being
		// unreachable, rejected is the hub answering and refusing. The second
		// is what a sequence that has gone backwards looks like from here —
		// exactly the diagnostic the durable state file exists to make
		// unnecessary and the one an operator needs when it has failed
		// anyway. internal/metrics documented "rejected" as a distinct reason
		// and nothing emitted it.
		reason := "send_failed"
		if errors.Is(err, errHubRefused) {
			reason = "rejected"
		}
		return b.reject(reason, fmt.Errorf("agent: send beat to %s: %w", b.url, err))
	}

	b.sent.Add(1)
	b.cfg.Metrics.HeartbeatSent()
	b.log.Debug("sent heartbeat", "epoch", epoch, "sequence", sequence)
	return nil
}

// send posts one signed beat record. An explicit Timeout on the client
// (connect, headers, and body together), ctx propagated onto the request so
// the caller's own cancellation aborts an in-flight send, and a capped
// reader on the response so a hostile or merely enormous reply is truncated
// rather than read in full — the same defenses pull.go's fetch applies to
// the opposite direction.
func (b *Beater) send(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBeatResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%w: %s", errHubRefused, resp.Status)
	}
	return nil
}

// errHubRefused means the hub answered and did not accept the beat, as
// opposed to not answering at all. See BeatOnce for why the two are labelled
// differently.
var errHubRefused = errors.New("hub refused the beat")

// reject counts a rejection, logs it at most once per logWindow, and returns
// err — the same throttling reject in pull.go performs, for the same reason:
// a hub down for a month must not write a month of identical lines. The
// window is a multiple of Interval rather than Interval itself; see
// rejectLogWindowFactor for the arithmetic, and for what the old
// window-equals-interval version actually produced.
func (b *Beater) reject(reason string, err error) error {
	b.rejections.Add(1)
	b.cfg.Metrics.HeartbeatRejected(reason)

	now := b.now()
	b.logMu.Lock()
	throttled := !b.lastLogAt.IsZero() && now.Sub(b.lastLogAt) < b.logWindow
	if !throttled {
		b.lastLogAt = now
	}
	b.logMu.Unlock()

	if !throttled {
		b.log.Warn("heartbeat rejected", "reason", reason, "err", err)
	}
	return err
}

// Stats reports this Beater's counters since construction.
func (b *Beater) Stats() BeatStats {
	return BeatStats{
		Attempts:   b.attempts.Load(),
		Rejections: b.rejections.Load(),
		Sent:       b.sent.Load(),
	}
}

// Close releases the durable state file. It does not stop Run; the caller's
// ctx does that.
//
// Call it once, and only once Run has returned. It takes the same mutex the
// state file holds across its fsync, so a Close underneath a running loop
// either closes the descriptor out from under the next beat's write or
// blocks for as long as that fsync does. Daemon.shutdown honours this by
// waiting for the beat loop first and skipping Close outright when that loop
// did not stop.
func (b *Beater) Close() error {
	return b.state.Close()
}

// jitteredInterval mirrors Puller.jitteredInterval exactly: Interval scaled
// by a uniform factor in [1-Jitter, 1+Jitter), or Interval exactly when
// Jitter is zero.
func (b *Beater) jitteredInterval() time.Duration {
	if b.cfg.Jitter <= 0 {
		return b.interval
	}
	//nolint:gosec // G404: this spreads sleep timing across a fleet, not a security
	// decision; a predictable jitter value gives an attacker nothing to exploit.
	factor := 1 + b.cfg.Jitter*(2*rand.Float64()-1)
	return time.Duration(float64(b.interval) * factor)
}

// --- durable (epoch, sequence) state ---------------------------------------

// beatStateMagic and beatStateFormatVersion open the persisted state file the
// same way internal/replay/log.go opens its own: a fixed magic value and a
// format version at the front, so a file too short or short a different
// format is rejected outright rather than silently treated as empty. Treating
// a corrupt file as empty here would mean starting sequence over from zero —
// exactly the failure this whole file exists to prevent — so "reject" and
// "start fresh" must never be the same code path.
var beatStateMagic = [4]byte{'P', 'B', 'S', 'T'}

const (
	beatStateHeaderLen     = 8  // magic(4) + version(1) + reserved(3)
	beatStateRecordLen     = 16 // epoch(8) + sequence(8), big-endian
	beatStateFormatVersion = 1

	// beatStateCompactThreshold bounds how many records this file's own
	// append-only log accumulates before it is rewritten down to just the
	// current one. Every record after the first is dead as soon as it is
	// written — only the last ever matters — so letting the file grow
	// forever would cost disk for no benefit; at 60s beats that is roughly 6
	// hours of records before one compaction, a cost paid once in a while
	// rather than an unbounded file.
	beatStateCompactThreshold = 360
)

// beatDurableCheckpoint, when non-nil, is called with the state file's path
// immediately after every fsync this file performs — that is, at every point
// the file has been committed to disk in a state a crash could leave behind.
//
// It exists for one property, and the property is the whole reason
// compactLocked is shaped the way it is: reopening the file at ANY durable
// checkpoint must yield a sequence no lower than the last one already handed
// to a beat. A test that could only observe the file before and after a
// compaction would have missed the defect entirely, because the defect lived
// only in between. Set through export_test.go; nil in production.
var (
	beatCheckpointMu sync.Mutex
	beatCheckpoint   func(path string)
)

// syncLocked fsyncs the state file and announces the durable state it just
// created. Every write path here goes through it rather than calling Sync
// directly, so a checkpoint cannot be forgotten by a future edit that adds
// another one.
func (s *beatState) syncLocked() error {
	if err := s.f.Sync(); err != nil {
		return err
	}
	beatCheckpointMu.Lock()
	hook := beatCheckpoint
	beatCheckpointMu.Unlock()
	if hook != nil {
		hook(s.f.Name())
	}
	return nil
}

// beatState persists a Beater's (epoch, sequence) pair beside the replay
// store, following internal/replay's own durable-write discipline rather
// than inventing a second one: an exclusive, non-blocking flock so two
// processes never maintain two independent counters against the same host
// identity, a magic-and-version header, and a value committed to disk,
// fsynced, before it is ever used to build the beat that will carry it —
// mirroring replay.Store.Reserve committing before its caller applies any
// effect.
type beatState struct {
	// mu guards every field below, including the file handle. next is this
	// type's whole reason to exist — deciding, durably, the next sequence
	// this process may use — so two calls racing on the same in-memory
	// counter could both compute the same "next" value before either
	// persisted it, which is a sequence reused across two beats.
	mu       sync.Mutex
	f        *os.File
	epoch    uint64
	sequence uint64
	// haveRecord is false only before this state has ever persisted a
	// record — the state a freshly enrolled host's first beat ever finds,
	// distinct from "sequence happens to be zero" after a real record has
	// been read back.
	haveRecord bool
	// records counts how many records are in the file's append-only log
	// since the last compaction, to decide when compactLocked runs.
	records int
}

// openBeatState loads or creates the state file at path.
func openBeatState(path string) (*beatState, error) {
	// path is BeatConfig.StatePath, set by this host's own root-owned CLI
	// wiring beside the replay store's path — the identical trust boundary
	// internal/replay's own G304 exclusion covers, never anything derived
	// from a fetched bundle or a hub response.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304
	if err != nil {
		return nil, fmt.Errorf("agent: open beat state %s: %w", path, err)
	}
	// Exclusive, non-blocking, tied to this file descriptor's open file
	// description: it releases automatically on Close or an unclean exit, no
	// separate unlock path to get wrong. See internal/replay/log.go's Open
	// for the identical reasoning, applied to the identical failure mode: a
	// systemd restart race producing two openers with independent in-memory
	// sequence counters, either of which could then send a beat carrying a
	// sequence the other one already used.
	//nolint:gosec // G115: Fd() is a small, non-negative OS file descriptor number.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("agent: beat state %s is already open by another process: %w", path, err)
	}

	s := &beatState{f: f}
	if err := s.load(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

func (s *beatState) load() error {
	info, err := s.f.Stat()
	if err != nil {
		return fmt.Errorf("agent: stat beat state: %w", err)
	}
	if info.Size() == 0 {
		return s.writeHeader()
	}
	if err := s.readHeader(); err != nil {
		return err
	}
	if _, err := s.f.Seek(beatStateHeaderLen, io.SeekStart); err != nil {
		return fmt.Errorf("agent: seek past beat state header: %w", err)
	}

	buf := make([]byte, beatStateRecordLen)
	for {
		_, err := io.ReadFull(s.f, buf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// A torn tail record from a crash mid-write. Everything before it
			// is intact; truncate to the last whole record and carry on —
			// the identical recovery internal/replay/log.go's load performs.
			off, serr := s.f.Seek(0, io.SeekCurrent)
			if serr != nil {
				return fmt.Errorf("agent: seek after torn beat record: %w", serr)
			}
			whole := beatStateHeaderLen + ((off-beatStateHeaderLen)/beatStateRecordLen)*beatStateRecordLen
			if err := s.f.Truncate(whole); err != nil {
				return fmt.Errorf("agent: truncate torn beat record: %w", err)
			}
			if _, err := s.f.Seek(whole, io.SeekStart); err != nil {
				return fmt.Errorf("agent: seek to truncated end: %w", err)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("agent: read beat record: %w", err)
		}
		s.epoch = binary.BigEndian.Uint64(buf[0:8])
		s.sequence = binary.BigEndian.Uint64(buf[8:16])
		s.haveRecord = true
		s.records++
	}
}

// writeHeader stamps a brand-new state file with the magic value and format
// version, syncs it durably, and leaves the file offset positioned right
// after the header for the first record append.
func (s *beatState) writeHeader() error {
	var buf [beatStateHeaderLen]byte
	copy(buf[0:4], beatStateMagic[:])
	buf[4] = beatStateFormatVersion
	if _, err := s.f.WriteAt(buf[:], 0); err != nil {
		return fmt.Errorf("agent: write beat state header: %w", err)
	}
	if err := s.syncLocked(); err != nil {
		return fmt.Errorf("agent: sync beat state header: %w", err)
	}
	if _, err := s.f.Seek(beatStateHeaderLen, io.SeekStart); err != nil {
		return fmt.Errorf("agent: seek past beat state header: %w", err)
	}
	return nil
}

// readHeader verifies an existing file's header without moving the file
// offset, rejecting the file outright — rather than silently truncating it
// back to empty, which would reopen the exact sequence-reset failure this
// file exists to close — whenever it is too short, does not start with the
// expected magic, or declares a format version this build does not
// understand.
func (s *beatState) readHeader() error {
	buf := make([]byte, beatStateHeaderLen)
	if _, err := s.f.ReadAt(buf, 0); err != nil {
		return fmt.Errorf("agent: beat state file is too short to contain a valid %d-byte header: %w",
			beatStateHeaderLen, err)
	}
	if !bytes.Equal(buf[0:4], beatStateMagic[:]) {
		return errors.New("agent: beat state file does not start with the expected magic value; " +
			"refusing to treat an unrecognized file as an empty one")
	}
	if buf[4] != beatStateFormatVersion {
		return fmt.Errorf("agent: beat state file format version %d is not supported by this build (want %d)",
			buf[4], beatStateFormatVersion)
	}
	return nil
}

// next durably records the (epoch, sequence) the next beat will carry and
// returns it. The first call this state has ever made — nothing on disk yet,
// haveRecord false — returns (0, 1): epoch 0 is what every host starts at
// (Phase B's signed epoch bump is the only way that ever changes, and it is
// not built here), and sequence begins at 1 so a freshly enrolled host's
// first beat is already strictly greater than the hub's "nothing recorded
// yet" starting point. Every later call returns the same epoch with sequence
// advanced by exactly one.
//
// The write lands on disk, fsynced, before this function returns, so a crash
// between this call and the beat actually being sent leaves nothing to redo:
// the next process to open this file resumes from a sequence already at
// least this high, never lower — which is what makes a restart survive
// rather than reset.
func (s *beatState) next() (epoch, sequence uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	epoch = s.epoch
	sequence = s.sequence + 1
	if !s.haveRecord {
		sequence = 1
	}

	if err := s.appendLocked(epoch, sequence); err != nil {
		return 0, 0, err
	}
	s.epoch = epoch
	s.sequence = sequence
	s.haveRecord = true
	return epoch, sequence, nil
}

// appendLocked commits one (epoch, sequence) to disk, and compacts afterward
// rather than instead.
//
// The ordering is the crash-safety property. The record is appended and
// fsynced FIRST, so it is durable at the end of the file before anything else
// moves; compaction then copies those same bytes down over the first record
// and truncates. At every instant, from the moment the append lands, the last
// whole record in the file is either the previously recorded pair or this
// one — never anything older — which is exactly what load reads back.
func (s *beatState) appendLocked(epoch, sequence uint64) error {
	var buf [beatStateRecordLen]byte
	binary.BigEndian.PutUint64(buf[0:8], epoch)
	binary.BigEndian.PutUint64(buf[8:16], sequence)
	if _, err := s.f.Write(buf[:]); err != nil {
		return fmt.Errorf("agent: write beat record: %w", err)
	}
	if err := s.syncLocked(); err != nil {
		return fmt.Errorf("agent: sync beat record: %w", err)
	}
	s.records++
	if s.records >= beatStateCompactThreshold {
		return s.compactLocked(buf)
	}
	return nil
}

// compactLocked rewrites the file down to the header and the one record that
// was just appended and fsynced. Every earlier record is already dead — load
// only ever reads the last one back — so this loses nothing a restart could
// need.
//
// It replaced a truncate-then-rewrite, which was not crash-safe and failed in
// the one direction this file cannot tolerate. That version did Truncate(0),
// then writeHeader, then wrote the record; a crash anywhere in between left a
// header-only file, load found no records, haveRecord stayed false, and next
// returned sequence 1 — while hub.Beats.Accept goes on rejecting every
// sequence at or below the high-water mark for the life of the epoch, and the
// signed epoch bump is Phase B. The host's heartbeat would be permanently
// dead while looking identical to an unreachable hub, and the window opened
// every 360 beats: roughly every six hours, per host.
//
// Copy-down-then-truncate has no such window, and it is chosen over the other
// ordinary answer — write beside and rename — because this file's exclusive
// flock is held on the open file description. A rename would leave the lock
// protecting an unlinked inode, and a second process could then flock the new
// path and maintain an independent sequence counter against the same host
// identity, which is the failure the lock exists to prevent.
func (s *beatState) compactLocked(rec [beatStateRecordLen]byte) error {
	if _, err := s.f.WriteAt(rec[:], beatStateHeaderLen); err != nil {
		return fmt.Errorf("agent: write beat record for compaction: %w", err)
	}
	if err := s.syncLocked(); err != nil {
		return fmt.Errorf("agent: sync beat state before compaction truncates: %w", err)
	}
	if err := s.f.Truncate(beatStateHeaderLen + beatStateRecordLen); err != nil {
		return fmt.Errorf("agent: truncate beat state for compaction: %w", err)
	}
	if err := s.syncLocked(); err != nil {
		return fmt.Errorf("agent: sync beat state after compaction: %w", err)
	}
	// WriteAt does not move the offset and Truncate leaves it past the new
	// end, so the next append would write into a hole. Put it back on the end.
	if _, err := s.f.Seek(beatStateHeaderLen+beatStateRecordLen, io.SeekStart); err != nil {
		return fmt.Errorf("agent: seek to the compacted end: %w", err)
	}
	s.records = 1
	return nil
}

// Close flushes and releases the state file.
func (s *beatState) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		return fmt.Errorf("agent: sync beat state on close: %w", err)
	}
	return s.f.Close()
}
