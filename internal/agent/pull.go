package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
	"time"

	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/metrics"
)

// This file is the agent's half of M2 fleet mode: fetch this host's own
// sealed bundle, verify it, and apply it or keep the last good policy
// running. It is the ONE file in this package that talks to the hub, and the
// invariant it exists to prove is that talking to the hub is optional in the
// same sense a mesh VPN is optional — the hub is a management convenience,
// and design section 1 exists to remove exactly this kind of external
// control-plane dependency from the packet path. If a pull failure, or a
// slow one, could stop a knock, postern would have reintroduced it.
//
// So: Run owns its own goroutine, and nothing in this file — not the fetch,
// not the verify, not the parse — ever touches a lock the packet loop takes.
// The locks declared below are this Puller's own and nothing else takes them.
// apply is injected, so this file never reaches for gate.Gate or Daemon
// internals itself and never imports internal/gate: a hub that accepts a
// connection and never answers must not be able to hold anything a knock
// needs, and a package that cannot import the gate layer cannot be the one
// holding it.
//
// One qualification, stated here rather than left to be discovered. The
// injected apply DOES share a lock with the packet loop, for the length of the
// arm it performs: Transactions' own mutex, held across `nft -f` and two
// `systemctl enable`, is the same mutex a dead-man check or a confirm or
// disarm packet takes. That is not this file's to fix and it is not a hub's to
// trigger — apply runs only after a bundle has been verified against a
// locally-configured signer, and only after the fetch has entirely finished —
// but the claim "shares no lock with the packet loop" was false of the whole
// pull path, and this comment used to make it. See Transactions' doc for why
// that one cannot be narrowed and what bounds it.

// DefaultPullInterval is how often a Puller fetches when PullConfig.Interval
// is zero.
const DefaultPullInterval = 300 * time.Second

// DefaultPullTimeout bounds one fetch — connect, headers, and body — when
// PullConfig.Timeout is zero. It is deliberately far shorter than the pull
// interval: a hub that cannot answer within ten seconds is not a hub a
// ten-second stall against will fix, and every second this Timeout does not
// cover is a second a slow-loris hub can hold a goroutine open for instead.
const DefaultPullTimeout = 10 * time.Second

// rejectLogWindowFactor multiplies a loop's own interval to get the window
// its rejection logging is throttled to.
//
// It exists because the window used to BE the interval, which throttled
// nothing in production. Every sleep between attempts is jittered, so roughly
// half of them come out longer than the nominal interval and the very next
// rejection is outside the window — a hub down for a month wrote most of a
// month of identical lines, about 43,000 of them for the 60-second heartbeat
// loop, while both doc comments claimed the opposite. The unit test that
// "proved" the throttle drove two calls at the same instant, a state the loop
// never produces.
//
// Twenty is chosen against what it leaves behind rather than for roundness:
// one line per 20 minutes for the 60s beat loop and one per 100 minutes for
// the 300s pull loop, so a fault that lasts a month leaves a couple of
// thousand lines and a couple of hundred respectively — enough to see when it
// started and that it never stopped, few enough that the journal still holds
// everything else. The counters move on every rejection regardless, and they
// are what an alert reads.
const rejectLogWindowFactor = 20

// maxBundleResponseBytes bounds what a single fetch will read into memory,
// regardless of what Content-Length claims or how the hub paces its bytes.
// It sits comfortably above what a legitimate bundle can ever be —
// bundle.MaxPolicyLen (1 MiB) plus the fixed record header, signer key,
// signature, and box overhead — while still being a small, fixed cost against
// a hub that decides to stream gigabytes: an io.LimitReader alone does not
// need Content-Length to be honest, because it never asks.
const maxBundleResponseBytes = 2 << 20 // 2 MiB

// PullConfig configures a Puller. Every field here is read once, at
// NewPuller, and never mutated afterward — in particular, HubURL,
// TrustedSigners and EnrollmentFloor come from this host's own local,
// root-owned configuration and are never taken from a fetched bundle, or a
// compromised hub could redirect a host to fetch from somewhere else, or
// expand its own trusted signer set, simply by answering a request.
type PullConfig struct {
	// HubURL is the hub's base address, e.g. "https://hub.example.com". The
	// per-host path (design section 6: GET /bundle/<host_id_hex>) is appended
	// by the Puller itself from HostID.
	HubURL string
	// FleetID and HostID are this host's own identity, exactly as recorded in
	// its local standalone configuration. They are what AcceptCriteria checks
	// a fetched bundle's claimed fleet_id and host_id against — see
	// bundle.Open — and HostID is also what names this host's bundle in the
	// URL, so both must be known before the very first fetch is ever made;
	// neither can be learned from a bundle, because a bundle cannot be
	// verified until they are already known.
	FleetID [16]byte
	HostID  [16]byte

	// Interval is how often to pull. Zero selects DefaultPullInterval.
	Interval time.Duration
	// Jitter is a fraction of Interval, 0.1 meaning +/-10%, applied to every
	// sleep between attempts so a fleet restarted together does not
	// synchronise into a thundering herd against the one component with a
	// public address. Zero disables jitter entirely (every sleep is exactly
	// Interval), which is never the production default but is what a test
	// wants when it needs a deterministic cadence.
	Jitter float64
	// Timeout bounds one fetch's connect, header read, and body read
	// combined. Zero selects DefaultPullTimeout.
	Timeout time.Duration

	// HostSigner unseals a fetched bundle: box.SealAnonymous names no
	// recipient, so opening is the only way to learn whether a ciphertext was
	// sealed to this host.
	HostSigner identity.Signer
	// TrustedSigners is the set of raw Ed25519 public keys (config's
	// bundle_signers) whose signature over a bundle this host accepts.
	TrustedSigners [][32]byte
	// EnrollmentFloor is the version stamped into this host's local
	// configuration at enrollment. See bundle.AcceptCriteria.EnrollmentFloor.
	EnrollmentFloor uint64
	// StatePath is where the version this host last applied is recorded, so
	// anti-rollback survives a restart. Required, for the same reason
	// BeatConfig.StatePath is.
	//
	// Without it the only durable guard is EnrollmentFloor, which is stamped
	// once and never advances — and Transactions.Commit deletes pending.json,
	// so a confirmed revision leaves nothing behind to block a lower one
	// either. A host on revision 48 with floor 47, freshly restarted, accepted
	// a validly-signed version-47 bundle and installed it. Anyone who can
	// serve /bundle/<host_id> — a compromised hub, a compromised origin, or
	// plain HTTP on the wire, since hub_url may be http:// — replays a
	// historical bundle and waits for a reboot. AcceptCriteria's own doc names
	// the threat: an old but validly-signed bundle, one still naming a
	// since-removed operator, replays cleanly.
	StatePath string

	// Metrics receives every rejection and every successful apply. Nil means
	// no metrics are recorded; every Recorder method is nil-safe.
	Metrics *metrics.Recorder
	// Logger receives at most one line per rejection per Interval — see
	// reject — and one line per successful apply. Nil selects a text handler
	// on os.Stderr.
	Logger *slog.Logger
	// Now defaults to time.Now. Tests use it to make the log-throttling
	// window and the jitter band deterministic.
	Now func() time.Time
}

// Puller fetches this host's own sealed bundle on an interval, verifies it,
// and applies it or leaves the running policy exactly as it was.
type Puller struct {
	cfg      PullConfig
	apply    func(*config.Policy) (bool, error)
	interval time.Duration
	// logWindow is how long one rejection log line suppresses the next. It is
	// a multiple of interval, never interval itself — see
	// rejectLogWindowFactor.
	logWindow time.Duration
	timeout   time.Duration
	url       string
	client    *http.Client
	now       func() time.Time
	log       *slog.Logger

	// versionMu guards the two fields below, which together are this
	// Puller's own view of "the version already accepted" — bundle.Open's
	// AcceptCriteria.CurrentVersion/HasCurrent. They are updated only after
	// apply has returned nil, in the same call that just verified and applied
	// the bundle carrying that version, so this Puller's notion of "current"
	// and the daemon's running policy move together.
	//
	// This mutex belongs to the Puller alone. Nothing on the packet path ever
	// takes it, and PullOnce never takes it while blocked on the fetch — it
	// is acquired only for the instant of reading or writing these two
	// fields, exactly the shape the injected apply closure uses for the
	// daemon's own lock.
	versionMu   sync.Mutex
	haveVersion bool
	version     uint64

	// logMu serialises the log-throttling state below. Separate from
	// versionMu because a rejection logs without touching version state and
	// vice versa, and separate from anything the daemon owns because this
	// package must not share a lock with the packet path.
	logMu     sync.Mutex
	lastLogAt time.Time

	// stateErr is set when the recorded-version file exists and could not be
	// read. It makes every PullOnce a refusal without a fetch — see PullOnce.
	stateErr error

	attempts   atomic.Uint64
	rejections atomic.Uint64
	applied    atomic.Uint64
}

// PullStats are the counters an operator or a test can read without
// depending on log lines, which are throttled (see reject).
type PullStats struct {
	Attempts   uint64
	Rejections uint64
	Applied    uint64
}

// NewPuller builds a Puller. apply is called with a fully verified, parsed,
// and validated Policy — never with anything unverified — and is expected to
// arm it through the same confirm-or-revert transaction a locally-driven
// change goes through. NewPuller does not call apply; the first call happens
// from Run or from an explicit PullOnce.
//
// apply reports whether it ACTUALLY armed the policy, separately from whether
// anything went wrong. The three outcomes are distinct and this Puller treats
// them differently: armed, refused-without-error (the revision was already
// pending or already reverted, so the host keeps what it is running), and
// failed. Collapsing the middle case into success made a refused re-arm
// increment postern_bundle_pull_applied_total, write "applied a fetched
// bundle" into the journal one line after "refusing to re-arm", and advance
// this Puller's own notion of the current version past a revision that was
// never installed — after which a corrected bundle re-issued at the same
// version is refused as not_newer.
func NewPuller(cfg PullConfig, apply func(*config.Policy) (bool, error)) (*Puller, error) {
	if cfg.HubURL == "" {
		return nil, errors.New("agent: PullConfig.HubURL is required")
	}
	if cfg.HostSigner == nil {
		return nil, errors.New("agent: PullConfig.HostSigner is required")
	}
	if len(cfg.TrustedSigners) == 0 {
		return nil, errors.New("agent: PullConfig.TrustedSigners is required; " +
			"a puller with no trusted signer can accept no bundle at all")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("agent: PullConfig.StatePath is required; without it the version this " +
			"host has applied lives only in memory, so a restart forgets it and any validly-signed " +
			"older bundle replays cleanly")
	}
	if apply == nil {
		return nil, errors.New("agent: apply is required")
	}
	if cfg.Jitter < 0 || cfg.Jitter >= 1 {
		return nil, fmt.Errorf("agent: PullConfig.Jitter must be in [0, 1), got %v", cfg.Jitter)
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultPullInterval
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultPullTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	p := &Puller{
		cfg:       cfg,
		apply:     apply,
		interval:  interval,
		logWindow: interval * rejectLogWindowFactor,
		timeout:   timeout,
		url:       strings.TrimRight(cfg.HubURL, "/") + "/bundle/" + hex.EncodeToString(cfg.HostID[:]),
		client:    &http.Client{Timeout: timeout},
		now:       now,
		log:       log,
	}
	// Seeded here rather than left to the first successful apply: this is the
	// whole point of the file. An absent file is a host that has applied
	// nothing, which is a legitimate state and the one a freshly enrolled host
	// is in — EnrollmentFloor is what guards that case.
	//
	// A file that exists and cannot be read is NOT treated as absent, for the
	// reason beatState refuses an unrecognised header: "reject" and "start
	// fresh" must never be the same code path when starting fresh is the
	// failure. It is remembered instead, and PullOnce refuses without
	// fetching — the control plane declines to act rather than acting on a
	// guard it cannot read, and nothing about the packet plane changes.
	version, have, err := readAppliedVersion(cfg.StatePath)
	switch {
	case err != nil:
		p.stateErr = err
		log.Error("the recorded bundle version could not be read, so this host cannot tell an older "+
			"bundle from a newer one; refusing to apply any bundle until it can",
			"path", cfg.StatePath, "err", err)
	case have:
		p.version = version
		p.haveVersion = true
		// Seed the gauge from the persisted record so it reads the running
		// version from the first scrape, before any pull, rather than only after
		// the next apply.
		p.cfg.Metrics.SetAppliedBundleVersion(version)
	}
	return p, nil
}

// appliedVersion is the on-disk anti-rollback record: the bundle version this
// host has actually installed. One field, JSON, beside the replay store and
// beat.state, written the same write-then-rename way every other artifact in
// this package is.
type appliedVersion struct {
	Version uint64 `json:"version"`
}

// readAppliedVersion reports the recorded version and whether there is one.
// An absent file is "none recorded" rather than version zero, because zero is
// a legal bundle version — the same distinction RecordedRevision draws.
func readAppliedVersion(path string) (uint64, bool, error) {
	b, err := readBlob(path)
	if err != nil {
		return 0, false, fmt.Errorf("agent: read %s: %w", path, err)
	}
	if !b.present {
		return 0, false, nil
	}
	var rec appliedVersion
	if err := json.Unmarshal(b.data, &rec); err != nil {
		return 0, false, fmt.Errorf("agent: parse %s: %w", path, err)
	}
	return rec.Version, true, nil
}

// writeAppliedVersion records the version now installed.
func writeAppliedVersion(path string, version uint64) error {
	data, err := json.MarshalIndent(appliedVersion{Version: version}, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode the applied bundle version: %w", err)
	}
	if err := writeBlob(path, blob{data: append(data, '\n'), present: true}, 0o600); err != nil {
		return fmt.Errorf("agent: write %s: %w", path, err)
	}
	return nil
}

// Run pulls immediately, then sleeps a jittered Interval between further
// attempts until ctx is done. It never returns a value: every outcome of
// PullOnce, success or rejection, is already recorded through Metrics and
// logged through reject, and a background loop returning nowhere is
// consistent with Daemon's other background goroutine, receiveLoop.
func (p *Puller) Run(ctx context.Context) {
	for {
		_ = p.PullOnce(ctx)

		select {
		case <-ctx.Done():
			return
		case <-time.After(p.jitteredInterval()):
		}
	}
}

// PullOnce fetches this host's bundle once, verifies it, and applies it or
// keeps the last good policy. Every rejection path returns a non-nil error
// but changes nothing this host is currently running: the running policy is
// only ever touched by apply, which is only ever called once every
// preceding check has already passed.
func (p *Puller) PullOnce(ctx context.Context) error {
	p.attempts.Add(1)

	// Before the fetch, not after: a host that cannot read its own
	// anti-rollback record has no way to tell a replayed bundle from a new
	// one, and fetching first would only mean discovering that later.
	if p.stateErr != nil {
		return p.reject("state_failed", fmt.Errorf(
			"agent: the recorded bundle version is unreadable, so an older bundle cannot be "+
				"distinguished from a newer one: %w", p.stateErr))
	}

	sealed, err := p.fetch(ctx)
	if err != nil {
		return p.reject("fetch_failed", fmt.Errorf("agent: fetch %s: %w", p.url, err))
	}

	criteria := bundle.AcceptCriteria{
		FleetID:         p.cfg.FleetID,
		HostID:          p.cfg.HostID,
		EnrollmentFloor: p.cfg.EnrollmentFloor,
	}
	p.versionMu.Lock()
	criteria.CurrentVersion = p.version
	criteria.HasCurrent = p.haveVersion
	p.versionMu.Unlock()

	contents, err := bundle.Open(sealed, p.cfg.HostSigner, p.cfg.TrustedSigners, criteria)
	if err != nil {
		return p.reject(bundleRejectReason(err), fmt.Errorf("agent: verify fetched bundle: %w", err))
	}

	policy, err := config.ParseStandalone(contents.Policy)
	if err != nil {
		return p.reject("parse_failed", fmt.Errorf("agent: parse fetched bundle's policy: %w", err))
	}
	if err := policy.Validate(); err != nil {
		return p.reject("validate_failed", fmt.Errorf("agent: fetched bundle's policy failed validation: %w", err))
	}
	// The policy body carries its own fleet_id and host_id, and until here
	// nothing checked them: bundle.Open validates the RECORD HEADER's pair,
	// and the two are separate fields under one signature. A signer that
	// compiled the wrong host's policy into the right host's record — a
	// mistake, not an attack, since forging either half needs the signing key
	// — would install another host's gates, ports and operator set here, and
	// the only symptom would be a config_hash nobody was comparing yet.
	// Two lines, and they make the record's own claim and the policy's agree.
	if policy.FleetID != p.cfg.FleetID {
		return p.reject("wrong_fleet", fmt.Errorf(
			"agent: fetched bundle's policy names fleet_id %x, this host is %x",
			policy.FleetID, p.cfg.FleetID))
	}
	if policy.HostID != p.cfg.HostID {
		return p.reject("wrong_host", fmt.Errorf(
			"agent: fetched bundle's policy names host_id %x, this host is %x",
			policy.HostID, p.cfg.HostID))
	}

	armed, err := p.apply(policy)
	if err != nil {
		return p.reject("apply_failed", fmt.Errorf("agent: apply fetched bundle: %w", err))
	}
	if !armed {
		// Verified, accepted, and deliberately not installed: the arm step
		// refused this revision because it was already tried and left pending
		// or reverted, and it has already logged and flagged standing. Nothing
		// is counted, nothing is logged as applied, and the version is NOT
		// advanced — a corrected bundle re-issued at this same version has to
		// remain acceptable, which it would not be if this recorded it.
		return p.reject("not_armed", fmt.Errorf(
			"agent: bundle version %d verified but the arm step declined to install it", contents.Version))
	}

	p.versionMu.Lock()
	p.version = contents.Version
	p.haveVersion = true
	p.versionMu.Unlock()

	// Counted before the record is written, so anything synchronising on
	// Stats().Applied observes the apply as soon as it has happened rather
	// than one file write later.
	p.applied.Add(1)
	p.cfg.Metrics.BundlePullApplied()
	p.cfg.Metrics.SetAppliedBundleVersion(contents.Version)

	// Recorded after the arm, never before: this file's meaning is "the
	// version this host has installed", and a record written ahead of the
	// install would refuse the very bundle that had not been installed yet.
	//
	// A write failure is logged rather than returned. The revision IS armed
	// and running, so reporting a rejection here would be the same false
	// signal I5 removed in the other direction; what is lost is durability of
	// the guard until the next successful apply, which leaves this host
	// exactly where it was before this record existed.
	if err := writeAppliedVersion(p.cfg.StatePath, contents.Version); err != nil {
		p.log.Error("could not record the applied bundle version, so a restart would no longer "+
			"recognise an older bundle as a rollback", "path", p.cfg.StatePath,
			"version", contents.Version, "err", err)
	}

	p.log.Info("applied a fetched bundle", "version", contents.Version)
	return nil
}

// fetch retrieves the sealed bytes on file for this host, with every defense
// design section 8's ledger and this task's brief name: an explicit Timeout
// on the client (connect, headers and body together), ctx propagated onto
// the request so the caller's own cancellation aborts an in-flight fetch, and
// a capped reader so a hostile or merely enormous response is truncated
// rather than exhausting memory — independently of Timeout, which a server
// pacing its bytes just slowly enough could otherwise ride out indefinitely.
func (p *Puller) fetch(ctx context.Context) (bundle.Sealed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	// Read one more byte than the cap allows, so exceeding it is
	// distinguishable from landing on it exactly.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(data) > maxBundleResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBundleResponseBytes)
	}
	return bundle.Sealed(data), nil
}

// reject counts a rejection, logs it at most once per logWindow, and returns
// err so PullOnce's callers get both a value to check and a side effect that
// never floods the journal. A hub down for a month must not write a month of
// identical lines — the unbounded-ERROR-log item the M1 ledger already
// recorded once — so the counter increments on every rejection,
// unconditionally, and the log line is the thing that is throttled.
//
// The window is a MULTIPLE of the interval rather than the interval itself,
// because jitter makes half of all sleeps longer than nominal and a window
// equal to the interval therefore suppresses almost nothing. See
// rejectLogWindowFactor.
func (p *Puller) reject(reason string, err error) error {
	p.rejections.Add(1)
	p.cfg.Metrics.BundlePullRejected(reason)

	now := p.now()
	p.logMu.Lock()
	throttled := !p.lastLogAt.IsZero() && now.Sub(p.lastLogAt) < p.logWindow
	if !throttled {
		p.lastLogAt = now
	}
	p.logMu.Unlock()

	if !throttled {
		p.log.Warn("bundle pull rejected", "reason", reason, "err", err)
	}
	return err
}

// Stats reports this Puller's counters since construction.
func (p *Puller) Stats() PullStats {
	return PullStats{
		Attempts:   p.attempts.Load(),
		Rejections: p.rejections.Load(),
		Applied:    p.applied.Load(),
	}
}

// jitteredInterval returns Interval scaled by a uniform factor in
// [1-Jitter, 1+Jitter). Jitter zero returns Interval exactly.
func (p *Puller) jitteredInterval() time.Duration {
	if p.cfg.Jitter <= 0 {
		return p.interval
	}
	//nolint:gosec // G404: this spreads sleep timing across a fleet, not a security
	// decision; a predictable jitter value gives an attacker nothing to exploit.
	factor := 1 + p.cfg.Jitter*(2*rand.Float64()-1)
	return time.Duration(float64(p.interval) * factor)
}

// bundleRejectReason maps a bundle.Open error onto the closed label set
// internal/metrics accepts, the same way rejectReason does for a Validate
// error on the packet path: a mapping onto a fixed enumeration, owned by the
// package that defines the sentinels, rather than a label derived from error
// text an attacker (or a compromised hub) could shape.
func bundleRejectReason(err error) string {
	switch {
	case errors.Is(err, bundle.ErrUnseal):
		return "unseal_failed"
	case errors.Is(err, bundle.ErrFormat):
		return "malformed"
	case errors.Is(err, bundle.ErrUntrustedSigner):
		return "untrusted_signer"
	case errors.Is(err, bundle.ErrBadSignature):
		return "bad_signature"
	case errors.Is(err, bundle.ErrWrongFleet):
		return "wrong_fleet"
	case errors.Is(err, bundle.ErrWrongHost):
		return "wrong_host"
	case errors.Is(err, bundle.ErrBelowFloor):
		return "below_floor"
	case errors.Is(err, bundle.ErrNotNewer):
		return "not_newer"
	default:
		return metrics.ReasonOther
	}
}
