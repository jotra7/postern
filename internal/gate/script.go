package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/childenv"
	"github.com/jotra7/postern/internal/config"
)

// The script contract. An operator-supplied executable is invoked with a verb
// and a fixed argument vector — never a shell, never an interpolated command
// line. The source prefix reaching it came out of a signed packet and is
// bounded by the operator's own grant, but it is still externally influenced
// and this runs as root, so it is passed as one argv element and nothing
// parses it on the way.
//
//	<script> open   <service> <source> <ttl-seconds> <observed|asserted>
//	<script> close  <service> <source>
//	<script> state  <service>
//	<script> health <service>
//
// <source> is always a CIDR in canonical form: a /32 or /128 for an observed
// address, the operator's asserted prefix otherwise. It is normalized first
// (see normalizeSource), so an IPv4-mapped IPv6 address never reaches a
// script wearing its v6 costume.
//
// Exit codes:
//
//	0   the verb succeeded.
//	10  refused: the target understood the request and declined it. Retrying
//	    is pointless, and this is reported as ErrScriptRefused so it can be
//	    told apart from a transient failure.
//	*   anything else is a failure, reported as ErrScriptFailed.
//
// 10 rather than 1 or 2 for the refusal, because the failure modes a shell
// script reaches by accident all land low: 1 from `set -e` or a false test, 2
// from a usage error in most getopt implementations, 126 from a file that is
// not executable, 127 from a command that is not found. A refusal has to be
// deliberate, and a value nothing hits by accident is what makes it so.
//
// stdout of `state` is parsed. stdout of every other verb is ignored. stderr
// of every verb is captured, truncated, and logged, because a script that
// fails silently is a script whose operator debugs it by reading this
// package's source.
const (
	ScriptVerbOpen   = "open"
	ScriptVerbClose  = "close"
	ScriptVerbState  = "state"
	ScriptVerbHealth = "health"

	// ScriptExitRefused is the exit code that means "understood and
	// declined", as opposed to "went wrong".
	ScriptExitRefused = 10

	// ScriptStateHeader is the first non-blank, non-comment line `state` must
	// print. It exists for the same reason the replay store has a magic
	// value: without one, output from a different tool — or from a future
	// revision of this format — is indistinguishable from a gate holding no
	// admissions at all, and "holds nothing" is the answer that makes a live
	// hole invisible.
	ScriptStateHeader = "postern-state-v1"

	// ScriptSourceUnknownExpiry is what a script prints in the expiry column
	// for an admission whose remaining lifetime the target cannot report.
	// Most cannot: a cloud security group rule has no TTL. The backend fills
	// the gap from its own lease store.
	ScriptSourceUnknownExpiry = "-"
)

// Sentinels for what an invocation did. Callers distinguish them; the agent
// logs them differently, and a refusal is not worth retrying while a failure
// is.
var (
	// ErrScriptRefused is exit code ScriptExitRefused: the target declined.
	ErrScriptRefused = errors.New("gate: script refused the request")
	// ErrScriptFailed is any other non-zero exit, or a script that could not
	// be started at all.
	ErrScriptFailed = errors.New("gate: script failed")
	// ErrScriptTimeout is an invocation that outlived its service's
	// script_timeout and was killed, along with its process group.
	ErrScriptTimeout = errors.New("gate: script timed out")
	// ErrScriptBusy is a service whose single invocation slot is already
	// occupied. It is what a hung script looks like to the next knock for
	// that service — a refused knock, on that service alone, rather than a
	// packet loop that stopped.
	ErrScriptBusy = errors.New("gate: script for this service is still running")
	// ErrScriptNoState is a service whose `state` has not yet been read back
	// successfully, so this backend has nothing truthful to report about what
	// is admitted.
	ErrScriptNoState = errors.New("gate: no state has been read back from the script yet")
)

// Defaults for the backend's own schedule. They are not configuration: a
// reaper interval is an implementation detail of keeping the lease deadlines
// this package promised, and a health cadence is bookkeeping.
const (
	// scriptReapInterval is how often lapsed leases are swept. It is well
	// under the shortest TTL any service in the design's own examples uses
	// (30s for the canary), because this interval is added to every
	// admission's real lifetime.
	scriptReapInterval = 2 * time.Second
	// scriptHealthInterval is how often each service's `health` verb runs.
	scriptHealthInterval = 30 * time.Second
	// scriptStateMinInterval throttles `state` refreshes. State is read on
	// every heartbeat and the heartbeat also fires after every packet, so
	// without a floor a burst of knocks would fork a subprocess per packet.
	scriptStateMinInterval = 5 * time.Second
	// scriptOutputLimit caps how much of a script's stdout and stderr is
	// retained. A script that prints without end must not be able to grow the
	// agent's heap.
	scriptOutputLimit = 64 << 10
	// scriptStateMaxLines caps how many admissions one `state` may report,
	// for the same reason.
	scriptStateMaxLines = 4096
)

// Script is the per-service gate backend that drives an operator-supplied
// executable.
//
// It is deliberately not a Gate. Gate carries RefreshAgentUp, AgentUpExpiry
// and SilenceAgentUp, which manage the agent_up dead-man element that makes
// the SPA port reachable at all (design section 4, invariant 1) — the single
// mechanism the whole product rests on. Putting that behind a subprocess
// would make the port's concealment depend on a script returning; for a cloud
// backend it would mean rewriting a security group every thirty seconds.
// nftables keeps agent_up, the SPA port, boot.nft, and every fail-posture
// rule. This moves one service's admissions and nothing else.
//
// # Nothing here runs a subprocess on the caller's goroutine
//
// The agent's packet loop calls Open inline, and the same loop renews
// agent_up (design section 7: "agent_up renewal and the watchdog must share
// one definition of health"). A backend that ran a subprocess synchronously
// would therefore be able to stall the renewal for as long as that subprocess
// took, and a script that never returns would stall it until the timeout —
// which is the shape of the Critical finding this project's last security
// review turned up, where a control-plane failure prevented the SPA socket
// binding at all.
//
// So every invocation happens on this type's own goroutines. Open records the
// lease durably and dispatches; State returns the last successfully parsed
// readback and schedules the next; Health for a script service is reported
// separately from Gate.Health and never folds into pre-arm's global
// precondition. Each service has exactly one invocation slot, so a hung
// script occupies its own service's slot, is killed at its own timeout along
// with its process group, and touches nothing else.
//
// # What Open returning nil means, and what it does not
//
// It means the lease is on disk and the invocation has been dispatched. It
// does not mean the perimeter changed. That is a real weakening against the
// nftables backend, where a nil from Open means the kernel accepted the
// element, and it is why State exists as a readback rather than a mirror of
// what this process believes it did — the same reason AgentUpExpiry exists
// beside RefreshAgentUp.
type Script struct {
	mu       sync.Mutex
	services map[string]scriptService
	state    map[string]*scriptServiceState
	closed   bool

	leases   *leaseStore
	now      func() time.Time
	log      *slog.Logger
	ownerUID int

	reapInterval   time.Duration
	healthInterval time.Duration

	// baseCtx bounds every invocation this type starts on its own
	// goroutines. Close cancels it, so a shutdown does not wait out a hung
	// script's full timeout before it can proceed.
	baseCtx  context.Context
	stopBase context.CancelFunc
	stopReap chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type scriptService struct {
	name    string
	path    string
	timeout time.Duration
}

// scriptServiceState is what this backend knows about one service, as opposed
// to what it hopes.
type scriptServiceState struct {
	// inflight is the single invocation slot. It is the whole isolation
	// mechanism: a service whose script hangs has its slot held until the
	// timeout kills the process group, and every other service's slot is
	// untouched.
	inflight  bool
	startedAt time.Time

	admissions []ElementState
	haveState  bool
	stateAt    time.Time

	health     Health
	haveHealth bool
	healthAt   time.Time
}

// ScriptOptions configures a Script.
type ScriptOptions struct {
	// LeasePath is the durable record of which admissions are outstanding.
	// It belongs beside the replay store, for the reason that one lives
	// where it does: it is per-host state the agent owns, and without it the
	// schedule exists only in memory and a restart forgets every hole it
	// still owes a close to.
	LeasePath string
	// OwnerUID is the uid every gate script must belong to. The zero value
	// is root, which is also the production answer; see CheckScriptPath.
	OwnerUID int
	// Now defaults to time.Now.
	Now func() time.Time
	// Logger defaults to a discarding logger, so a Script built by a test
	// does not write to stderr.
	Logger *slog.Logger
	// ReapInterval overrides the lapsed-lease sweep. Zero selects
	// scriptReapInterval.
	ReapInterval time.Duration
	// HealthInterval overrides the `health` cadence. Zero selects
	// scriptHealthInterval.
	HealthInterval time.Duration
}

// NewScript validates every script-backed service in policy and starts the
// backend's reaper.
//
// Validation is here, at load, and not at first knock. A script this host
// will not execute is a service that must fail to arm while the operator
// still has another way in, rather than a knock that mysteriously does
// nothing during the outage it was sent to fix.
//
// The returned Script owns a goroutine and a locked file; Close releases
// both.
func NewScript(policy *config.Policy, opts ScriptOptions) (*Script, error) {
	if policy == nil {
		return nil, errors.New("gate: NewScript: policy is nil")
	}
	if opts.LeasePath == "" {
		return nil, errors.New("gate: NewScript: LeasePath is required; without it a lapsed admission " +
			"survives a restart with nothing left that knows to withdraw it")
	}
	services, err := resolveScriptServices(policy, opts.OwnerUID)
	if err != nil {
		return nil, err
	}

	leases, err := openLeaseStore(opts.LeasePath)
	if err != nil {
		return nil, err
	}

	s := &Script{
		ownerUID:       opts.OwnerUID,
		services:       services,
		state:          make(map[string]*scriptServiceState, len(services)),
		leases:         leases,
		now:            opts.Now,
		log:            opts.Logger,
		reapInterval:   opts.ReapInterval,
		healthInterval: opts.HealthInterval,
		stopReap:       make(chan struct{}),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if s.reapInterval <= 0 {
		s.reapInterval = scriptReapInterval
	}
	if s.healthInterval <= 0 {
		s.healthInterval = scriptHealthInterval
	}
	for name := range services {
		s.state[name] = &scriptServiceState{}
	}
	// The cancel is stored rather than deferred: it is Close that must call
	// it, so a shutdown does not wait out a hung script.
	s.baseCtx, s.stopBase = context.WithCancel(context.Background()) //nolint:gosec // G118: cancel is held on the struct and called by Close

	// Leases recovered from disk are logged rather than silently adopted: an
	// agent that comes back to find admissions outstanding is an agent that
	// did not shut down cleanly, and that is the exact case the honest
	// caveat in this package's doc is about.
	if live := leases.Live(); len(live) > 0 {
		s.log.Warn("recovered script-backend leases from a previous run; "+
			"these admissions were open while no agent was running",
			"count", len(live))
	}

	s.wg.Add(1)
	go s.reap()
	return s, nil
}

func resolveScriptServices(policy *config.Policy, ownerUID int) (map[string]scriptService, error) {
	out := map[string]scriptService{}
	var errs []error
	for name, svc := range policy.Services {
		if svc.Kind != config.KindGate || svc.Backend != config.BackendScript {
			continue
		}
		if err := CheckScriptPath(svc.ScriptPath, ownerUID); err != nil {
			errs = append(errs, fmt.Errorf("service %q: %w", name, err))
			continue
		}
		timeout := svc.ScriptTimeout
		if timeout <= 0 {
			timeout = config.DefaultScriptTimeout
		}
		out[name] = scriptService{name: name, path: svc.ScriptPath, timeout: timeout}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// SetPolicy re-resolves the service catalogue against a new policy, and
// re-runs every path check against it.
//
// A fetched bundle can add a script-backed service or repoint an existing one
// at a different executable, and re-checking is what stops a bundle naming a
// path this host would have refused at boot. A policy that fails leaves this
// Script exactly as it was, so a refusal is never a backend that half-adopted
// a catalogue.
func (s *Script) SetPolicy(policy *config.Policy) error {
	services, err := s.resolve(policy)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.services = services
	next := make(map[string]*scriptServiceState, len(services))
	for name := range services {
		if prev, ok := s.state[name]; ok {
			next[name] = prev
			continue
		}
		next[name] = &scriptServiceState{}
	}
	s.state = next
	return nil
}

// CheckPolicy answers whether SetPolicy would accept this policy, without
// adopting it.
//
// It exists so the Dispatcher can validate both backends before committing
// either. Without it, a policy the nftables side accepts and this side
// refuses would leave the two halves of one gate holding different
// catalogues, which is a host where a knock resolves against one revision and
// opens against another.
func (s *Script) CheckPolicy(policy *config.Policy) error {
	_, err := s.resolve(policy)
	return err
}

func (s *Script) resolve(policy *config.Policy) (map[string]scriptService, error) {
	if policy == nil {
		return nil, errors.New("gate: Script: policy is nil")
	}
	s.mu.Lock()
	uid := s.ownerUID
	s.mu.Unlock()
	return resolveScriptServices(policy, uid)
}

// Services names every service this backend owns, sorted, for a caller
// building a dispatch table.
func (s *Script) Services() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.services))
	for name := range s.services {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Open records a lease and dispatches the script's `open` verb.
//
// It returns without waiting for the subprocess: see the type's doc comment
// for why, and for what a nil return does and does not promise. The lease is
// written and fsynced before the dispatch, in that order and on the caller's
// goroutine, for the same reason internal/replay commits a reservation before
// its effect is applied — a crash between the two must leave an admission
// this host still knows to withdraw, never one nothing remembers.
func (s *Script) Open(ctx context.Context, service string, src Source, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("gate: ttl must be positive, got %s", ttl)
	}
	norm, _, err := normalizeSource(src)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("gate: script backend is closed; %q cannot be opened", service)
	}
	svc, ok := s.services[service]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("gate: %q is not a script-backed gate service", service)
	}
	st := s.state[service]
	if st.inflight {
		// Refused rather than queued. A queue behind a hung script turns one
		// stuck invocation into a backlog that fires all at once when it
		// finally clears, re-opening sources whose grants have since lapsed.
		// A refused knock is a knock the operator retries.
		since := s.now().Sub(st.startedAt)
		s.mu.Unlock()
		return fmt.Errorf("%w: %q has had an invocation running for %s", ErrScriptBusy, service, since.Round(time.Millisecond))
	}
	st.inflight = true
	st.startedAt = s.now()
	s.mu.Unlock()

	lease := Lease{
		Service: service,
		Source:  norm,
		// ttl is checked positive at the top of Open, so the conversion is of
		// a positive int64 and cannot wrap.
		ExpiresAtMS: nowMS(s.now) + uint64(ttl.Milliseconds()), //nolint:gosec // G115: ttl > 0, checked above
	}
	if err := s.leases.Put(lease); err != nil {
		s.release(service)
		return err
	}

	s.dispatch(func(runCtx context.Context) {
		_, err := s.invoke(runCtx, svc, ScriptVerbOpen,
			service, norm.Prefix.String(), strconv.FormatInt(int64(ttl.Seconds()), 10), norm.Kind.String())
		switch {
		case err == nil:
			s.log.Info("script gate opened", "service", service, "source", norm.Prefix.String(), "ttl", ttl)
		case errors.Is(err, ErrScriptRefused):
			// The target declined, so nothing was admitted and there is
			// nothing to withdraw. Dropping the lease here is what keeps the
			// reaper from later issuing a close for an admission that never
			// existed — harmless against an idempotent script, but a line in
			// the operator's audit log describing something that did not
			// happen.
			if derr := s.leases.Delete(service, norm.Prefix); derr != nil {
				s.log.Error("could not drop the lease for a refused open", "service", service, "err", derr)
			}
			s.log.Warn("script gate refused an open", "service", service, "source", norm.Prefix.String(), "err", err)
		default:
			// The lease is deliberately kept. A failed open may have applied
			// partially — a provider that accepted the call and then timed
			// out on the reply is indistinguishable from one that did not —
			// so the close still owed is the safe assumption. Scripts are
			// required to make close idempotent for exactly this.
			s.log.Error("script gate open failed", "service", service, "source", norm.Prefix.String(), "err", err)
		}
		s.release(service)
	})
	return nil
}

// State reports what the script last said it was admitting.
//
// The elements come from parsing the `state` verb's output, not from this
// process's own record of what it asked for: a backend that reported its
// intentions would report a hole as closed the moment it dispatched the
// close, which is the failure AgentUpExpiry exists to prevent on the nftables
// side. Expiry is filled from the lease store wherever the script reported it
// as unknown, which is most of the time — a security group rule has no TTL to
// report.
//
// A refresh is scheduled but never waited on. Until the first readback lands,
// this returns ErrScriptNoState rather than an empty ServiceState: "admitting
// nothing" is a claim, and this backend has not earned it yet.
func (s *Script) State(ctx context.Context, service string) (ServiceState, error) {
	s.mu.Lock()
	svc, ok := s.services[service]
	if !ok {
		s.mu.Unlock()
		return ServiceState{}, fmt.Errorf("gate: %q is not a script-backed gate service", service)
	}
	st := s.state[service]
	now := s.now()
	stale := !st.haveState || now.Sub(st.stateAt) >= scriptStateMinInterval
	shouldRefresh := stale && !st.inflight && !s.closed
	if shouldRefresh {
		st.inflight = true
		st.startedAt = now
	}
	have := st.haveState
	admissions := append([]ElementState(nil), st.admissions...)
	s.mu.Unlock()

	if shouldRefresh {
		s.dispatch(func(runCtx context.Context) {
			s.refreshState(runCtx, svc)
			s.release(service)
		})
	}
	if !have {
		return ServiceState{}, fmt.Errorf("%w: %q", ErrScriptNoState, service)
	}
	return ServiceState{Service: service, Elements: s.fillExpiry(service, admissions)}, nil
}

// fillExpiry replaces an unknown remaining lifetime with what the lease store
// knows. An admission the script reports that this host holds no lease for
// keeps a zero expiry, and is still reported: an element nothing here
// scheduled a close for is exactly the one an operator needs to see.
func (s *Script) fillExpiry(service string, elems []ElementState) []ElementState {
	byPrefix := map[netip.Prefix]Lease{}
	for _, l := range s.leases.LiveFor(service) {
		byPrefix[l.Source.Prefix] = l
	}
	now := nowMS(s.now)
	out := make([]ElementState, 0, len(elems))
	for _, e := range elems {
		if e.Expires == 0 {
			if l, ok := byPrefix[e.Source.Prefix]; ok && l.ExpiresAtMS > now {
				// Guarded by l.ExpiresAtMS > now in the condition, so the
				// subtraction is positive and fits.
				e.Expires = time.Duration(l.ExpiresAtMS-now) * time.Millisecond //nolint:gosec // G115: see the guard in the condition
			}
		}
		out = append(out, e)
	}
	return out
}

// ServiceHealth reports what the service's `health` verb last said.
//
// It is deliberately not folded into Gate.Health. Gate.Health answers pre-arm's
// global precondition, and a global precondition that a subprocess can fail is
// a subprocess that can stop the agent starting — which would silence the SPA
// port for every service on the host because one operator's cloud API was
// having an afternoon. A script service's health degrades that service.
func (s *Script) ServiceHealth(service string) (Health, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state[service]
	if !ok {
		return Health{}, fmt.Errorf("gate: %q is not a script-backed gate service", service)
	}
	if !st.haveHealth {
		return Health{Detail: "no health verb has completed for this service yet"}, nil
	}
	return st.health, nil
}

// Close withdraws every outstanding admission and stops the reaper.
//
// It is the clean-shutdown half of the honesty in this package's doc: a stop
// that reaches here closes the holes. A stop that does not — SIGKILL, an OOM
// kill, power loss — leaves them, and only a restart's reaper catches up.
//
// Close is idempotent, because the agent reaches it twice on the disarm path
// (once from the action, once from shutdown), and because a teardown that
// errored the second time would report a failure for work that was already
// done.
func (s *Script) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	services := make(map[string]scriptService, len(s.services))
	for k, v := range s.services {
		services[k] = v
	}
	s.mu.Unlock()

	s.stopOnce.Do(func() {
		close(s.stopReap)
		// Cancelling the base context kills any invocation still running,
		// with its process group. Shutdown gets a bounded window from the
		// caller (the agent allows ten seconds for the whole teardown) and a
		// script whose own timeout is longer than that must not be what
		// decides whether the rest of it happens.
		s.stopBase()
	})
	s.wg.Wait()

	err := s.closeAll(ctx, services)
	if cerr := s.leases.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	return err
}

// closeAll withdraws the outstanding admissions, one goroutine per service so
// a slow target does not serialize behind another service's slow target, and
// sequentially within a service so one service's script is never running
// twice at once.
func (s *Script) closeAll(ctx context.Context, services map[string]scriptService) error {
	byService := map[string][]Lease{}
	for _, l := range s.leases.Live() {
		byService[l.Service] = append(byService[l.Service], l)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for name, leases := range byService {
		svc, ok := services[name]
		if !ok {
			// A lease for a service this policy no longer declares. Nothing
			// here can close it — there is no script left to invoke — and
			// dropping the record silently would hide an open hole, so it is
			// said out loud and the record is kept.
			mu.Lock()
			errs = append(errs, fmt.Errorf("gate: %d lease(s) for %q remain open: the policy no longer "+
				"declares that service, so no script exists to withdraw them", len(leases), name))
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(svc scriptService, leases []Lease) {
			defer wg.Done()
			for _, l := range leases {
				if err := s.closeLease(ctx, svc, l); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}(svc, leases)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// closeLease invokes `close` and drops the lease once the admission is gone.
//
// A refusal counts as gone: a target that declines to remove a rule it does
// not have is telling us the admission is not there. A failure does not, so
// the lease survives to be retried by the next sweep or recovered by the next
// start.
func (s *Script) closeLease(ctx context.Context, svc scriptService, l Lease) error {
	_, err := s.invoke(ctx, svc, ScriptVerbClose, l.Service, l.Source.Prefix.String())
	if err != nil && !errors.Is(err, ErrScriptRefused) {
		return fmt.Errorf("gate: close %s from %q: %w", l.Source.Prefix, l.Service, err)
	}
	if derr := s.leases.Delete(l.Service, l.Source.Prefix); derr != nil {
		return derr
	}
	return nil
}

// reap is the expiry this backend has to provide for itself.
//
// nftables gives per-element, kernel-owned expiry, which is why the README
// can say the bolt falls even if the porter dies. A script backend cannot
// promise that: most targets have no per-entry TTL at all, so the deadline
// lives in the lease store and something has to act on it. This is that
// something, and it is a goroutine inside the agent — which is the whole of
// the honest caveat in this package's doc.
func (s *Script) reap() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.reapInterval)
	defer ticker.Stop()
	var lastHealth time.Time

	for {
		select {
		case <-s.stopReap:
			return
		case <-ticker.C:
			s.sweep()
			if now := s.now(); now.Sub(lastHealth) >= s.healthInterval {
				lastHealth = now
				s.sweepHealth()
			}
		}
	}
}

// sweep closes every lease whose deadline has passed. It runs on the reaper's
// own goroutine and dispatches per service, so a service whose slot is busy
// is skipped this tick rather than blocking the sweep for every other one.
func (s *Script) sweep() {
	due := s.leases.Due(nowMS(s.now))
	if len(due) == 0 {
		return
	}
	byService := map[string][]Lease{}
	for _, l := range due {
		byService[l.Service] = append(byService[l.Service], l)
	}

	for name, leases := range byService {
		svc, ok := s.acquire(name)
		if !ok {
			continue
		}
		s.dispatch(func(runCtx context.Context) {
			for _, l := range leases {
				if err := s.closeLease(runCtx, svc, l); err != nil {
					s.log.Error("reaper could not close a lapsed admission",
						"service", l.Service, "source", l.Source.Prefix.String(), "err", err)
					// Left in the store on purpose, so the next sweep tries
					// again. A lapsed admission that this host has given up on
					// is one nothing will ever withdraw.
					continue
				}
				s.log.Info("reaper closed a lapsed admission",
					"service", l.Service, "source", l.Source.Prefix.String())
			}
			s.release(name)
		})
	}
}

func (s *Script) sweepHealth() {
	for _, name := range s.Services() {
		svc, ok := s.acquire(name)
		if !ok {
			continue
		}
		s.dispatch(func(runCtx context.Context) {
			s.refreshHealth(runCtx, svc)
			s.release(name)
		})
	}
}

func (s *Script) refreshState(ctx context.Context, svc scriptService) {
	res, err := s.invoke(ctx, svc, ScriptVerbState, svc.name)
	if err != nil {
		s.log.Warn("script state readback failed; this service's admissions are being reported "+
			"from the last successful read", "service", svc.name, "err", err)
		return
	}
	elems, err := parseScriptState(res.stdout)
	if err != nil {
		// Not adopted. A parse failure means this backend does not know what
		// the target is admitting, and the one answer it must never invent is
		// "nothing".
		s.log.Error("script state output could not be parsed; the previous readback stands",
			"service", svc.name, "err", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state[svc.name]
	if !ok {
		return
	}
	st.admissions = elems
	st.haveState = true
	st.stateAt = s.now()
}

func (s *Script) refreshHealth(ctx context.Context, svc scriptService) {
	_, err := s.invoke(ctx, svc, ScriptVerbHealth, svc.name)

	h := Health{
		Healthy: err == nil,
		// A script backend is asked nothing about interval sets: it never
		// holds a CIDR in an nftables set, so the capability those two fields
		// describe is not its to have or lack. They are reported as capable
		// so a caller joining this with the nftables backend's answer does
		// not read an unrelated false as a lost capability.
		IPv4CIDRCapable: true,
		IPv6CIDRCapable: true,
		Detail:          "health verb succeeded",
	}
	if err != nil {
		h.Detail = err.Error()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state[svc.name]
	if !ok {
		return
	}
	if st.haveHealth && st.health.Healthy != h.Healthy {
		if h.Healthy {
			s.log.Info("script backend is healthy again", "service", svc.name)
		} else {
			s.log.Error("script backend went unhealthy", "service", svc.name, "err", err)
		}
	}
	st.health = h
	st.haveHealth = true
	st.healthAt = s.now()
}

// acquire takes a service's single invocation slot, reporting false when it
// is already held or the backend is closed.
func (s *Script) acquire(service string) (scriptService, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return scriptService{}, false
	}
	svc, ok := s.services[service]
	if !ok {
		return scriptService{}, false
	}
	st := s.state[service]
	if st.inflight {
		return scriptService{}, false
	}
	st.inflight = true
	st.startedAt = s.now()
	return svc, true
}

func (s *Script) release(service string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.state[service]; ok {
		st.inflight = false
	}
}

// dispatch runs fn on this type's own goroutine, under the base context, and
// accounts for it so Close can wait. It is the one place a subprocess ever
// leaves the caller's goroutine, which is what makes the "nothing runs a
// subprocess on the caller's goroutine" claim in the type doc checkable by
// reading rather than by hoping.
func (s *Script) dispatch(fn func(context.Context)) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn(s.baseCtx)
	}()
}

type scriptResult struct {
	stdout []byte
	stderr []byte
}

// invoke runs one verb with an explicit argument vector and a hard deadline.
//
// exec.CommandContext, never a shell. The service name and the source prefix
// are argv elements, so no quoting, splitting, or expansion happens to them
// between here and the script's own $2 and $3 — which matters because the
// prefix originated in a packet, and the only reason to trust it is that it
// was signed, not that it looks harmless.
func (s *Script) invoke(ctx context.Context, svc scriptService, verb string, args ...string) (scriptResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, svc.timeout)
	defer cancel()

	argv := append([]string{verb}, args...)
	cmd := exec.CommandContext(runCtx, svc.path, argv...) //nolint:gosec // svc.path passed CheckScriptPath at load; argv is explicit, never a shell
	cmd.Stdin = nil
	// The agent's own environment is inherited, which is how an operator
	// configures the script: systemd's Environment= or an EnvironmentFile on
	// posternd.service is root-owned and reviewed the same way the config is.
	// NOTIFY_SOCKET is the one entry held back. It is not operator
	// configuration, it is systemd's sd_notify(3) rendezvous for posternd
	// itself, and an executable postern does not control has no business
	// holding a handle that talks to systemd about posternd. See
	// internal/childenv.
	cmd.Env = os.Environ()
	childenv.Sanitize(cmd)
	isolateProcessGroup(cmd)
	// A killed child whose grandchild still holds the pipe would otherwise
	// keep Wait blocked past the deadline it was supposed to enforce.
	cmd.WaitDelay = 2 * time.Second

	var stdout, stderr limitedBuffer
	stdout.limit = scriptOutputLimit
	stderr.limit = scriptOutputLimit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := scriptResult{stdout: stdout.b, stderr: stderr.b}
	if err == nil {
		return res, nil
	}

	detail := strings.TrimSpace(string(res.stderr))
	if detail != "" {
		detail = ": " + firstLines(detail, 5)
	}
	if runCtx.Err() != nil && errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("%w: %q %s after %s%s", ErrScriptTimeout, svc.name, verb, svc.timeout, detail)
	}

	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() == ScriptExitRefused {
			return res, fmt.Errorf("%w: %q %s exited %d%s", ErrScriptRefused, svc.name, verb, ScriptExitRefused, detail)
		}
		return res, fmt.Errorf("%w: %q %s exited %d%s", ErrScriptFailed, svc.name, verb, ee.ExitCode(), detail)
	}
	return res, fmt.Errorf("%w: %q %s: %v%s", ErrScriptFailed, svc.name, verb, err, detail)
}

// parseScriptState turns the `state` verb's stdout into elements.
//
// The format, one admission per line after a version header:
//
//	postern-state-v1
//	203.0.113.5/32 observed 84
//	198.51.100.0/24 asserted -
//
// Blank lines and lines beginning with # are ignored. The third field is the
// remaining lifetime in whole seconds, or "-" when the target cannot say —
// which most cannot, and which the caller then fills from the lease store.
//
// Every failure here is an error rather than a partial parse. A state
// readback that silently dropped the lines it could not understand would
// report a smaller set of open holes than really exist, which is the wrong
// direction for a tool whose entire job is knowing what is open.
func parseScriptState(out []byte) ([]ElementState, error) {
	lines := strings.Split(string(out), "\n")
	seenHeader := false
	elems := make([]ElementState, 0, 8)

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seenHeader {
			if line != ScriptStateHeader {
				return nil, fmt.Errorf("gate: state output begins with %q, want %q", line, ScriptStateHeader)
			}
			seenHeader = true
			continue
		}
		if len(elems) >= scriptStateMaxLines {
			return nil, fmt.Errorf("gate: state output has more than %d admissions", scriptStateMaxLines)
		}
		el, err := parseScriptStateLine(line)
		if err != nil {
			return nil, fmt.Errorf("gate: state output line %d: %w", i+1, err)
		}
		elems = append(elems, el)
	}
	if !seenHeader {
		return nil, fmt.Errorf("gate: state output has no %q header line", ScriptStateHeader)
	}
	return elems, nil
}

func parseScriptStateLine(line string) (ElementState, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return ElementState{}, fmt.Errorf("has %d fields, want 3 (<source> <observed|asserted> <seconds|%s>)",
			len(fields), ScriptSourceUnknownExpiry)
	}

	pfx, err := parseSourcePrefix(fields[0])
	if err != nil {
		return ElementState{}, err
	}

	var kind SourceKind
	switch fields[1] {
	case SourceObserved.String():
		kind = SourceObserved
	case SourceAsserted.String():
		kind = SourceAsserted
	default:
		return ElementState{}, fmt.Errorf("has source kind %q, want %q or %q",
			fields[1], SourceObserved, SourceAsserted)
	}

	var expires time.Duration
	if fields[2] != ScriptSourceUnknownExpiry {
		secs, err := strconv.ParseInt(fields[2], 10, 32)
		if err != nil || secs < 0 {
			return ElementState{}, fmt.Errorf("has remaining lifetime %q, want a non-negative whole number of seconds or %q",
				fields[2], ScriptSourceUnknownExpiry)
		}
		expires = time.Duration(secs) * time.Second
	}

	return ElementState{Source: Source{Kind: kind, Prefix: pfx}, Expires: expires}, nil
}

// parseSourcePrefix accepts either a CIDR or a bare address. A bare address
// is the natural thing for a script to echo back from a provider that stores
// single hosts, and reading it as a full-length prefix is what this package
// means by it everywhere else.
func parseSourcePrefix(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		norm, _, nerr := normalizeSource(Source{Prefix: pfx})
		if nerr != nil {
			return netip.Prefix{}, nerr
		}
		return norm.Prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("has source %q, which is neither a CIDR nor an address", s)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// limitedBuffer collects at most limit bytes and silently discards the rest.
// A script that prints without end is a script whose output must not become
// this process's memory problem.
type limitedBuffer struct {
	b     []byte
	limit int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if room := w.limit - len(w.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		w.b = append(w.b, p[:room]...)
	}
	// The full length is reported written so the child is never handed a
	// short-write error for output we chose not to keep.
	return len(p), nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + " ..."
}
