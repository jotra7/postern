package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/metrics"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
	"github.com/jotra7/postern/internal/version"
)

var (
	// ErrInert means a global pre-arm precondition failed. The agent armed
	// nothing, never set agent_up, and never bound the SPA port. On a host
	// with a fail-closed service this is not "nothing is happening":
	// boot.nft's drop rules loaded at boot, independently of the agent, so
	// inert means the drops are enforced with nothing able to open them and
	// no SPA to knock with (design section 7).
	ErrInert = errors.New("agent: global pre-arm precondition failed; agent is inert")

	// ErrIncapacitated means the replay store proved unusable while the
	// agent was running. The agent has silenced agent_up, emptied the
	// fail-closed gate sets, torn down postern_open, and stopped accepting.
	// Run returns this so the process exits and systemd runs the established
	// failure path rather than a second, invented one.
	ErrIncapacitated = errors.New("agent: replay store is unusable; agent has incapacitated itself")
)

// Default cadences. Design section 4 gives 90s refreshed every 30s and
// section 7 calls those numbers "a tuning question"; the watchdog observes the
// same token from the same loop, so the unit's WatchdogSec is sized against
// the lease rather than the other way round.
//
// The lease is 100s rather than 90s, and the ten seconds are the entire point:
// 90 is exactly three heartbeats, so the lease expired at the same instant as
// the beat that was meant to renew it. Whether the SPA port stayed up came
// down to which of the two won by microseconds — the design intends three
// beats of slack and there was effectively none. A lease that is not a
// multiple of the beat cannot have that coincidence at all.
//
// What the numbers now mean, exactly: after the last refresh that landed, the
// beats at +30s, +60s and +90s may all fail and the SPA port stays open; the
// element lapses at +100s, ten seconds after the third missed beat and twenty
// seconds before the fourth. Three missed beats tolerated, with margin either
// side, and no instant where expiry and renewal race.
const (
	DefaultAgentUpTTL      = 100 * time.Second
	DefaultHeartbeatPeriod = 30 * time.Second
	// DefaultConfirmWindow is how long a prepared transaction waits for its
	// bound confirm before the dead-man timer reverts it.
	DefaultConfirmWindow = 10 * time.Minute
	// applyBundlePolicyTimeout bounds applyBundlePolicy's own local work —
	// rendering, writing boot.nft, and the systemctl/nft calls a locally-driven
	// arm already makes. It is not part of PullConfig because it is not a hub
	// interaction at all: by the time apply runs, PullOnce's fetch has already
	// returned.
	applyBundlePolicyTimeout = 30 * time.Second
)

// loopStopTimeout bounds how long shutdown waits for Run's background loops
// after cancelling them.
//
// It is sized against what a cancelled loop still has left to do, which is
// one fsync: both the puller and the heartbeat emitter propagate ctx onto
// their HTTP requests, so a fetch or a send in flight aborts at once, and
// what remains is the durable write each performs around it. That is
// milliseconds on a healthy disk and hundreds of milliseconds under the
// contention a stop under load produces, so two seconds is wide margin
// rather than a guess at a typical case.
//
// The ceiling matters more than the floor. It must stay well under systemd's
// TimeoutStopSec (90s by default) and under the unit's WatchdogSec, because
// a bound that systemd's SIGKILL reaches first would never write the line
// this bound exists to produce, and being killed silently is the outcome it
// is here to replace. It is also under the five seconds internal/agent's own
// daemon harness allows Run after cancellation, so a loop that will not stop
// is reported by the daemon, naming the loop, rather than surfacing as a
// harness timeout that names nothing.
//
// It is deliberately NOT sized against applyBundlePolicyTimeout's 30s. A
// puller inside apply holds a context detached from Run's on purpose, and an
// arm cut off by process exit is the case confirm-or-revert and the dead-man
// timer already cover; waiting 30s on every stop to protect it would make
// every restart 30s slower against a hazard that is already handled.
const loopStopTimeout = 2 * time.Second

// Datagram is one received packet plus the facts about its arrival that
// validation needs and cannot recover from the bytes: where it came from,
// whether it arrived on the always-allow path, and which local port it
// arrived on. LocalPort exists so the one transmission postern ever makes —
// the liveness pong — goes back out the socket the ping arrived on, which
// under the rotating knock port is the only source port the client's
// connected reply socket will accept a reply from.
type Datagram struct {
	Payload           []byte
	Source            netip.AddrPort
	OnAlwaysAllowPath bool
	LocalPort         uint16
}

// Receiver is the daemon's entire network surface. It exists as an interface
// so the packet loop — where every invariant in this file lives — is
// testable without a socket, and so the one place the agent ever transmits
// (Reply, for a liveness pong) is a single, auditable method rather than a
// call scattered through the handler.
type Receiver interface {
	// Receive blocks until a datagram arrives or ctx is done.
	Receive(ctx context.Context) (Datagram, error)
	// Reply transmits payload to to, sent from the local socket bound to
	// fromPort. The agent calls this only for a liveness pong, and only for
	// a ping that arrived on the always-allow path; fromPort is that ping's
	// Datagram.LocalPort, so the reply goes out the one socket the client is
	// listening on for it.
	Reply(ctx context.Context, to netip.AddrPort, fromPort uint16, payload []byte) error
	Close() error
}

// Armer creates postern_open at startup. *gate.NFTables satisfies it.
// postern_open has no on-disk form and no boot persistence — it is created
// by the agent when it starts and removed when it exits (design section 4)
// — so it is the one table the daemon itself brings into being.
//
// postern_boot is deliberately NOT in this interface. It is loaded at boot
// by the oneshot unit running nft(8), before the agent runs and
// independently of it; an agent that recreated it would duplicate every rule
// it found (see gate.Apply's additive contract) and would make the
// fail-closed posture depend on the agent starting, which is precisely what
// that posture exists to avoid.
type Armer interface {
	ApplyOpen(ctx context.Context) error
}

// Stats are the SPA counters design section 8's self-attestation reports
// each beat. Received counts every datagram the loop has finished handling,
// whatever the outcome — incremented after the effect has been applied, so
// it is a fact rather than a promise, and so it doubles as the loop's
// progress signal.
type Stats struct {
	Received uint64
	Accepted uint64
	Rejected uint64
}

// Health is the daemon's current self-assessment.
//
// It has two independent sources and they are kept apart deliberately. The
// agent_up renewal is a *live* signal: it goes red the moment a renewal
// fails and green again the moment one succeeds. Everything else the daemon
// can go red about — a reverted transaction, an unusable replay store — is a
// *standing* condition that a later successful renewal has no business
// clearing. Folding both into one last-writer-wins field meant a beat
// running immediately after a dead-man revert erased the revert's red before
// anything could observe it, which is how this split was found.
type Health struct {
	Red    bool
	Reason string
	At     time.Time
}

// Options configures a Daemon.
type Options struct {
	Policy *config.Policy
	Gate   gate.Gate
	Opener *spa.Opener
	Store  replay.Store
	// Host signs liveness pongs. The pong is signed rather than encrypted:
	// it travels only over the always-allow path, after that path has been
	// proven trusted by a fully authenticated ping, and carries no secret.
	Host identity.Signer

	// Receiver defaults to a UDP receiver bound to Policy.SPAPort.
	Receiver Receiver
	// Armer defaults to Gate when Gate implements it.
	Armer Armer
	// Checks are pre-arm's probes. Nil fields are filled from
	// ProductionChecks.
	Checks PreArmChecks
	// StorePath is where the replay store lives; pre-arm's writability probe
	// asks about its directory.
	StorePath string

	// Transactions owns confirm-or-revert. Nil disables the arm step, the
	// confirm action, and the dead-man timer — a daemon built without one
	// never arms a configuration and never has anything to confirm.
	Transactions *Transactions
	// ConfirmWindow is how long a prepared transaction waits for its bound
	// confirm. Zero selects DefaultConfirmWindow.
	ConfirmWindow time.Duration

	// Pull configures M2's fleet bundle pull loop. Nil means standalone: no
	// goroutine starts, and this host is never anything but what Policy
	// already says. A non-nil Pull with Transactions nil is a construction
	// error (see New): a fetched bundle can only ever be armed through
	// confirm-or-revert, so a puller with nothing to arm through can accept
	// no bundle at all.
	Pull *PullConfig
	// RunningPolicyPath is where the confirmed running policy is persisted, so
	// a restart runs the configuration a fetched bundle installed rather than
	// the enrollment-time bootstrap (#52). It is written on every commit and
	// left untouched by a revert, so it always names the policy whose ruleset
	// boot.nft holds. Empty disables persistence, which is standalone mode's
	// answer — there the bootstrap file already is the running config — and
	// every test's default.
	RunningPolicyPath string
	// LocalConsoleRecovery is the console-recovery acknowledgment from the
	// host's local, root-written enrollment bootstrap config — not from
	// Policy, which on a fleet host is the running policy and can already be
	// whatever a prior bundle swapped it to. It is the trust anchor
	// checkConsoleRecoveryUnchanged compares a fetched bundle against: a
	// bundle may only turn this host into a console-recovery host (drop
	// always_allow_iface) when this was true at construction. See
	// cmd_agent_linux.go, which sets it from the bootstrap's own parsed
	// policy rather than the effective/running one LoadRunningPolicy returns.
	LocalConsoleRecovery bool
	// FlushDropIn keeps posternd.service's per-set flush drop-in in step with
	// the live gate catalogue, regenerating it and reloading systemd whenever a
	// bundle changes which fail-closed sets exist (#47). Its zero value is
	// disabled, which is standalone mode's answer — a host that never applies a
	// bundle has a fixed catalogue and the enrolled drop-in stays correct — and
	// every test's default.
	FlushDropIn FlushDropIn
	// Beat configures M2's heartbeat-emitter loop. Nil means no goroutine
	// starts and this host never reports itself to a hub. Beat.Signer,
	// Beat.FleetID and Beat.HostID are set by the caller rather than derived
	// here from Options.Host/Options.Policy, the same way PullConfig's own
	// copies of those values are — see PullConfig's doc comment for why.
	Beat *BeatConfig

	// Metrics receives everything design section 8 publishes. Nil means the
	// agent keeps no metrics; every recorder method is nil-safe, so the
	// packet loop calls them unconditionally rather than guarding each site.
	// A non-empty MetricsListen with a nil Metrics builds one.
	Metrics *metrics.Recorder
	// MetricsListen is the address the /metrics endpoint binds to, as
	// "host:port" or ":port". Empty means no endpoint is served.
	//
	// It is resolved at construction, not at Run, so a bind that design
	// section 8 forbids — a wildcard, or an address on neither loopback nor
	// the always-allow interface — is a refusal to build the daemon at all,
	// before anything has been armed. See metrics.ResolveBind.
	MetricsListen string
	// MetricsInterfaceAddrs overrides how the always-allow interface's
	// addresses are read when resolving MetricsListen. Nil selects the real
	// lookup.
	MetricsInterfaceAddrs metrics.InterfaceAddrs

	AgentUpTTL      time.Duration
	HeartbeatPeriod time.Duration

	// Ticks replaces the internal heartbeat ticker. Tests drive it; in
	// production it is nil and a time.Ticker is used.
	Ticks <-chan time.Time
	// Now defaults to time.Now.
	Now func() time.Time
	// Notify sends an sd_notify state string. Nil selects the real one,
	// which is a no-op when NOTIFY_SOCKET is unset.
	Notify func(state string) error
	Logger *slog.Logger
}

// Daemon is the long-running process: it binds the SPA port, runs each
// datagram through Validate, applies accepted decisions through the Gate,
// and renews agent_up from the same loop.
type Daemon struct {
	// policy is read through currentPolicy and written through setPolicy,
	// both of which take mu for exactly the instant of the access — never
	// while blocked on I/O. It starts immutable in every mode this project
	// shipped before M2; the bundle pull loop (pull.go) is what makes it
	// swap after construction, through applyBundlePolicy, and that is the
	// only writer it will ever have.
	policy *config.Policy
	gate   gate.Gate
	// opener is read through currentOpener and written through setPolicy,
	// under the same lock and with the same discipline as policy: the two are
	// one fact — who may knock this host — split across two representations,
	// and a swap that moved only one of them is what made an operator added by
	// a bundle pass the grant check and never decrypt (see setPolicy).
	opener   *spa.Opener
	store    replay.Store
	host     identity.Signer
	receiver Receiver
	// rebinder is non-nil whenever the daemon's receiver is a PortRebinder:
	// the rotating-knock-port carrier bindCarriers builds, or a caller- or
	// test-supplied Options.Receiver that happens to implement the same
	// interface (see New). Fixed-port mode leaves it nil. rotateAndRefresh
	// is the one reader.
	rebinder PortRebinder
	// lastWindow and haveWindow track which window's sockets are currently
	// bound, so rotateAndRefresh calls Rebind only on a window change rather
	// than every beat. Touched only from beat, which runs in Run's single
	// select.
	lastWindow uint64
	haveWindow bool
	armer      Armer
	checks     PreArmChecks
	txns       *Transactions
	// runningPolicyPath persists the confirmed policy so a restart runs the
	// fetched configuration rather than the bootstrap file (#52). Empty in
	// standalone mode and in tests that do not opt in. See persistRunningPolicy.
	runningPolicyPath string
	// localConsoleRecovery is the enrollment bootstrap's own console-recovery
	// acknowledgment, set once at construction and never touched again — in
	// particular never by setPolicy, which is what lets it keep meaning "the
	// root-written config on this host said so" after a bundle has swapped
	// the running policy. See checkConsoleRecoveryUnchanged and
	// Options.LocalConsoleRecovery.
	localConsoleRecovery bool
	// flushDropIn regenerates the per-set flush drop-in and reloads systemd on
	// a catalogue change (#47). Its zero value is disabled: standalone mode and
	// tests that do not opt in. See syncFlushDropIn.
	flushDropIn FlushDropIn
	// puller is nil in standalone mode. Set once at construction and never
	// reassigned, so reading it needs no lock; Run starts its goroutine and
	// nothing else in this type ever touches it.
	puller *Puller
	// beater is nil unless Options.Beat is set. Same shape as puller: set
	// once at construction, never reassigned, its own goroutine started from
	// Run and touched nowhere else.
	beater *Beater

	metrics     *metrics.Recorder
	metricsAddr netip.AddrPort
	// gateStateErr names the gate services whose state read is currently
	// failing, so recordGateState can log the transition rather than the
	// state. Touched only from beat, which runs in Run's single select, and
	// deliberately not under d.mu: it is log bookkeeping and nothing outside
	// this file reads it.
	gateStateErr map[string]bool
	// agentUpReadErr is the same transition-logging bookkeeping for the
	// agent_up read-back, and is touched only from beat.
	agentUpReadErr bool

	agentUpTTL      time.Duration
	heartbeatPeriod time.Duration
	confirmWindow   time.Duration

	ticks  <-chan time.Time
	now    func() time.Time
	notify func(string) error
	log    *slog.Logger

	mu     sync.Mutex
	prearm PreArm
	// agentUp is the live half of Health: reset by every beat.
	agentUp Health
	// standing is the half a successful beat must not clear.
	standing Health
	stats    Stats
	pending  *Transaction

	// afterResolveHook, when non-nil, runs between a transaction being
	// resolved (reverted or committed) and the pending slot being cleared.
	//
	// It exists for one test and is never set in production. The
	// interleaving clearPending guards against — a BeginTransaction landing
	// after a resolution's I/O but before its clear — became unreachable
	// through the public API once Transactions grew a mutex, because Prepare
	// and Revert are now mutually exclusive and the clear almost always wins
	// the remaining race. "Almost always" is not "always", so the compare
	// stays; this hook is how it stays tested rather than assumed.
	afterResolveHook func()
}

// New builds a Daemon. It refuses a policy it cannot serve rather than
// starting and discovering the problem later: a daemon that came up against
// a policy with no SPA port would bind nothing and still look healthy.
func New(opts Options) (*Daemon, error) {
	if opts.Policy == nil {
		return nil, errors.New("agent: Options.Policy is required")
	}
	if opts.Gate == nil {
		return nil, errors.New("agent: Options.Gate is required")
	}
	if opts.Opener == nil {
		return nil, errors.New("agent: Options.Opener is required")
	}
	if opts.Store == nil {
		return nil, errors.New("agent: Options.Store is required")
	}
	if opts.Policy.SPAPort == 0 {
		return nil, errors.New("agent: policy has no spa_port; there is nothing to bind")
	}
	if opts.Policy.AlwaysAllowIface == "" && !opts.Policy.ConsoleRecovery {
		// Same refusal gate.BuildRulesetPlan makes, for the same reason:
		// under fail-closed the always-allow path is the only route in.
		// Console-recovery is the explicit, acknowledged exception — Console
		// is that host's declared last resort instead.
		return nil, errors.New("agent: policy has no always_allow_iface; postern will not arm without a path it cannot remove")
	}
	// A transaction manager that can enable the boot unit but not the agent
	// unit is the lockout, wired up: every arm would leave the host loading
	// fail-closed drop rules at boot with nothing alive to open them. It is a
	// construction-time refusal because it is a wiring mistake, and it is one
	// that already shipped once — the arm step enabled the boot unit and
	// nothing anywhere enabled the agent.
	if t := opts.Transactions; t != nil && t.BootUnit != nil && t.AgentUnit == nil {
		return nil, errors.New("agent: Options.Transactions has a BootUnit but no AgentUnit; arming would " +
			"enable postern-boot.service without posternd.service, so every reboot would load the " +
			"fail-closed drop rules with no agent alive to open them")
	}

	// Resolved before anything else is built, so an out-of-bounds metrics
	// bind stops the daemon existing rather than being discovered halfway
	// through Run with a configuration already armed.
	metricsAddr, recorder, err := resolveMetrics(opts)
	if err != nil {
		return nil, err
	}

	d := &Daemon{
		metrics:              recorder,
		metricsAddr:          metricsAddr,
		policy:               opts.Policy,
		gate:                 opts.Gate,
		opener:               opts.Opener,
		store:                opts.Store,
		host:                 opts.Host,
		receiver:             opts.Receiver,
		armer:                opts.Armer,
		txns:                 opts.Transactions,
		runningPolicyPath:    opts.RunningPolicyPath,
		localConsoleRecovery: opts.LocalConsoleRecovery,
		flushDropIn:          opts.FlushDropIn,
		agentUpTTL:           orDuration(opts.AgentUpTTL, DefaultAgentUpTTL),
		heartbeatPeriod:      orDuration(opts.HeartbeatPeriod, DefaultHeartbeatPeriod),
		confirmWindow:        orDuration(opts.ConfirmWindow, DefaultConfirmWindow),
		ticks:                opts.Ticks,
		now:                  opts.Now,
		notify:               opts.Notify,
		log:                  opts.Logger,
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.notify == nil {
		d.notify = SdNotify
	}
	if d.log == nil {
		d.log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if d.armer == nil {
		if a, ok := opts.Gate.(Armer); ok {
			d.armer = a
		}
	}
	// StorePath is required whenever the default writability probe will be
	// built, because that probe has no other way to learn which filesystem
	// to ask about and silently answers about the working directory when it
	// is unset (see ProductionChecks). A caller supplying its own
	// StoreWritable has already answered the question and is not asked for a
	// path it would not use.
	if opts.StorePath == "" && opts.Checks.StoreWritable == nil {
		return nil, errors.New("agent: Options.StorePath is required; without it the replay-store " +
			"writability precondition would probe the working directory instead of the store's own filesystem")
	}
	d.checks = ProductionChecks(opts.Checks, opts.Gate, opts.StorePath, "")

	if d.receiver == nil {
		r, rebinder, err := bindCarriers(opts.Policy, d.now)
		if err != nil {
			return nil, err
		}
		d.receiver = r
		d.rebinder = rebinder
	} else if rebinder, ok := d.receiver.(PortRebinder); ok {
		// The same discovery bindCarriers does above, run over a
		// caller-supplied receiver instead of one this constructor built.
		// This is what lets a test drive the rotation loop's Rebind calls
		// against a fake receiver rather than a real socket; a production
		// caller that hands in its own PortRebinder-and-Receiver gets the
		// identical wiring for the identical reason.
		d.rebinder = rebinder
	}

	if opts.Pull != nil {
		// A puller with nothing to arm through is a construction error, not a
		// runtime one: the whole point of confirm-or-revert is that a bundle
		// that locks the host out rolls itself back the same way a bad local
		// config does, and a daemon that skipped that machinery for a fetched
		// bundle would be exactly the "silently inverted fail posture" this
		// project exists to prevent.
		if opts.Transactions == nil {
			return nil, errors.New("agent: Options.Pull is set but Options.Transactions is nil; a fetched " +
				"bundle can only ever be armed through confirm-or-revert, so a puller with nothing to arm " +
				"through can accept no bundle at all")
		}
		pullCfg := *opts.Pull
		if pullCfg.Metrics == nil {
			pullCfg.Metrics = d.metrics
		}
		if pullCfg.Logger == nil {
			pullCfg.Logger = d.log
		}
		// NewPuller's apply is func(*config.Policy) error, with no context
		// parameter — pull.go never blocks on anything that needs one, and
		// applyBundlePolicy's own work is local (render, write, and the same
		// systemctl/nft calls a locally-driven arm makes), so this bounds it
		// rather than inheriting Run's own long-lived ctx: a wedged nft or
		// systemctl child stalls the pull loop's own goroutine for at most
		// applyBundlePolicyTimeout, never the packet loop, and never forever.
		applyFn := func(p *config.Policy) (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), applyBundlePolicyTimeout)
			defer cancel()
			return d.applyBundlePolicy(ctx, p)
		}
		puller, err := NewPuller(pullCfg, applyFn)
		if err != nil {
			return nil, fmt.Errorf("agent: build the bundle puller: %w", err)
		}
		d.puller = puller
	}

	if opts.Beat != nil {
		beatCfg := *opts.Beat
		if beatCfg.Metrics == nil {
			beatCfg.Metrics = d.metrics
		}
		if beatCfg.Logger == nil {
			beatCfg.Logger = d.log
		}
		// A heartbeat emitter that cannot be built is logged and left nil, not
		// returned as a construction error, and the asymmetry with every
		// refusal above it is the entire point.
		//
		// Everything New refuses above is a policy this daemon could not
		// serve: no SPA port to bind, no always-allow path, a transaction
		// manager wired into the lockout. This is different in kind. Every way
		// openBeatState fails is local and none of them involves SPA — a torn
		// or unrecognised state file, the flock held by a lingering process on
		// the same state directory, /var/lib/postern read-only or full — and a
		// failure returned from here means runAgent never reaches d.Run, so
		// the SPA socket is never bound, the gate is never armed, and no valid
		// knock is ever answered. Taking the break-glass daemon down because
		// its reporting could not start produces exactly the outage the
		// reporting exists to catch.
		//
		// serveMetrics already answers this question the same way for the same
		// reason, and the heartbeat is strictly less load-bearing than
		// /metrics: nothing on this host reads it, and the hub's view of this
		// host going stale is a fleet-management problem, not a break-glass
		// one. Rejecting the corrupt file itself stays correct — see
		// readHeader, where treating an unrecognised file as empty would reset
		// the sequence and get every later beat refused for the life of the
		// epoch. What was wrong was the wiring, not the refusal.
		beater, err := NewBeater(beatCfg, d.collectBeatBody)
		if err != nil {
			d.log.Error("could not start the heartbeat emitter; the agent is running without one, so "+
				"this host will look unreachable to the hub while still answering every knock",
				"state_path", beatCfg.StatePath, "err", err)
		} else {
			d.beater = beater
		}
	}

	return d, nil
}

// bindCarriers binds every SPA carrier this policy configures: the UDP port
// always, and the HTTP one only when spa_http_port is set.
//
// The asymmetry between the two failures is deliberate. A UDP bind that fails
// is fatal, because that is the SPA port and a daemon without it is a daemon
// with no way in. An HTTP bind that fails is fatal too — and here that is the
// same answer for the opposite reason: an operator who configured the carrier
// did so because their network blocks UDP, so a carrier that silently did not
// come up would leave them with a host that looks armed and cannot be knocked
// from the place they need to knock it. Refusing at construction surfaces it
// in the journal at the moment it can still be fixed, rather than during the
// outage.
func bindCarriers(policy *config.Policy, now func() time.Time) (Receiver, PortRebinder, error) {
	if policy.PortRotation != nil {
		r := policy.PortRotation
		w := knockport.Window(now().Unix(), r.Window)
		live := knockport.LiveSet(r.Secret, w, r.RangeLo, r.RangeHi)
		udp, err := newRotatingUDPReceiver(live, policy.AlwaysAllowIface)
		if err != nil {
			return nil, nil, fmt.Errorf("agent: bind rotating spa ports %v: %w", live, err)
		}
		if policy.SPAHTTPPort == 0 {
			return udp, udp, nil
		}
		httpRecv, err := NewHTTPReceiver(policy.SPAHTTPPort)
		if err != nil {
			_ = udp.Close()
			return nil, nil, fmt.Errorf("agent: bind spa http carrier port %d: %w", policy.SPAHTTPPort, err)
		}
		// udp is the primary for the same reason it is below: it is the only
		// carrier that can report a packet as having arrived on the
		// always-allow path, and so the only one a liveness pong can ever be
		// sent back through.
		return newMultiReceiver(udp, udp, httpRecv), udp, nil
	}

	udp, err := NewUDPReceiver(policy.SPAPort, policy.AlwaysAllowIface)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: bind spa port %d: %w", policy.SPAPort, err)
	}
	if policy.SPAHTTPPort == 0 {
		return udp, nil, nil
	}
	httpRecv, err := NewHTTPReceiver(policy.SPAHTTPPort)
	if err != nil {
		_ = udp.Close()
		return nil, nil, fmt.Errorf("agent: bind spa http carrier port %d: %w", policy.SPAHTTPPort, err)
	}
	// udp is the primary: it is the only carrier that can report a packet as
	// having arrived on the always-allow path, and so the only one a liveness
	// pong can ever be sent back through.
	return newMultiReceiver(udp, udp, httpRecv), nil, nil
}

// Puller reports the bundle puller this daemon runs, or nil in standalone
// mode. Exported so a caller — production wiring, or a test driving PullOnce
// directly instead of waiting on Run's own interval — can reach it.
func (d *Daemon) Puller() *Puller { return d.puller }

// Beater reports the heartbeat emitter this daemon runs, or nil unless
// Options.Beat was set. Exported for the same reason Puller is: production
// wiring and a test driving BeatOnce directly both need it.
func (d *Daemon) Beater() *Beater { return d.beater }

// collectBeatBody gathers this beat's telemetry, taking d.mu for no longer
// than each individual read — never held across anything that could block —
// the same discipline currentPolicy and Health already follow, and the same
// reason: this runs from the Beater's own goroutine, on its own schedule,
// and must never be a second way to contend for a lock the packet path
// needs.
//
// It populates what the agent can compute cheaply today: AgentVersion,
// BundleVersion, ConfigHash, AgentUpHealthy, and the SPA counters since
// start. ListenerStatus, GateElements and ClockSkewMS are left at their zero
// value here — the body is JSON and additive precisely so a later phase can
// fill them in without a format change (see internal/attest/beat.go), and
// populating GateElements would mean reading the firewall backend from a
// second goroutine, a concurrency question this task does not settle.
func (d *Daemon) collectBeatBody() attest.Body {
	return attest.Body{
		AgentVersion:   version.Version(),
		BundleVersion:  d.currentPolicy().Revision,
		ConfigHash:     d.configHash(),
		AgentUpHealthy: d.agentUpHealthy(),
		SPAAccepted:    d.Stats().Accepted,
		SPARejected:    d.Stats().Rejected,
	}
}

// agentUpHealthy reads the live half of Health directly, rather than through
// Health() itself: Health() prioritises the live signal but falls back to
// the standing one when agent_up is green, and a beat's AgentUpHealthy field
// is documented (design section 8) as the live renewal signal specifically —
// folding the standing condition in here would answer a different question
// than the field's name asks.
func (d *Daemon) agentUpHealthy() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.agentUp.Red
}

// configHash reports a hex sha256 of the running policy's standalone-YAML
// encoding, computed fresh on every beat. It is a fact about what this host
// is currently enforcing, not a claim about drift: comparing it across beats
// or across hosts is the ruleset-hash source design section 8 lists among
// Phase B's drift detection, and is out of scope here (see the Phase-A task
// brief's explicitly-deferred list).
func (d *Daemon) configHash() string {
	data, err := config.MarshalStandalone(d.currentPolicy())
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Policy reports the policy this daemon is currently validating packets
// against. In standalone mode it never changes after construction; once a
// bundle puller is configured it can change at any time, from applyBundlePolicy,
// which is why this goes through the same lock-guarded read the packet loop
// uses rather than returning the field directly.
func (d *Daemon) Policy() *config.Policy { return d.currentPolicy() }

// resolveMetrics decides what the daemon will publish and where.
//
// A Recorder with no listener is legitimate and is what the agent's own tests
// use: the metrics are still updated by the real packet loop, they just are
// not served. A listener with no Recorder builds one, because an endpoint
// serving nothing is worse than no endpoint.
func resolveMetrics(opts Options) (netip.AddrPort, *metrics.Recorder, error) {
	recorder := opts.Metrics
	if opts.MetricsListen == "" {
		return netip.AddrPort{}, recorder, nil
	}
	lookup := opts.MetricsInterfaceAddrs
	if lookup == nil {
		lookup = metrics.SystemInterfaceAddrs
	}
	addr, err := metrics.ResolveBind(opts.MetricsListen, opts.Policy.AlwaysAllowIface, lookup)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	if recorder == nil {
		recorder = metrics.New()
	}
	// The identity the external probe joins on. Published here rather than at
	// first beat because a host whose agent is red from the first second still
	// has to be joinable — a join key that only appears once things are working
	// is a join key that is absent exactly when it is needed.
	recorder.SetHostID(hex.EncodeToString(opts.Policy.HostID[:]))
	return addr, recorder, nil
}

// Metrics reports the recorder this daemon publishes into, or nil.
func (d *Daemon) Metrics() *metrics.Recorder { return d.metrics }

// MetricsAddr reports the address the /metrics endpoint was resolved to,
// and once Run has bound it, the address it is actually serving on. It is the
// invalid zero value when no endpoint is served, and it is never an
// unspecified address — see metrics.ResolveBind and metrics.Listen.
func (d *Daemon) MetricsAddr() netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.metricsAddr
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// PreArm reports what pre-arm decided. Valid after Run has started.
func (d *Daemon) PreArm() PreArm {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.prearm
}

// Health reports the daemon's current self-assessment. A failed agent_up
// renewal takes precedence when both are red: it is the condition that has
// already broken SPA silence, so it is the one an operator must see first.
func (d *Daemon) Health() Health {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.agentUp.Red {
		return d.agentUp
	}
	if d.standing.Red {
		return d.standing
	}
	return d.agentUp
}

// Stats reports the SPA counters since start.
func (d *Daemon) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// Run is the agent. Its non-nil returns, which callers map to exit codes,
// are:
//
//   - ErrInert — the agent armed nothing and never became reachable. A
//     global pre-arm precondition failed, or the arm step could not arm the
//     configuration, or postern_open could not be created, or the very first
//     agent_up renewal did not land. All of them leave the host in the same
//     place: nothing armed, no SPA, and a cause that may clear on its own, so
//     systemd should retry rather than give up.
//   - ErrIncapacitated — the replay store proved unusable mid-run. The agent
//     has already silenced agent_up and torn down its tables.
//   - a receive error, if the socket fails for a reason other than shutdown.
//
// A cancelled ctx returns nil.
//
// Run owns the background loops it starts and does not return until they
// have stopped or loopStopTimeout has elapsed, so a caller that has seen Run
// return knows the agent is no longer writing anything. A loop that does not
// stop in time is logged, at ERROR, naming the loop; it does not become a
// fourth non-nil return. Three reasons, in order of weight. The returns above
// each describe a host that is unprotected or unreachable and each maps to a
// systemd outcome that fits it, where by the time this wait runs agent_up is
// already silenced and the tables are already torn down: the teardown that
// matters has completed, and reporting a failed stop would describe a host
// that is in exactly the state a clean stop leaves. Under Restart=always the
// exit status changes nothing systemd does about the process, so the only
// thing a non-nil return would alter is what `systemctl stop` prints, which
// would be a false alarm on the one path where an operator can act least.
// And giving up costs nothing further: Run returning means main returns and
// the process exits, which ends the loop anyway, and both loops' state writes
// are atomic, so the outcome of giving up is the outcome that existed before
// this wait did.
//
// Returning on inert rather than idling is deliberate. Type=notify plus
// WatchdogSec means an agent that never announces readiness is a startup
// failure to systemd, which is exactly what an unsatisfied global
// precondition is; RestartSec then retries it, so a precondition that clears
// (a filesystem remounted read-write, nft installed) heals without an
// operator. An agent that idled instead would sit there, never ready, until
// TimeoutStartSec killed it anyway — with a less obvious reason in the
// journal.
func (d *Daemon) Run(ctx context.Context) error {
	// The exposition endpoint comes up first and comes down last, so an
	// operator watching a host through its metrics sees the pre-arm verdict
	// on a host that then goes inert, rather than a target that vanished.
	stopMetrics := d.serveMetrics()
	defer stopMetrics()

	pre := RunPreArm(ctx, d.currentPolicy(), d.checks)
	d.mu.Lock()
	d.prearm = pre
	d.mu.Unlock()
	d.recordPreArm(pre)

	if pre.Inert() {
		d.log.Error("pre-arm failed", "summary", pre.Summary())
		return fmt.Errorf("%w: %s", ErrInert, pre.Summary())
	}

	// The arm step sits between the two halves of pre-arm, and the position is
	// forced from both sides. It must come after the global preconditions,
	// because arming a ruleset on a host with no nft(8) or an unwritable
	// replay store is exactly what "inert" exists to prevent. It must come
	// before the per-service ones are believed, because PortsArmable resolves
	// a fail-closed service's sets in the live postern_boot table — on a first
	// arm that table does not exist yet, so every fail-closed service would be
	// disabled by a check asking about a ruleset this step is about to load.
	//
	// So: pre-arm decides whether to arm at all, the arm happens, and the
	// per-service verdicts are then re-taken against the ruleset that is
	// actually live. Nothing between the two runs can change a global
	// precondition's answer.
	armed, err := d.armIfNewRevision(ctx)
	if err != nil {
		// ErrInert for the same reason a failed ApplyOpen is: nothing is
		// armed, nothing became reachable, and the cause may clear on a retry.
		return fmt.Errorf("%w: %v", ErrInert, err)
	}
	if armed {
		pre = RunPreArm(ctx, d.currentPolicy(), d.checks)
		d.mu.Lock()
		d.prearm = pre
		d.mu.Unlock()
		d.recordPreArm(pre)
		if pre.Inert() {
			d.log.Error("pre-arm failed after arming", "summary", pre.Summary())
			return fmt.Errorf("%w: %s", ErrInert, pre.Summary())
		}
	}

	d.log.Info("pre-arm", "summary", pre.Summary())
	for name, why := range pre.Disabled {
		d.log.Warn("service disabled by pre-arm", "service", name, "reason", why)
	}
	// Warnings are the findings that deliberately did not keep the agent
	// inert (today: a degraded always-allow path). They get their own line
	// at WARN rather than only riding on the summary, because the whole
	// point of not making them an interlock is that someone has to notice
	// them instead.
	for _, why := range pre.Warnings {
		d.log.Warn("pre-arm warning; armed anyway", "reason", why)
	}

	// postern_open is the agent's own table: created here, removed on exit.
	if d.armer != nil {
		if err := d.armer.ApplyOpen(ctx); err != nil {
			// ErrInert for the same reason the failed startup beat is: the
			// agent armed nothing and never became reachable, and the cause
			// may clear on a retry. Left unsentinelled this was Run's fourth
			// non-nil return, and a caller matching the documented three
			// would have attributed it to the SPA socket.
			return fmt.Errorf("%w: could not create %s: %v", ErrInert, gate.TableOpen, err)
		}
	}

	// loops is read at teardown, not here: the closure sees whatever Run has
	// appended by the time it runs, and on the early returns below that is
	// nothing, which is the right answer for a Run that never started one.
	var loops []backgroundLoop
	defer func() { d.shutdown(ctx, loops) }()

	// The first beat gates readiness, and its failure is fatal where a later
	// one is not. The asymmetry is deliberate. A failed renewal means the
	// write into agent_up did not land, which means postern_boot is not
	// there — and design section 6 is explicit that an absent postern_boot
	// leaves the SPA port *unconcealed* as well as unreachable, because the
	// guard rules are gone and the chain policy is accept. Announcing
	// READY=1 from that state hands systemd an active, ready unit for up to
	// WatchdogSec while the host advertises a service it cannot provide and
	// no longer hides. A later failure is different only because the agent
	// has already proven it can renew, so a transient netlink error is worth
	// riding out for one beat with the watchdog unfed.
	if err := d.beat(ctx); err != nil {
		// Reported as ErrInert rather than as its own sentinel: the observable
		// state is identical to a failed global precondition — nothing armed,
		// nothing reachable, a cause that may clear without an operator — and
		// a caller mapping returns to exit codes would give the two the same
		// code anyway. The message carries the distinction that matters.
		return fmt.Errorf("%w: initial agent_up renewal failed, so the SPA port is neither "+
			"concealed nor openable; refusing to announce readiness: %v", ErrInert, err)
	}
	_ = d.notify("READY=1")

	ticks, stopTicker := d.tickSource()
	defer stopTicker()

	// loopCtx, not ctx. Run returns for reasons other than cancellation (a
	// receive error, an unusable replay store), and on those paths ctx is
	// still live, so a loop selecting on it would never be told to stop and
	// the wait below would burn its whole bound on an ordinary exit. This
	// cancels on every return from Run, cancellation or not.
	loopCtx, stopLoops := context.WithCancel(ctx)
	// Registered after shutdown's defer and therefore run before it: the
	// loops are told to stop first, the teardown then runs, and only after
	// the teardown does anything wait. See shutdown for why that order is
	// the one the split-plane invariant requires.
	defer stopLoops()

	received := make(chan Datagram)
	recvErr := make(chan error, 1)
	loops = append(loops, startLoop(receiveLoopName, func() {
		d.receiveLoop(loopCtx, received, recvErr)
	}))

	// The bundle puller, like receiveLoop, is a goroutine this select never
	// waits on. Nothing it does against the hub — connect, fetch, verify —
	// touches a lock this loop takes, so a hub that accepts a connection and
	// never answers cannot delay a single iteration of the loop that follows.
	//
	// Once a bundle has verified, applyBundlePolicy does contend with this
	// loop, twice: d.mu for the instant of the policy swap, and Transactions'
	// own mutex for the length of the arm, which includes subprocess
	// execution. Only the second is more than instantaneous, it is bounded by
	// applyBundlePolicyTimeout, and reaching it at all requires a signature
	// from a signer this host's own local config names. See Transactions' doc
	// comment for why that lock cannot be narrowed.
	if d.puller != nil {
		loops = append(loops, startLoop(pullLoopName, func() { d.puller.Run(loopCtx) }))
	}
	// The heartbeat emitter, like the puller, is a goroutine this select
	// neither waits on nor can be blocked by: it shares no lock with the
	// packet path (collectBeatBody takes d.mu for nothing slower than each
	// individual read), so a hub that accepts a connection and never answers
	// a heartbeat cannot delay, let alone stop, a single iteration of the
	// loop that follows any more than an unreachable hub can stop a pull.
	if d.beater != nil {
		loops = append(loops, startLoop(beatLoopName, func() { d.beater.Run(loopCtx) }))
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case err := <-recvErr:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("agent: receive: %w", err)

		case dg := <-received:
			// Handling and renewal share one loop and therefore one
			// definition of liveness: a handler that wedges stops the
			// renewal too, the lease lapses, and the SPA port goes silent —
			// rather than staying open and accepting into an agent that does
			// nothing with what it receives (design section 7).
			if err := d.handle(ctx, dg); err != nil {
				return err
			}
			d.checkDeadMan(ctx)
			// Deliberately discarded: beat has already logged this and
			// driven the red transition, and it withheld WATCHDOG=1, so a
			// persistent failure escalates to a restart on systemd's
			// schedule. Ending the run here instead would turn one bad
			// netlink call into an outage.
			_ = d.beat(ctx)

		case <-ticks:
			d.checkDeadMan(ctx)
			_ = d.beat(ctx)
		}
	}
}

// Names for the background loops Run starts, used in the line shutdown logs
// when one of them does not stop. They are the operator's whole diagnosis:
// "a loop did not stop" says nothing they can act on, and which loop it was
// says which plane is wedged.
const (
	receiveLoopName = "receive"
	pullLoopName    = "pull"
	beatLoopName    = "beat"
)

// backgroundLoop is one goroutine Run started, and a channel closed when it
// returns.
//
// Per-loop channels rather than one sync.WaitGroup, and the reason is the
// log line: a WaitGroup can say that something is still running and cannot
// say what, so the bound would expire into a message an operator cannot act
// on. Waiting on named channels against a single deadline costs the same and
// keeps the name.
type backgroundLoop struct {
	name string
	done chan struct{}
}

// startLoop runs f in its own goroutine and returns the record shutdown
// waits on.
func startLoop(name string, f func()) backgroundLoop {
	l := backgroundLoop{name: name, done: make(chan struct{})}
	go func() {
		defer close(l.done)
		f()
	}()
	return l
}

// waitLoops blocks until every loop has returned or bound elapses, and
// reports the ones still running when it gave up, in the order they were
// started.
//
// The bound covers the set rather than each loop in turn, so a caller cannot
// be held for a multiple of it by having started several.
func waitLoops(loops []backgroundLoop, bound time.Duration) []string {
	timer := time.NewTimer(bound)
	defer timer.Stop()

	for i, l := range loops {
		select {
		case <-l.done:
			continue
		case <-timer.C:
			var stuck []string
			for _, rest := range loops[i:] {
				select {
				case <-rest.done:
				default:
					stuck = append(stuck, rest.name)
				}
			}
			return stuck
		}
	}
	return nil
}

// serveMetrics brings up the exposition endpoint and returns its shutdown.
//
// A bind failure here is logged and survived rather than fatal, and the
// asymmetry with New's refusal is the point: New refuses a bind that design
// section 8 forbids, which is a configuration error and must never run. This
// is a bind that was permitted and did not work today — a port already taken,
// an address that has not come back yet after a mesh flap — and taking the
// break-glass daemon down because its monitoring port was busy would let a
// monitoring problem produce the outage monitoring exists to catch.
func (d *Daemon) serveMetrics() func() {
	want := d.MetricsAddr()
	if !want.IsValid() || d.metrics == nil {
		return func() {}
	}
	ln, err := metrics.Listen(want)
	if err != nil {
		d.log.Error("could not serve the metrics endpoint; the agent is running without one",
			"addr", want.String(), "err", err)
		return func() {}
	}
	// Republished from the socket, so a caller that asked for port 0 can find
	// out what it got — and so MetricsAddr always describes something that is
	// really bound rather than something that was merely requested.
	if bound, ok := ln.Addr().(*net.TCPAddr); ok {
		if ap := bound.AddrPort(); ap.IsValid() {
			d.mu.Lock()
			d.metricsAddr = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			d.mu.Unlock()
		}
	}
	d.log.Info("serving metrics", "addr", ln.Addr().String())
	srv := metrics.Serve(ln, d.metrics.Handler())
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}
}

// recordPreArm publishes pre-arm's verdict: the global one as a single inert
// gauge, and the per-service ones as one gauge per gate service. Every gate
// service is published, not only the disabled ones, so an alert can say "ssh
// is not armed" rather than having to infer it from a series that is absent.
func (d *Daemon) recordPreArm(pre PreArm) {
	d.metrics.SetInert(pre.Inert())
	for name, svc := range d.currentPolicy().Services {
		if svc.Kind != config.KindGate {
			continue
		}
		// ServiceEnabled, not the Disabled map alone: a global precondition
		// failure never populates Disabled but disables every service, so
		// reading Disabled directly would publish armed=1 for a service the
		// knock path is refusing. This gauge must match the decision apply
		// actually makes, which is prearmed() -> ServiceEnabled().
		d.metrics.SetServiceArmed(name, pre.ServiceEnabled(name))
	}
}

// recordGateState reads back what each gate is currently admitting and
// publishes the counts. It runs on the beat rather than being maintained
// incrementally from Open, because gate elements expire on their own timeout:
// a counter maintained from this side would only ever go up.
func (d *Daemon) recordGateState(ctx context.Context) {
	if d.metrics == nil {
		return
	}
	for name, svc := range d.currentPolicy().Services {
		if svc.Kind != config.KindGate {
			continue
		}
		st, err := d.gate.State(ctx, name)
		if err != nil {
			// Not a health transition. A gate whose set cannot be read is
			// already covered by pre-arm and by agent_up; failing the beat
			// over a metrics read would let the exposition endpoint decide
			// whether the SPA port stays open.
			//
			// Logged on the transition and not on the state. A missing table
			// does not heal on its own, so an unconditional line here repeats
			// once per service per beat forever — and the state it repeats
			// through is exactly the one an operator would be reading the
			// journal in, where the signal they need is buried under a page of
			// this. The recovery is logged too: an error that stops without a
			// line saying so leaves a reader with a permanent last-known-bad.
			if !d.gateStateErr[name] {
				d.markGateStateErr(name, true)
				d.log.Warn("gate state is unreadable, so its metrics have stopped moving",
					"service", name, "err", err)
			}
			continue
		}
		if d.gateStateErr[name] {
			d.markGateStateErr(name, false)
			d.log.Info("gate state is readable again", "service", name)
		}
		var observed, asserted int
		for _, el := range st.Elements {
			if el.Source.Kind == gate.SourceAsserted {
				asserted++
			} else {
				observed++
			}
		}
		d.metrics.SetGateOpenSources(name, observed, asserted)
	}
}

func (d *Daemon) markGateStateErr(service string, failing bool) {
	if d.gateStateErr == nil {
		d.gateStateErr = map[string]bool{}
	}
	d.gateStateErr[service] = failing
}

func (d *Daemon) tickSource() (<-chan time.Time, func()) {
	if d.ticks != nil {
		return d.ticks, func() {}
	}
	t := time.NewTicker(d.heartbeatPeriod)
	return t.C, t.Stop
}

// receiveLoop is the only goroutine besides the packet loop, and it does
// exactly one thing: block on the socket. It deliberately holds no health
// signal and touches no state — everything that could wedge, and everything
// that renews the lease, lives in the single select in Run.
func (d *Daemon) receiveLoop(ctx context.Context, out chan<- Datagram, errc chan<- error) {
	for {
		dg, err := d.receiver.Receive(ctx)
		if err != nil {
			select {
			case errc <- err:
			case <-ctx.Done():
			}
			return
		}
		select {
		case out <- dg:
		case <-ctx.Done():
			return
		}
	}
}

// beat is the single definition of health design section 7 requires: it
// renews the agent_up lease and, only if that succeeded, feeds the watchdog.
// Two mechanisms observing one token is the correctness property; whether
// their intervals match is tuning.
//
// A failed renewal is its own immediate red transition (design section 8),
// not something drift detection discovers later: the write targets a set
// inside postern_boot, so a failure means that table is gone and SPA silence
// is already broken. It is not fatal — a transient netlink failure should
// recover on the next beat — but the watchdog goes unfed, so a persistent
// failure escalates to a restart on systemd's schedule rather than postern's.
func (d *Daemon) beat(ctx context.Context) error {
	// After the renewal, not before: reading gate state is the one thing on
	// this path that exists purely for the metrics, and it must never sit
	// between the loop arriving here and the lease being renewed.
	defer d.recordGateState(ctx)

	if r := d.currentPolicy().PortRotation; r != nil {
		if err := d.rotateAndRefresh(ctx, r); err != nil {
			d.metrics.AgentUpRenewal(false, d.now())
			d.setAgentUpHealth(Health{
				Red:    true,
				Reason: fmt.Sprintf("agent_up renewal failed: %v", err),
				At:     d.now(),
			})
			d.log.Error("agent_up renewal failed; SPA silence is already broken and the fail-closed drop "+
				"rules may be gone", "err", err)
			// Returned rather than swallowed, for the identical reason the
			// fixed-mode branch below returns it: both callers (Run's
			// startup beat and its steady-state one) treat this value
			// differently on purpose.
			return err
		}
	} else {
		if err := d.gate.RefreshAgentUp(ctx, d.agentUpTTL); err != nil {
			d.metrics.AgentUpRenewal(false, d.now())
			d.setAgentUpHealth(Health{
				Red:    true,
				Reason: fmt.Sprintf("agent_up renewal failed: %v", err),
				At:     d.now(),
			})
			d.log.Error("agent_up renewal failed; SPA silence is already broken and the fail-closed drop "+
				"rules may be gone", "err", err)
			// Returned rather than swallowed. Both callers see the same value
			// and treat it differently on purpose (see Run): the startup beat
			// refuses to announce readiness, the steady-state beat rides it out.
			// An earlier version returned nil unconditionally, which made both
			// of Run's error checks dead code and let READY=1 be announced from
			// a host whose SPA port was not concealed.
			return err
		}
	}
	d.metrics.AgentUpRenewal(true, d.now())
	if h := d.checkLease(ctx); h.Red {
		d.setAgentUpHealth(h)
		return nil
	}
	d.setAgentUpHealth(Health{At: d.now()})
	_ = d.notify("WATCHDOG=1")
	return nil
}

// rotateAndRefresh renews agent_up with the current window's live set every
// beat (so the dead-man ttl and its slack are unchanged from fixed mode) and
// rebinds the sockets only when the window advances.
func (d *Daemon) rotateAndRefresh(ctx context.Context, r *config.PortRotation) error {
	w := knockport.Window(d.now().Unix(), r.Window)
	live := knockport.LiveSet(r.Secret, w, r.RangeLo, r.RangeHi)
	if err := d.gate.RefreshAgentUpPorts(ctx, live, d.agentUpTTL); err != nil {
		return err
	}
	if d.rebinder != nil && (!d.haveWindow || w != d.lastWindow) {
		if err := d.rebinder.Rebind(ctx, live); err != nil {
			// A rebind failure is logged, not fatal: agent_up already holds the
			// new live set, so the neighbor windows whose sockets are already
			// bound still carry most knocks, and the next beat retries the bind.
			d.log.Error("could not rebind the rotating SPA sockets; some live ports may not be listening",
				"window", w, "ports", live, "err", err)
		} else {
			d.lastWindow, d.haveWindow = w, true
		}
	}
	return nil
}

// checkLease reads back what the kernel actually holds for agent_up, so a
// beat that reported success can be checked against what was really written
// (see checkAgentUpLease). Under rotation the port that matters is the one an
// operator would knock right now, so it reads AgentUpExpiryFor(port(w));
// otherwise it reads the fixed-mode AgentUpExpiry.
func (d *Daemon) checkLease(ctx context.Context) Health {
	if r := d.currentPolicy().PortRotation; r != nil {
		w := knockport.Window(d.now().Unix(), r.Window)
		port := knockport.Port(r.Secret, w, r.RangeLo, r.RangeHi)
		return d.checkAgentUpLease(ctx, func(ctx context.Context) (time.Duration, error) {
			return d.gate.AgentUpExpiryFor(ctx, port)
		})
	}
	return d.checkAgentUpLease(ctx, d.gate.AgentUpExpiry)
}

// checkAgentUpLease reads back what the kernel actually holds for agent_up and
// publishes when the SPA port will close. read is d.gate.AgentUpExpiry in
// fixed mode and a closure over d.gate.AgentUpExpiryFor(port(w)) under
// rotation (see checkLease); the logic below is identical either way.
//
// The renewal above returning nil is not evidence that the lease moved. It was
// not, for the whole life of this daemon before the fix in internal/gate: a
// re-add of a live element with an identical ttl is silently ignored, so every
// beat "succeeded" and changed nothing, the port went silent on the first
// add's clock, and the agent reported itself healthy the entire time. Nothing
// looked at the effect of the write.
//
// So this looks. A lease shorter than one heartbeat is red — the next beat is
// the last chance to renew it and something has already gone wrong — and an
// absent element immediately after a successful renewal is red on its face:
// invariant 1 says the SPA port is reachable only while agent_up holds it, so
// that is break-glass access already gone.
//
// A failed read is NOT red. It is a metrics-path read like recordGateState's,
// and letting it take the agent down would hand the exposition path a veto
// over whether the SPA port stays open.
func (d *Daemon) checkAgentUpLease(ctx context.Context, read func(context.Context) (time.Duration, error)) Health {
	left, err := read(ctx)
	if err != nil {
		if !d.agentUpReadErr {
			d.agentUpReadErr = true
			d.log.Warn("could not read back the agent_up lease, so nothing is checking that the SPA "+
				"port is actually open", "err", err)
		}
		return Health{At: d.now()}
	}
	if d.agentUpReadErr {
		d.agentUpReadErr = false
		d.log.Info("the agent_up lease is readable again")
	}

	d.metrics.SetAgentUpExpiry(d.now(), left)
	if left >= d.heartbeatPeriod {
		return Health{At: d.now()}
	}
	reason := fmt.Sprintf("agent_up renewal reported success but the lease has %s left, "+
		"less than one %s heartbeat", left.Round(time.Second), d.heartbeatPeriod)
	if left <= 0 {
		reason = "agent_up renewal reported success and the element is not in the set: the SPA port " +
			"is closed right now and no knock can reach this host"
	}
	d.log.Error("the SPA port is not open despite a successful agent_up renewal", "remaining", left)
	return Health{Red: true, Reason: reason, At: d.now()}
}

func (d *Daemon) count(accepted bool) {
	d.mu.Lock()
	d.stats.Received++
	if accepted {
		d.stats.Accepted++
	} else {
		d.stats.Rejected++
	}
	d.mu.Unlock()
	d.metrics.SPAHandled()
}

// setAgentUpHealth records the outcome of one beat. It touches only the live
// half.
func (d *Daemon) setAgentUpHealth(h Health) {
	d.mu.Lock()
	d.agentUp = h
	d.mu.Unlock()
	// The reason string is deliberately not published. It is error text —
	// netlink messages, paths — and a Prometheus label carrying it would be
	// both a disclosure and an unbounded series.
	d.metrics.SetHealthRed(metrics.HealthSourceAgentUp, h.Red)
}

// flagStanding records a condition that persists until something explicitly
// supersedes it, rather than until the next successful heartbeat.
func (d *Daemon) flagStanding(reason string) {
	d.mu.Lock()
	d.standing = Health{Red: true, Reason: reason, At: d.now()}
	d.mu.Unlock()
	d.metrics.SetHealthRed(metrics.HealthSourceStanding, true)
}

func (d *Daemon) clearStanding() {
	d.mu.Lock()
	d.standing = Health{}
	d.mu.Unlock()
	d.metrics.SetHealthRed(metrics.HealthSourceStanding, false)
}

// handle runs one datagram through the validation pipeline and applies what
// it authorizes. It returns a non-nil error only for conditions that must
// end the process; an ordinary rejection is logged and dropped, never
// answered — nothing here writes to the network, and relaying a rejection
// would turn the SPA port into an oracle.
func (d *Daemon) handle(ctx context.Context, dg Datagram) error {
	// Counted on the way out, after whatever this datagram authorized has
	// actually been applied, and on every exit path including the one that
	// ends the process — a datagram that incapacitated the agent was still
	// received, and a counter that skipped it would understate exactly the
	// traffic an operator would be looking at. Counting on the way in
	// instead would make Received a promise rather than a fact, and anything
	// reading it (self-attestation, or a test synchronising on progress)
	// would observe the packet before its effect.
	accepted := false
	defer func() { d.count(accepted) }()

	dec, err := Validate(dg.Payload, dg.Source.Addr(), d.currentPolicy(), d.currentOpener(), d.store, d.pendingTransaction(),
		dg.OnAlwaysAllowPath, d.now())
	if err != nil {
		// Counted by reason, never logged per packet: at the 20/second kernel
		// limit an individual record per rejection is roughly 1.7 million rows
		// a day, which turns the flood defense into an I/O attack (design
		// section 8). The source address is not a label either — it is
		// attacker-chosen, so it is unbounded by construction.
		d.metrics.SPARejected(rejectReason(err))
		// Both conditions, in this order. StoreUnusable alone answers
		// "is this a fatal store error assuming it came from the store" —
		// applied to every Validate error it would classify a malformed
		// datagram as a disk failure, handing anyone who can reach the SPA
		// port a one-packet shutdown. ErrStore is what establishes the
		// assumption StoreUnusable is documented under.
		if errors.Is(err, ErrStore) && StoreUnusable(err) {
			// The Task 2 carry-forward's call site. Without it every packet
			// would still reject — fail-closed, bounded — but agent_up would
			// keep refreshing and the host would advertise health it does
			// not have.
			d.log.Error("replay store is unusable; incapacitating", "err", err)
			d.flagStanding("replay store unusable: " + err.Error())
			return errors.Join(ErrIncapacitated, Incapacitate(ctx, d.gate))
		}
		d.log.Debug("packet rejected", "err", err, "source", dg.Source.Addr().String())
		return nil
	}

	accepted = true
	d.metrics.SPAAccepted(dec.Service)
	// Skew is recorded only for a packet that got this far, because only an
	// authenticated, granted, non-replayed packet's timestamp is evidence
	// about a clock rather than about an attacker. It is recorded before the
	// decision is applied so a gate open that fails still contributes the
	// clock reading it carried.
	d.metrics.ObserveClockSkew(dec.Skew)
	if dec.FreshByCounterOnly {
		d.metrics.AcceptedBeyondFreshnessWindow()
	}
	d.apply(ctx, dec, dg)
	return nil
}

// apply executes an authorized Decision. Failures here are logged rather
// than fatal: a gate that could not be opened is a failed knock the operator
// retries, not a reason to take the agent down and with it every other
// service's SPA.
func (d *Daemon) apply(ctx context.Context, dec Decision, dg Datagram) {
	switch dec.ServiceKind {
	case config.KindGate:
		if !d.prearmed(dec.Service) {
			// Pre-arm disabled this service. Refusing here is what makes
			// "only that service is disabled" an enforcement rather than a
			// report: the ruleset was never armed for it, so opening it
			// would punch a hole in rules that do not exist.
			d.log.Warn("refusing to open a service pre-arm disabled", "service", dec.Service)
			return
		}
		if err := d.gate.Open(ctx, dec.Service, dec.Source, dec.TTL); err != nil {
			d.metrics.GateOpenFailed(dec.Service)
			d.log.Error("gate open failed", "service", dec.Service, "err", err)
			return
		}
		// The last-successful-open timestamp moves here and nowhere else.
		// Authorization is not an open: the SPA path never replies, so the
		// client cannot prove the gate acted, and the only place in the whole
		// system that knows an element was genuinely installed is this line,
		// after the backend returned success.
		d.metrics.GateOpened(dec.Service, d.now())
		d.log.Info("gate opened", "service", dec.Service, "source", dec.Source.Prefix.String(), "ttl", dec.TTL)

	case config.KindAction:
		d.applyAction(ctx, dec, dg)
	}
}

func (d *Daemon) applyAction(ctx context.Context, dec Decision, dg Datagram) {
	switch dec.Service {
	case "confirm":
		if err := d.commitTransaction(ctx, dec.PendingRevision, dec.DeploymentNonce); err != nil {
			d.log.Error("confirm failed", "err", err)
			return
		}
		d.log.Info("transaction confirmed", "revision", dec.PendingRevision)

	case "disarm":
		if err := d.disarm(ctx); err != nil {
			d.log.Error("disarm failed", "err", err)
			return
		}
		d.log.Warn("host disarmed by operator action")

	case "liveness":
		d.pong(ctx, dec, dg)
	}
}

// pong is the only transmission postern ever makes. The defensive
// always-allow check duplicates one Validate already performed: this is the
// single call site that puts bytes on the wire, so it does not delegate the
// condition that makes transmitting safe.
func (d *Daemon) pong(ctx context.Context, dec Decision, dg Datagram) {
	if !dg.OnAlwaysAllowPath {
		d.log.Error("refusing to answer a liveness ping that did not arrive on the always-allow path")
		return
	}
	if d.host == nil {
		d.log.Error("cannot answer liveness: no host signing identity is configured")
		return
	}

	p := &spa.Pong{
		Version:     spa.Version1,
		Alg:         spa.AlgEd25519X25519,
		HostID:      d.currentPolicy().HostID,
		RequestID:   dec.RequestID,
		Challenge:   dec.Challenge,
		TimestampMS: uint64(d.now().UnixMilli()), //nolint:gosec // a unix-millisecond clock is non-negative for any real time
	}
	out, err := spa.SignPong(p, d.host)
	if err != nil {
		d.log.Error("signing pong failed", "err", err)
		return
	}
	// Padded to a random length before it leaves, so the pong is not a second
	// constant size on the wire. The client slices off the PongSize prefix.
	out, err = spa.Pad(out)
	if err != nil {
		d.log.Error("padding pong failed", "err", err)
		return
	}
	if err := d.receiver.Reply(ctx, dg.Source, dg.LocalPort, out); err != nil {
		d.log.Error("sending pong failed", "err", err)
	}
}

func (d *Daemon) prearmed(service string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.prearm.ServiceEnabled(service)
}

// currentPolicy is every read of d.policy off the packet loop and off
// applyBundlePolicy. It takes mu for exactly the read, never for anything
// slower, which is what lets a bundle pull's fetch — arbitrarily slow,
// arbitrarily hostile — run concurrently with every packet Validate
// resolves against whatever policy was current at the instant it asked.
func (d *Daemon) currentPolicy() *config.Policy {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.policy
}

// setPolicy swaps the running policy AND the two things derived from it that
// a packet is decided by: the SPA opener's precomputed shared secrets, and
// the gate's own view of the service catalogue.
//
// Swapping the policy pointer alone was a silent no-op for the central
// feature of fleet mode. An operator added by a bundle passes Validate's
// grant check — that walks the current policy — and then TrialOpen holds no
// precomputed X25519 shared secret for their key, so their datagram never
// decrypts and their knock is refused in silence until posternd restarts. A
// gate service added by a bundle is the same shape one step later:
// gate.NFTables.Open answers "%q is not a known gate service" from the
// catalogue it was constructed with, after Validate has passed and after the
// replay store has already consumed that packet's slot.
//
// Removal never had this problem, because Policy.Grants walks the current
// policy — so the defect was fail-closed rather than an escalation, which is
// why it survived to a live fleet.
//
// Two things it deliberately does not do. It does not fail: an opener that
// cannot be rebuilt leaves the previous one in place and logs, because every
// operator the new policy removed is already refused by Validate against the
// new policy, and a daemon that tore itself down over a key it could not
// precompute would be the control plane taking out the packet plane again. And
// it holds mu for exactly the swap — the opener is built before the lock is
// taken, never under it.
//
// It is called from applyBundlePolicy after a genuine arm, and from the
// dead-man revert, which is the other direction of the same requirement: after
// a revert the kernel is back on the old revision, so the running policy has
// to be too.
func (d *Daemon) setPolicy(p *config.Policy) {
	opener := d.buildOpener(p)

	d.mu.Lock()
	d.policy = p
	if opener != nil {
		d.opener = opener
	}
	d.mu.Unlock()

	// The gate's catalogue, after the swap rather than before it: a packet
	// that resolved against the old policy must never be applied against the
	// new gate, and Validate and Open are one step apart on the packet loop.
	if r, ok := d.gate.(PolicyReloader); ok {
		if err := r.SetPolicy(p); err != nil {
			d.log.Error("the gate could not adopt the new policy, so a service this revision adds "+
				"cannot be opened until posternd restarts", "err", err)
		}
	}
}

// PolicyReloader is a Gate that can rebuild its view of the service catalogue
// from a new policy. *gate.NFTables satisfies it.
//
// It is an optional interface rather than a method on gate.Gate because a
// backend that resolves services per call has nothing to rebuild, and adding
// a method every implementation must write in order to do nothing is how an
// interface acquires a method somebody implements wrongly. A Gate that does
// not satisfy it keeps whatever catalogue it was built with, which is what
// every mode before M2 did.
type PolicyReloader interface {
	SetPolicy(policy *config.Policy) error
}

// buildOpener precomputes the shared secrets for p's operators, or returns
// nil when it cannot — a daemon built without a host signing identity (some
// tests), or a policy in which every operator's encryption key is unusable.
//
// nil means "keep the opener you have". That is the fail-closed answer: the
// operators a bad policy would have added cannot knock either way, and the
// ones it would have removed are refused by Validate against the new policy
// regardless of what the opener holds.
func (d *Daemon) buildOpener(p *config.Policy) *spa.Opener {
	if d.host == nil {
		return nil
	}
	operators := make([]identity.PublicIdentity, 0, len(p.Operators))
	for _, op := range p.Operators {
		operators = append(operators, op.Identity)
	}
	opener, rejected, err := spa.NewOpenerFromSigner(d.host, operators)
	for _, name := range rejected {
		// Loudly not silent, the same way runAgent reports it at startup: one
		// bad key must not stop the others, but that operator can never knock
		// this host and nothing else would say so.
		d.log.Warn("operator key rejected by the new policy; this operator cannot knock this host",
			"operator", name)
	}
	if err != nil {
		d.log.Error("the new policy has no usable operator key, so the previous operator set stays "+
			"loaded; every operator it names is still refused by the grant check", "err", err)
		return nil
	}
	return opener
}

// currentOpener is every read of d.opener off the packet loop, taking mu for
// exactly the read — the same discipline currentPolicy follows, and for the
// same reason: applyBundlePolicy can replace it at any time.
func (d *Daemon) currentOpener() *spa.Opener {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.opener
}

// shutdown runs on every return from Run. It silences agent_up first, so the
// SPA port stops being reachable at once rather than for the remainder of
// the lease pointing at a process that has exited — something ExecStopPost
// cannot do, since it only reaches the gate sets and postern_open. Then it
// performs the same teardown ExecStopPost would, so a clean stop does not
// depend on systemd running those lines at all.
//
// ctx is already done by the time this runs, so it is detached: a teardown
// that skipped itself because the context was cancelled would leave exactly
// the state this exists to prevent.
//
// The order of the two halves is the split-plane invariant, not a
// preference. Every step that touches the knock path, meaning silencing
// agent_up, emptying the gate and closing the receiver, runs to completion
// BEFORE
// anything waits on a background loop. The puller and the heartbeat emitter
// are the management plane, and a wedged one of them delays Run's return and
// the heartbeat state file's close; it cannot delay, by any amount, the
// instant the SPA port stops being reachable. An unbounded Wait placed ahead
// of this teardown would be worse than slow on a real host: udpReceiver's
// Receive blocks in recvmsg and does not observe a cancelled context at all,
// so closing the socket is what ends the receive loop, and waiting for that
// loop before closing its socket would never return.
//
// loops may be empty, which is what Run's early returns hand it.
func (d *Daemon) shutdown(ctx context.Context, loops []backgroundLoop) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if err := d.gate.SilenceAgentUp(ctx); err != nil {
		d.log.Error("silencing agent_up on shutdown failed", "err", err)
	}
	if err := d.gate.Close(ctx); err != nil {
		d.log.Error("closing the gate on shutdown failed", "err", err)
	}
	if d.receiver != nil {
		if err := d.receiver.Close(); err != nil {
			d.log.Error("closing the receiver failed", "err", err)
		}
	}

	// Waited for rather than left running, because both management-plane
	// loops write a file whose whole purpose is to survive this process. The
	// puller records the version it installed, which is what lets a restart
	// recognise an older but validly signed bundle as a rollback; the
	// heartbeat emitter records the (epoch, sequence) that stops a restart
	// reusing a sequence the hub has already seen. Both writes are atomic, so
	// a process that exits mid-write corrupts nothing. What it loses is the
	// record, silently, at the one moment nobody is reading logs.
	stuck := waitLoops(loops, loopStopTimeout)
	if len(stuck) > 0 {
		// Logged rather than returned. See Run's doc comment for why a loop
		// that will not stop is not one of Run's error returns.
		d.log.Error("background loops did not stop within the shutdown timeout; their state files may "+
			"be missing this run's last write, and a restart would read the previous one",
			"loops", strings.Join(stuck, ","), "timeout", loopStopTimeout)
	}

	// After the wait, and skipped entirely if the beat loop is one of the
	// ones that did not stop. Close syncs and closes the state file under the
	// same mutex the loop holds across its own fsync, so closing underneath a
	// running loop is both the use-after-close its own doc comment rules out
	// and, if that fsync is what wedged, a block with no bound at all, which
	// would spend the timeout above and then hang anyway. An unclosed
	// descriptor is released by process exit, and the flock with it.
	if d.beater != nil && !slices.Contains(stuck, beatLoopName) {
		if err := d.beater.Close(); err != nil {
			d.log.Error("closing the heartbeat state file failed", "err", err)
		}
	}
}
