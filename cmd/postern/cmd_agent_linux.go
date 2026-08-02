//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

func init() {
	register(&command{
		name:    "agent",
		usage:   "agent --config /etc/postern/postern.yaml [flags]",
		summary: "run posternd: bind the SPA port, validate packets, open gates (Linux, root)",
		run:     runAgent,
	})
}

// runAgent wires the daemon and maps its four returns onto exit codes.
//
// The mapping is the interface systemd reads, and each case means something
// different to it:
//
//   - nil: the context was cancelled. An ordinary stop.
//   - ErrInert: nothing was armed and the agent never became reachable. All
//     the causes — a failed global precondition, postern_open not creatable,
//     a first agent_up renewal that did not land — may clear on their own,
//     so RestartSec should retry.
//   - ErrIncapacitated: the replay store proved unusable mid-run. agent_up
//     is already silenced and the tables torn down. Retrying blindly will
//     not help.
//   - anything else: the SPA socket failed.
//
// errors.Is is the supported check against the two sentinels; Run wraps both
// with context, so == would silently fall through. exitCode does the
// mapping and is asserted by a test.
func runAgent(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "agent", "agent --config /etc/postern/postern.yaml [flags]")
	configPath := fs.String("config", filepath.Join(defaultStateDirs.etc, "postern.yaml"), "standalone config path")
	keyPath := fs.String("host-key", "", "host identity file (default: host.key beside the config)")
	stateDir := fs.String("state-dir", defaultStateDirs.state, "where the replay store and recorded hashes live")
	bootNFT := fs.String("boot-nft", "", "generated boot ruleset (default: boot.nft beside the config)")
	// Set by init-standalone in the fleet-mode ExecStart it writes, empty
	// otherwise. It is where posternd.service's per-set flush drop-in lives, so
	// the daemon can rewrite it as bundles change the fail-closed catalogue and
	// keep the teardown flush lines in step with boot.nft (#47). A standalone
	// host never applies a bundle, so it is never handed one.
	flushDropIn := fs.String("flush-dropin", "",
		"posternd.service.d/flush.conf `path` the daemon regenerates as bundles change the gate catalogue "+
			"(fleet mode only; set by init-standalone)")
	debug := fs.Bool("debug", false, "log rejected packets")
	confirmWindow := fs.Duration("confirm-window", agent.DefaultConfirmWindow,
		"how long an armed configuration waits for `postern confirm` before the dead-man timer reverts it")
	// Off unless asked for. /metrics on a root daemon holding the fleet's
	// gate state is an information-disclosure surface, so it is opt-in, and
	// where it may land is not the operator's choice to get wrong: an empty
	// host means the always-allow interface (falling back to loopback), an
	// explicit host must be loopback or on that interface, and a wildcard is
	// refused outright. See internal/metrics.ResolveBind.
	metricsListen := fs.String("metrics-listen", "",
		"serve Prometheus /metrics on this `address` (host:port, or :port for the always-allow interface); "+
			"empty serves nothing. Must be loopback or an address on the always-allow interface")
	// Only meaningful when the config's hub_url is set; both are ignored in
	// standalone mode. Zero selects each loop's own package default
	// (agent.DefaultPullInterval, agent.DefaultBeatInterval).
	pullInterval := fs.Duration("pull-interval", 0,
		"how often to fetch this host's own bundle from the fleet hub (fleet mode only; 0 selects the package default)")
	beatInterval := fs.Duration("beat-interval", 0,
		"how often to send a signed heartbeat to the fleet hub (fleet mode only; 0 selects the package default)")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	data, err := os.ReadFile(*configPath) //nolint:gosec // the operator named this path
	if err != nil {
		return usagef("read %s: %v", *configPath, err)
	}
	policy, err := config.ParseStandalone(data)
	if err != nil {
		return usageError{err}
	}
	if err := policy.Validate(); err != nil {
		return usageError{err}
	}

	dir := filepath.Dir(*configPath)
	if *keyPath == "" {
		*keyPath = filepath.Join(dir, "host.key")
	}
	if *bootNFT == "" {
		*bootNFT = filepath.Join(dir, "boot.nft")
	}

	// The host key carries no passphrase: it is unlocked unattended at every
	// boot and there is nobody to type one. See init-standalone.
	host, err := identity.LoadFile(*keyPath, nil)
	if err != nil {
		return usagef("load host identity %s: %v", *keyPath, err)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: level}))

	// The config just parsed is the enrollment bootstrap: the trust anchor the
	// pull loop authenticates bundles against, and the running config only until
	// the first bundle is confirmed. On a fleet host a prior confirm persisted
	// the fetched policy beside the other durable state, and running THAT rather
	// than the bootstrap is what stops a restart reverting the host to its
	// enrollment config (#52). Everything the daemon arms and validates against
	// — opener, gate, dispatcher, Options.Policy — is built from the effective
	// policy below; only the hub-facing pull and beat loops keep reading the
	// bootstrap, because the bundle signers and fleet identity that authenticate
	// a pull must stay anchored to the operator-written file, never to something
	// a bundle could one day carry.
	runningPolicyPath := ""
	if policy.HubURL != "" {
		runningPolicyPath = filepath.Join(*stateDir, "policy.yaml")
	}
	effective, err := agent.LoadRunningPolicy(policy, runningPolicyPath, log)
	if err != nil {
		return err
	}

	operators := make([]identity.PublicIdentity, 0, len(effective.Operators))
	for _, op := range effective.Operators {
		operators = append(operators, op.Identity)
	}
	opener, rejected, err := spa.NewOpenerFromSigner(host, operators)
	if err != nil {
		return usageError{err}
	}

	// Config warnings before anything is armed, at WARN, on their own lines.
	// They name properties the operator chose that are worse than the default
	// and that this package cannot fix — today, a script-backed service's
	// missing expiry guarantee. A warning nobody is shown is the same as no
	// warning, and the whole point of not making these an interlock is that
	// someone has to notice them instead.
	for _, w := range effective.Warnings() {
		log.Warn("configuration warning", "detail", w)
	}
	for _, name := range rejected {
		// Not fatal, and loudly not silent: one bad key in a config must not
		// stop the agent opening packets for every other operator, but that
		// operator's packets can never pass and nothing else would say so.
		log.Warn("operator key rejected; this operator cannot knock this host", "operator", name)
	}

	storePath := filepath.Join(*stateDir, "replay.db")
	store, err := replay.Open(storePath, replay.Options{})
	if err != nil {
		return fmt.Errorf("open replay store %s: %w", storePath, err)
	}
	defer func() { _ = store.Close() }()

	g, err := gate.NewNFTables(effective)
	if err != nil {
		return fmt.Errorf("open the nftables backend: %w", err)
	}

	// The script backend is built only when a service asks for one, and it
	// never replaces the nftables gate: nftables keeps agent_up, the SPA
	// port, boot.nft and every fail-posture rule whatever the services
	// declare. Every path check runs here, at load, so a script this host
	// will not execute stops the agent starting while the operator still has
	// another way in — rather than during the outage the knock was sent to
	// fix.
	var scripts gate.ServiceBackend
	if effective.HasScriptBackend() {
		sc, err := gate.NewScript(effective, gate.ScriptOptions{
			// Beside the replay store, for the same reason bundle.json and
			// beat.state are: durable per-host state the agent owns. Without
			// it a restart forgets which admissions it still owes a close to.
			LeasePath: filepath.Join(*stateDir, "gate-leases.db"),
			Logger:    log,
		})
		if err != nil {
			return usagef("script gate backend: %v", err)
		}
		// The daemon's own shutdown closes the gate, which closes this; the
		// deferred close covers the paths that never reach Run.
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := sc.Close(closeCtx); err != nil {
				log.Error("closing the script gate backend failed", "err", err)
			}
		}()
		scripts = sc
	}
	dispatch, err := gate.NewDispatcher(g, scripts, effective)
	if err != nil {
		return usageError{err}
	}

	// hub_url set means fleet mode: pull this host's own bundle and push
	// heartbeats. Both are nil in standalone mode, the empty string's
	// documented meaning (see config.Policy.HubURL) — no goroutine starts and
	// this host is never anything but what its local config already says.
	//
	// PullConfig and BeatConfig each carry their own copy of FleetID, HostID,
	// and (for Pull) HostSigner rather than reaching into Options.Policy or
	// Options.Host themselves — see PullConfig's own doc comment for why: a
	// hub-facing config seam has to be handed exactly the local, root-owned
	// facts it needs, never left to infer them from something the hub could
	// one day influence.
	var pullCfg *agent.PullConfig
	var beatCfg *agent.BeatConfig
	if policy.HubURL != "" {
		pullCfg = &agent.PullConfig{
			HubURL:          policy.HubURL,
			FleetID:         policy.FleetID,
			HostID:          policy.HostID,
			Interval:        *pullInterval,
			Jitter:          0.1,
			HostSigner:      host,
			TrustedSigners:  policy.BundleSigners,
			EnrollmentFloor: policy.EnrollmentFloor,
			// Beside the replay store and beat.state, for the same reason both
			// of those are there: it is durable per-host state the agent owns,
			// and without it anti-rollback lives only in memory and a restart
			// forgets which version this host has applied.
			StatePath: filepath.Join(*stateDir, "bundle.json"),
		}
		beatCfg = &agent.BeatConfig{
			HubURL:    policy.HubURL,
			FleetID:   policy.FleetID,
			HostID:    policy.HostID,
			Interval:  *beatInterval,
			Jitter:    0.1,
			Signer:    host,
			StatePath: filepath.Join(*stateDir, "beat.state"),
		}
	}

	d, err := agent.New(agent.Options{
		Policy:            effective,
		Gate:              dispatch,
		Opener:            opener,
		Store:             store,
		Host:              host,
		StorePath:         storePath,
		ConfirmWindow:     *confirmWindow,
		MetricsListen:     *metricsListen,
		Pull:              pullCfg,
		Beat:              beatCfg,
		RunningPolicyPath: runningPolicyPath,
		// The local acknowledgment, not effective: effective is the running
		// policy, which a bundle can already have swapped by the time this
		// runs. policy is the enrollment bootstrap this daemon started from —
		// a file only root can write — so it stays the trust anchor
		// checkConsoleRecoveryUnchanged needs even after later bundles change
		// what is running.
		LocalConsoleRecovery: policy.ConsoleRecovery,
		// The daemon rewrites this drop-in and reloads systemd whenever a bundle
		// changes the fail-closed set catalogue, so a crash still empties a
		// bundle-added gate's grant (#47). Empty (standalone) disables it. Its
		// nft path is left at the default, matching the agent's own NFTRuleset
		// below rather than any --nft an operator enrolled with.
		FlushDropIn: agent.FlushDropIn{Path: *flushDropIn},
		Transactions: &agent.Transactions{
			Paths: agent.Paths{
				BootNFT: *bootNFT,
				State:   filepath.Join(*stateDir, "state.json"),
				Pending: filepath.Join(*stateDir, "pending.json"),
			},
			// Both units, always. postern-boot.service enabled means the
			// fail-closed drops load at every boot; posternd.service enabled
			// means something is alive after that boot to open them. Enabling
			// only the first is indefinite unreachability at the next reboot.
			BootUnit:  agent.SystemdUnit{Name: gate.BootUnitName},
			AgentUnit: agent.SystemdUnit{Name: gate.PosterndUnitName},
			Ruleset:   agent.NFTRuleset{},
		},
		Logger: log,
	})
	if err != nil {
		return err
	}
	return d.Run(ctx)
}
