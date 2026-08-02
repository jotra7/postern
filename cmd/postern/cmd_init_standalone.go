package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/metrics"
)

// systemctlRun runs systemctl and returns its combined output. It is a package
// var so a test can stand in for systemd without a running init system; the
// real value is the only one that ever shells out.
var systemctlRun = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "systemctl", args...).CombinedOutput() //nolint:gosec // fixed binary, fixed verbs
}

func init() {
	register(&command{
		name:    "init-standalone",
		usage:   "init-standalone --host-name NAME --knock-addr IP --operator NAME=SIGN,ENC [flags]",
		summary: "write a host's root-owned config, host identity, boot ruleset, and units (run on the host)",
		run:     runInitStandalone,
	})
}

// Bounds init-standalone writes whenever it grants an asserted source, so the
// config it generates is one the agent will actually load. Policy.Validate
// refuses allow_source_cidr with either minimum left at zero — an operator
// who may assert 0.0.0.0/0 or ::/0 can open a gate to the entire internet —
// and a generator that emitted the permission without the bounds would ship a
// host that refuses to start.
//
// /24 and /64 are design section 6's example values: a /24 is 256 addresses,
// which is the size of thing a carrier NAT pool is worth widening a gate to.
// --min-ipv4-prefix and --min-ipv6-prefix move them for a carrier whose pool
// is wider than that.
const (
	defaultMinIPv4Prefix = 24
	defaultMinIPv6Prefix = 64
)

// defaultGrantMaxTTL is the ceiling a generated grant carries when --max-ttl
// says nothing, and it matches design section 6's admin operator.
//
// It is bounded in practice by the service's own max_ttl, which
// agent/validate.go clamps against first, so on the generated configuration
// the ssh gate's 300s and the canary's 60s already bind. That is exactly why
// it was worth making a flag rather than leaving it as a literal: a value
// whose wrongness is currently masked by another value is one that becomes
// wrong the moment someone declares a service with a looser ceiling, and it
// would do so without an error.
const defaultGrantMaxTTL = "300s"

// alreadyEnrolledMarker is the clause the already-exists refusal is built
// around, factored out into its own constant so that anything which later
// needs to recognise this specific refusal cannot drift from its exact
// wording by editing the message in only one of two places.
const alreadyEnrolledMarker = "re-enrolling mints a new host identity"

// operatorList collects repeatable --operator flags.
type operatorList []operatorSpec

type operatorSpec struct {
	name       string
	signing    [32]byte
	encryption [32]byte
	services   []string
	maxTTL     string
	// allowSourceCIDR and the two minimums come from --allow-source-cidr
	// rather than from the --operator spec: see applySourceCIDRGrants.
	allowSourceCIDR bool
	minIPv4Prefix   int
	minIPv6Prefix   int
}

// nameList collects a repeatable flag whose value names an operator.
type nameList []string

func (n *nameList) String() string { return strings.Join(*n, ",") }

func (n *nameList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("names no operator")
	}
	*n = append(*n, v)
	return nil
}

func (o *operatorList) String() string { return fmt.Sprintf("%d operator(s)", len(*o)) }

// Set parses NAME=SIGNING_B64,ENCRYPTION_B64[:service,service]. The keys are
// public halves; nothing here ever sees an operator's private material.
func (o *operatorList) Set(v string) error {
	spec, grants, _ := strings.Cut(v, ":")
	name, keys, ok := strings.Cut(spec, "=")
	if !ok {
		return fmt.Errorf("want NAME=SIGNING_B64,ENCRYPTION_B64[:service,service]")
	}
	signB64, encB64, ok := strings.Cut(keys, ",")
	if !ok {
		return fmt.Errorf("want both keys: NAME=SIGNING_B64,ENCRYPTION_B64")
	}
	spec2 := operatorSpec{name: name, services: []string{"ssh", "confirm", "disarm", "liveness"}, maxTTL: defaultGrantMaxTTL}
	if err := decodeKey32(signB64, &spec2.signing); err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if err := decodeKey32(encB64, &spec2.encryption); err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	if grants != "" {
		spec2.services = strings.Split(grants, ",")
	}
	*o = append(*o, spec2)
	return nil
}

// disarmOperatorList collects repeatable --disarm-operator flags (#30).
//
// Its grant is always exactly [disarm] — the flag takes no service list of
// its own, unlike --operator's [:service,service], because a recovery
// operator whose grant could be widened by a typo is not the control the
// flag exists to make easy.
type disarmOperatorList []operatorSpec

func (o *disarmOperatorList) String() string { return fmt.Sprintf("%d disarm operator(s)", len(*o)) }

// Set parses NAME=SIGNING_B64,ENCRYPTION_B64. A colon is refused rather than
// silently accepted and ignored, on the same reasoning enrollssh.go's check
// documents elsewhere in this package: a flag that looks like it configured
// something and did not is the same defect as one wired to nothing.
func (o *disarmOperatorList) Set(v string) error {
	if strings.Contains(v, ":") {
		return fmt.Errorf("--disarm-operator's grant is always [disarm] and takes no service list: " +
			"want NAME=SIGNING_B64,ENCRYPTION_B64")
	}
	name, keys, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want NAME=SIGNING_B64,ENCRYPTION_B64")
	}
	signB64, encB64, ok := strings.Cut(keys, ",")
	if !ok {
		return fmt.Errorf("want both keys: NAME=SIGNING_B64,ENCRYPTION_B64")
	}
	spec := operatorSpec{name: name, services: []string{"disarm"}, maxTTL: defaultGrantMaxTTL}
	if err := decodeKey32(signB64, &spec.signing); err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if err := decodeKey32(encB64, &spec.encryption); err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	*o = append(*o, spec)
	return nil
}

func decodeKey32(s string, out *[32]byte) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("is %d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return nil
}

type initOptions struct {
	dir             string
	stateDir        string
	unitDir         string
	hostName        string
	knockAddr       string
	spaPort         uint
	noPortRotation  bool
	portRange       string
	portRotation    *config.PortRotation
	alwaysAllowIf   string
	consoleRecovery string
	recoveryService string
	sshHost         string
	sshUser         string
	execStart       string
	metricsListen   string
	nftPath         string
	sshPort         uint
	revision        uint64
	operators       operatorList
	disarmOperators disarmOperatorList
	allowSourceCIDR nameList
	maxTTL          nameList
	minIPv4Prefix   int
	minIPv6Prefix   int
	export          string
	force           bool
	noNFTCheck      bool
	noIfaceCheck    bool
	goLive          bool

	// The four fleet-mode values. See applyFleetOptions for why they are
	// checked together and why an incomplete set is a refusal.
	fleetID         string
	hubURL          string
	bundleSigners   nameList
	enrollmentFloor uint64
}

// sshPortOr keeps the zero value meaning 22 rather than port 0, so a caller
// building initOptions in code (the demo does) gets the documented default
// instead of a config that fails validation.
func (o initOptions) sshPortOr() uint16 {
	if o.sshPort == 0 || o.sshPort > 65535 {
		return 22
	}
	return uint16(o.sshPort)
}

// mergeDisarmOperators folds --disarm-operator entries into the main
// operator list, once the "at least one operator" check has already run
// against --operator alone (see initStandalone). Folding them in, rather
// than keeping the split live throughout, is what lets applySourceCIDRGrants,
// applyMaxTTLGrants, and renderStandaloneConfig walk operators by name
// exactly as they always have, with no separate awareness of #30's split.
func mergeDisarmOperators(o *initOptions) error {
	for _, d := range o.disarmOperators {
		for _, existing := range o.operators {
			if existing.name == d.name {
				return usagef("--disarm-operator %q names the same operator as --operator %q; give the "+
					"recovery key its own name", d.name, existing.name)
			}
		}
		o.operators = append(o.operators, d)
	}
	return nil
}

func runInitStandalone(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "init-standalone", "init-standalone --host-name NAME --knock-addr IP --operator NAME=SIGN,ENC [flags]")
	var o initOptions
	fs.StringVar(&o.dir, "dir", defaultStateDirs.etc, "configuration directory")
	fs.StringVar(&o.stateDir, "state-dir", defaultStateDirs.state, "state directory (replay store, recorded hashes)")
	fs.StringVar(&o.unitDir, "unit-dir", "/etc/systemd/system", "where the systemd units are written")
	fs.StringVar(&o.hostName, "host-name", "", "this host's name, as the operator will refer to it")
	fs.StringVar(&o.knockAddr, "knock-addr", "", "the address operators send SPA packets to (an IP literal, never a name)")
	fs.UintVar(&o.spaPort, "spa-port", 62201, "UDP port the agent binds")
	fs.BoolVar(&o.noPortRotation, "no-port-rotation", false,
		"disable the rotating knock port and bind the fixed --spa-port instead. Rotation is the default: "+
			"the SPA port is derived from a per-host secret and a time window, so a network adversary cannot "+
			"find or predict it. Opt out only where a fixed port is required")
	fs.StringVar(&o.portRange, "port-range", "",
		"the inclusive UDP band the rotating port lives in, as `LO-HI`. Empty selects 20000-30000, which "+
			"sits below the kernel ephemeral range. Ignored with --no-port-rotation")
	fs.StringVar(&o.alwaysAllowIf, "always-allow-iface", "", "interface that is never filtered; postern refuses to arm without one")
	fs.StringVar(&o.consoleRecovery, "console-recovery", "",
		"arm with no mesh; declare this out-of-band console `URL` as the recovery path (accepts that "+
			"postern cannot verify a way back in before arming). Permits --always-allow-iface to be "+
			"empty; given alongside it, the iface is still used and verified normally")
	fs.StringVar(&o.recoveryService, "recovery-service", "ssh", "what arm-time liveness TCP-connects to")
	fs.StringVar(&o.sshHost, "ssh-host", "", "hostname an operator SSHes to (recorded for the client, never resolved by postern)")
	fs.StringVar(&o.sshUser, "ssh-user", "", "SSH user, recorded for the client")
	fs.StringVar(&o.execStart, "exec-start", "", "posternd command line for the unit (default: this binary, absolute, plus --config)")
	fs.StringVar(&o.metricsListen, "metrics-listen", "",
		"serve Prometheus /metrics from the generated unit on this `address` (host:port, or :port for "+
			"the always-allow interface). Empty serves nothing. A wildcard is refused here, not at first "+
			"boot: this endpoint publishes a root daemon's gate state")
	fs.StringVar(&o.nftPath, "nft", gate.DefaultNFTPath, "absolute path to nft(8) for the units")
	fs.UintVar(&o.sshPort, "ssh-port", 22, "TCP port the ssh gate service covers")
	fs.Uint64Var(&o.revision, "revision", 1,
		"this configuration's revision; the agent arms a revision it has not recorded as confirmed, "+
			"then reverts it unless `postern confirm` arrives")
	fs.Var(&o.operators, "operator", "NAME=SIGNING_B64,ENCRYPTION_B64[:svc,svc] — repeatable")
	// A recovery operator's grant is always exactly [disarm], never anything
	// else — that is the whole reason this is a flag of its own rather than
	// telling every fleet to reach for --operator's own [:svc,svc] syntax to
	// build a disarm-only grant by hand. #30: for a fleet, the everyday
	// operator should hold [ssh, confirm, liveness] and a separate, offline
	// key should hold disarm alone, because disarm is transitively
	// door-opening authority (design section 6) — a stolen laptop key should
	// not strip postern from every host in the fleet. Standalone mode is not
	// required to use it: --operator alone still defaults to all four
	// services, so a single-box deployment with no second key keeps its
	// panic button. See the README's disarm paragraph.
	fs.Var(&o.disarmOperators, "disarm-operator",
		"NAME=SIGNING_B64,ENCRYPTION_B64 — a recovery operator granted disarm alone, meant to be kept "+
			"offline rather than knocked with day to day; repeatable")
	// A flag of its own rather than a third field on --operator. The
	// --operator value is already NAME=SIGN,ENC[:svc,svc] carrying two base64
	// blobs and a colon-delimited list; a fourth section would be a fifth
	// thing to get right in a string an operator pastes from another
	// terminal, and getting it wrong is silent — an unrecognised service name
	// is a grant that never fires. Naming the operator instead makes a typo a
	// refusal (see applySourceCIDRGrants), keeps the permission grep-able in
	// shell history, and leaves the common case — no asserted sources — with
	// the same --operator string it has today.
	fs.Var(&o.allowSourceCIDR, "allow-source-cidr",
		"operator `NAME` (as given to --operator) may assert a source prefix in the knock, which is the "+
			"fix for a carrier NAT that egresses UDP and TCP from different pools; repeatable, and off "+
			"for every operator not named here")
	// Repeatable, and in two forms, because design section 6's example needs
	// both: the admin operator's grant is capped at 300s and the probe
	// operator's at 30s, in one configuration. A single global flag could not
	// express that, and a fourth colon-delimited section on --operator would
	// add a fifth thing to get right in a string an operator pastes between
	// terminals — the same reasoning that put --allow-source-cidr on a flag of
	// its own.
	fs.Var(&o.maxTTL, "max-ttl",
		"ceiling on the ttl a generated grant may request, as `DURATION` for every operator or "+
			"NAME=DURATION for one; repeatable, later values win. Default 300s. The service's own "+
			"max_ttl is clamped against first, so this is the tighter of the two only when it is smaller")
	fs.IntVar(&o.minIPv4Prefix, "min-ipv4-prefix", 0,
		"the widest IPv4 block an asserted source may name, as a prefix length: 24 permits a /24 and "+
			"refuses anything wider. 0 selects 24. Only with --allow-source-cidr")
	fs.IntVar(&o.minIPv6Prefix, "min-ipv6-prefix", 0,
		"the same bound for IPv6. 0 selects 64. Only with --allow-source-cidr")
	// The four fleet-mode flags. Without them there is no CLI path to a
	// fleet-mode host at all: this command mints a fresh fleet_id per host, so
	// two hosts enrolled the documented way land in two different fleets and
	// bundle.Open refuses every bundle either of them fetches. See
	// applyFleetOptions for the refusals.
	fs.StringVar(&o.fleetID, "fleet-id", "",
		"the fleet this host joins, as 32 `HEX` characters. Empty mints a fresh one, which is what a "+
			"standalone host wants and is exactly wrong for the second host of a fleet: bundle.Open "+
			"checks fleet_id, so a host that minted its own can never be sent a bundle")
	fs.StringVar(&o.hubURL, "hub-url",
		"", "the fleet hub's base `URL` this host pulls its own sealed bundle from and posts heartbeats "+
			"to. Empty is standalone: no pull loop, no heartbeat, and this host is only ever what its "+
			"local config says. Requires --bundle-signers")
	fs.Var(&o.bundleSigners, "bundle-signers",
		"a raw Ed25519 public `KEY`, 64 hex characters, whose signature over a bundle this host will "+
			"accept; repeatable. Only with --hub-url")
	fs.Uint64Var(&o.enrollmentFloor, "enrollment-floor", 0,
		"the lowest bundle `VERSION` this host will ever accept, stamped at enrollment. A freshly "+
			"enrolled host has applied nothing, so without a floor an old but validly-signed bundle — one "+
			"still naming a since-removed operator — replays against it cleanly. Only with --hub-url")
	// The entry itself still goes to stdout unconditionally (see
	// initStandalone): --export is additive, not a replacement for the
	// documented `> entry.yaml` flow. What it buys over that flow is a write
	// this process makes deliberately: a chosen mode, a directory created if
	// missing, and a refusal rather than a silent overwrite, instead of a
	// file the invoking shell happened to create under sudo, owned by
	// whoever ran sudo, in whatever directory the shell was sitting in, with
	// whatever umask was in force.
	fs.StringVar(&o.export, "export", "",
		"also write the client host entry to `FILE`, rather than relying on shell redirection of "+
			"stdout; refuses to overwrite an existing file unless --force is also given")
	fs.BoolVar(&o.force, "force", false, "overwrite an existing configuration")
	fs.BoolVar(&o.noNFTCheck, "no-nft-check", false,
		"skip validating the generated ruleset with `nft -c -f` (only for generating a config off-host)")
	// Separate from --no-nft-check rather than folded into it, because the
	// two do not co-occur: generating a config for another Linux host from a
	// machine that has nft(8) passes the ruleset check and would still be
	// blocked here, with no flag to say why it should not be. Symmetrically
	// named so an operator who knows one guesses the other.
	fs.BoolVar(&o.noIfaceCheck, "no-iface-check", false,
		"skip verifying --always-allow-iface exists here (only for generating a config off-host; "+
			"loopback is still refused)")
	fs.BoolVar(&o.goLive, "go-live", false,
		"after staging, start posternd (the arm) and print the confirm line to run from your laptop")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	return initStandalone(ctx, e, o)
}

func initStandalone(ctx context.Context, e *env, o initOptions) error {
	switch {
	case o.hostName == "":
		return usagef("--host-name is required")
	case o.knockAddr == "":
		return usagef("--knock-addr is required; it is the address an operator knocks and it must be an IP literal")
	case o.alwaysAllowIf == "" && o.consoleRecovery == "":
		// The same refusal gate.BuildRulesetPlan and agent.New make, for the
		// same reason: under fail-closed the always-allow path is the only
		// route in, so postern will not generate a ruleset without one.
		// --console-recovery is the one thing that permits its absence: the
		// operator has declared an out-of-band console URL as the recovery
		// path instead, and accepts that postern cannot verify it before
		// arming (unlike an interface, which checkAlwaysAllowIface can probe).
		return usagef("--always-allow-iface is required; postern will not arm without a path it cannot " +
			"remove (or pass --console-recovery to declare an out-of-band console URL as the recovery " +
			"path instead)")
	case len(o.operators) == 0:
		return usagef("at least one --operator is required; a host no identity may knock is a host nobody can open")
	}
	// Checked against --operator alone, before --disarm-operator's entries
	// join the list below: a host enrolled with only a disarm-only recovery
	// operator and no everyday one would satisfy "at least one operator" and
	// still be unable to open ssh at all, which is a worse outcome than the
	// flag not existing (#30).
	if err := mergeDisarmOperators(&o); err != nil {
		return err
	}
	if err := applySourceCIDRGrants(&o); err != nil {
		return err
	}
	if err := applyMaxTTLGrants(&o); err != nil {
		return err
	}
	if err := applyFleetOptions(&o); err != nil {
		return err
	}
	// Resolved once, here, into o.portRotation, and read from there by both
	// renderStandaloneConfig and renderHostEntry below: the secret has to be
	// the same 32 bytes in both artifacts, or the client and the agent would
	// derive different ports and no knock would ever land. Generating it
	// twice — once per render call — is exactly the mistake this ordering
	// rules out.
	if err := resolvePortRotation(&o); err != nil {
		return err
	}
	// Both are skipped outright when there is no interface to check: an empty
	// --always-allow-iface only reaches here at all when --console-recovery
	// permitted it above, and checkAlwaysAllowIface's refusals (loopback,
	// does-not-exist) are about a *named* interface being wrong, not about
	// naming none.
	if o.alwaysAllowIf != "" {
		if err := checkAlwaysAllowIface(o.alwaysAllowIf, o.noIfaceCheck); err != nil {
			return err
		}
	}
	alwaysAllowAddr := alwaysAllowEntryAddr(o.alwaysAllowIf, o.noIfaceCheck, metrics.SystemInterfaceAddrs)
	// Refused here, before anything is written, for the same reason a
	// loopback always-allow interface is: the operator still has a working way
	// in, and a metrics endpoint that lands on a public interface publishes a
	// root daemon's gate state to every network the host is on. The other half
	// of the rule — is this address actually on the always-allow interface —
	// can only be answered on the host itself, and agent.New answers it there.
	if o.metricsListen != "" {
		if err := metrics.CheckBindSpec(o.metricsListen); err != nil {
			return usageError{err}
		}
	}
	if o.noIfaceCheck && o.alwaysAllowIf != "" {
		outf(e.stderr, "--no-iface-check: %q was NOT verified to exist, because this is not the host "+
			"being configured. If it is misspelled, the agent will go inert at first arm.\n", o.alwaysAllowIf)
	}

	configPath := filepath.Join(o.dir, "postern.yaml")
	keyPath := filepath.Join(o.dir, "host.key")
	bootPath := filepath.Join(o.dir, "boot.nft")
	if !o.force {
		for _, p := range []string{configPath, keyPath} {
			if _, err := os.Stat(p); err == nil {
				return usagef("%s already exists; %s and invalidates every operator's cached entry — "+
					"pass --force if that is what you mean", p, alreadyEnrolledMarker)
			}
		}
		// --export gets its own check, separate from the config/key pair
		// above, because the failure it guards against is different: this is
		// not about a second identity clobbering the first, it is that the
		// named file may be the operator's only local copy of a host's
		// current entry, and re-running init-standalone is exactly the
		// operation that makes an old copy wrong. Tied to the same --force
		// rather than a flag of its own, because it is the same "I mean to
		// replace what is here" gesture as the check above, and a second
		// override flag would be one more thing to remember for a case that
		// only ever arises together with the first.
		if o.export != "" {
			if _, err := os.Stat(o.export); err == nil {
				return usagef("%s already exists; --export refuses to overwrite it without --force, "+
					"since it may be the only local copy of this host's current entry and re-running "+
					"init-standalone mints a new host identity that would make the old entry wrong; "+
					"pass --force if replacing it is what you mean", o.export)
			}
		}
	}
	// Everything is rendered and validated before anything is written.
	//
	// This ordering is not tidiness. An earlier version wrote host.key and
	// postern.yaml before validating the ruleset, so a rejected ruleset left
	// both behind — and the operator's next attempt, after legitimately
	// fixing the problem, hit the already-exists refusal below, whose text
	// warns about invalidating cached entries that were never issued. A
	// command that fails must leave the host as it found it.

	// Re-enrollment always generates a new host_id (design section 5), which
	// is what makes "a rotated host is a new host to the replay store" true
	// rather than merely stated.
	//
	// fleet_id is the opposite: it is the one identifier every host of a fleet
	// has to agree on, so --fleet-id joins an existing fleet and an absent flag
	// mints a fresh one. applyFleetOptions has already checked the hex.
	fleetID, err := resolveFleetID(o.fleetID)
	if err != nil {
		return err
	}
	var hostID [16]byte
	if _, err := rand.Read(hostID[:]); err != nil {
		return fmt.Errorf("mint host_id: %w", err)
	}

	host, err := identity.Generate(o.hostName)
	if err != nil {
		return fmt.Errorf("generate host identity: %w", err)
	}

	// Rendered once, here, rather than again at the point it is printed: the
	// same bytes go to stdout below and, with --export, into the staged
	// file, and computing it twice would be two chances for the two to say
	// something different.
	hostEntry := renderHostEntry(o, hostID, host.Public(), alwaysAllowAddr)

	cfgYAML := renderStandaloneConfig(o, fleetID, hostID)

	// Parse and validate through the same code the agent uses. A shipped
	// configuration that cannot arm is the failure design section 1 exists to
	// prevent, arriving through the generator instead of the code.
	policy, err := config.ParseStandalone([]byte(cfgYAML))
	if err != nil {
		return fmt.Errorf("the generated config does not parse: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("the generated config does not validate: %w", err)
	}

	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		return fmt.Errorf("plan the ruleset: %w", err)
	}
	bootRuleset := gate.RenderBootNFT(plan)
	if err := checkBootNFT(ctx, o, bootRuleset); err != nil {
		return err
	}

	// The per-set flush lines live in a drop-in the agent regenerates as
	// bundles change the catalogue (#47). Enrollment writes the first one from
	// the bootstrap policy; a fleet host is then told where it is so the daemon
	// can rewrite it. A standalone host never applies a bundle, so its
	// catalogue is fixed and the enrolled drop-in is never regenerated — it is
	// still written, because the teardown flush has to exist from the start.
	dropInDir := filepath.Join(o.unitDir, gate.PosterndDropInDir)
	dropInPath := filepath.Join(dropInDir, gate.FlushDropInName)
	flushDropIn := gate.RenderFlushDropIn(plan, o.nftPath)

	execStart := o.execStart
	if execStart == "" {
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate this binary for the unit's ExecStart: %w", err)
		}
		execStart = fmt.Sprintf("%s agent --config %s --state-dir %s", self, configPath, o.stateDir)
		// Appended only to the generated command line. An operator who
		// supplied --exec-start wrote the whole thing and owns what is on it;
		// silently adding a flag to someone else's command line is how a
		// duplicate or contradictory argument gets into a unit nobody reads
		// again until the day it matters.
		if o.metricsListen != "" {
			execStart += " --metrics-listen " + o.metricsListen
		}
	}
	// A fleet host must know where its flush drop-in is so the daemon can
	// regenerate it as bundles change the catalogue (#47). Unlike
	// --metrics-listen above, this is appended even to an operator-supplied
	// --exec-start, because it is not a preference the operator owns but wiring
	// #47 needs: the agent cannot derive the systemd unit directory on its own,
	// and a fleet host without this flag silently keeps a frozen enumeration.
	// Guarded so a re-run, or an operator who already added it, does not double
	// it. A standalone host is left without it: its catalogue is fixed at
	// enrollment, so the daemon must never rewrite the file init wrote.
	if o.hubURL != "" && !strings.Contains(execStart, "--flush-dropin") {
		execStart += " --flush-dropin " + dropInPath
	}
	unitOpts := gate.UnitOptions{ExecStart: execStart, NFTPath: o.nftPath, BootNFTPath: bootPath}

	// Both units come from internal/gate, never from a second renderer here:
	// divergence between the three renderings inverts a posture silently, so
	// they stay in one package where equivalence testing can catch drift
	// (design section 10).
	posternd, err := gate.RenderPosterndUnit(plan, unitOpts)
	if err != nil {
		return fmt.Errorf("render %s: %w", gate.PosterndUnitName, err)
	}
	bootUnit, err := gate.RenderBootUnit(unitOpts)
	if err != nil {
		return fmt.Errorf("render %s: %w", gate.BootUnitName, err)
	}

	// Past here, everything is decided and only I/O remains. It is staged
	// beside its destination and renamed into place, so a failure part-way
	// through leaves the host as it was found rather than leaving debris the
	// already-exists guard above will refuse on the next attempt. See
	// installer's doc for what that does and does not guarantee.
	inst := newInstaller()
	committed := false
	defer func() {
		if !committed {
			inst.rollback()
		}
	}()

	if err := inst.mkdirAll(o.dir, 0o750); err != nil {
		return err
	}
	if err := inst.mkdirAll(o.unitDir, 0o750); err != nil {
		return err
	}
	if err := inst.mkdirAll(o.stateDir, 0o750); err != nil {
		return err
	}
	// --export's directory, only if it does not exist yet. Named by the
	// operator rather than fixed like the three above, so a relative path
	// with no directory component (the common case: --export entry.yaml)
	// resolves to ".", which always exists and this is a no-op.
	if o.export != "" {
		if err := inst.mkdirAll(filepath.Dir(o.export), 0o755); err != nil {
			return err
		}
	}

	// The host key is unlocked unattended at every boot, so it carries no
	// passphrase: there is nobody to type one. Confidentiality comes from
	// 0600 and root ownership instead, which is the same trust boundary
	// standalone mode already stands on — an attacker who can read this file
	// already has root, at which point postern is irrelevant to their
	// position (design section 1).
	if err := inst.stageWith(keyPath, func(path string) error {
		if err := identity.SaveFile(path, host, nil); err != nil {
			return fmt.Errorf("write host key: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	// The modes differ by what each artifact carries. postern.yaml and
	// boot.nft are 0600: they hold the operator key set, the SPA port, and
	// every gated port — the inventory design section 6 says a public bundle
	// must never leak — and posternd reads them as root. The unit files are
	// 0644 because systemd's own tooling reads them and they hold nothing
	// `systemctl cat` would not show.
	if err := inst.stage(configPath, []byte(cfgYAML), 0o600); err != nil {
		return err
	}
	if err := inst.stage(bootPath, []byte(bootRuleset), 0o600); err != nil {
		return err
	}
	if err := inst.stage(filepath.Join(o.unitDir, gate.PosterndUnitName), []byte(posternd), 0o644); err != nil {
		return err
	}
	if err := inst.stage(filepath.Join(o.unitDir, gate.BootUnitName), []byte(bootUnit), 0o644); err != nil {
		return err
	}
	// 0644 like the two units, and for the same reason: systemd reads it, and
	// it holds only gate-set names — which the main unit's ExecStopPost carried
	// at 0644 before this drop-in existed, so nothing new is exposed.
	if err := inst.mkdirAll(dropInDir, 0o750); err != nil {
		return err
	}
	if err := inst.stage(dropInPath, []byte(flushDropIn), 0o644); err != nil {
		return err
	}
	// 0644, not 0600: the entry carries only public material, the same
	// reason README gives for handing it to another operator without a
	// second thought, so there is nothing here for a restrictive mode to
	// protect. Staged through the same installer as everything else above,
	// so a failure writing it (a full disk, a directory that turns out not
	// to be one) rolls the whole run back rather than leaving a host
	// enrolled with no captured entry and no clean way to retry without
	// --force.
	if o.export != "" {
		if err := inst.stage(o.export, []byte(hostEntry), 0o644); err != nil {
			return err
		}
	}

	if err := inst.commit(); err != nil {
		return err
	}
	committed = true

	outf(e.stderr, "wrote %s, %s, %s\n", configPath, keyPath, bootPath)
	outf(e.stderr, "wrote %s (with %s/%s), %s in %s — staged, NOT enabled\n",
		gate.PosterndUnitName, gate.PosterndDropInDir, gate.FlushDropInName, gate.BootUnitName, o.unitDir)
	if !o.goLive {
		outln(e.stderr, "gates are staged inert: nothing drops traffic until the units are enabled and started.")
	}
	if !alwaysAllowAddr.IsValid() && o.alwaysAllowIf != "" {
		outf(e.stderr, "note: this entry records no always_allow_addr, so `postern status` will ping "+
			"knock_addr instead. A liveness pong is emitted only for a ping that arrived on the "+
			"always-allow interface, and one that arrives anywhere else is refused without a reply, so "+
			"on a host reached publicly at one address and over a mesh at another that check reads as a "+
			"timeout however healthy the agent is. Add `always_allow_addr: <this host's address on %s>` "+
			"to the entry by hand.\n", o.alwaysAllowIf)
	}
	if o.export != "" {
		outf(e.stderr, "the client host entry was written to %s and also follows on stdout; give "+
			"either to `postern host add --from`.\n", o.export)
	} else {
		outln(e.stderr, "the client host entry follows on stdout — give it to `postern host add --from`.")
	}

	outs(e.stdout, hostEntry)
	if o.goLive {
		return goLiveArm(ctx, e, o)
	}
	return nil
}

// goLiveArm starts posternd after staging (the arm) and prints the confirm line
// the operator runs from their laptop. Called only under --go-live. A failure
// here leaves the staged files in place: enrollment succeeded, only the arm did
// not, and the operator can start posternd by hand.
func goLiveArm(ctx context.Context, e *env, o initOptions) error {
	if out, err := systemctlRun(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload after staging: %w: %s", err, bytes.TrimSpace(out))
	}
	if out, err := systemctlRun(ctx, "restart", gate.PosterndUnitName); err != nil {
		return fmt.Errorf("systemctl restart %s (the arm): %w: %s", gate.PosterndUnitName, err, bytes.TrimSpace(out))
	}
	rec, err := waitForPendingArm(ctx, filepath.Join(o.stateDir, "pending.json"))
	if err != nil {
		return fmt.Errorf("%s started but published no confirmable record: %w; inspect "+
			"`journalctl -u %s` and confirm by hand", gate.PosterndUnitName, err, gate.PosterndUnitName)
	}
	outf(e.stderr, "armed revision %d, pending confirmation.\n", rec.Revision)
	outf(e.stderr, "from your laptop, once this host is registered:\n"+
		"  postern confirm %s --revision %d --nonce %s\n", o.hostName, rec.Revision, rec.Nonce)
	return nil
}

// goLivePendingWait bounds how long goLiveArm waits for posternd to publish its
// pending record after start. systemctl start returns when the unit is active,
// but the agent writes pending.json a moment into its own startup.
const goLivePendingWait = 10 * time.Second

func waitForPendingArm(ctx context.Context, path string) (agent.ArmRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, goLivePendingWait)
	defer cancel()
	for {
		rec, err := readArmRecord(path)
		if err == nil && rec.Outcome == agent.ArmPending {
			return rec, nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return agent.ArmRecord{}, err
			}
			return agent.ArmRecord{}, fmt.Errorf("pending record did not reach %q within %s", agent.ArmPending, goLivePendingWait)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func readArmRecord(path string) (agent.ArmRecord, error) {
	var rec agent.ArmRecord
	body, err := os.ReadFile(path) //nolint:gosec // path is this command's own --state-dir
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return rec, err
	}
	if len(rec.Nonce) != 32 {
		return rec, fmt.Errorf("published nonce %q is not 16 bytes of hex", rec.Nonce)
	}
	if _, err := hex.DecodeString(rec.Nonce); err != nil {
		return rec, fmt.Errorf("published nonce %q is not hex: %w", rec.Nonce, err)
	}
	return rec, nil
}

// alwaysAllowEntryAddr is the address the printed host entry records as this
// host's always-allow address, or an invalid Addr when this command has no
// honest answer.
//
// Resolved here rather than asked for on the command line because the operator
// would be typing back a value this command has already looked up:
// --always-allow-iface is verified to exist a few lines above, and an
// enrollment flag whose value can be derived is one more thing to mistype at
// the one moment a mistake is still cheap to fix.
//
// When the interface carries several addresses, the first routable one wins,
// in the order the kernel reports them and skipping loopback, unspecified and
// link-local. That is metrics.FirstRoutableAddr, shared rather than
// reimplemented, so an operator's --metrics-listen :9873 and their own host
// entry name the same address of the same interface. A mesh interface with
// both an IPv4 and an IPv6 address is the ordinary case and either one reaches
// the agent, so picking between them is a question with no wrong answer that
// needs an operator; a link-local address is the one that would need a zone
// the client has no way to know, and is skipped rather than chosen.
//
// Nothing is recorded when the interface carries no routable address, and
// nothing is recorded under --no-iface-check even when an interface of that
// name is sitting right here. That flag is the operator asserting the one
// thing that makes this machine's interfaces inapplicable, namely that they
// are not the target host's. A machine generating a config for a fleet of hosts
// that all name eth0 would otherwise stamp its own address into every one of
// their entries, each of which would then check an address belonging to the
// laptop. Silence falls back to knock_addr, which is what every entry written
// before this field existed already does.
func alwaysAllowEntryAddr(iface string, offHost bool, lookup metrics.InterfaceAddrs) netip.Addr {
	if offHost {
		return netip.Addr{}
	}
	addr, ok := metrics.FirstRoutableAddr(iface, lookup)
	if !ok {
		return netip.Addr{}
	}
	return addr
}

// checkAlwaysAllowIface is the enrollment gate on design section 7's rail 1.
// It returns a usage error, or nil.
//
// It exists because of a real lockout: a host enrolled with
// `--always-allow-iface lo` satisfied every check postern had — both of them
// were non-emptiness — armed fail-closed, rebooted, and was never reachable
// again. The rail was present in the ruleset, never touched, and never
// useful. Enrollment is where refusing costs nothing: init-standalone runs
// on the host, the operator still has a working way in, and nothing has been
// written at this point.
//
// Three refusals, in the order their evidence is strongest:
//
//  1. The kernel's own loopback flag, whenever the interface resolves here.
//     This is authoritative and catches a loopback under any name — the
//     reason it runs before the name list, which let `loopback0` through.
//  2. The name, when the interface does not resolve here. It is the only
//     probe available when the config is being generated for another host,
//     and it is the one that caught the case that actually happened.
//  3. Existence. This is the typo gate: `tailscale1` is one character from
//     `tailscale0` and is otherwise indistinguishable from a correct
//     configuration. Follow it through — an interface that resolves to
//     nothing is a global pre-arm failure, so the agent goes inert, and
//     inert on a fail-closed host means boot.nft's drops are live with
//     nothing able to open them and no SPA to knock with. A typo at
//     enrollment would become a lockout at first arm. The refusal names the
//     interfaces that *were* found, because a typo is far easier to fix with
//     the correct spelling on screen.
//
// offHost skips only the third. See --no-iface-check for why that is a flag
// rather than a warning, and why the loopback refusals have no override.
func checkAlwaysAllowIface(name string, offHost bool) error {
	// net.InterfaceByName and net.Interfaces are stdlib and CGO-free on
	// every platform this command builds for, so all of this stays portable
	// and init-standalone keeps building and running on darwin.
	iface, err := net.InterfaceByName(name)
	if err == nil {
		if iface.Flags&net.FlagLoopback != 0 {
			return loopbackRefusal(name, "flagged loopback by this kernel")
		}
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "lo", "lo0", "loopback", "localhost":
		return loopbackRefusal(name, "a loopback interface name")
	}

	if offHost {
		return nil
	}
	found := nonLoopbackIfaceNames()
	detail := "this host reports no non-loopback interface at all"
	if len(found) > 0 {
		detail = "this host has: " + strings.Join(found, ", ")
	}
	return usagef("--always-allow-iface %q does not exist on this host (%v). %s.\n"+
		"A one-character typo here is not a small mistake: postern refuses to arm without an "+
		"always-allow path that resolves, so the agent would go inert at first arm — and on a "+
		"fail-closed host inert means boot.nft's drop rules are already live with nothing able to "+
		"open them and no SPA to knock with. Fix the spelling, or pass --no-iface-check if you are "+
		"generating this configuration somewhere other than the host it describes.",
		name, err, detail)
}

// loopbackRefusal is the same refusal from either probe, so the two cannot
// drift into saying different things about the same mistake.
//
// Deliberately no override, in contrast to --no-iface-check. That flag lets
// an operator assert something that can be true and is unknowable from here
// — that these are not the target host's interfaces. A loopback override
// would assert something that is never true: that a path no remote operator
// can arrive on is an acceptable last way in. Hosts with genuinely no
// non-loopback interface are not a counterexample — `postern demo` already
// answers that case by creating a dummy interface, which is a real path
// where a suppressed warning is not.
func loopbackRefusal(name, why string) error {
	return usagef("--always-allow-iface %q is %s. Loopback carries no remote operator, so the "+
		"`iifname %q accept` rule above every gate would protect nobody: the moment posternd is "+
		"not running, a fail-closed service is reachable from the console and nowhere else. There "+
		"is no override, because there is no host on which this is the right answer — name the "+
		"interface an operator would actually reach this host over (a mesh interface such as "+
		"tailscale0, or a management NIC).", name, why, name)
}

// nonLoopbackIfaceNames is what the existence refusal offers the operator
// instead of only telling them they are wrong. Loopback is filtered out
// because suggesting it would contradict the refusal above it.
func nonLoopbackIfaceNames() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 {
			names = append(names, i.Name)
		}
	}
	sort.Strings(names)
	return names
}

// applySourceCIDRGrants resolves --allow-source-cidr onto the operators it
// names, with the bounds the agent requires. It runs before anything is
// written, and before initOptions is used for anything else, so a
// programmatic caller (postern demo builds initOptions in code) goes through
// the same checks the flags do.
//
// The failure this closes is not an unset flag. Before it there was no flag:
// `allow_source_cidr` had no path through init-standalone at all, so on every
// default-enrolled host an operator behind a carrier NAT that splits UDP and
// TCP egress got a knock refused with "grant does not permit an asserted
// source" — a refusal the SPA path never sends, so what they saw was a
// timeout, followed by advice to retry with --source-cidr, followed by an
// identical timeout. Recovery was hand-editing postern.yaml on the host they
// could not reach.
//
// Three refusals, all of them cheap here and expensive later:
//
//  1. A name that matches no --operator. It would grant nothing, silently,
//     and the operator would meet it as a knock the host ignores. The refusal
//     lists the names that were declared, because this is nearly always a
//     spelling or a copy-paste from another host's command line.
//  2. A minimum without a grant to bound. It reads as though it configured
//     something and configures nothing.
//  3. A minimum outside its address family's range. Policy.Validate would
//     refuse the generated file, and the operator would be holding a
//     generator error about their own flag.
func applySourceCIDRGrants(o *initOptions) error {
	minV4, minV6 := o.minIPv4Prefix, o.minIPv6Prefix
	if len(o.allowSourceCIDR) == 0 {
		if minV4 != 0 || minV6 != 0 {
			return usagef("--min-ipv4-prefix/--min-ipv6-prefix bound an asserted source prefix, and no " +
				"operator was granted one, so they bound nothing. Name an operator with " +
				"--allow-source-cidr NAME, or drop these flags.")
		}
		return nil
	}
	if minV4 == 0 {
		minV4 = defaultMinIPv4Prefix
	}
	if minV6 == 0 {
		minV6 = defaultMinIPv6Prefix
	}
	if minV4 < 1 || minV4 > 32 {
		return usagef("--min-ipv4-prefix %d is not an IPv4 prefix length; it must be 1..32. It is a floor "+
			"rather than a suggestion: without one, an authorised operator could assert 0.0.0.0/0 and "+
			"open the gate to everyone.", minV4)
	}
	if minV6 < 1 || minV6 > 128 {
		return usagef("--min-ipv6-prefix %d is not an IPv6 prefix length; it must be 1..128. It is a floor "+
			"rather than a suggestion: without one, an authorised operator could assert ::/0 and open the "+
			"gate to everyone.", minV6)
	}
	for _, name := range o.allowSourceCIDR {
		found := false
		for i := range o.operators {
			if o.operators[i].name == name {
				o.operators[i].allowSourceCIDR = true
				o.operators[i].minIPv4Prefix = minV4
				o.operators[i].minIPv6Prefix = minV6
				found = true
			}
		}
		if !found {
			return usagef("--allow-source-cidr %q names no operator; this command declares %s. A name that "+
				"matches nothing grants nothing, and the operator would meet that as a knock the host "+
				"refuses without replying.", name, strings.Join(operatorNames(o.operators), ", "))
		}
	}
	return nil
}

// applyMaxTTLGrants resolves --max-ttl onto the grants it names.
//
// It runs on initOptions rather than inside the flag's Set, so the
// programmatic caller goes through the same checks the flags do, and so a
// NAME= form can be matched against the full --operator list however the two
// were ordered on the command line.
//
// The refusals mirror --allow-source-cidr's, and for the same reason: a
// --max-ttl naming an operator that does not exist reads as though it tightened
// something and tightens nothing, and the operator would meet that as a grant
// wider than they believe they configured.
func applyMaxTTLGrants(o *initOptions) error {
	for _, spec := range o.maxTTL {
		name, value, named := strings.Cut(spec, "=")
		if !named {
			name, value = "", spec
		}
		d, err := time.ParseDuration(strings.TrimSpace(value))
		if err != nil {
			return usagef("--max-ttl %q is not a duration: %v. Write it as a Go duration — 30s, 5m — "+
				"optionally prefixed with an operator name, as in probe-local=30s.", spec, err)
		}
		switch {
		case d <= 0:
			return usagef("--max-ttl %q is not positive; a grant whose ceiling is zero can open nothing, "+
				"which is a revoked grant written as a ttl. Drop the operator from --operator instead.", spec)
		case d%time.Second != 0:
			// ttl_seconds is uint16 on the wire (design section 5), so a
			// fractional ceiling is a number the packet format cannot carry and
			// would be truncated somewhere an operator never sees.
			return usagef("--max-ttl %q is not a whole number of seconds; a ttl is carried as whole "+
				"seconds on the wire, so anything finer would be silently truncated.", spec)
		case int64(d.Seconds()) > config.MaxTTLSeconds:
			return usagef("--max-ttl %q exceeds the wire limit of %d seconds; ttl_seconds is a uint16, "+
				"and Policy.Validate would refuse the generated file.", spec, config.MaxTTLSeconds)
		}
		// Rendered as whole seconds rather than through Duration.String, which
		// would turn 300s into "5m0s" and make the generated file stop looking
		// like design section 6's example it is a copy of.
		rendered := fmt.Sprintf("%ds", int64(d.Seconds()))

		found := false
		for i := range o.operators {
			if name == "" || o.operators[i].name == name {
				o.operators[i].maxTTL = rendered
				found = true
			}
		}
		if !found {
			return usagef("--max-ttl %q names no operator; this command declares %s. A name that matches "+
				"nothing bounds nothing, and the grant it was meant to tighten keeps the %s default.",
				spec, strings.Join(operatorNames(o.operators), ", "), defaultGrantMaxTTL)
		}
	}
	return nil
}

// applyFleetOptions validates the four fleet-mode flags and normalises the
// hex ones, before anything is written.
//
// The failure this closes is not a wrong value. Before it there was no flag:
// `init-standalone` minted a fresh fleet_id per host and had no path to
// hub_url, bundle_signers or enrollment_floor at all, so enrolling two hosts
// the documented way put them in two different fleets, and bundle.Open checks
// fleet_id — which made every M2 bundle unopenable by every host an operator
// could actually produce. The only working configuration was one no command
// generated.
//
// Four refusals, all of them cheap here and expensive later:
//
//  1. A fleet_id that is not 32 hex characters. It is copied by hand from
//     another host's postern.yaml, which is exactly the operation a truncated
//     paste survives, and the symptom is every bundle rejected as wrong_fleet
//     — in silence, on the pull path, on a host the operator is not watching.
//  2. --hub-url without --bundle-signers. agent.New refuses to build a puller
//     with an empty trusted set, so this writes a config posternd will not
//     start from: a host that is inert on a fail-closed service is unreachable
//     with nothing able to open it.
//  3. --bundle-signers or --enrollment-floor without --hub-url. Nothing reads
//     either key in standalone mode, so this reads as though it configured a
//     trust decision and configures nothing.
//  4. A bundle signer that is not 64 hex characters. ParseStandalone would
//     refuse the generated file and the operator would be holding a generator
//     error about their own flag.
func applyFleetOptions(o *initOptions) error {
	if o.fleetID != "" {
		normalised, err := normalizeHex(o.fleetID, 16)
		if err != nil {
			return usagef("--fleet-id %q is not a fleet id: %v. It is 32 hex characters, copied verbatim "+
				"from the fleet_id line of a host already in this fleet — every host of one fleet carries "+
				"the same value, and bundle.Open refuses a bundle whose fleet_id does not match.",
				o.fleetID, err)
		}
		o.fleetID = normalised
	}

	o.hubURL = strings.TrimSpace(o.hubURL)
	if o.hubURL == "" {
		switch {
		case len(o.bundleSigners) > 0:
			return usagef("--bundle-signers names the keys whose bundles this host will accept, and " +
				"without --hub-url this host never fetches a bundle, so it would trust nothing. Pass " +
				"--hub-url, or drop --bundle-signers.")
		case o.enrollmentFloor != 0:
			return usagef("--enrollment-floor bounds the bundles this host will accept, and without " +
				"--hub-url this host never fetches one, so it would bound nothing. Pass --hub-url, or " +
				"drop --enrollment-floor.")
		}
		return nil
	}
	if len(o.bundleSigners) == 0 {
		return usagef("--hub-url without --bundle-signers writes a configuration posternd refuses to " +
			"start from: a puller with no trusted signer can accept no bundle at all, so the agent goes " +
			"inert — and on a fail-closed host inert means boot.nft's drop rules are live with nothing " +
			"able to open them. Name at least one signer's public key.")
	}
	for i, s := range o.bundleSigners {
		normalised, err := normalizeHex(s, 32)
		if err != nil {
			return usagef("--bundle-signers %q is not an Ed25519 public key: %v. It is 64 hex "+
				"characters — the same encoding the config's bundle_signers list carries.", s, err)
		}
		o.bundleSigners[i] = normalised
	}
	return nil
}

// resolvePortRotation builds the rotating knock port configuration, unless
// --no-port-rotation opted out. It generates a fresh secret from
// crypto/rand every time it is called, so a caller must call it exactly
// once and hand the result to both renderStandaloneConfig and
// renderHostEntry — calling it twice would put a different secret in each
// artifact, and the client and agent would then derive different ports.
//
// A range malformed at the string level (not "lo-hi", or a half that is not
// a number) is refused here, before anything is written. A range that
// parses but is inverted, or overlaps a service, the kernel ephemeral band,
// or the http carrier port, is left to Policy.Validate a few lines below,
// which already names the offending service or band specifically.
func resolvePortRotation(o *initOptions) error {
	if o.noPortRotation {
		return nil
	}
	lo, hi := knockport.DefaultRangeLo, knockport.DefaultRangeHi
	if o.portRange != "" {
		var err error
		lo, hi, err = parsePortRangeFlag(o.portRange)
		if err != nil {
			return usagef("--port-range %q: %v", o.portRange, err)
		}
	}
	secret := make([]byte, knockport.SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate port_rotation secret: %w", err)
	}
	o.portRotation = &config.PortRotation{
		Secret:  secret,
		Window:  knockport.DefaultWindow,
		RangeLo: lo,
		RangeHi: hi,
	}
	return nil
}

// parsePortRangeFlag parses --port-range's "LO-HI" form into its two
// bounds. It only catches malformed syntax; whether the resulting band
// makes sense (inverted, or overlapping something) is Policy.Validate's job.
func parsePortRangeFlag(s string) (lo, hi uint16, err error) {
	before, after, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf(`not of the form "lo-hi"`)
	}
	loN, err := strconv.ParseUint(before, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("lo %q: %w", before, err)
	}
	hiN, err := strconv.ParseUint(after, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("hi %q: %w", after, err)
	}
	return uint16(loN), uint16(hiN), nil
}

// normalizeHex decodes s as exactly n bytes of hex and returns the canonical
// lower-case encoding, so the generated file does not depend on how the
// operator's terminal happened to case the value they pasted.
func normalizeHex(s string, n int) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != n {
		return "", fmt.Errorf("is %d bytes, want %d", len(raw), n)
	}
	return hex.EncodeToString(raw), nil
}

// resolveFleetID returns the fleet this host joins: the one named on the
// command line, or a fresh one when none was. applyFleetOptions has already
// rejected anything that is not 32 hex characters, so a failure here is a
// programmatic caller that skipped it.
func resolveFleetID(fleetID string) ([16]byte, error) {
	var out [16]byte
	if fleetID == "" {
		if _, err := rand.Read(out[:]); err != nil {
			return out, fmt.Errorf("mint fleet_id: %w", err)
		}
		return out, nil
	}
	raw, err := hex.DecodeString(fleetID)
	if err != nil || len(raw) != 16 {
		return out, usagef("--fleet-id %q is not 32 hex characters", fleetID)
	}
	copy(out[:], raw)
	return out, nil
}

func operatorNames(ops operatorList) []string {
	names := make([]string, 0, len(ops))
	for _, op := range ops {
		names = append(names, fmt.Sprintf("%q", op.name))
	}
	return names
}

// renderStandaloneConfig writes design section 6's standalone example with
// this host's own values. The service set is that example verbatim,
// including the canary and all three actions: a service no identity may
// knock is a service that never gets knocked, and without the liveness grant
// no fail-closed service could ever be armed from the shipped config at all.
func renderStandaloneConfig(o initOptions, fleetID, hostID [16]byte) string {
	var b strings.Builder
	outf(&b, "# generated by postern init-standalone for %s\n", o.hostName)
	outf(&b, "fleet_id: %q\n", hex.EncodeToString(fleetID[:]))
	outf(&b, "host_id: %q\n", hex.EncodeToString(hostID[:]))
	// The revision is what a confirm packet binds to. Bumping it is how an
	// operator says "this is a change": the agent arms a revision it has not
	// recorded as confirmed, publishes the nonce, and reverts on the dead-man
	// timer if nothing confirms (design section 5).
	outf(&b, "revision: %d\n", o.revision)
	outf(&b, "spa_port: %d\n", o.spaPort)
	// spa_port is written unconditionally, rotation or not: gate.BuildRulesetPlan
	// still plans the fixed udp carrier port around it (see resolve.go), and
	// Policy.Validate refuses a config with spa_port unset. port_rotation, when
	// present, is what actually moves the knock: the agent derives the current
	// window's port from the secret below rather than binding spa_port, but
	// spa_port keeps meaning what it always has for the ruleset and for a host
	// run with --no-port-rotation.
	if o.portRotation != nil {
		r := o.portRotation
		outf(&b, "port_rotation: { secret: %q, window: %s, range: %d-%d }\n",
			base64.StdEncoding.EncodeToString(r.Secret), r.Window, r.RangeLo, r.RangeHi)
	}
	// Conditional, in the same style as hub_url in fleetFields: emitted only
	// when it was actually given, rather than as an empty string, so a config
	// with none of it in a diff looks like it was never asked for. The two
	// keys are mutually exclusive on the wire the way this generator writes
	// them — always_allow_iface is the interface path, console_recovery/console
	// is the out-of-band one — but --console-recovery only permits the iface's
	// absence, it does not forbid its presence: given both, the iface line
	// below still comes out and is still used and verified normally.
	if o.alwaysAllowIf != "" {
		outf(&b, "always_allow_iface: %q\n", o.alwaysAllowIf)
	}
	if o.consoleRecovery != "" {
		b.WriteString("console_recovery: true\n")
		outf(&b, "console: %q\n", o.consoleRecovery)
	}
	outf(&b, "recovery_service: %q\n", o.recoveryService)
	b.WriteString("breakglass_services: [ssh]\n")
	b.WriteString("\nservices:\n")
	outf(&b, "  ssh:      { kind: gate, proto: tcp, ports: [%d], default_ttl: 120s, max_ttl: 300s,\n"+
		"              listener_expectation: present }\n", o.sshPortOr())
	b.WriteString("  canary:   { kind: gate, proto: tcp, ports: [62202], default_ttl: 30s, max_ttl: 60s,\n" +
		"              listener_expectation: absent, verification: tcp_rst }\n")
	b.WriteString("  confirm:  { kind: action }\n")
	b.WriteString("  disarm:   { kind: action }\n")
	b.WriteString("  liveness: { kind: action }\n")
	b.WriteString("\noperators:\n")
	for _, op := range o.operators {
		outf(&b, "  - name: %q\n", op.name)
		outf(&b, "    alg: %q\n", identity.AlgEd25519X25519)
		outf(&b, "    signing:    %q\n", base64.StdEncoding.EncodeToString(op.signing[:]))
		outf(&b, "    encryption: %q\n", base64.StdEncoding.EncodeToString(op.encryption[:]))
		outf(&b, "    grants: [{ services: [%s], max_ttl: %s%s }]\n",
			quoteList(op.services), op.maxTTL, sourceGrantFields(op))
	}
	b.WriteString(fleetFields(o))
	return b.String()
}

// fleetFields writes the three fleet-mode keys, and writes nothing at all
// when this is a standalone enrollment.
//
// Emitting them only when --hub-url was given is what keeps a standalone
// config byte-identical to the one this command produced before fleet mode
// existed. It is not cosmetic: hub_url is the switch cmd_agent_linux.go reads
// to decide whether a pull loop and a heartbeat emitter start at all, and a
// generated `hub_url: ""` would be indistinguishable in a diff from a value
// somebody meant to fill in.
//
// enrollment_floor is emitted whenever hub_url is, including at its zero
// value, because zero is a deliberate answer here — "accept any version this
// fleet's signers have produced" — and a key absent from a fleet config is a
// question an operator has to go and re-answer.
func fleetFields(o initOptions) string {
	if o.hubURL == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	outf(&b, "hub_url: %q\n", o.hubURL)
	outf(&b, "bundle_signers: [%s]\n", quoteList(o.bundleSigners))
	outf(&b, "enrollment_floor: %d\n", o.enrollmentFloor)
	return b.String()
}

// sourceGrantFields writes the asserted-source permission and, inseparably,
// the two bounds on it. They are emitted together and never apart: the
// permission alone is a config Policy.Validate refuses, so splitting them
// would be a way to generate a host that will not start.
func sourceGrantFields(op operatorSpec) string {
	if !op.allowSourceCIDR {
		return ""
	}
	return fmt.Sprintf(", allow_source_cidr: true, min_ipv4_prefix: %d, min_ipv6_prefix: %d",
		op.minIPv4Prefix, op.minIPv6Prefix)
}

// renderHostEntry is the block an operator pastes into their client config
// (or pipes into `postern enroll --from`). It carries only public material.
func renderHostEntry(
	o initOptions, hostID [16]byte, pub identity.PublicIdentity, alwaysAllowAddr netip.Addr,
) string {
	var b strings.Builder
	outf(&b, "name: %s\n", o.hostName)
	outf(&b, "host_id: %s\n", hex.EncodeToString(hostID[:]))
	outf(&b, "knock_addr: %s\n", o.knockAddr)
	outf(&b, "knock_port: %d\n", o.spaPort)
	// knock_port is still written under rotation, for backward compatibility
	// with a client that does not yet understand port_rotation. A client that
	// does prefers port_rotation and never reads knock_port at all; the two
	// only ever agree because both come from --spa-port and o.portRotation at
	// the default range, not because anything keeps them in sync.
	//
	// The block below carries the same secret rendered into postern.yaml
	// above: this is the client's half, and the operator needs it to knock at
	// all. Holding the secret is not itself an authenticating fact — see the
	// design doc — so it is handled like the rest of this entry, no more and
	// no less carefully.
	if o.portRotation != nil {
		r := o.portRotation
		outf(&b, "port_rotation: { secret: %q, window: %s, range: %d-%d }\n",
			base64.StdEncoding.EncodeToString(r.Secret), r.Window, r.RangeLo, r.RangeHi)
	}
	// `open` knocks knock_addr and `status` pings this, and on a host reached
	// publicly at one address and over a mesh at another they are two
	// different addresses. Omitted rather than guessed when the interface
	// could not be read; see alwaysAllowEntryAddr.
	if alwaysAllowAddr.IsValid() {
		outf(&b, "always_allow_addr: %s\n", alwaysAllowAddr)
	}
	outf(&b, "host_encryption: %s\n", base64.StdEncoding.EncodeToString(pub.Encryption[:]))
	outf(&b, "host_signing: %s\n", base64.StdEncoding.EncodeToString(pub.Signing[:]))
	outf(&b, "recovery_service: %s\n", o.recoveryService)
	if allowed, known := assertedSourceEntryValue(o.operators); known {
		outf(&b, "allow_source_cidr: %t\n", allowed)
	}
	if o.sshHost != "" || o.sshUser != "" {
		outf(&b, "ssh: { host: %s, user: %s, port: %d }\n", orString(o.sshHost, o.knockAddr), o.sshUser, o.sshPortOr())
	}
	b.WriteString("services:\n")
	outf(&b, "  ssh: { port: %d, ttl: 120s }\n", o.sshPortOr())
	b.WriteString("  canary: { port: 62202, ttl: 30s }\n")
	return b.String()
}

// assertedSourceEntryValue is what the printed host entry may honestly say
// about asserted sources, and whether it may say anything at all.
//
// One entry is printed per host, not per operator, and the same block is
// handed to every operator enrolled in this invocation. When their grants
// agree it states the fact, which is what lets `postern open` stop
// recommending a retry that cannot work and lets `postern enroll` say so
// while the operator still has a way in. When they disagree it says nothing,
// because a single document that claimed either answer would be wrong for
// somebody holding it — and the client treats silence as silence.
func assertedSourceEntryValue(ops operatorList) (allowed, known bool) {
	granted, denied := 0, 0
	for _, op := range ops {
		if op.allowSourceCIDR {
			granted++
		} else {
			denied++
		}
	}
	switch {
	case granted > 0 && denied == 0:
		return true, true
	case denied > 0 && granted == 0:
		return false, true
	default:
		return false, false
	}
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

func orString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// checkBootNFT validates the generated ruleset with `nft -c -f` before it is
// written.
//
// Design section 7 asks for this by name, and the reason is the asymmetry
// the boot path carries: postern-boot.service loads this file before the
// agent runs and independently of it, so a syntax error here does not
// produce a failed command an operator sees — it produces a host that
// silently fails *open* on every service configured closed, discovered at
// the next reboot or never.
//
// A missing nft(8) is a refusal rather than a skip. nft is a runtime
// requirement on every postern host, for this path and for fail-open
// teardown, so its absence is a finding; --no-nft-check exists for
// generating a configuration somewhere other than the host it describes,
// and says so.
func checkBootNFT(ctx context.Context, o initOptions, ruleset string) error {
	if o.noNFTCheck {
		return nil
	}
	// The check runs the same nft the boot unit will run, not whichever one
	// happens to be on PATH. Falling back to PATH would validate with a
	// binary the unit never invokes and hide the more common misconfiguration
	// of the two: nft installed somewhere other than --nft points, so the
	// ruleset is fine and the unit that loads it names a path that does not
	// exist.
	if _, err := os.Stat(o.nftPath); err != nil {
		if found, lookErr := exec.LookPath("nft"); lookErr == nil {
			return usagef("nft(8) is not at %s but is at %s. The units generated here run %s, so they "+
				"would fail on this host — pass --nft %s.", o.nftPath, found, o.nftPath, found)
		}
		return usagef("nft(8) is not at %s and not on PATH, so the generated ruleset cannot be "+
			"validated and the generated units would not run. nft is a runtime requirement on every "+
			"postern host: the boot unit runs it, and so does fail-open teardown. Install it, pass "+
			"--nft with its real path, or pass --no-nft-check if you are generating this "+
			"configuration somewhere other than the host it describes.", o.nftPath)
	}

	tmp, err := os.CreateTemp("", "postern-boot-*.nft")
	if err != nil {
		return fmt.Errorf("create a temp file to validate the ruleset: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.WriteString(ruleset); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the ruleset for validation: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close the ruleset temp file: %w", err)
	}

	out, err := exec.CommandContext(ctx, o.nftPath, "-c", "-f", name).CombinedOutput() //nolint:gosec // both operands are this command's own flags
	if err != nil {
		return fmt.Errorf("the generated ruleset was rejected by %s -c -f, so it was not written; "+
			"a syntax error here fails the host OPEN on every fail-closed service at the next boot: %w: %s",
			o.nftPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}
