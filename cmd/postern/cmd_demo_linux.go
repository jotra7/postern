//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

func init() {
	register(&command{
		name:    "demo",
		usage:   "demo [--port 22] [--dir PATH] [flags]",
		summary: "run the whole sequence against this machine's real firewall and report what happened",
		run:     runDemo,
	})
}

// runDemo is design section 11's end-to-end harness, pointed at the machine
// it is running on: enroll, arm, knock, connect, expire, confirm, disarm.
//
// It exists because every other test in this repository drives one layer.
// This one is the only thing that answers "does the product work here", and
// it answers it the way an operator would rather than the way the code
// would: every assertion is made against `nft list ruleset` run as a separate
// process and against real TCP connections. Nothing postern reports about
// itself is treated as evidence, because a build that had stopped talking to
// the kernel entirely would still report every step succeeding.
//
// What it does NOT do, and the difference matters when reading its output:
// it knocks over loopback from this same machine, so it does not prove
// anything about routing, a provider firewall, or NAT. scripts/e2e.sh runs
// the same sequence across three network namespaces with real systemd, which
// is where those parts are covered.
func runDemo(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "demo", "demo [--port 22] [--dir PATH] [flags]")
	port := fs.Uint("port", 22, "TCP port to gate; the demo listens on it if nothing else does")
	spaPort := fs.Uint("spa-port", 62201, "UDP port the demo agent binds")
	dir := fs.String("dir", "", "where to put the demo's configuration and state (default: a temp directory)")
	iface := fs.String("always-allow-iface", "",
		"interface postern must never filter (default: the first non-loopback interface, else a temporary dummy)")
	ttl := fs.Duration("ttl", 15*time.Second, "gate TTL to knock with; the demo waits for it to lapse")
	nftPath := fs.String("nft", gate.DefaultNFTPath, "absolute path to nft(8)")
	keep := fs.Bool("keep", false, "leave the demo's directory behind")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return usagef("demo writes real firewall rules, so it needs root")
	}
	if *port > 65535 || *spaPort > 65535 {
		return usagef("--port and --spa-port must be valid port numbers")
	}

	d := &demo{
		env:     e,
		port:    uint16(*port),
		spaPort: uint16(*spaPort),
		ttl:     *ttl,
		nft:     *nftPath,
		host:    netip.MustParseAddr("127.0.0.1"),
	}
	if err := d.setup(ctx, *dir, *iface, *keep); err != nil {
		return err
	}
	defer d.cleanup()
	if err := d.run(ctx); err != nil {
		// Printed here rather than left to the caller: a failedError is
		// deliberately not re-printed by main, on the grounds that the command
		// has already explained itself. The demo has to actually do that.
		outf(e.stdout, "\ndemo stopped: %v\n", err)
		return failedError{err}
	}
	return nil
}

type demo struct {
	env     *env
	port    uint16
	spaPort uint16
	ttl     time.Duration
	nft     string
	host    netip.Addr

	dir       string
	etc       string
	state     string
	keep      bool
	iface     string
	dummyMade bool

	listener net.Listener
	operator identity.Signer
	target   *client.Host
	daemon   *agent.Daemon
	daemonUp chan error
	cancel   context.CancelFunc

	failures int
}

func (d *demo) sayf(format string, args ...any) { outf(d.env.stdout, "\n== "+format+"\n", args...) }
func (d *demo) ok(format string, args ...any)   { outf(d.env.stdout, "ok   "+format+"\n", args...) }

func (d *demo) fail(format string, args ...any) {
	d.failures++
	outf(d.env.stdout, "FAIL "+format+"\n", args...)
}

// setup builds a complete standalone host in a scratch directory, using the
// same code paths `postern init-standalone` and `postern enroll` use — the
// generated config, the generated boot.nft, and the host entry an operator
// would paste into their client config all come from the product rather than
// from fixtures written for the demo.
func (d *demo) setup(ctx context.Context, dir, iface string, keep bool) error {
	d.keep = keep
	if dir == "" {
		tmp, err := os.MkdirTemp("", "postern-demo-*")
		if err != nil {
			return fmt.Errorf("create the demo directory: %w", err)
		}
		dir = tmp
	} else if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	d.dir = dir
	d.etc = filepath.Join(dir, "etc")
	d.state = filepath.Join(dir, "var")

	if err := d.resolveAlwaysAllow(iface); err != nil {
		return err
	}

	// The service behind the gate. If something is already listening — sshd
	// on a real host — the demo gates that instead, which is the more honest
	// arrangement of the two.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", d.port))
	if err == nil {
		d.listener = ln
		go acceptAndGreet(ln)
		outf(d.env.stderr, "demo: listening on :%d as the service behind the gate\n", d.port)
	} else {
		outf(d.env.stderr, "demo: something is already listening on :%d; gating that instead\n", d.port)
	}

	op, err := identity.Generate("demo-operator")
	if err != nil {
		return fmt.Errorf("generate the operator identity: %w", err)
	}
	d.operator = op

	// init-standalone prints the client's host entry on stdout, so capture
	// that rather than reconstructing it: what the operator would knock with
	// is exactly what is under test.
	var entry bytes.Buffer
	sub := *d.env
	sub.stdout = &entry
	pub := op.Public()
	if err := initStandalone(ctx, &sub, initOptions{
		dir:             d.etc,
		stateDir:        d.state,
		unitDir:         filepath.Join(d.dir, "units"),
		hostName:        "demo-host",
		knockAddr:       d.host.String(),
		spaPort:         uint(d.spaPort),
		alwaysAllowIf:   d.iface,
		recoveryService: "ssh",
		sshPort:         uint(d.port),
		execStart:       "/usr/local/bin/postern agent --config " + filepath.Join(d.etc, "postern.yaml"),
		nftPath:         d.nft,
		revision:        1,
		operators: operatorList{{
			name:       "demo-operator",
			signing:    pub.Signing,
			encryption: pub.Encryption,
			services:   []string{"ssh", "confirm", "disarm", "liveness"},
			maxTTL:     "300s",
		}},
	}); err != nil {
		return fmt.Errorf("init-standalone: %w", err)
	}

	// Register the host the way an operator does — `postern host add --from`
	// — rather than by decoding the entry here. The client config that
	// command writes is what LoadConfig validates and what turns the entry's
	// base64 into usable keys; a Host built any other way is a Host no
	// operator will ever hold. runHostAdd, not the deprecated runEnroll: the
	// operator identity below already exists, written directly rather than
	// minted, so this never needs the auto-mint path (#28).
	entryPath := filepath.Join(d.dir, "entry.yaml")
	if err := os.WriteFile(entryPath, entry.Bytes(), 0o600); err != nil {
		return err
	}
	keyPath := filepath.Join(d.dir, "identity.json")
	if err := identity.SaveFile(keyPath, op, nil); err != nil {
		return fmt.Errorf("write the demo operator key: %w", err)
	}
	cfgPath := filepath.Join(d.dir, "client.yaml")
	if err := runHostAdd(ctx, &sub, []string{
		"demo-host", "--from", entryPath,
		"--config", cfgPath, "--key-file", keyPath,
	}); err != nil {
		return fmt.Errorf("register the demo host: %w", err)
	}
	cfg, err := client.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load the client config host add just wrote: %w", err)
	}
	host, err := cfg.Host("demo-host")
	if err != nil {
		return err
	}
	d.target = host
	return nil
}

// resolveAlwaysAllow finds an interface postern will never filter.
//
// Loopback is deliberately not eligible, and the reason is the whole demo:
// the rendered rule is `iifname "<iface>" accept` above every gate, so
// choosing lo would accept every packet this demo sends before any gate saw
// it, and every step would pass against a firewall that was doing nothing.
func (d *demo) resolveAlwaysAllow(name string) error {
	if name != "" {
		if _, err := net.InterfaceByName(name); err != nil {
			return usagef("--always-allow-iface %q: %v", name, err)
		}
		if name == "lo" {
			return usagef("lo cannot be the always-allow interface for the demo: the demo knocks over " +
				"loopback, so an accept rule on lo would let every packet past every gate")
		}
		d.iface = name
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 {
			d.iface = i.Name
			return nil
		}
	}
	// A network-isolated container has only lo. Making one is better than
	// refusing: the interface carries no traffic here, it exists so the
	// generated ruleset has the path postern refuses to arm without.
	const dummy = "postern-demo0"
	if out, err := exec.Command("ip", "link", "add", dummy, "type", "dummy").CombinedOutput(); err != nil { //nolint:gosec // fixed argv
		return fmt.Errorf("this machine has no non-loopback interface and creating %s failed "+
			"(%v: %s); pass --always-allow-iface", dummy, err, strings.TrimSpace(string(out)))
	}
	d.iface = dummy
	d.dummyMade = true
	return nil
}

func acceptAndGreet(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "POSTERN-DEMO-SERVICE\r\n")
		_ = conn.Close()
	}
}

func (d *demo) cleanup() {
	if d.cancel != nil {
		d.cancel()
		select {
		case <-d.daemonUp:
		case <-time.After(15 * time.Second):
			outf(d.env.stderr, "demo: the agent did not stop within 15s\n")
		}
	}
	if d.listener != nil {
		_ = d.listener.Close()
	}
	// Whatever the sequence did or failed to do, this machine must not be
	// left with postern's rules on it. The disarm step is part of the
	// sequence; this is the belt to that braces, and it runs the same
	// operator-facing path.
	_ = runLocalDisarm(context.Background(), &env{stdout: io.Discard, stderr: io.Discard}, localDisarm{
		Boot:      agent.NFTRuleset{NFT: d.nft, Table: gate.TableBoot},
		Open:      agent.NFTRuleset{NFT: d.nft, Table: gate.TableOpen},
		BootUnit:  d.unitFlag("boot-unit-enabled"),
		AgentUnit: d.unitFlag("agent-unit-enabled"),
		Paths:     d.paths(),
	})
	if d.dummyMade {
		_ = exec.Command("ip", "link", "del", "postern-demo0").Run() //nolint:gosec // fixed argv
	}
	if d.keep {
		outf(d.env.stderr, "demo: left %s behind\n", d.dir)
		return
	}
	_ = os.RemoveAll(d.dir)
}

func (d *demo) paths() agent.Paths {
	return agent.Paths{
		BootNFT: filepath.Join(d.etc, "boot.nft"),
		State:   filepath.Join(d.state, "state.json"),
		Pending: filepath.Join(d.state, "pending.json"),
	}
}

// unitFlag names one of the demo's stand-in unit files under the state
// directory.
func (d *demo) unitFlag(name string) demoUnit {
	return demoUnit{path: filepath.Join(d.state, name)}
}

// demoUnit stands in for systemd. The demo must not enable or disable a unit
// on the machine it runs on — it is a demonstration, not an installation — so
// each unit's enabled state is recorded in a file and asserted from there.
// scripts/e2e.sh is where the real systemctl path runs.
type demoUnit struct{ path string }

func (u demoUnit) Enabled(context.Context) (bool, error) {
	_, err := os.Stat(u.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (u demoUnit) SetEnabled(_ context.Context, enabled bool) error {
	if !enabled {
		if err := os.Remove(u.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(u.path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(u.path, []byte("enabled\n"), 0o600)
}

func (d *demo) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	d.sayf("1. the host before postern arms anything")
	d.dumpRuleset()
	d.assertConnect("connected", "the service is reachable; postern has not armed anything yet")

	if err := d.startAgent(ctx); err != nil {
		return err
	}

	d.sayf("2. the agent armed revision 1 and published what a confirm must carry")
	rec := d.pendingRecord()
	outf(d.env.stdout, "   pending.json: revision=%d nonce=%s outcome=%s\n", rec.Revision, rec.Nonce, rec.Outcome)
	outf(d.env.stdout, "   the operator confirms with: postern confirm demo-host --revision %d --nonce %s\n",
		rec.Revision, rec.Nonce)
	d.dumpRuleset()
	d.assertTable(gate.TableBoot, true, "the arm step loaded the generated ruleset")
	d.assertTable(gate.TableOpen, true, "the agent created its own table")
	d.assertConnect("timeout", "an armed gate drops connections from an unknocked source")

	d.sayf("3. one signed UDP datagram")
	if err := d.knock(ctx); err != nil {
		return err
	}
	d.dumpSet(gate.TableOpen, "gate_ssh_v4_obs")
	d.assertGateHolds("127.0.0.1", "the gate opened for the address the packet was seen from")
	d.assertConnect("connected", "the port that was dropping traffic a moment ago now answers")

	d.sayf("4. a second knock while the gate is live refreshes rather than stacks")
	// Both knocks carry the same TTL, which is what an operator's second
	// `postern open` does. That is the shape the kernel does not refresh on
	// its own — it updates an element's expiry only when the re-inserted
	// timeout VALUE differs — so a gate layer that just re-inserts leaves the
	// original schedule running and the session drops anyway.
	time.Sleep(3 * time.Second)
	before, beforeLeft := d.gateElementCount(), d.gateExpiry()
	if err := d.knock(ctx); err != nil {
		return err
	}
	d.dumpSet(gate.TableOpen, "gate_ssh_v4_obs")
	after, afterLeft := d.gateElementCount(), d.gateExpiry()
	if after == 1 && before == 1 {
		d.ok("the set still holds exactly one element")
	} else {
		d.fail("the set holds %d elements after a second knock (was %d); it stacked instead of refreshing", after, before)
	}
	if afterLeft > beforeLeft {
		d.ok("the lease was extended: %s left before the second knock, %s after", beforeLeft, afterLeft)
	} else {
		d.fail("the lease was not extended: %s left before the second knock, %s after — an operator "+
			"re-knocking to hold a session open gets a gate that shuts on the original schedule", beforeLeft, afterLeft)
	}

	d.sayf("5. the TTL lapses with nothing helping it along")
	d.waitForGateToClose()
	d.dumpSet(gate.TableOpen, "gate_ssh_v4_obs")
	d.assertConnect("timeout", "the kernel expired the element and the gate closed again")

	d.sayf("6. confirm, bound to the published revision and nonce")
	nonce, err := decodeNonce(rec.Nonce)
	if err != nil {
		return err
	}
	if err := d.action(ctx, func(nowMS uint64) (*spa.Request, error) {
		return client.Builder{Signer: d.operator}.Confirm(d.target, rec.Revision, nonce, nowMS)
	}); err != nil {
		return err
	}
	d.waitFor("the confirm to be recorded", func() bool {
		_, err := os.Stat(d.paths().State)
		return err == nil
	})
	d.assertFile(d.paths().State, true, "the confirmed revision is recorded")
	d.assertFile(d.paths().Pending, false, "a confirmed configuration is no longer waiting for anything")

	d.sayf("7. disarm")
	if err := d.action(ctx, func(nowMS uint64) (*spa.Request, error) {
		return client.Builder{Signer: d.operator}.Disarm(d.target, nowMS)
	}); err != nil {
		return err
	}
	d.waitFor("both tables to go away", func() bool {
		return !d.tableExists(gate.TableBoot) && !d.tableExists(gate.TableOpen)
	})
	d.dumpRuleset()
	d.assertTable(gate.TableBoot, false, "disarm removes the persistent table")
	d.assertTable(gate.TableOpen, false, "disarm removes the agent's table")
	d.assertFile(d.paths().BootNFT, false, "disarm clears persistence, or the host re-locks at the next reboot")
	d.assertConnect("connected", "the host is back to how the demo found it")

	if d.failures > 0 {
		return fmt.Errorf("%d of the demo's assertions failed", d.failures)
	}
	outf(d.env.stdout, "\nall assertions passed\n")
	return nil
}

func (d *demo) startAgent(ctx context.Context) error {
	body, err := os.ReadFile(filepath.Join(d.etc, "postern.yaml")) //nolint:gosec // the demo generated this path
	if err != nil {
		return err
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	hostKey, err := identity.LoadFile(filepath.Join(d.etc, "host.key"), nil)
	if err != nil {
		return err
	}
	opener, _, err := spa.NewOpenerFromSigner(hostKey, []identity.PublicIdentity{d.operator.Public()})
	if err != nil {
		return err
	}
	storePath := filepath.Join(d.state, "replay.db")
	store, err := replay.Open(storePath, replay.Options{})
	if err != nil {
		return err
	}
	g, err := gate.NewNFTables(policy)
	if err != nil {
		return err
	}

	dm, err := agent.New(agent.Options{
		Policy:    policy,
		Gate:      g,
		Opener:    opener,
		Store:     store,
		Host:      hostKey,
		StorePath: storePath,
		// Short on purpose: the demo has to watch a dead-man timer and a gate
		// TTL inside one command, and both are checked from the packet loop.
		ConfirmWindow:   2 * time.Minute,
		HeartbeatPeriod: 2 * time.Second,
		Transactions: &agent.Transactions{
			Paths:     d.paths(),
			BootUnit:  d.unitFlag("boot-unit-enabled"),
			AgentUnit: d.unitFlag("agent-unit-enabled"),
			Ruleset:   agent.NFTRuleset{NFT: d.nft},
		},
		Logger: slog.New(slog.NewTextHandler(d.env.stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		_ = store.Close()
		return err
	}
	d.daemon = dm
	d.daemonUp = make(chan error, 1)
	go func() {
		err := dm.Run(ctx)
		_ = store.Close()
		d.daemonUp <- err
	}()

	// Wait for the agent to be serving rather than merely started: the
	// published record appears before the ruleset is armed, so the table is
	// the thing to wait on.
	if !d.waitFor("the agent to arm", func() bool { return d.tableExists(gate.TableOpen) }) {
		select {
		case err := <-d.daemonUp:
			return fmt.Errorf("the agent stopped before it armed: %w", err)
		default:
			return errors.New("the agent did not arm")
		}
	}
	return nil
}

func (d *demo) knock(ctx context.Context) error {
	rep, err := client.Open(ctx, client.OpenOptions{
		Builder:         client.Builder{Signer: d.operator},
		Host:            d.target,
		Service:         "ssh",
		TTL:             d.ttl,
		Counter:         client.NewCounter(filepath.Join(d.dir, "counter.json")),
		ConnectTimeout:  2 * time.Second,
		ConnectAttempts: 2,
	})
	if err != nil {
		outf(d.env.stdout, "   postern open -> %v\n", err)
		return err
	}
	outf(d.env.stdout, "   postern open -> %s (%s)\n", rep.Result.Outcome, rep.Advice.Summary)
	return nil
}

func (d *demo) action(ctx context.Context, build func(uint64) (*spa.Request, error)) error {
	rep, err := client.SendAction(ctx, client.ActionOptions{
		Builder: client.Builder{Signer: d.operator},
		Host:    d.target,
		Sends:   client.DefaultActionSends,
	}, build)
	if err != nil {
		return err
	}
	outf(d.env.stdout, "   %d action datagrams sent to %s\n", rep.Sent, rep.To)
	return nil
}

// --- assertions, all of them against something postern did not say -----

// connectOutcome dials the gated port itself rather than asking postern what
// it thinks the port is doing.
func (d *demo) connectOutcome() string {
	conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(d.host, d.port).String(), 3*time.Second)
	if err == nil {
		_ = conn.Close()
		return "connected"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if strings.Contains(err.Error(), "refused") {
		return "refused"
	}
	return "error: " + err.Error()
}

func (d *demo) assertConnect(want, why string) {
	got := d.connectOutcome()
	if got == want {
		d.ok("connect %s:%d = %s — %s", d.host, d.port, got, why)
		return
	}
	d.fail("connect %s:%d = %s, want %s — %s", d.host, d.port, got, want, why)
}

// nftList shells out to nft(8). The agent writes its rules over netlink, so
// reading them back with a different tool is what makes this evidence rather
// than a round trip through the same code.
func (d *demo) nftList(args ...string) (string, error) {
	out, err := exec.Command(d.nft, append([]string{"list"}, args...)...).CombinedOutput() //nolint:gosec // d.nft is a flag with a fixed default
	return string(out), err
}

func (d *demo) dumpRuleset() {
	out, _ := d.nftList("ruleset")
	outf(d.env.stdout, "\n$ %s list ruleset\n%s\n", d.nft, strings.TrimRight(out, "\n"))
}

func (d *demo) dumpSet(table, set string) {
	out, _ := d.nftList("set", "inet", table, set)
	outf(d.env.stdout, "\n$ %s list set inet %s %s\n%s\n", d.nft, table, set, strings.TrimRight(out, "\n"))
}

func (d *demo) tableExists(table string) bool {
	_, err := d.nftList("table", "inet", table)
	return err == nil
}

func (d *demo) assertTable(table string, want bool, why string) {
	if d.tableExists(table) == want {
		d.ok("table inet %s %s — %s", table, presence(want), why)
		return
	}
	d.fail("table inet %s %s, want %s — %s", table, presence(!want), presence(want), why)
}

func presence(b bool) string {
	if b {
		return "is present"
	}
	return "is absent"
}

func (d *demo) gateElementCount() int {
	out, err := d.nftList("set", "inet", gate.TableOpen, "gate_ssh_v4_obs")
	if err != nil {
		return 0
	}
	return strings.Count(out, "127.0.0.1")
}

// gateExpiry is how long the kernel says the open source has left, read out
// of nft(8)'s own rendering rather than through the netlink path that wrote
// it.
func (d *demo) gateExpiry() time.Duration {
	out, err := d.nftList("set", "inet", gate.TableOpen, "gate_ssh_v4_obs")
	if err != nil {
		return 0
	}
	m := expiresPattern.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	dur, err := time.ParseDuration(strings.ReplaceAll(m[1], " ", ""))
	if err != nil {
		return 0
	}
	return dur
}

// nft renders "expires 7s123ms", which time.ParseDuration reads as-is.
var expiresPattern = regexp.MustCompile(`expires ([0-9hms]+)`)

func (d *demo) assertGateHolds(addr, why string) {
	out, err := d.nftList("set", "inet", gate.TableOpen, "gate_ssh_v4_obs")
	if err == nil && strings.Contains(out, addr) {
		d.ok("the gate set holds %s — %s", addr, why)
		return
	}
	d.fail("the gate set does not hold %s — %s", addr, why)
}

func (d *demo) assertFile(path string, want bool, why string) {
	_, err := os.Stat(path)
	if (err == nil) == want {
		d.ok("%s %s — %s", path, presence(want), why)
		return
	}
	d.fail("%s %s, want %s — %s", path, presence(!want), presence(want), why)
}

func (d *demo) pendingRecord() agent.ArmRecord {
	var rec agent.ArmRecord
	body, err := os.ReadFile(d.paths().Pending) //nolint:gosec // the demo generated this path
	if err != nil {
		d.fail("nothing was published for the operator to confirm with: %v", err)
		return rec
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		d.fail("the published record does not decode: %v", err)
	}
	if len(rec.Nonce) != 2*len(agent.Transaction{}.Nonce) {
		d.fail("the published nonce %q is not 16 bytes of hex", rec.Nonce)
	}
	if _, err := hex.DecodeString(rec.Nonce); err != nil {
		d.fail("the published nonce %q is not hex: %v", rec.Nonce, err)
	}
	return rec
}

func (d *demo) waitForGateToClose() {
	if !d.waitFor("the gate set to empty", func() bool { return d.gateElementCount() == 0 }) {
		d.fail("the gate never closed on its own")
	}
}

func (d *demo) waitFor(what string, done func() bool) bool {
	deadline := time.Now().Add(d.ttl + 90*time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	outf(d.env.stdout, "     (timed out waiting for %s)\n", what)
	return false
}
