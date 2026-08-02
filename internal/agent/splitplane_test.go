package agent_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

// The one property this whole file exists for: the control plane must never
// be able to take down the packet plane. Every test below is a different
// route to that same failure — a heartbeat file that stops the daemon
// starting, a reverted bundle that re-locks the host at the next reboot, a
// bundle-added operator whose knock silently never decrypts — and the
// assertion in each case is that a knock still works.

// --- C1: a bad heartbeat state file must not stop the daemon -------------

// beatStateHeader is what openBeatState writes into a brand-new file: the
// magic value and the format version, and no records. It is a legitimate
// state — every host's file looks exactly like this between enrollment and
// its first beat — and it is also the shape a crash during the old,
// truncate-in-place compaction left behind, which is why it is one of the
// rows below.
var beatStateHeader = []byte{'P', 'B', 'S', 'T', 1, 0, 0, 0}

// agent.New used to treat every openBeatState failure as fatal, so runAgent
// never reached d.Run: the SPA socket was never bound, the gate was never
// armed, and no valid knock was ever answered. Every trigger is local and
// none of them involves SPA — a torn state file, the flock held by a
// lingering process on the same state directory, /var/lib/postern read-only
// or full — so a heartbeat that cannot start was taking break-glass access
// down with it.
//
// Rejecting a corrupt file stays correct (see readHeader: treating an
// unrecognised file as empty resets the sequence, and the hub then refuses
// every beat for the life of the epoch). What was wrong was the wiring.
//
// The assertion is deliberately not "New returned nil error". It is that the
// daemon this returns binds, announces readiness, and opens a gate for a real
// signed knock — the thing the failure actually cost.
//
// Mutation verified: restoring `return nil, fmt.Errorf(...)` in New's beat
// block fails the two bad-file rows at agent.New with
// "agent: build the heartbeat emitter: agent: open beat state: ... refusing
// to treat an unrecognized file as an empty one".
func TestAgent_New_ABadBeatStateDegradesTheHeartbeatNotTheDaemon(t *testing.T) {
	for _, tc := range []struct {
		name string
		// content is what is on disk at BeatConfig.StatePath before New runs.
		content []byte
		// wantBeater is whether this file is one openBeatState accepts.
		wantBeater bool
	}{
		{
			// The exact bytes the reviewer demonstrated the outage with.
			name:       "unrecognized magic",
			content:    []byte("NOTPBST\x01"),
			wantBeater: false,
		},
		{
			// A header torn mid-write: too short to read at all. This is what
			// a crash inside the old compaction's writeHeader could leave.
			name:       "truncated header",
			content:    []byte{'P', 'B', 'S'},
			wantBeater: false,
		},
		{
			// A file that is nothing but a header — the state the old
			// compaction produced when a crash landed between its Truncate(0)
			// and its Sync, and the state every host is in before its first
			// beat. This one is legitimate and must be accepted; it is here
			// because it is the file I7 was producing, and because a row that
			// must succeed is what stops this test passing by refusing
			// everything.
			name:       "header only",
			content:    beatStateHeader,
			wantBeater: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "beat.state")
			if err := os.WriteFile(statePath, tc.content, 0o600); err != nil {
				t.Fatalf("stage the beat state: %v", err)
			}

			h := newDaemonHarness(t, func(o *agent.Options) {
				o.Beat = &agent.BeatConfig{
					HubURL:    "http://127.0.0.1:1", // never reached; nothing here sends
					FleetID:   o.Policy.FleetID,
					HostID:    o.Policy.HostID,
					Interval:  time.Hour,
					Signer:    o.Host,
					StatePath: statePath,
				}
			})
			if (h.daemon.Beater() != nil) != tc.wantBeater {
				t.Fatalf("Beater() non-nil = %v, want %v", h.daemon.Beater() != nil, tc.wantBeater)
			}

			// The part that matters. A daemon that exists but never binds is
			// the same outage as one that was never built.
			h.start(t)
			h.send(t, h.seal(h.gateRequest()), false)
			h.awaitProcessed(t, 1)

			opens := h.gate.openCalls()
			if len(opens) != 1 || opens[0].service != sshName {
				t.Fatalf("gate opens = %+v, want exactly one for %q: a heartbeat state file decided "+
					"whether this host answers a knock", opens, sshName)
			}
		})
	}
}

// --- C2: a reverted bundle must not re-lock the host ---------------------

// applyBundlePolicy used to write the new boot.nft BEFORE armRevision, and
// Transactions.Prepare snapshots boot.nft by reading it off disk — so the
// transaction captured the NEW ruleset as the thing to roll back to, and
// Revert wrote it straight back. The host stayed reachable, the operator
// moved on, and the next reboot loaded a configuration nobody confirmed.
// Design section 7 names this case exactly: "a revert that restores the live
// table alone looks successful and re-locks the host at the next reboot."
//
// The second half is the running policy. checkDeadMan never restored it, so
// after a revert the kernel was back on the old revision while Validate was
// still authorizing against the new one — an operator the rejected bundle
// removed stays locked out, one it added stays authorized.
//
// Both halves are asserted here, because fixing either alone still leaves a
// host that lies about itself in one direction.
//
// Mutation verified: moving the boot.nft write back above armRevision fails
// the boot.nft assertion with the rendered ruleset in place of "OLD BOOT
// NFT\n"; deleting the setPolicy call from checkDeadMan fails the revision
// assertion with 42 in place of 41.
func TestAgent_Daemon_DeadManRevertOfABundleArmRestoresBootNFTAndTheRunningPolicy(t *testing.T) {
	srv, set := newBundleServer(t)
	clock := &testClock{at: time.Now()}
	tx := newTxnHarness(t)
	hubSigner, err := identity.Generate("hub")
	if err != nil {
		t.Fatalf("generate hub signer: %v", err)
	}
	var fleetID [16]byte
	if _, err := rand.Read(fleetID[:]); err != nil {
		t.Fatalf("rand fleet_id: %v", err)
	}

	h := newDaemonHarness(t, func(o *agent.Options) {
		o.Transactions = tx.txns
		// Already-confirmed at the staged revision, so nothing arms at startup
		// and the ONLY arm in this test is the bundle's.
		o.Policy.Revision = txnHarnessRecordedRevision
		o.Policy.FleetID = fleetID
		o.ConfirmWindow = 5 * time.Minute
		o.Now = clock.Now
		tx.txns.Now = clock.Now
		o.Pull = &agent.PullConfig{
			HubURL:         srv.URL,
			FleetID:        fleetID,
			HostID:         o.Policy.HostID,
			Interval:       time.Hour,
			Timeout:        2 * time.Second,
			HostSigner:     o.Host,
			TrustedSigners: [][32]byte{hubSigner.Public().Signing},
			StatePath:      filepath.Join(t.TempDir(), "bundle.json"),
		}
	})

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	c := &bundle.Contents{
		FleetID:  fleetID,
		HostID:   h.policy.HostID,
		Version:  version,
		IssuedAt: time.Now(),
		Policy:   data,
	}
	sealed, err := bundle.Seal(c, hubSigner, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("bundle.Seal: %v", err)
	}
	set(sealed)

	h.start(t)
	waitFor(t, "the fetched bundle to be armed", func() bool {
		return h.daemon.Policy().Revision == version
	})

	// Preconditions, or the assertions below prove nothing: the arm really did
	// replace boot.nft, and the daemon really is running the fetched revision.
	staged, _ := readFile(t, tx.paths.BootNFT)
	if staged == "OLD BOOT NFT\n" {
		t.Fatal("precondition: the bundle arm left the previous boot.nft in place, so a revert that " +
			"restored the wrong one would be indistinguishable from one that worked")
	}

	// No confirm arrives, and the window elapses.
	clock.advance(6 * time.Minute)
	h.tick(t, true)
	waitFor(t, "the dead-man revert to complete", func() bool {
		return h.daemon.Health().Red
	})

	// Half one: the file the boot unit loads. A revert that restored the live
	// table alone looks successful — the host is reachable, the operator moves
	// on — and re-locks at the next reboot.
	if got, _ := readFile(t, tx.paths.BootNFT); got != "OLD BOOT NFT\n" {
		t.Fatalf("boot.nft after reverting a bundle-driven arm = %q, want the pre-bundle file; the "+
			"transaction snapshotted the NEW ruleset and wrote it back as if it were the old one, so "+
			"the host re-locks at the next reboot", got)
	}
	// Half two: the policy the packet loop is deciding against. The kernel is
	// back on the old revision; a daemon still validating against the new one
	// authorizes against a policy nobody is enforcing.
	if got := h.daemon.Policy().Revision; got != txnHarnessRecordedRevision {
		t.Fatalf("running policy after the revert is revision %d, want %d: the kernel is back on the "+
			"old revision and Validate is still deciding against the reverted one", got, txnHarnessRecordedRevision)
	}
}

// --- I3: a policy swap must move the opener and the gate with it ---------

// The central feature of M2, and it failed at exactly the moment the product
// exists for. applyBundlePolicy swapped the policy pointer alone; the SPA
// opener was built once, at startup, from the local config's operators. An
// operator a bundle adds therefore passes Validate's grant check — that walks
// the current policy — and then TrialOpen holds no precomputed shared secret
// for their key, so their datagram never decrypts. The bundle applies
// cleanly, the metric counts it, the journal says "applied a fetched bundle",
// and the new operator's knock does nothing at all until posternd restarts.
//
// Driven end to end: a real sealed bundle naming a second operator, fetched
// and armed by the running daemon's own pull loop, then a real signed knock
// from that operator into the real packet loop.
//
// Mutation verified: reverting setPolicy to `d.policy = p` alone leaves the
// bundle applied (Policy().Operators == 2, revision armed) and this test
// fails on the gate never opening — the exact live-hardware symptom.
func TestAgent_Daemon_AnOperatorAddedByABundleCanKnockWithoutARestart(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)

	// The operator the bundle adds. Nothing on this host has ever seen this
	// key: it is not in the local config the daemon started from.
	newcomer, err := identity.Generate("laptop-secondary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	p.Operators = append(append([]config.Operator(nil), h.policy.Operators...), config.Operator{
		Identity: newcomer.Public(),
		Grants: []config.Grant{{
			Services: []string{sshName, confirmName, disarmName, livenessName},
			MaxTTL:   300 * time.Second,
		}},
	})
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	set(h.sealValid(t, version, data))

	h.start(t)
	waitFor(t, "the bundle adding a second operator to be applied", func() bool {
		return h.daemon.Policy().Revision == version && len(h.daemon.Policy().Operators) == 2
	})

	// The knock. Built and sealed by the newcomer, against this host's real
	// encryption key, through the real packet loop.
	req := h.gateRequest()
	req.KeyID = newcomer.Public().KeyID()
	req.RequestID = randID()
	dg, err := spa.Seal(req, newcomer, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	before := len(h.gate.openCalls())
	h.send(t, dg, false)
	waitFor(t, "the new operator's knock to open the gate", func() bool {
		return len(h.gate.openCalls()) > before
	})

	opens := h.gate.openCalls()
	if opens[len(opens)-1].service != sshName {
		t.Fatalf("last gate open was for %q, want %q", opens[len(opens)-1].service, sshName)
	}

	// The gate's own catalogue moved too. A service a bundle adds is the same
	// defect one step later: gate.NFTables.Open answers "%q is not a known
	// gate service" from its construction-time policy, AFTER Validate passed
	// and after the replay store consumed the packet's slot.
	adopted := h.gate.adoptedPolicies()
	if len(adopted) == 0 {
		t.Fatal("the gate was never told about the new policy; a gate service the bundle adds would " +
			"be refused as unknown after validation had already passed")
	}
	if got := adopted[len(adopted)-1].Revision; got != version {
		t.Fatalf("the gate's catalogue is at revision %d, want %d", got, version)
	}
}

// The control for the test above, and the reason it is attributable. If the
// grant check were the thing admitting the newcomer, an opener that was never
// rebuilt would still pass — so here the SAME bundle is applied with the
// newcomer's grants removed, and the same knock must be refused. What differs
// between the two runs is exactly one control.
func TestAgent_Daemon_AnOperatorTheBundleDoesNotGrantStillCannotKnock(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarness(t, srv.URL, 0, nil)

	newcomer, err := identity.Generate("laptop-secondary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const version = txnHarnessRecordedRevision + 1
	p := *h.policy
	p.Revision = version
	p.SPAPort = 62201
	p.AlwaysAllowIface = "tailscale0"
	p.RecoveryService = sshName
	// Present in the operator set — so the opener DOES hold a shared secret
	// for this key — but granted nothing.
	p.Operators = append(append([]config.Operator(nil), h.policy.Operators...), config.Operator{
		Identity: newcomer.Public(),
		Grants:   []config.Grant{{Services: []string{livenessName}, MaxTTL: 30 * time.Second}},
	})
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	set(h.sealValid(t, version, data))

	h.start(t)
	waitFor(t, "the bundle to be applied", func() bool {
		return h.daemon.Policy().Revision == version
	})

	req := h.gateRequest()
	req.KeyID = newcomer.Public().KeyID()
	req.RequestID = randID()
	dg, err := spa.Seal(req, newcomer, h.host.Public().Encryption)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	before := len(h.gate.openCalls())
	h.send(t, dg, false)
	h.awaitProcessed(t, 1)

	if got := len(h.gate.openCalls()); got != before {
		t.Fatalf("gate opens = %d, want %d: an operator the bundle grants no ssh must be refused, so "+
			"rebuilding the opener is not what admits the operator in the test above", got, before)
	}
}

// --- I6: Prepare must not hold Transactions' mutex across a subprocess ----

// Transactions' mutex IS taken on the packet path — checkDeadMan reaches
// Revert on every tick and every packet, and a confirm or disarm packet
// reaches Commit or Disarm from inside handle — so whoever holds it stalls
// the packet loop. Prepare used to hold it across two `systemctl is-enabled`
// execs and an `nft list table` exec, driven from the pull loop, which put
// the fleet control plane in the panic button's path for as long as three
// child processes take.
//
// The assertion is the property, not the timing: while Prepare is parked
// inside its Ruleset.Snapshot, a Disarm must be able to run to completion.
//
// Mutation verified: taking m.mu for the whole of Prepare again (one
// Lock/defer Unlock at the top, as it was) times this out at the disarm.
func TestAgent_Transaction_PrepareDoesNotHoldTheLockAcrossItsSubprocessReads(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	entered, release := h.ruleset.blockNextSnapshot()
	prepared := make(chan preparedTxn, 1)
	go func() {
		tx, err := h.txns.Prepare(ctx, 42, time.Minute)
		prepared <- preparedTxn{tx, err}
	}()
	awaitPark(t, entered, "Prepare never reached the ruleset snapshot")

	// The panic button, while Prepare is inside a subprocess-backed read.
	disarmed := make(chan error, 1)
	go func() { disarmed <- h.txns.Disarm(ctx) }()
	select {
	case err := <-disarmed:
		if err != nil {
			t.Fatalf("Disarm: %v", err)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("Disarm blocked behind a Prepare that was parked in a subprocess read; the fleet " +
			"control plane is in the panic button's path")
	}

	close(release)
	got := <-prepared
	// And the snapshot it was assembling is discarded rather than committed:
	// an artifact changed under it, so what it holds describes a host that no
	// longer exists.
	if got.err == nil {
		t.Fatal("Prepare returned a transaction assembled across a disarm; reverting it would restore " +
			"a configuration the host was never in")
	}
	if !errors.Is(got.err, agent.ErrConcurrentChange) {
		t.Fatalf("Prepare failed with %v, want the concurrent-change refusal", got.err)
	}
}

// The other half of the same trade, and the property the corrected doc
// comment on Transactions now asserts: Arm cannot be narrowed the same way.
//
// A disarm packet arriving during a bundle-driven arm must not be able to
// remove the tables, delete boot.nft and disable both units while the arm's
// own subprocesses are still running — the arm would then finish, reload the
// ruleset and re-enable the units, and the host would be re-locked despite
// the operator having pressed the panic button. Unlike Prepare, Arm has
// already changed the host by the time it could discover the conflict, so
// optimistic retry cannot rescue it.
//
// Mutation verified: releasing m.mu around Arm's Ruleset.Restore and setUnits
// leaves boot.nft present and both units enabled after the disarm, which this
// test reports as the panic button being undone.
func TestAgent_Transaction_ArmIsExclusiveWithDisarm(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()
	writeFile(t, h.paths.BootNFT, "NEW BOOT NFT\n")

	// Park inside Arm's ruleset load, which is where the real `nft -f` runs.
	entered := make(chan struct{})
	release := make(chan struct{})
	h.ruleset.hook(func([]byte) error {
		select {
		case <-entered:
		default:
			close(entered)
			<-release
		}
		return nil
	})

	armed := make(chan error, 1)
	go func() { armed <- h.txns.Arm(ctx) }()
	awaitPark(t, entered, "Arm never reached the ruleset load")

	disarmed := make(chan error, 1)
	go func() { disarmed <- h.txns.Disarm(ctx) }()
	// Long enough for an unserialized Disarm to run to completion inside the
	// arm's window.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-disarmed:
		t.Fatal("Disarm completed inside an in-flight Arm; the arm then finishes, reloads the ruleset " +
			"and re-enables both units, and the host is re-locked despite the panic button")
	default:
	}

	close(release)
	if err := <-armed; err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := <-disarmed; err != nil {
		t.Fatalf("Disarm: %v", err)
	}

	// Disarm ran last, so its effect is what stands.
	if content, present := readFile(t, h.paths.BootNFT); present {
		t.Fatalf("boot.nft survived the disarm (%q); the host re-locks at the next reboot", content)
	}
	if h.unit.state() || h.agentUnit.state() {
		t.Fatal("a unit is still enabled after the disarm")
	}
}
