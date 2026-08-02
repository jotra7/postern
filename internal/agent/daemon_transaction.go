package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// The daemon's half of confirm-or-revert: it holds the one transaction
// currently awaiting confirmation, hands it to Validate as the binding a
// confirm packet must match, and runs the dead-man timer that reverts when
// no bound confirm arrives.

// ErrNoPendingTransaction means a confirm reached the daemon with nothing
// armed. Validate refuses that packet before it gets here, so this is the
// belt to that braces — reachable only if the pending state changed between
// validation and application.
var ErrNoPendingTransaction = errors.New("agent: no transaction is awaiting confirmation")

// ErrConfirmSuperseded means the transaction a confirm was bound to is no
// longer the pending one: a newer BeginTransaction replaced it in the window
// between the packet's validation and this commit. Committing d.pending here
// would ratify a revision no operator confirmed, and that revision's dead-man
// would then never fire — a host armed on rules nothing can confirm or
// revert. So the confirm is refused and the newer transaction is left to its
// own confirm-or-revert. Validate refuses an unbound confirm long before it
// reaches here; this guards the narrower race Validate cannot see, since it
// snapshots the pending slot at a different instant than the commit reads it.
var ErrConfirmSuperseded = errors.New("agent: the transaction this confirm was bound to was superseded before it could commit")

// BeginTransaction prepares a confirm-or-revert transaction and returns the
// pending_revision and deployment_nonce a confirm must carry.
//
// The caller must deliver those two values to the operator BEFORE arming the
// new ruleset (design section 5): the nonce reaching the client after the
// dangerous rules are live means it travels over a channel those rules may
// have just broken. Prepare deliberately changes nothing, so the sequence is
//
//	tx := d.BeginTransaction(ctx, revision)   // nothing has changed yet
//	send tx.Revision and tx.Nonce to the operator
//	arm the new ruleset
//	// the daemon now awaits a bound confirm, or reverts on the dead-man timer
func (d *Daemon) BeginTransaction(ctx context.Context, revision uint64) (PendingTransaction, error) {
	if d.txns == nil {
		return PendingTransaction{}, errors.New("agent: no transaction manager is configured")
	}
	tx, err := d.txns.Prepare(ctx, revision, d.confirmWindow)
	if err != nil {
		return PendingTransaction{}, err
	}
	d.mu.Lock()
	// The running policy is snapshotted onto the transaction in the same lock
	// acquisition that installs it, so it can never name a policy other than
	// the one in force when this transaction was prepared. A revert has to put
	// it back: after the kernel is rolled onto the old revision, a daemon still
	// validating against the new one authorizes against a policy nobody is
	// enforcing — an operator the rejected bundle removed stays locked out, one
	// it added stays authorized. On the local path it is the same pointer, so
	// restoring it is a no-op and the two paths stay identical.
	tx.policy = d.policy
	d.pending = tx
	d.mu.Unlock()
	// A new deploy supersedes the previous one's verdict: a red left over
	// from an earlier revert must not make this attempt look failed before
	// it has been tried.
	d.clearStanding()
	d.metrics.SetTransactionPending(true, tx.Deadline)
	d.log.Info("transaction prepared", "revision", tx.Revision, "deadline", tx.Deadline)
	return PendingTransaction{Pending: true, Revision: tx.Revision, Nonce: tx.Nonce}, nil
}

// armIfNewRevision is the arm step: the one place in standalone mode where a
// configuration change becomes live, and therefore the one place
// confirm-or-revert can attach to.
//
// It runs design section 5's ordering literally:
//
//  1. prepare the transaction — snapshots the four artifacts, changes nothing
//  2. establish pending_revision and deployment_nonce
//  3. publish both, to the pending file and the journal, BEFORE arming
//  4. arm: load boot.nft into the kernel, enable the boot unit
//  5. the packet loop's dead-man timer now reverts unless a bound confirm
//     arrives
//
// It arms only when the configuration's revision differs from the one the
// host last recorded as confirmed, so an ordinary restart of an unchanged,
// confirmed host arms nothing and starts no transaction — the boot unit
// already loaded that ruleset, which is the arrangement that keeps the
// fail-closed posture independent of the agent.
//
// It reports whether it armed, because arming changes what the per-service
// pre-arm checks see.
func (d *Daemon) armIfNewRevision(ctx context.Context) (bool, error) {
	if d.txns == nil {
		return false, nil
	}
	// nil boot.nft: the local path arms the file init-standalone already wrote,
	// so there is nothing to stage. See armRevision.
	return d.armRevision(ctx, d.currentPolicy().Revision, nil)
}

// armRevision is the arm step: the one place a configuration change becomes
// live, and therefore the one place confirm-or-revert can attach to. It is
// armIfNewRevision's logic generalised over an explicit revision rather than
// always d.policy.Revision, so applyBundlePolicy can drive the identical
// arm-or-refuse decision for a freshly fetched policy without duplicating
// it — a bundle pull and a locally-driven redeploy are the same kind of
// event from here down, and diverging them is exactly how one of the two
// paths ends up not rolling back the way the other one does.
//
// It runs design section 5's ordering literally:
//
//  1. prepare the transaction — snapshots the four artifacts, changes nothing
//  2. establish pending_revision and deployment_nonce
//  3. publish both, to the pending file and the journal, BEFORE arming
//  4. arm: load boot.nft into the kernel, enable the boot unit
//  5. the packet loop's dead-man timer now reverts unless a bound confirm
//     arrives
//
// It arms only when revision differs from the one the host last recorded as
// confirmed, so an ordinary restart of an unchanged, confirmed host arms
// nothing and starts no transaction — the boot unit already loaded that
// ruleset, which is the arrangement that keeps the fail-closed posture
// independent of the agent.
//
// It reports whether it armed, because arming changes what the per-service
// pre-arm checks see, and because "did not arm" covers two very different
// outcomes a caller must not conflate: nothing to do (already confirmed at
// this revision) and refused to re-arm (this revision was already tried and
// left pending or reverted). Both leave the running policy exactly where it
// was, which is the only thing either caller has to guarantee.
//
// newBootNFT is the ruleset a bundle-driven arm wants on disk, or nil when
// the file already holds what is to be armed (the local path, where
// init-standalone wrote it). It is written HERE — after Prepare has
// snapshotted the old one, and after both no-arm branches have returned —
// and not by the caller, and both halves of that matter:
//
//   - Prepare snapshots boot.nft by reading it off disk, so a caller that
//     wrote the new one first would have the transaction capture the NEW
//     ruleset as the thing to roll back to. Revert would then write it back
//     as if it were the old one, and the host would re-lock at the next boot
//     on a configuration nobody confirmed — the exact failure design section
//     7's "a revert that restores the live table alone looks successful"
//     describes, arriving through the wrong write order instead of a missing
//     write.
//   - A refused re-arm must leave the host exactly as it found it. Writing
//     the new boot.nft before the refuse-checks left a rejected bundle's
//     ruleset on disk with the old one live: nothing changes until the next
//     reboot, which then loads a configuration this function explicitly
//     declined to arm.
func (d *Daemon) armRevision(ctx context.Context, revision uint64, newBootNFT []byte) (bool, error) {
	if d.txns == nil {
		return false, errors.New("agent: no transaction manager is configured")
	}
	recorded, haveRecorded, err := d.txns.RecordedRevision()
	if err != nil {
		return false, err
	}
	if haveRecorded && recorded == revision {
		return false, nil
	}

	// A published record naming this same revision means this configuration
	// has already had its turn: either it was armed and reverted (nothing
	// confirmed it, and re-arming would re-lock the host on every start), or a
	// previous run armed it and died before the transaction resolved (in which
	// case the ruleset is already live and the snapshot that could roll it
	// back died with that process). Neither is a state to arm from, and
	// neither may be cleared by the agent on its own — v1 does not
	// auto-remediate. The operator's way forward is in the message.
	//
	// For a bundle-driven arm this is also what stops a repeat pull of an
	// already-pending bundle from starting a second transaction on top of the
	// first: a process restart resets nothing in Transactions, so a bundle
	// still awaiting confirm is found here on the next attempt regardless of
	// what this Puller instance remembers about its own last-applied version.
	if rec, ok, err := d.txns.LastArm(); err != nil {
		return false, err
	} else if ok && rec.Revision == revision {
		reason := fmt.Sprintf("revision %d was armed and %s; not arming it again. "+
			"Bump the config's revision to deploy a change, confirm it if it is still armed, "+
			"or run `postern disarm --local` to clear postern from this host.", rec.Revision, rec.Outcome)
		d.log.Error("refusing to re-arm", "revision", rec.Revision, "outcome", rec.Outcome)
		d.flagStanding(reason)
		return false, nil
	}

	pending, err := d.BeginTransaction(ctx, revision)
	if err != nil {
		return false, fmt.Errorf("prepare the arm transaction: %w", err)
	}
	if err := d.txns.Publish(d.currentPending()); err != nil {
		// Nothing has been armed yet, so abandoning is free and is the correct
		// answer: arming a configuration whose nonce nobody can read produces a
		// host that will revert in ten minutes and cannot be confirmed in the
		// meantime.
		d.clearPendingUnconditionally()
		return false, fmt.Errorf("publish the pending revision and nonce: %w", err)
	}
	d.log.Warn("ARMING a new configuration; it reverts unless a bound confirm arrives",
		"revision", pending.Revision,
		"deployment_nonce", hex.EncodeToString(pending.Nonce[:]),
		"confirm_with", fmt.Sprintf("postern confirm <host> --revision %d --nonce %s",
			pending.Revision, hex.EncodeToString(pending.Nonce[:])))

	// The new ruleset lands here: after the snapshot that can roll it back,
	// and after the pending record that lets an operator confirm it. A failure
	// is handled the same way an Arm failure is, because at this point the
	// transaction is published and the old boot.nft may already be gone.
	if newBootNFT != nil {
		if err := writeBlob(d.txns.Paths.BootNFT, blob{data: newBootNFT, present: true}, 0o600); err != nil {
			if rerr := d.txns.Revert(ctx, d.currentPending()); rerr != nil {
				d.log.Error("staging the new ruleset failed and so did the revert; the host is in "+
					"neither configuration", "err", rerr)
			}
			d.clearPendingUnconditionally()
			return false, fmt.Errorf("write %s for revision %d: %w", d.txns.Paths.BootNFT, revision, err)
		}
	}

	if err := d.txns.Arm(ctx); err != nil {
		// A half-applied arm is the state the whole mechanism exists to avoid,
		// and there is a snapshot in hand, so use it rather than leaving the
		// host to the dead-man timer ten minutes from now.
		if rerr := d.txns.Revert(ctx, d.currentPending()); rerr != nil {
			d.log.Error("the arm failed and so did the revert; the host is in neither configuration", "err", rerr)
		}
		d.clearPendingUnconditionally()
		return false, fmt.Errorf("arm revision %d: %w", revision, err)
	}
	return true, nil
}

// checkCarrierPortsUnchanged refuses a fetched bundle that moves either SPA
// carrier's identity: the fixed spa_port in fixed mode, or the port_rotation
// secret/window/range under rotation.
//
// The sockets are bound once, at construction, from the local root-owned
// config; nothing rebinds them when a bundle swaps the running policy. So a
// bundle that changed a carrier port would leave the listener on the old port
// and the ruleset describing the new one — the two halves of one control
// pointing at different numbers.
//
// Under rotation the effective udp port legitimately moves every window, so
// the stable identity this guard protects is the secret, the window, and the
// range, not the port. A bundle that changed any of them on a running agent
// would leave the sockets bound and agent_up refreshed against one derivation
// while the ruleset's range drop describes another. Refused for the same
// reason the fixed-port move is: the sockets were bound at startup from the
// derivation this process is running, and nothing re-derives them mid-run.
//
// The http carrier fails a different way, in both modes: its drop rule is
// what keeps the chain's accept policy from carrying everything the agent_up
// accept did not match, so a bundle that dropped spa_http_port would delete
// that rule while the TCP listener stayed bound, and the carrier would become
// a permanently-open, ungated port on a break-glass host. Refusing the bundle
// keeps the last good revision, which is what every other refusal on this
// path also does.
func (d *Daemon) checkCarrierPortsUnchanged(p *config.Policy) error {
	cur := d.currentPolicy()
	if (cur.PortRotation == nil) != (p.PortRotation == nil) {
		return fmt.Errorf("agent: refusing a bundle that turns port rotation %s; rotation decides how the "+
			"sockets were bound at startup and nothing rebinds them for a different mode",
			onOff(p.PortRotation != nil))
	}
	if cur.PortRotation != nil {
		if !bytes.Equal(cur.PortRotation.Secret, p.PortRotation.Secret) {
			return fmt.Errorf("agent: refusing a bundle that moves the port_rotation secret; the sockets and " +
				"agent_up were derived from the running secret and nothing re-derives them mid-run")
		}
		if cur.PortRotation.Window != p.PortRotation.Window {
			return fmt.Errorf("agent: refusing a bundle that moves the port_rotation window from %s to %s",
				cur.PortRotation.Window, p.PortRotation.Window)
		}
		if cur.PortRotation.RangeLo != p.PortRotation.RangeLo || cur.PortRotation.RangeHi != p.PortRotation.RangeHi {
			return fmt.Errorf("agent: refusing a bundle that moves the port_rotation range from %d-%d to %d-%d",
				cur.PortRotation.RangeLo, cur.PortRotation.RangeHi, p.PortRotation.RangeLo, p.PortRotation.RangeHi)
		}
	} else {
		// fixed mode: the spa_port refusal, unchanged from before rotation
		// existed.
		if p.SPAPort != cur.SPAPort {
			return fmt.Errorf("agent: refusing a bundle that moves spa_port from %d to %d; the socket was "+
				"bound at startup and nothing rebinds it, so the ruleset would gate a port nothing is listening on",
				cur.SPAPort, p.SPAPort)
		}
	}
	// spa_http_port stays fixed in both modes: the http carrier is not part
	// of the rotation and is bound once, the same as the UDP port is in
	// fixed mode.
	if p.SPAHTTPPort != cur.SPAHTTPPort {
		return fmt.Errorf("agent: refusing a bundle that moves spa_http_port from %d to %d; the listener was "+
			"bound at startup and nothing rebinds it, so the carrier would keep answering on a port the "+
			"ruleset no longer gates", cur.SPAHTTPPort, p.SPAHTTPPort)
	}
	return nil
}

// onOff renders a bool as "on"/"off" for a log or error message about a
// feature toggle, rather than the bare true/false Go's %v would print.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// checkConsoleRecoveryUnchanged refuses a bundle that would turn this host into
// a console-recovery host (dropping the always-allow interface) when the local
// root config never acknowledged it. console_recovery is a local, root-owned
// decision; a bundle enabling it would let the hub strip a host's recovery path,
// the same class of remote takeover checkCarrierPortsUnchanged refuses for a
// carrier port.
//
// The comparison is against d.localConsoleRecovery, not against the running
// policy: the running policy is exactly what a prior bundle could have already
// swapped, so checking it here would let a first bundle flip the acknowledgment
// and a second one cash it in. localConsoleRecovery is set once, at
// construction, from the enrollment bootstrap the daemon started from — a file
// only root can write.
func (d *Daemon) checkConsoleRecoveryUnchanged(p *config.Policy) error {
	if p.AlwaysAllowIface == "" && !d.localConsoleRecovery {
		return fmt.Errorf("agent: refusing a bundle with no always_allow_iface; console_recovery is a " +
			"local decision and this host's config did not enable it")
	}
	return nil
}

// applyBundlePolicy is armRevision's bundle counterpart, and it is the only
// function pull.go's injected apply ever calls: render the new ruleset, run
// the identical arm-or-refuse decision armRevision already makes for a
// locally-driven redeploy, and only on a genuine arm swap the running policy
// in and re-evaluate pre-arm against it.
//
// It reports whether it actually armed. "Applied" and "did not refuse" are
// not the same event, and conflating them made the pull loop count a refused
// re-arm as an apply, log "applied a fetched bundle" one line after
// "refusing to re-arm", and advance its own version past a revision that was
// never installed — a false all-clear in exactly the metric and journal an
// operator reads during the incident.
//
// The rendered ruleset is handed to armRevision rather than written here,
// because writing it before Prepare would have the transaction snapshot the
// NEW boot.nft as the thing to roll back to. See armRevision's newBootNFT.
//
// Nothing here is reached while blocked on the fetch that produced p —
// PullOnce has already returned from the network entirely by the time this
// runs. It does take Transactions' own mutex for the length of the arm, which
// includes subprocess execution; see that type's doc comment for why that one
// cannot be narrowed and what bounds it.
func (d *Daemon) applyBundlePolicy(ctx context.Context, p *config.Policy) (bool, error) {
	if p == nil {
		return false, errors.New("agent: nil policy")
	}
	if d.txns == nil {
		return false, errors.New("agent: no transaction manager is configured; a fetched bundle cannot be armed")
	}
	if err := d.checkCarrierPortsUnchanged(p); err != nil {
		return false, err
	}
	if err := d.checkConsoleRecoveryUnchanged(p); err != nil {
		return false, err
	}

	plan, err := gate.BuildRulesetPlan(p)
	if err != nil {
		return false, fmt.Errorf("agent: plan the ruleset for a fetched bundle: %w", err)
	}
	rendered := gate.RenderBootNFT(plan)

	armed, err := d.armRevision(ctx, p.Revision, []byte(rendered))
	if err != nil {
		return false, fmt.Errorf("agent: arm a fetched bundle: %w", err)
	}
	if !armed {
		// Either this revision is already the one on record (a repeat fetch of
		// a bundle that has not changed — harmless, since armRevision touched
		// nothing) or armRevision refused to re-arm an already-pending or
		// already-reverted one and has already logged and flagged standing.
		// Either way the running policy is untouched, which is the "keep the
		// last good one" this whole path exists to guarantee.
		return false, nil
	}

	// The policy, the opener and the gate's catalogue, all three. See
	// setPolicy: swapping only the policy pointer left an operator this bundle
	// added passing the grant check and never decrypting.
	d.setPolicy(p)

	// postern_open is recreated so its sets match the catalogue that is now
	// live. Arm has already reloaded postern_boot from the new boot.nft, and
	// leaving the agent's own table on the previous revision's sets would make
	// a gate service this bundle added fail at Open with a missing set — one
	// opaque error further along than the "not a known gate service" setPolicy
	// just fixed. Live elements in postern_open are lost, which is the same
	// cost the boot table's reload already pays; established connections
	// survive either way, because both rulesets accept established above
	// everything else.
	if d.armer != nil {
		if err := d.armer.ApplyOpen(ctx); err != nil {
			d.log.Error("could not recreate the agent's own table for the new revision; a gate service "+
				"this bundle adds cannot be opened until posternd restarts", "table", gate.TableOpen, "err", err)
		}
	}

	// The teardown drop-in tracks the catalogue this bundle just made live, so
	// a fail-closed service it adds also gets the ExecStopPost line that empties
	// that service's set on a crash (#47). Ordered after the arm — the set the
	// new line names now exists in the kernel — and before any knock can grant
	// it, since a knock for a service this bundle adds is only admitted once
	// setPolicy above has made it a known gate service.
	d.syncFlushDropIn(ctx, p)

	// Re-run pre-arm against the ruleset that is now actually live: a fresh
	// boot.nft can enable or disable different per-service checks (PortsArmable
	// resolves sets in the live table), the same reason Run re-checks pre-arm
	// after its own startup arm. A service pre-arm now disables is refused at
	// apply time (see (*Daemon).apply); nothing here can stop a knock that is
	// already in flight.
	pre := RunPreArm(ctx, p, d.checks)
	d.mu.Lock()
	d.prearm = pre
	d.mu.Unlock()
	d.recordPreArm(pre)

	// A global pre-arm failure after a bundle apply is reported and stood on,
	// never returned as fatal: returning an error here would only ever reach
	// the pull loop, which never tears down the packet loop over anything —
	// doing so would be precisely the "hub stops a knock" failure this task
	// exists to rule out. The dead-man timer, and an operator who does not
	// confirm, are what roll a bundle like this back — and that revert restores
	// the pre-arm verdict along with the policy (see checkDeadMan), so a host
	// left inert by such a bundle recovers when it rolls back rather than
	// refusing every knock until the process restarts.
	//
	// It is still an apply. The revision is armed and running, so the puller
	// must record it as installed; reporting otherwise would leave the puller
	// offering the same version again on every interval.
	if pre.Inert() {
		d.log.Error("pre-arm failed after applying a fetched bundle; the running policy is armed but "+
			"flagged, not torn down", "summary", pre.Summary())
		d.flagStanding("pre-arm failed after a bundle update: " + pre.Summary())
		return true, nil
	}
	d.log.Info("applied a fetched bundle", "revision", p.Revision, "summary", pre.Summary())
	return true, nil
}

func (d *Daemon) currentPending() *Transaction {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pending
}

func (d *Daemon) clearPendingUnconditionally() {
	d.mu.Lock()
	d.pending = nil
	d.mu.Unlock()
	d.metrics.SetTransactionPending(false, time.Time{})
}

// pendingTransaction is what Validate compares a confirm packet against. The
// zero value (Pending false) refuses every confirm outright, which is the
// behaviour design section 5 asks for: an unbound confirm authorises the
// wrong thing by construction, so "nothing is pending" is a refusal, not a
// null check standing in for the comparison.
func (d *Daemon) pendingTransaction() PendingTransaction {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		return PendingTransaction{}
	}
	return PendingTransaction{Pending: true, Revision: d.pending.Revision, Nonce: d.pending.Nonce}
}

func (d *Daemon) commitTransaction(ctx context.Context, revision uint64, nonce [16]byte) error {
	d.mu.Lock()
	tx := d.pending
	d.mu.Unlock()
	if tx == nil || d.txns == nil {
		return ErrNoPendingTransaction
	}
	// Commit the transaction the confirm was bound to, not whatever is pending
	// now. Validate proved this packet named (revision, nonce) when it ran; a
	// BeginTransaction landing since has swapped d.pending, and ratifying that
	// instead is exactly the unconfirmed-arm the dead-man exists to prevent.
	// (revision, nonce) is a transaction's identity: Prepare draws a fresh
	// nonce every time, so no two transactions ever share the pair.
	if tx.Revision != revision || tx.Nonce != nonce {
		return ErrConfirmSuperseded
	}
	if err := d.txns.Commit(ctx, tx); err != nil {
		return err
	}
	// The confirmed policy is now durable, so a restart runs it rather than the
	// enrollment-time bootstrap (#52). Written here and not on a revert, so the
	// file rolls back with boot.nft rather than ahead of it: a commit makes both
	// name revision N, a revert leaves both at N-1. The #46 guard above proved
	// d.pending is the transaction this confirm was bound to, and setPolicy only
	// ever runs alongside the BeginTransaction that installs that pending slot,
	// so d.currentPolicy() is the policy this commit just made live.
	d.persistRunningPolicy()
	d.runAfterResolveHook()
	if !d.clearPending(tx) {
		// A different transaction was prepared while Commit was running.
		// Clearing here would destroy it — see clearPending.
		return nil
	}
	d.clearStanding()
	return nil
}

// persistRunningPolicy writes the confirmed running policy to disk so a
// restart runs the configuration a fetched bundle installed rather than the
// enrollment-time bootstrap file (#52). Without it, a posternd restart reloaded
// postern.yaml, re-admitting operators a later bundle had removed and reopening
// services it had closed, and the hub's same-version bundle was then refused as
// not-newer so it could not put the host back.
//
// Empty runningPolicyPath disables it: standalone mode, where the bootstrap
// file already is the running config, and every test that does not opt in.
//
// A write failure is logged, not returned. The commit itself has already
// succeeded and the revision is armed and recorded, so failing the confirm over
// a durability write would be the same false signal writeAppliedVersion
// avoids; what is lost is that the next restart falls back to bootstrap, which
// is exactly where this host was before this file existed. MarshalStandalone is
// the exact inverse ParseStandalone reads back (a reflective round-trip test
// holds it so), and the hub compiles bundles through the same function, so what
// this writes is byte-for-byte what a fresh pull of the same revision would.
func (d *Daemon) persistRunningPolicy() {
	if d.runningPolicyPath == "" {
		return
	}
	p := d.currentPolicy()
	data, err := config.MarshalStandalone(p)
	if err != nil {
		d.log.Error("could not marshal the confirmed policy to persist it; a restart would fall back "+
			"to the enrollment-time config", "revision", p.Revision, "err", err)
		return
	}
	if err := writeBlob(d.runningPolicyPath, blob{data: data, present: true}, 0o600); err != nil {
		d.log.Error("could not persist the confirmed policy; a restart would fall back to the "+
			"enrollment-time config", "path", d.runningPolicyPath, "revision", p.Revision, "err", err)
	}
}

// syncFlushDropIn regenerates posternd.service's per-set flush drop-in from p
// and reloads systemd, so the ExecStopPost lines that empty a fail-closed gate
// on a crash name exactly the sets p has (#47). It runs at the two points the
// live catalogue changes under a fleet host: a bundle apply (the new
// catalogue) and a dead-man revert (the restored one).
//
// Disabled unless a drop-in path was configured, which only a fleet host is
// (see cmd_agent_linux). A standalone host's catalogue is fixed at enrollment,
// so the drop-in init wrote never needs rewriting.
//
// A failure is logged, not returned, for the same reason ApplyOpen's is: the
// arm or the revert has already happened and the gate it manages is live, so
// aborting over a systemctl hiccup would tear down a working configuration to
// avoid a bounded exposure — a drop-in that still names the previous catalogue
// is at worst missing a flush line for a just-added set, whose grant a crash
// would leave standing only until its own timeout expires. That is the exact
// window this closes, narrowed to a reload failure and made loud here.
func (d *Daemon) syncFlushDropIn(ctx context.Context, p *config.Policy) {
	if !d.flushDropIn.Enabled() {
		return
	}
	plan, err := gate.BuildRulesetPlan(p)
	if err != nil {
		d.log.Error("could not plan the ruleset to update the flush drop-in; a bundle-added fail-closed "+
			"gate may not be emptied if this agent is killed", "revision", p.Revision, "err", err)
		return
	}
	if err := d.flushDropIn.Sync(ctx, plan); err != nil {
		d.log.Error("could not update the systemd flush drop-in; a bundle-added fail-closed gate may not "+
			"be emptied if this agent is killed before its grant's timeout", "revision", p.Revision, "err", err)
	}
}

// clearPending clears d.pending only if it still holds the transaction the
// caller was working on, and reports whether it did.
//
// The compare is the whole point. Both callers read d.pending under the
// lock, then do slow I/O (a revert writes four artifacts and shells out to
// nft; a commit hashes two of them) with the lock released. A
// BeginTransaction landing in that window replaces d.pending, and an
// unconditional `d.pending = nil` afterwards then destroys a transaction
// this call never touched: the operator's correctly-bound confirm for the
// new revision is refused as unbound, and no dead-man will ever fire for it,
// leaving an armed and possibly host-locking configuration that can be
// neither confirmed nor auto-reverted. That is strictly worse than either
// outcome the mechanism is supposed to produce.
//
// On why the lock is not simply held across the I/O: not, as an earlier
// version of this comment claimed, to keep the packet loop moving.
// checkDeadMan runs ON the packet loop, so the loop is already stalled for
// the duration of the revert whether or not d.mu is held. What holding it
// would block is every OTHER goroutine's access to this Daemon —
// BeginTransaction, Health, Stats, PreArm — which is where a deploy path and
// a health endpoint live. Serializing the transaction *artifacts* is a real
// requirement and is handled where it belongs, by Transactions' own mutex;
// this lock covers one pointer and should be held for as little as that
// takes.

// runAfterResolveHook is a no-op unless a test installed one. See the field.
func (d *Daemon) runAfterResolveHook() {
	d.mu.Lock()
	hook := d.afterResolveHook
	d.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (d *Daemon) clearPending(tx *Transaction) bool {
	d.mu.Lock()
	if d.pending != tx {
		d.mu.Unlock()
		d.log.Warn("a transaction was prepared while an earlier one was being resolved; "+
			"leaving the newer one pending", "resolved", tx.Revision)
		// Deliberately not published as "nothing pending": a newer transaction
		// owns the slot and its own dead-man deadline, and clearing the gauge
		// here would show an armed, revertible configuration as settled.
		return false
	}
	d.pending = nil
	d.mu.Unlock()
	d.metrics.SetTransactionPending(false, time.Time{})
	return true
}

// checkDeadMan reverts a transaction whose confirmation window elapsed. It
// runs from the packet loop, on every packet and every heartbeat tick, so
// the revert shares the loop's liveness: a wedged agent does not silently
// hold a host in an unconfirmed configuration while a timer goroutine
// cheerfully expires it into a state nothing is left to serve.
//
// The trade is granularity — a revert lands within one heartbeat period of
// the deadline rather than exactly on it — against the confirmation window
// being minutes. That is the right side of the trade.
func (d *Daemon) checkDeadMan(ctx context.Context) {
	d.mu.Lock()
	tx := d.pending
	d.mu.Unlock()
	if tx == nil || d.txns == nil || d.now().Before(tx.Deadline) {
		return
	}

	d.log.Warn("confirmation window elapsed with no bound confirm; reverting",
		"revision", tx.Revision, "deadline", tx.Deadline)
	err := d.txns.Revert(ctx, tx)
	d.metrics.TransactionReverted()

	// The fifth artifact, and the only one that lives in memory: the running
	// policy the reverted transaction was armed from.
	//
	// Without it, a bundle-driven arm that is rolled back leaves the kernel on
	// the old revision and the daemon validating against the new one — so
	// Validate authorizes against a policy nobody is enforcing. An operator the
	// rejected bundle removed stays locked out of a host that no longer has the
	// rules to keep them out; one it added stays authorized against a gate that
	// no longer exists. On a locally-driven arm this restores the same pointer
	// and changes nothing, which is what keeps the two paths identical.
	//
	// Restored even when Revert reported an error. A failed revert leaves the
	// host in neither configuration, and the artifacts it did manage to write
	// are the OLD ones — so the old policy is the better description of what
	// this host is now enforcing, and the standing red flagged below is what
	// says the rest is unknown.
	if tx.policy != nil {
		d.setPolicy(tx.policy)
		// Pre-arm is derived state over the live ruleset and policy, and the
		// revert just rolled both back; re-derive its verdict too. Without this a
		// bundle apply that went inert leaves d.prearm inert for the life of the
		// process: ServiceEnabled would refuse every knock the restored ruleset is
		// enforcing, on a host the rollback has otherwise made healthy again. The
		// four-artifact Revert and the policy restore above are the ruleset and
		// the grants; this is the third piece of the same rolled-back state.
		pre := RunPreArm(ctx, tx.policy, d.checks)
		d.mu.Lock()
		d.prearm = pre
		d.mu.Unlock()
		d.recordPreArm(pre)

		// boot.nft rolled back to tx.policy's ruleset, so the flush drop-in has
		// to name that catalogue too. A bundle that added a fail-closed set and
		// then reverted must not leave the drop-in flushing a set the restored
		// ruleset no longer has (harmless, but wrong), and one that dropped a set
		// must get its flush line back. This is the third rolled-back artifact,
		// alongside the policy and the pre-arm verdict above.
		d.syncFlushDropIn(ctx, tx.policy)
	}

	d.runAfterResolveHook()
	if !d.clearPending(tx) {
		// A newer transaction was prepared while this one was reverting.
		// It owns the pending slot and its own dead-man deadline now; the
		// revert that just ran still applies to the configuration it
		// snapshotted, so it is still reported below.
		d.log.Warn("reverted an expired transaction while a newer one was pending", "reverted", tx.Revision)
	}

	reason := fmt.Sprintf("transaction %d reverted: no confirm arrived within the window", tx.Revision)
	if err != nil {
		// A failed revert is worse than an unconfirmed transaction: the host
		// is now in neither the old configuration nor a confirmed new one.
		reason = fmt.Sprintf("transaction %d revert FAILED: %v", tx.Revision, err)
		d.log.Error("revert failed; the host is in neither configuration", "err", err)
	}
	d.flagStanding(reason)
}

// disarm is the panic button reached over SPA: both postern tables go away,
// boot.nft is deleted, and the boot unit is disabled. The last two are what
// stop the host re-locking at the next reboot — "disarm must clear
// persistence" (design section 7) — and the Gate owns postern_open's removal
// because it owns that table's lifecycle.
func (d *Daemon) disarm(ctx context.Context) error {
	var errs []error
	if err := d.gate.Close(ctx); err != nil {
		errs = append(errs, fmt.Errorf("tear down the agent's tables: %w", err))
	}
	if d.txns != nil {
		if err := d.txns.Disarm(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	d.mu.Lock()
	d.pending = nil
	d.mu.Unlock()
	d.metrics.SetTransactionPending(false, time.Time{})
	return errors.Join(errs...)
}
