package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/childenv"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// Confirm-or-revert is transactional, and the word is load-bearing (design
// section 7). "First arm reverts to open" only holds if revert restores ALL
// of: the live postern_boot table, /etc/postern/boot.nft, the two units'
// enabled states, and the recorded hashes. A revert that restores the live
// table alone looks successful — the host is reachable, the operator moves
// on — and then re-locks at the next reboot, when the boot unit loads the
// boot.nft nobody rolled back. That is the failure this file exists to make
// impossible, and it is why Revert restores four artifacts rather than one.
//
// The units are counted as one artifact because they are one: see the
// BootUnit/AgentUnit fields on Transactions.

// Paths locates the on-disk artifacts a revert must restore. Every path is
// injectable rather than a constant, so a test can point the whole
// transaction at a temp directory and assert on real files.
type Paths struct {
	// BootNFT is the generated ruleset the boot oneshot loads,
	// conventionally /etc/postern/boot.nft.
	BootNFT string
	// State is where the recorded revision and hashes live,
	// conventionally /var/lib/postern/state.json.
	State string
	// Pending is where the armed-but-unconfirmed transaction is published,
	// conventionally /var/lib/postern/pending.json. It is written BEFORE the
	// ruleset is armed, because it is this mode's answer to design section
	// 5's step 3 — "return both to the client" — and a nonce that reaches the
	// operator after the dangerous rules are live travels over a channel
	// those rules may have just broken.
	//
	// It is deliberately not one of the four artifacts a revert restores. It
	// is the record OF a transaction, not part of the configuration a
	// transaction changes, and it has to outlive a revert: the outcome it
	// then carries is what stops the agent arming the same unconfirmed
	// revision again the next time it starts.
	Pending string
}

// Arm outcomes recorded in the pending file.
const (
	// ArmPending means the transaction is armed and waiting for a confirm.
	ArmPending = "pending"
	// ArmReverted means the dead-man timer fired: this revision was armed,
	// never confirmed, and rolled back.
	ArmReverted = "reverted"
)

// ArmRecord is the published half of a transaction: the two values a confirm
// packet must carry, and what became of the transaction they belong to.
//
// This is the standalone deploy channel. Design section 12 says the standalone
// channel "returns pending_revision and deployment_nonce synchronously, before
// arming"; with no hub and no deploy process, the agent is what arms, so it
// publishes the pair where the operator can read it — this file, plus the same
// values in the journal — before it touches the ruleset. Both reach an
// operator over a session opened before the arm, which survives it because
// boot.nft accepts established connections above every other rule.
type ArmRecord struct {
	Revision uint64 `json:"revision"`
	// Nonce is hex, because an operator retypes it into
	// `postern confirm --nonce`.
	Nonce string `json:"deployment_nonce"`
	// Outcome is ArmPending or ArmReverted.
	Outcome string `json:"outcome"`
	// ConfirmDeadlineUnix is when the dead-man timer will revert, so the
	// operator reading this knows how long they have.
	ConfirmDeadlineUnix int64 `json:"confirm_deadline_unix"`
	UpdatedAtUnix       int64 `json:"updated_at_unix"`
}

// Unit is one systemd unit's enabled state — whether systemd will start it at
// the next boot. Two of them matter to a transaction, and they are described
// together on Transactions because the whole point is that they move together.
type Unit interface {
	Enabled(ctx context.Context) (bool, error)
	SetEnabled(ctx context.Context, enabled bool) error
}

// LiveRuleset is the live postern_boot table, as text nft(8) can round-trip.
// Restoring an empty snapshot means "this table did not exist"; the
// implementation deletes it rather than loading nothing.
type LiveRuleset interface {
	Snapshot(ctx context.Context) ([]byte, error)
	Restore(ctx context.Context, snapshot []byte) error
}

// State is what the agent records about the configuration it accepted: the
// revision plus the hashes drift compares the live ruleset against. Design
// section 6 requires drift compare against a hash derived from the generated
// boot.nft rather than from an independent rendering, which is exactly why
// the hash has to be rolled back with everything else — a revert that left a
// stale hash behind would report drift forever against a ruleset that is
// correct.
type State struct {
	Revision      uint64 `json:"revision"`
	BootNFTSHA256 string `json:"boot_nft_sha256"`
	RulesetSHA256 string `json:"ruleset_sha256"`
	UpdatedAtUnix int64  `json:"updated_at_unix"`
}

// ErrConcurrentChange means an artifact-mutating method ran while Prepare was
// reading the host's external state, so the snapshot it was assembling would
// describe a host caught mid-change. Prepare returns it instead of a
// transaction; the caller retries, and has lost nothing, because Prepare
// changes nothing.
var ErrConcurrentChange = errors.New("agent: an artifact changed while this transaction was being prepared")

// Transactions owns confirm-or-revert.
//
// Arm, Revert, Commit and Disarm are serialized against each other by mu, and
// that is a correctness requirement rather than tidiness. The four artifacts
// are not updated atomically — Revert writes them one at a time, and must,
// since there is no transaction spanning a file, a systemd unit and a kernel
// table — so an operation interleaved with a Revert sees a host caught
// mid-rollback: boot.nft already back at revision 41 while state.json still
// claims 42. Acting on *that* restores a configuration the host was never in,
// and drift then compares 42's recorded hash against 41's file forever. The
// same window lets Commit record one deploy's revision against another's
// hashes, and lets an Arm undo a panic button that ran a moment earlier.
//
// Daemon.clearPending closes the neighbouring race on the pending *pointer*;
// this closes the one on the artifacts themselves. Both have the same
// precondition — a BeginTransaction concurrent with a resolution — and
// closing either alone leaves the other open.
//
// # What this mutex costs the packet loop, and why Arm still pays it
//
// This mutex IS taken on the packet path, which an earlier version of this
// comment denied: checkDeadMan reaches Revert on every heartbeat tick and
// every packet, and a confirm or disarm packet reaches Commit or Disarm from
// inside Daemon.handle. So whoever holds it stalls the packet loop.
//
// Prepare no longer holds it across its subprocess calls — see that method —
// which removes the pull loop's `systemctl is-enabled` and `nft list table`
// execs from the packet loop's critical path. Arm still holds it across
// `nft -f` and two `systemctl enable`, and that one is not narrowable:
// dropping the lock mid-Arm would let a disarm packet arriving during a
// bundle-driven arm remove the tables, delete boot.nft and disable both units
// while the arm's own subprocesses were still running — after which the arm
// finishes, re-loads the ruleset and re-enables the units, and the host is
// re-locked despite the operator having pressed the panic button. Optimistic
// retry cannot rescue that, because unlike Prepare, Arm has already changed
// the host by the time it could discover the conflict.
//
// The bound: applyBundlePolicyTimeout (30s) is the ctx every bundle-driven Arm
// runs under, and exec.CommandContext kills a child when it expires, so the
// worst case is a packet loop stalled for that long — never indefinitely, and
// never at the hands of anything a hostile hub can send, since a bundle
// reaches Arm only after a signature from a locally-configured signer.
// TestAgent_Transaction_ArmIsExclusiveWithDisarm and
// TestAgent_Transaction_PrepareDoesNotHoldTheLockAcrossItsSubprocessReads are
// what keep both halves of this paragraph true.
type Transactions struct {
	mu sync.Mutex
	// gen counts artifact mutations. Prepare reads it before its unlocked
	// subprocess work and rechecks it after, which is what lets that work
	// happen outside the lock without letting a snapshot span a change.
	gen   uint64
	Paths Paths
	// BootUnit is postern-boot.service: enabled means the fail-closed drop
	// rules load at the next boot, before anything can reach a gated port.
	//
	// AgentUnit is posternd.service: enabled means the agent that opens those
	// rules is alive after that boot to hold the agent_up lease and answer a
	// knock.
	//
	// Their enabled states are one state, not two, and every method here moves
	// them through snapshotUnits/restoreUnits/setUnits rather than touching
	// either field, so no call site can change one without the other. The
	// combination this forbids is boot-enabled with agent-disabled: the drops
	// come back at every boot and nothing is ever alive to open them, which is
	// indefinite unreachability on the normal path, reached with the
	// always-allow path as the only way back — the very path break-glass
	// exists to replace when it is gone.
	//
	// A host was found in exactly that state after a plain `systemctl reboot`,
	// because arming enabled the boot unit and nothing anywhere enabled the
	// agent.
	BootUnit  Unit
	AgentUnit Unit
	Ruleset   LiveRuleset
	// Rand supplies the deployment nonce. Nil selects crypto/rand.
	Rand io.Reader
	// Now defaults to time.Now.
	Now func() time.Time
}

// blob is one snapshotted artifact: its bytes, and whether it existed at
// all. The distinction matters on a first arm, where "restore" means
// "remove", not "write an empty file" — an empty boot.nft would still be
// loaded by the boot unit and an empty state file would parse as revision 0.
type blob struct {
	data    []byte
	present bool
}

// Transaction is one armed-but-unconfirmed configuration change, holding
// everything a revert needs.
type Transaction struct {
	Revision uint64
	Nonce    [16]byte
	Deadline time.Time

	bootNFT blob
	state   blob
	ruleset blob
	units   unitStates

	// policy is the running policy at the instant this transaction was
	// prepared — the fifth thing a revert restores, and the only one that
	// lives in memory rather than on disk or in the kernel.
	//
	// It is set by the Daemon (see BeginTransaction), not by Prepare, because
	// Transactions owns artifacts and knows nothing about who is validating
	// packets against what. Nil means "nothing to restore", which is what a
	// caller driving Transactions directly gets.
	policy *config.Policy
}

// unitStates is the enabled state of every unit postern manages, as one
// value. It is one struct rather than two booleans on Transaction so that a
// snapshot is taken, carried and restored as a unit: a revert that restored
// half of it would be free to leave the host boot-enabled and agent-disabled,
// which is the lockout.
type unitStates struct {
	boot  bool
	agent bool
}

// snapshotUnits reads both units' enabled states, for a revert to restore.
func (m *Transactions) snapshotUnits(ctx context.Context) (unitStates, error) {
	var s unitStates
	var err error
	if m.BootUnit != nil {
		if s.boot, err = m.BootUnit.Enabled(ctx); err != nil {
			return unitStates{}, fmt.Errorf("agent: read the boot unit's enabled state: %w", err)
		}
	}
	if m.AgentUnit != nil {
		if s.agent, err = m.AgentUnit.Enabled(ctx); err != nil {
			return unitStates{}, fmt.Errorf("agent: read the agent unit's enabled state: %w", err)
		}
	}
	return s, nil
}

// restoreUnits puts both units back to a snapshotted pair, attempting both
// even when one fails — a half-restored pair is the state this file exists to
// avoid.
//
// The boot unit goes first, which is the ordering that never passes through
// the lockout. Revert only ever restores a snapshot taken before an arm, and
// an arm drives both to enabled, so every restore either lowers the boot unit
// or leaves it alone: doing that first means a crash between the two calls
// leaves the host open rather than closed with nothing to open it.
func (m *Transactions) restoreUnits(ctx context.Context, s unitStates) error {
	var errs []error
	if m.BootUnit != nil {
		if err := m.BootUnit.SetEnabled(ctx, s.boot); err != nil {
			errs = append(errs, fmt.Errorf("restore the boot unit's enabled state: %w", err))
		}
	}
	if m.AgentUnit != nil {
		if err := m.AgentUnit.SetEnabled(ctx, s.agent); err != nil {
			errs = append(errs, fmt.Errorf("restore the agent unit's enabled state: %w", err))
		}
	}
	return errors.Join(errs...)
}

// setUnits drives every unit to the SAME enabled state. Arm and Disarm both
// go through it, and it takes one bool for both units on purpose: neither can
// express "enable the boot unit only", which is the shape of the defect.
//
// The order follows the direction, so that a crash between the two calls
// always lands on the reachable side: enabling does the agent first (a host
// that will run postern but load no drops), disabling does the boot unit
// first (a host that loads no drops but would still run postern). Both
// intermediate states are open; the reverse orderings are the lockout.
func (m *Transactions) setUnits(ctx context.Context, enabled bool) error {
	first, second := m.AgentUnit, m.BootUnit
	firstWhat, secondWhat := "agent", "boot"
	if !enabled {
		first, second = m.BootUnit, m.AgentUnit
		firstWhat, secondWhat = "boot", "agent"
	}
	verb := "enable"
	if !enabled {
		verb = "disable"
	}

	var errs []error
	if first != nil {
		if err := first.SetEnabled(ctx, enabled); err != nil {
			errs = append(errs, fmt.Errorf("%s the %s unit: %w", verb, firstWhat, err))
		}
	}
	if second != nil {
		if err := second.SetEnabled(ctx, enabled); err != nil {
			errs = append(errs, fmt.Errorf("%s the %s unit: %w", verb, secondWhat, err))
		}
	}
	return errors.Join(errs...)
}

func (m *Transactions) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Prepare snapshots every artifact a revert would have to restore and mints
// the deployment nonce, WITHOUT touching any of them.
//
// That ordering is the point (design section 5): the nonce must reach the
// client before the dangerous ruleset is armed, or it is delivered over a
// channel the new rules may have just broken. So Prepare is step 2 of
//
//  1. prepare transaction
//  2. establish pending_revision and deployment_nonce
//  3. return both to the client
//  4. arm the ruleset
//  5. await SPA confirmation, or revert on the dead-man timer
//
// and it must be safe to abandon a prepared transaction that was never
// armed: nothing has changed yet.
//
// # Why this one does not hold the mutex across its subprocess calls
//
// Reading the host's external state means two `systemctl is-enabled` execs
// and an `nft list table` exec. Holding mu across them meant the pull loop —
// which drives this for a fetched bundle — could hold, for as long as three
// child processes take, the same mutex the packet loop takes on every
// dead-man check and on every confirm or disarm packet. A panic button that
// waits on a subprocess is a panic button with a latency nobody chose.
//
// So the slow reads happen with no lock held, and consistency is kept by a
// generation counter instead: every method that mutates an artifact bumps
// m.gen under the lock, and this rechecks it before committing to the
// snapshot. If anything resolved in between, the snapshot describes a host
// that no longer exists — Transactions' doc comment describes exactly what
// reverting such a snapshot would do — and this returns
// ErrConcurrentChange rather than a transaction.
//
// Aborting is free precisely because Prepare changes nothing: the caller has
// not published a nonce or armed anything, and the pull loop simply tries
// again on its next interval. That is what makes optimistic concurrency the
// right shape here and the wrong shape for Arm, which cannot be undone by
// returning early.
func (m *Transactions) Prepare(ctx context.Context, revision uint64, window time.Duration) (*Transaction, error) {
	m.mu.Lock()
	gen := m.gen
	now := m.now()
	m.mu.Unlock()

	tx := &Transaction{Revision: revision, Deadline: now.Add(window)}

	src := m.Rand
	if src == nil {
		src = rand.Reader
	}
	if _, err := io.ReadFull(src, tx.Nonce[:]); err != nil {
		return nil, fmt.Errorf("agent: mint deployment nonce: %w", err)
	}

	// The two subprocess-backed reads, outside the lock.
	var live blob
	if m.Ruleset != nil {
		data, err := m.Ruleset.Snapshot(ctx)
		if err != nil {
			return nil, fmt.Errorf("agent: snapshot the live %s table: %w", gate.TableBoot, err)
		}
		live = blob{data: data, present: len(data) > 0}
	}
	units, err := m.snapshotUnits(ctx)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != gen {
		return nil, ErrConcurrentChange
	}
	tx.ruleset = live
	tx.units = units
	if tx.bootNFT, err = readBlob(m.Paths.BootNFT); err != nil {
		return nil, fmt.Errorf("agent: snapshot %s: %w", m.Paths.BootNFT, err)
	}
	if tx.state, err = readBlob(m.Paths.State); err != nil {
		return nil, fmt.Errorf("agent: snapshot %s: %w", m.Paths.State, err)
	}
	return tx, nil
}

// Publish writes the pending record: the revision and nonce a confirm must
// carry, and the deadline the dead-man timer will fire at.
//
// It is step 3 of design section 5's ordering and must complete before Arm
// runs. Prepare has changed nothing at this point, so a failure here is a
// transaction that can simply be abandoned — which is the reason the ordering
// is written this way round rather than "arm, then tell someone".
func (m *Transactions) Publish(tx *Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tx == nil {
		return errors.New("agent: no transaction to publish")
	}
	return m.writeArmRecord(ArmRecord{
		Revision:            tx.Revision,
		Nonce:               hex.EncodeToString(tx.Nonce[:]),
		Outcome:             ArmPending,
		ConfirmDeadlineUnix: tx.Deadline.Unix(),
	})
}

// Arm makes the prepared configuration live: it loads the generated boot.nft
// into the kernel, and enables BOTH units so that after the next boot the
// rules come back and the agent that opens them is running.
//
// All of it is the arm, and doing only part would be the failure design
// section 7 describes from one direction or the other. A configuration that is
// live now and gone after a reboot is as inconsistent as one that is reverted
// now and back after a reboot. And a boot unit enabled without the agent unit
// is design section 7's "host rebooted, agent fails → DROP (always-allow
// only)" row — the failure row — reached on the normal path, at every reboot.
//
// The order is load-then-enable, and it is chosen for what a crash between
// them leaves behind: rules live with no boot persistence, which fails toward
// the host being reachable again at the next boot. The reverse ordering fails
// toward a host that re-locks after a crash nobody confirmed. setUnits orders
// the two units on the same principle.
//
// The table is deleted and reloaded rather than loaded over: nft's table
// definitions are additive, so loading boot.nft over a live postern_boot
// would leave the previous revision's rules standing alongside this one's.
func (m *Transactions) Arm(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++ // see Prepare: this is what makes an in-flight snapshot detect the change

	b, err := readBlob(m.Paths.BootNFT)
	if err != nil {
		return fmt.Errorf("agent: read %s to arm it: %w", m.Paths.BootNFT, err)
	}
	if !b.present || len(b.data) == 0 {
		return fmt.Errorf("agent: there is no ruleset at %s to arm", m.Paths.BootNFT)
	}
	if m.Ruleset != nil {
		if err := m.Ruleset.Restore(ctx, b.data); err != nil {
			return fmt.Errorf("agent: load %s into the live %s table: %w", m.Paths.BootNFT, gate.TableBoot, err)
		}
	}
	if err := m.setUnits(ctx, true); err != nil {
		return fmt.Errorf("agent: arm: %w", err)
	}
	return nil
}

// RecordedRevision reports the revision the host last confirmed, and whether
// there is one at all. An absent state file is "none recorded" rather than
// revision zero, because zero is a legitimate first revision.
func (m *Transactions) RecordedRevision() (uint64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, err := readBlob(m.Paths.State)
	if err != nil {
		return 0, false, fmt.Errorf("agent: read %s: %w", m.Paths.State, err)
	}
	if !b.present {
		return 0, false, nil
	}
	var st State
	if err := json.Unmarshal(b.data, &st); err != nil {
		return 0, false, fmt.Errorf("agent: parse %s: %w", m.Paths.State, err)
	}
	return st.Revision, true, nil
}

// LastArm reports the published record of the most recent transaction, and
// whether one exists.
func (m *Transactions) LastArm() (ArmRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastArm()
}

func (m *Transactions) lastArm() (ArmRecord, bool, error) {
	b, err := readBlob(m.Paths.Pending)
	if err != nil {
		return ArmRecord{}, false, fmt.Errorf("agent: read %s: %w", m.Paths.Pending, err)
	}
	if !b.present {
		return ArmRecord{}, false, nil
	}
	var rec ArmRecord
	if err := json.Unmarshal(b.data, &rec); err != nil {
		return ArmRecord{}, false, fmt.Errorf("agent: parse %s: %w", m.Paths.Pending, err)
	}
	return rec, true, nil
}

func (m *Transactions) writeArmRecord(rec ArmRecord) error {
	if m.Paths.Pending == "" {
		return nil
	}
	rec.UpdatedAtUnix = m.now().Unix()
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode the pending record: %w", err)
	}
	if err := writeBlob(m.Paths.Pending, blob{data: append(data, '\n'), present: true}, 0o600); err != nil {
		return fmt.Errorf("agent: write %s: %w", m.Paths.Pending, err)
	}
	return nil
}

// Revert restores every artifact Prepare snapshotted. It attempts all four
// even when one fails and joins the errors, because a partial revert is the
// state this whole mechanism exists to avoid — stopping at the first failure
// would leave exactly the mixed configuration that looks reverted and is
// not.
func (m *Transactions) Revert(ctx context.Context, tx *Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++ // see Prepare: this is what makes an in-flight snapshot detect the change

	if tx == nil {
		return errors.New("agent: no transaction to revert")
	}
	var errs []error

	if m.Ruleset != nil {
		if err := m.Ruleset.Restore(ctx, tx.ruleset.data); err != nil {
			errs = append(errs, fmt.Errorf("restore the live %s table: %w", gate.TableBoot, err))
		}
	}
	if err := writeBlob(m.Paths.BootNFT, tx.bootNFT, 0o600); err != nil {
		errs = append(errs, fmt.Errorf("restore %s: %w", m.Paths.BootNFT, err))
	}
	// Both units, back to the pair Prepare found. Reverting a FIRST arm
	// therefore restores both to disabled: the host returns to exactly as
	// found — nothing drops, and postern does not run at the next boot. That
	// is not a bug and must not be "fixed" by leaving the agent unit enabled.
	// "First arm reverts to open" means the host is left as though postern had
	// never armed, and an unconfirmed transaction has earned no right to start
	// a service at boot on a host whose operator never answered.
	if err := m.restoreUnits(ctx, tx.units); err != nil {
		errs = append(errs, err)
	}
	if err := writeBlob(m.Paths.State, tx.state, 0o600); err != nil {
		errs = append(errs, fmt.Errorf("restore %s: %w", m.Paths.State, err))
	}
	// The published record outlives the revert, carrying the outcome. Without
	// it, an agent that reverted an unconfirmed first arm and was then
	// restarted — by systemd's Restart=always, or by the reboot the revert was
	// protecting against — would find the same unrecorded revision in its
	// config, arm it again, and lock the host again for another confirmation
	// window, on every start, with nobody there to confirm. "First arm reverts
	// to open" has to mean the host stays open.
	if err := m.writeArmRecord(ArmRecord{
		Revision: tx.Revision,
		Nonce:    hex.EncodeToString(tx.Nonce[:]),
		Outcome:  ArmReverted,
	}); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Commit accepts the armed configuration: it records the revision and the
// hashes of what is now live and on disk, so drift has something to compare
// against. Only a confirm bound to this exact transaction reaches here —
// Validate refuses an unbound one outright.
func (m *Transactions) Commit(ctx context.Context, tx *Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++ // see Prepare: this is what makes an in-flight snapshot detect the change

	if tx == nil {
		return errors.New("agent: no transaction to commit")
	}
	st := State{Revision: tx.Revision, UpdatedAtUnix: m.now().Unix()}

	if b, err := readBlob(m.Paths.BootNFT); err != nil {
		return fmt.Errorf("agent: hash %s: %w", m.Paths.BootNFT, err)
	} else if b.present {
		st.BootNFTSHA256 = hashHex(b.data)
	}
	if m.Ruleset != nil {
		live, err := m.Ruleset.Snapshot(ctx)
		if err != nil {
			return fmt.Errorf("agent: hash the live %s table: %w", gate.TableBoot, err)
		}
		st.RulesetSHA256 = hashHex(live)
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode state: %w", err)
	}
	if err := writeBlob(m.Paths.State, blob{data: append(data, '\n'), present: true}, 0o600); err != nil {
		return err
	}
	// The state file is now the record of this revision, so the pending one
	// goes: leaving it behind would block the agent from ever arming this
	// revision again after a later rollback, and would leave a confirmed
	// configuration described by a file that says it is waiting.
	return removeIfPresent(m.Paths.Pending)
}

// Disarm is the panic button (design section 7): it removes the persistent
// table, deletes boot.nft, and disables both units, so the host does not
// re-lock at the next reboot. "disarm must clear persistence, or the host
// re-locks at the next reboot" is why all of it happens here rather than only
// the live table. postern_open is removed by the caller through the Gate,
// which owns that table's lifecycle.
//
// Both units, because the panic button's job is to leave a host that boots as
// though postern were not installed: an agent still enabled would recreate
// postern_open at the next boot on a host the operator explicitly cleared.
func (m *Transactions) Disarm(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++ // see Prepare: this is what makes an in-flight snapshot detect the change

	var errs []error
	if m.Ruleset != nil {
		if err := m.Ruleset.Restore(ctx, nil); err != nil {
			errs = append(errs, fmt.Errorf("remove the live %s table: %w", gate.TableBoot, err))
		}
	}
	if err := removeIfPresent(m.Paths.BootNFT); err != nil {
		errs = append(errs, fmt.Errorf("delete %s: %w", m.Paths.BootNFT, err))
	}
	if err := m.setUnits(ctx, false); err != nil {
		errs = append(errs, err)
	}
	if err := removeIfPresent(m.Paths.State); err != nil {
		errs = append(errs, fmt.Errorf("delete %s: %w", m.Paths.State, err))
	}
	// Disarm clears persistence, and the pending record is persistence: a
	// disarmed host that still carried one would refuse to arm the revision it
	// names when the operator brought postern back.
	if err := removeIfPresent(m.Paths.Pending); err != nil {
		errs = append(errs, fmt.Errorf("delete %s: %w", m.Paths.Pending, err))
	}
	return errors.Join(errs...)
}

// --- artifact helpers --------------------------------------------------

func readBlob(path string) (blob, error) {
	if path == "" {
		return blob{}, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the daemon's own configuration, not from a packet
	if errors.Is(err, os.ErrNotExist) {
		return blob{}, nil
	}
	if err != nil {
		return blob{}, err
	}
	return blob{data: data, present: true}, nil
}

// writeBlob restores a snapshotted file. An absent snapshot removes the
// file rather than writing an empty one: on a first arm the artifact did not
// exist, and an empty boot.nft would still be loaded by the boot unit while
// an empty state file would parse as revision 0.
func writeBlob(path string, b blob, mode os.FileMode) error {
	if path == "" {
		return nil
	}
	if !b.present {
		return removeIfPresent(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// Write-then-rename, so a crash mid-revert leaves either the old file or
	// the new one, never a truncated boot.nft the boot unit would fail to
	// load.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b.data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

func removeIfPresent(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- production implementations ----------------------------------------

// SystemdUnit drives one unit's enabled state through systemctl. Both
// gate.BootUnitName and gate.PosterndUnitName are driven by this type; the
// paths are fields rather than constants so a test, or a host with a
// different layout, can point them elsewhere.
type SystemdUnit struct {
	// Name is the unit, e.g. gate.BootUnitName. It is required and has no
	// default: this type manages two different units now, and a zero value
	// that quietly meant "postern-boot.service" would turn a forgotten field
	// on the agent unit into a second enable of the boot unit and no enable
	// of the agent — which is the lockout, spelled as a typo.
	Name string
	// Systemctl defaults to "systemctl" resolved on PATH.
	Systemctl string
}

func (u SystemdUnit) unit() (string, error) {
	if u.Name == "" {
		return "", errors.New("agent: SystemdUnit.Name is required; there is no default unit")
	}
	return u.Name, nil
}

func (u SystemdUnit) systemctl() string {
	if u.Systemctl == "" {
		return "systemctl"
	}
	return u.Systemctl
}

// Enabled reads the unit's enabled state.
//
// `systemctl is-enabled` exits non-zero for "disabled", so the exit code is
// an answer rather than a failure and the state is read from stdout either
// way. But that cannot be stretched to cover an empty stdout: systemctl
// failing to run at all — the binary absent, not executable, killed — also
// produces "" with a non-nil error, and an earlier version of this function
// listed "" among the disabled states, which mapped "I could not ask" to
// "the answer is no". A genuinely enabled boot unit was then snapshotted as
// disabled, and Revert would go on to disable it, so the fail-closed drop
// rules would stop loading at the next boot. Silent, and in the direction
// that opens ports.
//
// The distinction that matters is therefore not the exit code but whether
// systemctl ran: an *exec.ExitError means it ran and declined to name a
// state, which for this question means the unit is not installed and so is
// not enabled. Anything else means the question went unasked, and that is an
// error.
func (u SystemdUnit) Enabled(ctx context.Context) (bool, error) {
	name, err := u.unit()
	if err != nil {
		return false, err
	}
	cmd := exec.CommandContext(ctx, u.systemctl(), "is-enabled", name) //nolint:gosec // both operands are this type's own configuration
	childenv.Sanitize(cmd)
	out, err := cmd.Output()
	state := strings.TrimSpace(string(out))
	switch state {
	case "enabled", "enabled-runtime", "static", "indirect", "alias":
		return true, nil
	case "disabled", "masked", "masked-runtime", "not-found":
		return false, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// systemctl ran and named no state: the unit file is not installed.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("agent: could not ask %s about %s: %w", u.systemctl(), name, err)
	}
	return false, fmt.Errorf("agent: unrecognized systemctl is-enabled output %q for %s", state, name)
}

func (u SystemdUnit) SetEnabled(ctx context.Context, enabled bool) error {
	name, err := u.unit()
	if err != nil {
		return err
	}
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	cmd := exec.CommandContext(ctx, u.systemctl(), verb, name) //nolint:gosec // both operands are this type's own configuration
	childenv.Sanitize(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("agent: systemctl %s %s: %w: %s", verb, name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

var _ Unit = SystemdUnit{}

// NFTRuleset snapshots and restores the live postern_boot table through
// nft(8) — the same tool the boot path uses, and deliberately not netlink:
// a snapshot has to round-trip through `nft -f` for a restore to be
// possible, so producing it with anything else would mean maintaining a
// second serializer that could disagree with the first.
type NFTRuleset struct {
	// NFT defaults to gate.DefaultNFTPath.
	NFT string
	// Table defaults to gate.TableBoot.
	Table string
}

func (r NFTRuleset) nft() string {
	if r.NFT == "" {
		return gate.DefaultNFTPath
	}
	return r.NFT
}

func (r NFTRuleset) table() string {
	if r.Table == "" {
		return gate.TableBoot
	}
	return r.Table
}

// Snapshot returns the table's text form, or nil when the table is absent.
// An absent table is not an error here: "table absent entirely" is a state
// the design names explicitly (design section 6), and a transaction that
// began before the table existed must be able to revert back to that.
func (r NFTRuleset) Snapshot(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.nft(), "list", "table", "inet", r.table()) //nolint:gosec // both operands are this type's own configuration
	childenv.Sanitize(cmd)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, nil // absent
		}
		return nil, err
	}
	return out, nil
}

// Restore deletes the table and, if the snapshot is non-empty, reloads it
// from the snapshot text. Delete-then-load rather than load-over: nft's
// table definitions are additive, so loading over a live table would leave
// whatever the transaction added standing alongside what it restored.
func (r NFTRuleset) Restore(ctx context.Context, snapshot []byte) error {
	del := exec.CommandContext(ctx, r.nft(), "delete", "table", "inet", r.table()) //nolint:gosec // both operands are this type's own configuration
	childenv.Sanitize(del)
	if out, err := del.CombinedOutput(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return fmt.Errorf("agent: %s delete table inet %s: %w: %s", r.nft(), r.table(), err, out)
		}
		// A non-zero exit is "no such table", which is the state we want.
	}
	if len(snapshot) == 0 {
		return nil
	}
	load := exec.CommandContext(ctx, r.nft(), "-f", "-") //nolint:gosec // the operand is this type's own configuration
	childenv.Sanitize(load)
	load.Stdin = strings.NewReader(string(snapshot))
	if out, err := load.CombinedOutput(); err != nil {
		return fmt.Errorf("agent: %s -f - (restore %s): %w: %s", r.nft(), r.table(), err, out)
	}
	return nil
}

var _ LiveRuleset = NFTRuleset{}
