package agent_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
)

// --- fakes -------------------------------------------------------------

type fakeUnit struct {
	mu      sync.Mutex
	enabled bool
	sets    int
	// blockSet / enteredSet park SetEnabled, which is Revert's THIRD step.
	// Parking there leaves the host genuinely half-reverted -- ruleset and
	// boot.nft already rolled back, unit and state.json not yet -- which is
	// the state a concurrent Prepare must not be able to snapshot.
	blockSet   chan struct{}
	enteredSet chan struct{}
	// name and order, when set, make SetEnabled append "name:enabled" to a
	// shared log, so a test can assert the ORDER in which the two units are
	// driven. Both nil in every existing test, so recording is off and those
	// tests are unaffected. See TestAgent_Transaction_SetUnitsOrdersToward...
	name  string
	order *unitOrderLog
}

// unitOrderLog records the sequence of unit SetEnabled calls across the two
// fake units, so a test can prove setUnits drives them in the crash-safe
// order (transaction.go's setUnits) rather than only that both end enabled.
type unitOrderLog struct {
	mu  sync.Mutex
	seq []string
}

func (l *unitOrderLog) record(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq = append(l.seq, s)
}

func (l *unitOrderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seq...)
}

// blockNextSetEnabled arms the park after staging is done, so the harness's
// own arm() is not caught by it.
func (u *fakeUnit) blockNextSetEnabled() (entered, release chan struct{}) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.enteredSet = make(chan struct{})
	u.blockSet = make(chan struct{})
	return u.enteredSet, u.blockSet
}

func (u *fakeUnit) Enabled(context.Context) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.enabled, nil
}

func (u *fakeUnit) SetEnabled(_ context.Context, enabled bool) error {
	u.mu.Lock()
	block := u.blockSet
	entered := u.enteredSet
	u.mu.Unlock()

	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}
	if block != nil {
		<-block
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	u.enabled = enabled
	u.sets++
	if u.order != nil {
		u.order.record(fmt.Sprintf("%s:%v", u.name, enabled))
	}
	return nil
}

func (u *fakeUnit) state() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.enabled
}

type fakeRuleset struct {
	mu          sync.Mutex
	table       []byte
	restores    int
	blockSnap   chan struct{}
	enteredSnap chan struct{}
	onRestore   func([]byte) error
}

func (r *fakeRuleset) Snapshot(context.Context) ([]byte, error) {
	r.mu.Lock()
	block := r.blockSnap
	entered := r.enteredSnap
	r.mu.Unlock()

	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}
	if block != nil {
		<-block
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.table...), nil
}

// blockNextSnapshot parks the next Ruleset.Snapshot, which is Commit's
// second step -- after boot.nft has been hashed and before the state file is
// written. Armed after staging, so the harness's own Prepare is not caught.
func (r *fakeRuleset) blockNextSnapshot() (entered, release chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enteredSnap = make(chan struct{})
	r.blockSnap = make(chan struct{})
	return r.enteredSnap, r.blockSnap
}

func (r *fakeRuleset) Restore(_ context.Context, snapshot []byte) error {
	r.mu.Lock()
	hook := r.onRestore
	r.mu.Unlock()
	if hook != nil {
		// Called outside the lock and before the write lands, so a hook can
		// observe the rest of the world at the instant the ruleset is about to
		// change — which is the only moment at which "the nonce was published
		// BEFORE the dangerous rules went live" is a checkable claim.
		if err := hook(snapshot); err != nil {
			return err
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.table = append([]byte(nil), snapshot...)
	r.restores++
	return nil
}

func (r *fakeRuleset) hook(f func([]byte) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRestore = f
}

func (r *fakeRuleset) restoreCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.restores
}

func (r *fakeRuleset) live() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.table)
}

// --- harness -----------------------------------------------------------

type txnHarness struct {
	txns      *agent.Transactions
	paths     agent.Paths
	unit      *fakeUnit
	agentUnit *fakeUnit
	ruleset   *fakeRuleset
}

// txnHarnessRecordedRevision is the revision the staged host has already
// recorded as confirmed. A daemon whose policy names this same revision arms
// nothing at startup, which is what tests about the dead-man timer and the
// confirm binding want.
const txnHarnessRecordedRevision = 41

// newTxnHarness stages a host that is ALREADY armed to a previous
// configuration: a boot.nft on disk, a recorded state file, an enabled boot
// unit, and a live postern_boot table. That is the state a revert has to get
// back to, and staging all four is what makes "restore only the live table"
// a detectable bug rather than an indistinguishable one.
func newTxnHarness(t *testing.T) *txnHarness {
	t.Helper()
	dir := t.TempDir()
	h := &txnHarness{
		paths: agent.Paths{
			BootNFT: filepath.Join(dir, "etc", "boot.nft"),
			State:   filepath.Join(dir, "lib", "state.json"),
			Pending: filepath.Join(dir, "lib", "pending.json"),
		},
		unit:      &fakeUnit{enabled: true},
		agentUnit: &fakeUnit{enabled: true},
		ruleset:   &fakeRuleset{table: []byte("table inet postern_boot { OLD }\n")},
	}
	writeFile(t, h.paths.BootNFT, "OLD BOOT NFT\n")
	writeFile(t, h.paths.State, `{"revision":41,"boot_nft_sha256":"old-nft","ruleset_sha256":"old-rules"}`)

	h.txns = &agent.Transactions{
		Paths:     h.paths,
		BootUnit:  h.unit,
		AgentUnit: h.agentUnit,
		Ruleset:   h.ruleset,
	}
	return h
}

// arm is what a deploy does after Prepare returned: it replaces all four
// artifacts with the new configuration.
func (h *txnHarness) arm(t *testing.T) {
	t.Helper()
	writeFile(t, h.paths.BootNFT, "NEW BOOT NFT\n")
	writeFile(t, h.paths.State, `{"revision":42,"boot_nft_sha256":"new-nft","ruleset_sha256":"new-rules"}`)
	if err := h.ruleset.Restore(context.Background(), []byte("table inet postern_boot { NEW }\n")); err != nil {
		t.Fatalf("arm the live table: %v", err)
	}
	if err := h.unit.SetEnabled(context.Background(), true); err != nil {
		t.Fatalf("enable the boot unit: %v", err)
	}
	if err := h.agentUnit.SetEnabled(context.Background(), true); err != nil {
		t.Fatalf("enable the agent unit: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // this test's own temp path
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b), true
}

// --- tests -------------------------------------------------------------

// Brief invariant 5. "First arm reverts to open" only holds if revert
// restores ALL of: the live postern_boot table, boot.nft, the boot unit's
// enabled state, and the recorded hashes. A revert restoring only the live
// table looks successful — the host is reachable, the operator moves on —
// and re-locks at the next reboot, when the boot unit loads a boot.nft
// nobody rolled back.
//
// The mutation this catches: deleting everything after the Ruleset.Restore
// call in Transactions.Revert. The live table is correct and all three
// remaining assertions fail. Deleting only the unit restore, or only the
// state restore, each fails its own assertion — so this is four independent
// mutations, not one.
func TestAgent_Transaction_RevertRestoresAllFourArtifacts(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	// The pre-transaction state a revert must return to. Deliberately
	// disabled: if the snapshot were taken after arming, or not taken at
	// all, "restore" would land on enabled and look correct.
	if err := h.unit.SetEnabled(ctx, false); err != nil {
		t.Fatalf("stage the boot unit: %v", err)
	}
	if err := h.agentUnit.SetEnabled(ctx, false); err != nil {
		t.Fatalf("stage the agent unit: %v", err)
	}
	tx, err := h.txns.Prepare(ctx, 42, time.Minute)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	h.arm(t)

	// Everything has moved.
	if got, _ := readFile(t, h.paths.BootNFT); got != "NEW BOOT NFT\n" {
		t.Fatalf("precondition: boot.nft was not armed, got %q", got)
	}
	if !h.unit.state() {
		t.Fatal("precondition: the boot unit was not enabled by arming")
	}

	if err := h.txns.Revert(ctx, tx); err != nil {
		t.Fatalf("Revert: %v", err)
	}

	// 1. The live table.
	if got := h.ruleset.live(); got != "table inet postern_boot { OLD }\n" {
		t.Fatalf("live table after revert = %q, want the pre-transaction table", got)
	}
	// 2. boot.nft — the artifact the boot unit loads at the next reboot.
	got, present := readFile(t, h.paths.BootNFT)
	if !present || got != "OLD BOOT NFT\n" {
		t.Fatalf("boot.nft after revert = %q (present=%v), want the pre-transaction file; "+
			"a revert that leaves this behind re-locks the host at the next reboot", got, present)
	}
	// 3. Both units' enabled states, which are one state.
	if h.unit.state() {
		t.Fatal("the boot unit is still enabled after revert; the transaction found it disabled, " +
			"so the host will load drop rules at the next boot that it was not loading before")
	}
	if h.agentUnit.state() {
		t.Fatal("the agent unit is still enabled after revert; the transaction found it disabled, " +
			"so the host will start posternd at the next boot when it was not doing so before")
	}
	// 4. The recorded hashes.
	st, present := readFile(t, h.paths.State)
	if !present {
		t.Fatal("the state file is missing after revert")
	}
	var decoded agent.State
	if err := json.Unmarshal([]byte(st), &decoded); err != nil {
		t.Fatalf("state file is not decodable after revert: %v (%q)", err, st)
	}
	if decoded.Revision != 41 || decoded.BootNFTSHA256 != "old-nft" || decoded.RulesetSHA256 != "old-rules" {
		t.Fatalf("recorded state after revert = %+v, want the pre-transaction revision and hashes; "+
			"a stale hash left behind reports drift forever against a ruleset that is correct", decoded)
	}
}

// First arm is the case the design calls out by name: a freshly enrolled
// host has no history, so reverting its first arm must leave NO persistence
// at all. Writing an empty boot.nft instead of removing it would still be
// loaded by the boot unit; writing an empty state file would decode as
// revision 0 and look like a host that had been armed.
func TestAgent_Transaction_FirstArmRevertsToNoPersistenceAtAll(t *testing.T) {
	dir := t.TempDir()
	unit := &fakeUnit{enabled: false}
	agentUnit := &fakeUnit{enabled: false}
	ruleset := &fakeRuleset{} // no live table yet
	paths := agent.Paths{
		BootNFT: filepath.Join(dir, "etc", "boot.nft"),
		State:   filepath.Join(dir, "lib", "state.json"),
	}
	txns := &agent.Transactions{Paths: paths, BootUnit: unit, AgentUnit: agentUnit, Ruleset: ruleset}
	ctx := context.Background()

	tx, err := txns.Prepare(ctx, 1, time.Minute)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// First arm.
	writeFile(t, paths.BootNFT, "FIRST BOOT NFT\n")
	writeFile(t, paths.State, `{"revision":1}`)
	if err := ruleset.Restore(ctx, []byte("table inet postern_boot { FIRST }\n")); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if err := unit.SetEnabled(ctx, true); err != nil {
		t.Fatalf("enable the boot unit: %v", err)
	}
	if err := agentUnit.SetEnabled(ctx, true); err != nil {
		t.Fatalf("enable the agent unit: %v", err)
	}

	if err := txns.Revert(ctx, tx); err != nil {
		t.Fatalf("Revert: %v", err)
	}

	if got := ruleset.live(); got != "" {
		t.Fatalf("live table after reverting a first arm = %q, want none", got)
	}
	if content, present := readFile(t, paths.BootNFT); present {
		t.Fatalf("boot.nft still exists after reverting a first arm (%q); the boot unit would load it "+
			"and re-lock a host that was never confirmed", content)
	}
	if _, present := readFile(t, paths.State); present {
		t.Fatal("the state file still exists after reverting a first arm; an empty or zero state " +
			"reads as a host that was armed")
	}
	if unit.state() {
		t.Fatal("the boot unit is still enabled after reverting a first arm")
	}
	// Both, and disabled is the right answer for the agent unit too: the host
	// returns to exactly as found. An unconfirmed transaction has earned no
	// right to leave a service starting at boot on a host whose operator never
	// answered, and with the boot unit disabled there is nothing for the agent
	// to open anyway.
	if agentUnit.state() {
		t.Fatal("the agent unit is still enabled after reverting a first arm; the host was found with " +
			"postern not running at boot and a revert must return it to as-found")
	}
}

// The nonce must reach the client BEFORE the dangerous ruleset is armed
// (design section 5's ordering), which means Prepare must be safe to
// abandon: it snapshots and mints, and changes nothing. A Prepare that
// armed as a side effect would deliver the nonce over a channel the new
// rules may have just broken.
func TestAgent_Transaction_PrepareChangesNothing(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	beforeNFT, _ := readFile(t, h.paths.BootNFT)
	beforeState, _ := readFile(t, h.paths.State)
	beforeTable := h.ruleset.live()
	beforeUnit := h.unit.state()
	beforeAgentUnit := h.agentUnit.state()

	tx, err := h.txns.Prepare(ctx, 42, time.Minute)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if got, _ := readFile(t, h.paths.BootNFT); got != beforeNFT {
		t.Fatal("Prepare modified boot.nft")
	}
	if got, _ := readFile(t, h.paths.State); got != beforeState {
		t.Fatal("Prepare modified the state file")
	}
	if h.ruleset.live() != beforeTable {
		t.Fatal("Prepare modified the live table; the nonce would be delivered over a channel the " +
			"new rules may already have broken")
	}
	if h.unit.state() != beforeUnit {
		t.Fatal("Prepare changed the boot unit's enabled state")
	}
	if h.agentUnit.state() != beforeAgentUnit {
		t.Fatal("Prepare changed the agent unit's enabled state")
	}
	if tx.Nonce == ([16]byte{}) {
		t.Fatal("Prepare minted a zero deployment nonce; a confirm bound to it would be bound to nothing")
	}
	if tx.Revision != 42 {
		t.Fatalf("Revision = %d, want 42", tx.Revision)
	}
}

// Two prepares must not produce the same nonce, or a captured confirm for
// one transaction ratifies the next.
func TestAgent_Transaction_NoncesAreUnique(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	seen := map[[16]byte]bool{}
	for i := 0; i < 16; i++ {
		tx, err := h.txns.Prepare(ctx, uint64(i), time.Minute)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if seen[tx.Nonce] {
			t.Fatalf("deployment nonce repeated after %d prepares", i)
		}
		seen[tx.Nonce] = true
	}
}

// Commit records what is now live, so drift has something to compare
// against — and records it from the artifacts themselves rather than from
// whatever the caller believed it wrote.
func TestAgent_Transaction_CommitRecordsTheArmedHashes(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	tx, err := h.txns.Prepare(ctx, 42, time.Minute)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	h.arm(t)

	if err := h.txns.Commit(ctx, tx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	raw, present := readFile(t, h.paths.State)
	if !present {
		t.Fatal("Commit wrote no state file")
	}
	var st agent.State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state file: %v", err)
	}
	if st.Revision != 42 {
		t.Fatalf("Revision = %d, want 42", st.Revision)
	}
	if st.BootNFTSHA256 == "" || st.BootNFTSHA256 == "new-nft" {
		t.Fatalf("boot_nft_sha256 = %q, want a hash computed from the armed file", st.BootNFTSHA256)
	}
	if st.RulesetSHA256 == "" || st.RulesetSHA256 == "new-rules" {
		t.Fatalf("ruleset_sha256 = %q, want a hash computed from the live table", st.RulesetSHA256)
	}
}

// disarm must clear persistence, or the host re-locks at the next reboot
// (design section 7). All three: the live table, boot.nft, and the boot
// unit.
func TestAgent_Transaction_DisarmClearsPersistence(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	if err := h.txns.Disarm(ctx); err != nil {
		t.Fatalf("Disarm: %v", err)
	}

	if got := h.ruleset.live(); got != "" {
		t.Fatalf("the live table survived disarm: %q", got)
	}
	if content, present := readFile(t, h.paths.BootNFT); present {
		t.Fatalf("boot.nft survived disarm (%q); the host re-locks at the next reboot", content)
	}
	if h.unit.state() {
		t.Fatal("the boot unit is still enabled after disarm; the host re-locks at the next reboot")
	}
	if h.agentUnit.state() {
		t.Fatal("the agent unit is still enabled after disarm; a host the operator explicitly cleared " +
			"would start posternd and recreate its table at the next boot")
	}
}

// Round 2, generalized in round 3. Daemon.clearPending closed the race on
// the pending *pointer*; this covers the race on the artifacts underneath
// it, which has the same precondition — a second transaction operation
// concurrent with a resolution — so closing either alone leaves the other
// open.
//
// Every one of Transactions' four exported methods touches the same four
// artifacts, and none of them updates those artifacts atomically: there is
// no transaction spanning a file, a systemd unit and a kernel table, so each
// method walks them one at a time and leaves a window in which the host is
// half-changed. A concurrent method that *observes* that window records or
// restores a configuration the host was never in.
//
// The table exists because an earlier version of this test covered only the
// Prepare/Revert pair, and removing the lock from Commit alone — or from
// Disarm alone — left the whole suite green. Two scenarios are enough to
// cover all four locks, and each row names which removals it catches.
func TestAgent_Transaction_MethodsAreSerializedAgainstEachOther(t *testing.T) {
	cases := []struct {
		name string
		// catches names the single-lock removals this row fails under, so a
		// future edit can tell what it would be giving up.
		catches string
		run     func(t *testing.T, h *txnHarness)
	}{
		{
			name:    "Prepare cannot snapshot a half-reverted host",
			catches: "Prepare, Revert",
			run:     runPrepareDuringRevert,
		},
		{
			name:    "Commit cannot resurrect state on a host being disarmed",
			catches: "Commit, Disarm",
			run:     runDisarmDuringCommit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("this row fails when the mutex is removed from: %s", tc.catches)
			tc.run(t, newTxnHarness(t))
		})
	}
}

// runPrepareDuringRevert parks a revert at its THIRD step (Unit.SetEnabled),
// which leaves the ruleset and boot.nft rolled back to revision 41 while
// state.json still claims 42 — a mix that never existed as a coherent
// configuration. A Prepare that snapshots it produces a transaction whose
// later revert restores boot.nft at 41's content alongside a recorded
// revision of 42, and drift then compares 42's hash against 41's file
// forever.
func runPrepareDuringRevert(t *testing.T, h *txnHarness) {
	ctx := context.Background()

	tx1, err := h.txns.Prepare(ctx, 42, time.Minute)
	if err != nil {
		t.Fatalf("Prepare 42: %v", err)
	}
	h.arm(t)

	entered, release := h.unit.blockNextSetEnabled()
	reverted := make(chan error, 1)
	go func() { reverted <- h.txns.Revert(ctx, tx1) }()

	awaitPark(t, entered, "the revert never reached the boot unit")

	// Confirm the host really is half-reverted, or this proves nothing.
	if got, _ := readFile(t, h.paths.BootNFT); got != "OLD BOOT NFT\n" {
		t.Fatalf("precondition: boot.nft was not rolled back before the park, got %q", got)
	}
	if raw, _ := readFile(t, h.paths.State); !strings.Contains(raw, `"revision":42`) {
		t.Fatalf("precondition: state.json was already rolled back before the park, got %q", raw)
	}

	prepared := make(chan preparedTxn, 1)
	go func() {
		tx, err := h.txns.Prepare(ctx, 43, time.Minute)
		prepared <- preparedTxn{tx, err}
	}()
	time.Sleep(50 * time.Millisecond) // long enough for an unserialized Prepare to finish

	close(release)
	if err := <-reverted; err != nil {
		t.Fatalf("Revert: %v", err)
	}
	got := <-prepared
	if got.err != nil {
		t.Fatalf("Prepare 43: %v", got.err)
	}

	// Roll deploy 2 back. Whatever it snapshotted is what the host becomes.
	if err := h.txns.Revert(ctx, got.tx); err != nil {
		t.Fatalf("Revert 43: %v", err)
	}

	nft, _ := readFile(t, h.paths.BootNFT)
	st := readState(t, h.paths.State)
	if nft == "OLD BOOT NFT\n" && st.Revision != 41 {
		t.Fatalf("reverting the second transaction produced a configuration the host was never in: "+
			"boot.nft is revision 41's content but the recorded state claims revision %d. Prepare "+
			"snapshotted the host mid-rollback; drift will now compare %d's hash against 41's file "+
			"forever", st.Revision, st.Revision)
	}
	if nft != "OLD BOOT NFT\n" {
		t.Fatalf("boot.nft after both reverts = %q, want the pre-transaction file", nft)
	}
}

// runDisarmDuringCommit parks a commit at its SECOND step (Ruleset.Snapshot),
// after boot.nft has been hashed and before the state file is written, and
// runs a disarm alongside it.
//
// disarm is the panic button: it removes both tables, deletes boot.nft, and
// disables the boot unit, precisely so the host does not re-lock at the next
// reboot. A commit that resumes afterwards and writes state.json has
// resurrected recorded persistence on a host the operator explicitly
// disarmed — recording a revision for a configuration that no longer exists
// anywhere.
func runDisarmDuringCommit(t *testing.T, h *txnHarness) {
	ctx := context.Background()

	tx1, err := h.txns.Prepare(ctx, 42, time.Minute)
	if err != nil {
		t.Fatalf("Prepare 42: %v", err)
	}
	h.arm(t)

	entered, release := h.ruleset.blockNextSnapshot()
	committed := make(chan error, 1)
	go func() { committed <- h.txns.Commit(ctx, tx1) }()

	awaitPark(t, entered, "the commit never reached the ruleset snapshot")

	disarmed := make(chan error, 1)
	go func() { disarmed <- h.txns.Disarm(ctx) }()
	time.Sleep(50 * time.Millisecond) // long enough for an unserialized Disarm to finish

	close(release)
	if err := <-committed; err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := <-disarmed; err != nil {
		t.Fatalf("Disarm: %v", err)
	}

	if content, present := readFile(t, h.paths.State); present {
		t.Fatalf("state.json survived a disarm (%q); a commit interleaved with the panic button "+
			"resurrected recorded persistence on a host the operator explicitly cleared", content)
	}
	if content, present := readFile(t, h.paths.BootNFT); present {
		t.Fatalf("boot.nft survived a disarm (%q); the host re-locks at the next reboot", content)
	}
	if h.unit.state() {
		t.Fatal("the boot unit is still enabled after a disarm")
	}
	if h.agentUnit.state() {
		t.Fatal("the agent unit is still enabled after a disarm")
	}
}

type preparedTxn struct {
	tx  *agent.Transaction
	err error
}

func awaitPark(t *testing.T, entered chan struct{}, whenNot string) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal(whenNot)
	}
}

func readState(t *testing.T, path string) agent.State {
	t.Helper()
	raw, present := readFile(t, path)
	if !present {
		t.Fatalf("no state file at %s", path)
	}
	var st agent.State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state file is not decodable: %v (%q)", err, raw)
	}
	return st
}

// --- the arm step ------------------------------------------------------

// Arm is all of its halves or it is not an arm: the rules have to be live now,
// they have to come back at the next boot, and something has to be running
// after that boot to open them. Doing only the first leaves a host whose
// posture evaporates the next time it reboots — the same class of silent
// inconsistency as a revert that restores only the live table, running in the
// other direction.
func TestAgent_Transaction_ArmLoadsTheGeneratedRulesetAndEnablesBothUnits(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()
	if err := h.unit.SetEnabled(ctx, false); err != nil {
		t.Fatalf("stage the boot unit disabled: %v", err)
	}
	if err := h.agentUnit.SetEnabled(ctx, false); err != nil {
		t.Fatalf("stage the agent unit disabled: %v", err)
	}
	writeFile(t, h.paths.BootNFT, "NEW BOOT NFT\n")

	if err := h.txns.Arm(ctx); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	if got := h.ruleset.live(); got != "NEW BOOT NFT\n" {
		t.Fatalf("live table after Arm = %q; the generated ruleset is not what became live", got)
	}
	if !h.unit.state() {
		t.Fatal("the boot unit is still disabled after Arm; the armed posture would vanish at the next boot")
	}
	// The defect this test was extended for. An arm that enables the boot unit
	// and not the agent leaves the host loading `udp dport <spa> drop` and
	// `tcp dport <svc> drop` at every boot with nothing alive to hold the
	// agent_up lease: nothing can knock, nothing can open a gate, and the only
	// way back is the always-allow path — the very path break-glass exists to
	// replace when it is gone. It was found on a real host after a plain
	// `systemctl reboot`.
	if !h.agentUnit.state() {
		t.Fatal("the agent unit is still disabled after Arm; the next boot loads the fail-closed drop " +
			"rules with no agent running to open them, which is indefinite unreachability")
	}
}

// setUnits orders the two units by the direction it drives them, so that a
// crash BETWEEN the two systemctl calls always lands on the reachable side
// (transaction.go's setUnits): enabling does the agent first (a host that runs
// postern but loads no drops), disabling does the boot unit first (a host that
// loads no drops but still runs postern). The reverse orderings are the
// lockout. Every other unit test asserts only the END state -- both enabled
// after Arm, both disabled after Disarm -- which a reversed ordering passes.
// This asserts the ORDER, so a swap of the two first/second assignments in
// setUnits is caught rather than silently shipping the crash-window lockout.
func TestAgent_Transaction_SetUnitsOrdersTowardTheReachableSideOnACrash(t *testing.T) {
	ctx := context.Background()
	order := &unitOrderLog{}
	boot := &fakeUnit{name: "boot", order: order}
	agentUnit := &fakeUnit{name: "agent", order: order}
	ruleset := &fakeRuleset{table: []byte("table inet postern_boot { X }\n")}

	dir := t.TempDir()
	paths := agent.Paths{
		BootNFT: filepath.Join(dir, "boot.nft"),
		State:   filepath.Join(dir, "state.json"),
		Pending: filepath.Join(dir, "pending.json"),
	}
	writeFile(t, paths.BootNFT, "BOOT NFT\n")
	txns := &agent.Transactions{Paths: paths, BootUnit: boot, AgentUnit: agentUnit, Ruleset: ruleset}

	if err := txns.Arm(ctx); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	armOrder := order.snapshot()
	if len(armOrder) != 2 || armOrder[0] != "agent:true" || armOrder[1] != "boot:true" {
		t.Fatalf("arm drove the units in order %v, want [agent:true boot:true]; a crash after the first "+
			"call must leave the agent running, not the drops loaded with nothing to open them", armOrder)
	}

	if err := txns.Disarm(ctx); err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	disarmOrder := order.snapshot()[2:]
	if len(disarmOrder) != 2 || disarmOrder[0] != "boot:false" || disarmOrder[1] != "agent:false" {
		t.Fatalf("disarm drove the units in order %v, want [boot:false agent:false]; a crash after the "+
			"first call must have stopped loading drops, not stopped the agent while drops still load", disarmOrder)
	}
}

// The invariant, stated as one test rather than inferred from four: if the
// boot unit is enabled then the agent unit is enabled. Boot-enabled means the
// drops load at boot; agent-disabled means nothing is alive to open them.
//
// It walks the states a host actually passes through — arm, revert, arm
// again, disarm — and checks the pair after each, because the defect was not
// any one of those steps being wrong in isolation. It was that the two
// enabled-states were free to move independently at all.
//
// The mutation this catches: dropping the AgentUnit call from setUnits, or
// from restoreUnits, or making either take a separate bool per unit.
func TestAgent_Transaction_BootUnitEnabledImpliesAgentUnitEnabled(t *testing.T) {
	h := newTxnHarness(t)
	ctx := context.Background()

	// A host as freshly enrolled: units installed, neither enabled.
	for _, u := range []*fakeUnit{h.unit, h.agentUnit} {
		if err := u.SetEnabled(ctx, false); err != nil {
			t.Fatalf("stage the units disabled: %v", err)
		}
	}
	check := func(when string) {
		t.Helper()
		if h.unit.state() && !h.agentUnit.state() {
			t.Fatalf("%s: postern-boot.service is enabled and posternd.service is not. The next boot "+
				"loads the fail-closed drop rules and nothing is alive to open them; the host is "+
				"unreachable until someone reaches it over the always-allow path", when)
		}
	}

	tx, err := h.txns.Prepare(ctx, 42, time.Minute)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	writeFile(t, h.paths.BootNFT, "NEW BOOT NFT\n")
	if err := h.txns.Arm(ctx); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	check("after an arm")
	if !h.unit.state() {
		t.Fatal("precondition: the arm did not enable the boot unit, so this proves nothing")
	}

	if err := h.txns.Revert(ctx, tx); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	check("after a revert")

	tx2, err := h.txns.Prepare(ctx, 43, time.Minute)
	if err != nil {
		t.Fatalf("Prepare 43: %v", err)
	}
	writeFile(t, h.paths.BootNFT, "NEWER BOOT NFT\n")
	if err := h.txns.Arm(ctx); err != nil {
		t.Fatalf("Arm 43: %v", err)
	}
	check("after a second arm")
	if err := h.txns.Commit(ctx, tx2); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	check("after a commit")

	if err := h.txns.Disarm(ctx); err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	check("after a disarm")
	if h.unit.state() || h.agentUnit.state() {
		t.Fatalf("the panic button left units enabled: boot=%v agent=%v", h.unit.state(), h.agentUnit.state())
	}
}

// Arming a host with no generated ruleset is a refusal, not a silent success.
// The alternative is an agent that reports itself armed while nothing is
// dropping anything.
func TestAgent_Transaction_ArmRefusesWhenThereIsNoGeneratedRuleset(t *testing.T) {
	h := newTxnHarness(t)
	if err := os.Remove(h.paths.BootNFT); err != nil {
		t.Fatalf("remove boot.nft: %v", err)
	}
	before := h.ruleset.live()

	err := h.txns.Arm(context.Background())
	if err == nil {
		t.Fatal("Arm succeeded with no boot.nft to arm")
	}
	if !strings.Contains(err.Error(), "no ruleset") {
		t.Fatalf("Arm error = %v; it should name the missing ruleset", err)
	}
	if got := h.ruleset.live(); got != before {
		t.Fatalf("the live table changed to %q despite the refusal", got)
	}
}

// Publish writes the two values a confirm must carry. It is the standalone
// deploy channel, and it exists so those values can reach an operator before
// the ruleset that might cut them off is armed.
func TestAgent_Transaction_PublishRecordsTheRevisionAndNonceAConfirmMustCarry(t *testing.T) {
	h := newTxnHarness(t)
	tx, err := h.txns.Prepare(context.Background(), 42, time.Hour)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.txns.Publish(tx); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	rec, ok, err := h.txns.LastArm()
	if err != nil || !ok {
		t.Fatalf("LastArm() = %+v, %v, %v", rec, ok, err)
	}
	if rec.Revision != 42 {
		t.Fatalf("published revision = %d, want 42", rec.Revision)
	}
	if rec.Outcome != agent.ArmPending {
		t.Fatalf("published outcome = %q, want %q", rec.Outcome, agent.ArmPending)
	}
	if want := hex.EncodeToString(tx.Nonce[:]); rec.Nonce != want {
		t.Fatalf("published nonce = %q, want %q — an operator retypes this into `postern confirm --nonce`",
			rec.Nonce, want)
	}
	if rec.ConfirmDeadlineUnix != tx.Deadline.Unix() {
		t.Fatalf("published deadline = %d, want %d; the operator cannot tell how long they have",
			rec.ConfirmDeadlineUnix, tx.Deadline.Unix())
	}
}

// A revert has to leave a record behind, and this is why: without one, an
// agent that reverted an unconfirmed arm and was then restarted would find
// the same unrecorded revision in its config and arm it again — locking the
// host for another confirmation window on every start, with nobody there to
// confirm. "First arm reverts to open" has to mean the host stays open.
func TestAgent_Transaction_RevertRecordsTheOutcomeItReachedForThatRevision(t *testing.T) {
	h := newTxnHarness(t)
	tx, err := h.txns.Prepare(context.Background(), 42, time.Hour)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.txns.Publish(tx); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	h.arm(t)
	if err := h.txns.Revert(context.Background(), tx); err != nil {
		t.Fatalf("Revert: %v", err)
	}

	rec, ok, err := h.txns.LastArm()
	if err != nil || !ok {
		t.Fatalf("LastArm() after a revert = %+v, %v, %v; the reverted revision is not recorded "+
			"and the next start would arm it again", rec, ok, err)
	}
	if rec.Revision != 42 || rec.Outcome != agent.ArmReverted {
		t.Fatalf("record after a revert = %+v, want revision 42 %q", rec, agent.ArmReverted)
	}
}

// A commit clears the record, because the state file is now the account of
// this revision. Leaving it would block the agent from ever arming this
// revision again after a later rollback.
func TestAgent_Transaction_CommitClearsThePendingRecord(t *testing.T) {
	h := newTxnHarness(t)
	tx, err := h.txns.Prepare(context.Background(), 42, time.Hour)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.txns.Publish(tx); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	h.arm(t)
	if err := h.txns.Commit(context.Background(), tx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if _, ok, err := h.txns.LastArm(); ok || err != nil {
		t.Fatalf("LastArm() after a commit = present %v, %v; a confirmed configuration is still "+
			"described by a file that says it is waiting", ok, err)
	}
	if st := readState(t, h.paths.State); st.Revision != 42 {
		t.Fatalf("recorded revision after a commit = %d, want 42", st.Revision)
	}
}

// Disarm clears persistence, and the pending record is persistence: a
// disarmed host that still carried one would refuse to arm the revision it
// names when the operator brought postern back.
func TestAgent_Transaction_DisarmClearsThePendingRecord(t *testing.T) {
	h := newTxnHarness(t)
	tx, err := h.txns.Prepare(context.Background(), 42, time.Hour)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.txns.Publish(tx); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := h.txns.Disarm(context.Background()); err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	if _, ok, err := h.txns.LastArm(); ok || err != nil {
		t.Fatalf("LastArm() after a disarm = present %v, %v", ok, err)
	}
}

// RecordedRevision distinguishes "no revision has ever been confirmed" from
// "revision zero was confirmed". Zero is a legitimate first revision, so
// collapsing the two would make a fresh host look like one that had already
// confirmed its configuration — and the arm step would then never run.
func TestAgent_Transaction_RecordedRevisionSeparatesAbsentFromZero(t *testing.T) {
	h := newTxnHarness(t)
	if err := os.Remove(h.paths.State); err != nil {
		t.Fatalf("remove state.json: %v", err)
	}
	rev, ok, err := h.txns.RecordedRevision()
	if err != nil || ok || rev != 0 {
		t.Fatalf("RecordedRevision() with no state file = %d, %v, %v; want 0, false, nil", rev, ok, err)
	}

	writeFile(t, h.paths.State, `{"revision":0}`)
	rev, ok, err = h.txns.RecordedRevision()
	if err != nil || !ok || rev != 0 {
		t.Fatalf("RecordedRevision() with a recorded zero = %d, %v, %v; want 0, true, nil", rev, ok, err)
	}
}
