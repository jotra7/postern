//go:build unix

package replay_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jotra7/postern/internal/replay"
)

func newStore(t *testing.T, now *uint64, capacity int) (replay.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replay.log")
	s, err := replay.Open(path, replay.Options{
		PerKeyCapacity: capacity,
		NowMS:          func() uint64 { return *now },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func res(key, req byte, counter uint64, isGate bool, expires uint64) replay.Reservation {
	r := replay.Reservation{Counter: counter, IsGate: isGate, ExpiresAtMS: expires}
	for i := range r.KeyID {
		r.KeyID[i] = key
		r.RequestID[i] = req
	}
	return r
}

func TestReplay_Reserve_AcceptsThenRejectsTheSameRequestID(t *testing.T) {
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 128)

	if err := s.Reserve(res(1, 1, 100, true, now+3600_000)); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := s.Reserve(res(1, 1, 100, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("second Reserve = %v, want ErrDuplicate", err)
	}
}

func TestReplay_HighWater_TakesMaximumNeverLastSeen(t *testing.T) {
	// Storing the packet's counter directly would let the timestamp path lower
	// the mark, re-enabling a suppressed packet with a higher counter.
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 128)

	if err := s.Reserve(res(1, 1, 1000, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Reserve(res(1, 2, 500, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	var key [16]byte
	for i := range key {
		key[i] = 1
	}
	if got := s.HighWater(key); got != 1000 {
		t.Fatalf("HighWater = %d, want 1000; a lower counter must not lower the mark", got)
	}
}

func TestReplay_HighWater_UnchangedByActions(t *testing.T) {
	// An accepted action must not move the gate high-water mark, or a confirm
	// could silently disable drift tolerance for later gate requests.
	//
	// The action below deliberately carries a counter ABOVE the established
	// mark. A zero counter here would make this test unable to fail: with
	// max(1000, 0) == 1000, an implementation that ignored IsGate entirely
	// would pass identically to a correct one. Wire-level canonicalisation
	// does force an action's counter to zero, but that is enforced one layer
	// up in internal/spa; this store takes a Reservation struct, and its own
	// contract is "counter is ignored unless IsGate" — so that is what gets
	// tested here.
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 128)

	if err := s.Reserve(res(1, 1, 1000, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve gate: %v", err)
	}
	if err := s.Reserve(res(1, 2, 5000, false, now+60_000)); err != nil {
		t.Fatalf("Reserve action: %v", err)
	}

	var key [16]byte
	for i := range key {
		key[i] = 1
	}
	if got := s.HighWater(key); got != 1000 {
		t.Fatalf("HighWater = %d after an action carrying counter 5000, want 1000", got)
	}
}

func TestReplay_Reserve_RejectsAtCapacityRatherThanEvicting(t *testing.T) {
	// Plain LRU could evict an entry while its packet still passes the
	// timestamp path, accepting the same packet twice. Capacity failure must
	// reject and report, never evict a live entry.
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 4)

	for i := 0; i < 4; i++ {
		if err := s.Reserve(res(1, byte(i), uint64(i+1), true, now+3600_000)); err != nil {
			t.Fatalf("Reserve %d: %v", i, err)
		}
	}
	err := s.Reserve(res(1, 99, 99, true, now+3600_000))
	if !errors.Is(err, replay.ErrCapacity) {
		t.Fatalf("Reserve at capacity = %v, want ErrCapacity", err)
	}

	// The earliest entry must still be present, i.e. still refused as a replay.
	if err := s.Reserve(res(1, 0, 1, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("earliest entry was evicted: Reserve = %v, want ErrDuplicate", err)
	}
}

func TestReplay_Capacity_IsIsolatedPerKey(t *testing.T) {
	// A stolen probe key must not be able to exhaust the storage that keeps
	// operator requests unique.
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 4)

	for i := 0; i < 4; i++ {
		if err := s.Reserve(res(2, byte(i), uint64(i+1), true, now+3600_000)); err != nil {
			t.Fatalf("Reserve for noisy key %d: %v", i, err)
		}
	}
	if err := s.Reserve(res(2, 9, 9, true, now+3600_000)); !errors.Is(err, replay.ErrCapacity) {
		t.Fatalf("noisy key = %v, want ErrCapacity", err)
	}
	if err := s.Reserve(res(1, 0, 1, true, now+3600_000)); err != nil {
		t.Fatalf("quiet key was starved by a noisy one: %v", err)
	}
}

func TestReplay_ExpiredEntriesFreeCapacity(t *testing.T) {
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 2)

	if err := s.Reserve(res(1, 0, 1, true, now+1000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Reserve(res(1, 1, 2, true, now+1000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	now += 5000 // both entries are now past their expiry

	if err := s.Reserve(res(1, 2, 3, true, now+1000)); err != nil {
		t.Fatalf("Reserve after expiry: %v", err)
	}
}

// TestReplay_Open_RejectsSecondOpenerOnSamePath is the exclusion FIX 5
// exists for: Open used os.OpenFile with no lock, so two openers on one
// path — a systemd restart race, or a future dump tool run alongside a
// running agent — would each hold their own offset and their own in-memory
// dedup map, and the same request_id could be accepted twice. A second Open
// against a path still held by a live first Open must fail immediately, and
// must succeed again once the first Close releases the lock.
func TestReplay_Open_RejectsSecondOpenerOnSamePath(t *testing.T) {
	now := uint64(1_000_000)
	path := filepath.Join(t.TempDir(), "replay.log")
	opts := replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }}

	first, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	if _, err := replay.Open(path, opts); err == nil {
		t.Fatal("second Open while the first is live = nil error, want a lock-contention error")
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("Open after the first closed = %v, want nil: the lock must release with the file", err)
	}
	defer func() { _ = second.Close() }()

	// The reopened store must still see state persisted by the first: this
	// is the exclusion test, not a substitute for the recovery tests below,
	// but a lock implementation that broke persistence in the process (e.g.
	// by opening a stale fd) would be worth catching here too.
	if err := second.Reserve(res(1, 1, 10, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve after reopen: %v", err)
	}
}

func TestReplay_Open_RecoversStateFromDisk(t *testing.T) {
	// Persistence is the point: a request accepted before a restart must not be
	// accepted again after one.
	now := uint64(1_000_000)
	path := filepath.Join(t.TempDir(), "replay.log")
	opts := replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }}

	s, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Reserve(res(1, 1, 4242, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if err := reopened.Reserve(res(1, 1, 4242, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("after restart Reserve = %v, want ErrDuplicate", err)
	}
	var key [16]byte
	for i := range key {
		key[i] = 1
	}
	if got := reopened.HighWater(key); got != 4242 {
		t.Fatalf("HighWater after restart = %d, want 4242", got)
	}
}

func TestReplay_Open_RecoversMultipleKeysAndEntries(t *testing.T) {
	// A restart test that only ever writes one record can't tell a correct
	// loader from one that merely echoes back a single hardcoded entry. Cover
	// multiple keys, multiple entries per key, and mixed gate/action records.
	now := uint64(1_000_000)
	path := filepath.Join(t.TempDir(), "replay.log")
	opts := replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }}

	s, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Reserve(res(1, 1, 10, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Reserve(res(1, 2, 5, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Reserve(res(1, 3, 999, false, now+3600_000)); err != nil {
		t.Fatalf("Reserve action: %v", err)
	}
	if err := s.Reserve(res(2, 1, 77, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve other key: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	var key1, key2 [16]byte
	for i := range key1 {
		key1[i] = 1
		key2[i] = 2
	}
	if got := reopened.HighWater(key1); got != 10 {
		t.Fatalf("HighWater(key1) = %d, want 10 (action counter 999 must not count)", got)
	}
	if got := reopened.HighWater(key2); got != 77 {
		t.Fatalf("HighWater(key2) = %d, want 77", got)
	}

	for _, req := range []byte{1, 2, 3} {
		if err := reopened.Reserve(res(1, req, 1, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
			t.Fatalf("key1 req %d after restart = %v, want ErrDuplicate", req, err)
		}
	}
	if err := reopened.Reserve(res(2, 1, 1, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("key2 req1 after restart = %v, want ErrDuplicate", err)
	}
}

func TestReplay_Open_RecoversFromTornTailRecord(t *testing.T) {
	// A crash mid-write leaves a partial final record on disk. load() must
	// discard exactly that torn tail and keep every whole record before it,
	// rather than failing to open or losing intact history.
	now := uint64(1_000_000)
	path := filepath.Join(t.TempDir(), "replay.log")
	opts := replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }}

	s, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Reserve(res(1, 1, 10, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Reserve(res(1, 2, 20, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Two whole 49-byte records were written. Append a partial third record
	// (fewer than 49 bytes) directly onto the file to simulate a crash
	// mid-write, then reopen.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("OpenFile append: %v", err)
	}
	torn := make([]byte, 30)
	for i := range torn {
		torn[i] = 0xAB
	}
	if _, err := f.Write(torn); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close after torn write: %v", err)
	}

	reopened, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("reopen with torn tail: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	var key [16]byte
	for i := range key {
		key[i] = 1
	}
	if got := reopened.HighWater(key); got != 20 {
		t.Fatalf("HighWater after torn-tail recovery = %d, want 20 (both whole records intact)", got)
	}
	if err := reopened.Reserve(res(1, 1, 10, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("req 1 after torn-tail recovery = %v, want ErrDuplicate", err)
	}
	if err := reopened.Reserve(res(1, 2, 20, true, now+3600_000)); !errors.Is(err, replay.ErrDuplicate) {
		t.Fatalf("req 2 after torn-tail recovery = %v, want ErrDuplicate", err)
	}

	// The file on disk should have been truncated back to whole records:
	// original size minus the 30-byte torn tail.
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after reopen: %v", err)
	}
	if after.Size() != info.Size() {
		t.Fatalf("file size after torn-tail truncation = %d, want %d (original whole-record size)", after.Size(), info.Size())
	}

	// A subsequent Reserve must append cleanly after the truncation point,
	// not after the discarded torn bytes.
	if err := reopened.Reserve(res(1, 3, 30, true, now+3600_000)); err != nil {
		t.Fatalf("Reserve after torn-tail recovery: %v", err)
	}
	final, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat final: %v", err)
	}
	if final.Size() != after.Size()+recordSizeForTest {
		t.Fatalf("file size after append = %d, want %d", final.Size(), after.Size()+recordSizeForTest)
	}
}

// recordSizeForTest mirrors the package-internal record size so the
// black-box test package can assert on file layout without importing
// unexported identifiers.
const recordSizeForTest = 49

// TestReplay_Open_RejectsFileTooSmallForOneRecord's name predates the file
// header this package now writes and verifies (FIX 6, deferred item): a
// nonzero file too short to even contain a header used to be silently
// recovered as an empty store — this test's name always said "Rejects" but
// its body actually asserted the opposite, successful recovery. Silently
// treating unrecognized garbage at the front of the file as "start fresh"
// is itself the hazard a versioned header exists to close: deleting or
// resetting a replay store reopens the exact replay window it exists to
// prevent, so a file that cannot be verified as this store's own format
// must now be rejected outright, matching what the test's name always
// claimed.
func TestReplay_Open_RejectsFileTooSmallForOneRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	if err := os.WriteFile(path, []byte{0x01, 0x02, 0x03}, 0o600); err != nil {
		t.Fatalf("seed short file: %v", err)
	}

	now := uint64(1_000_000)
	_, err := replay.Open(path, replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }})
	if err == nil {
		t.Fatal("Open on a file too short to contain a header = nil error, want a rejection")
	}
}

// headerSizeForTest mirrors the package-internal header size so the
// black-box test package can construct and inspect headers without
// importing unexported identifiers.
const headerSizeForTest = 8

func TestReplay_Open_WritesAVerifiableHeaderOnANewStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	now := uint64(1_000_000)
	opts := replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }}

	s, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	header, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(header) < headerSizeForTest {
		t.Fatalf("store file is %d bytes, want at least the %d-byte header", len(header), headerSizeForTest)
	}
	if !bytes.Equal(header[0:4], []byte("PRPL")) {
		t.Fatalf("header magic = %q, want %q", header[0:4], "PRPL")
	}
	if header[4] != 1 {
		t.Fatalf("header format version = %d, want 1", header[4])
	}

	// Reopening a store that already carries a valid header must succeed.
	reopened, err := replay.Open(path, opts)
	if err != nil {
		t.Fatalf("reopen a store with a valid header: %v", err)
	}
	_ = reopened.Close()
}

func TestReplay_Open_RejectsMismatchedMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	bad := append([]byte("XXXX"), 1, 0, 0, 0) // wrong magic, otherwise well-formed
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("seed file with mismatched magic: %v", err)
	}

	now := uint64(1_000_000)
	_, err := replay.Open(path, replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }})
	if err == nil {
		t.Fatal("Open on a file with the wrong magic = nil error, want a rejection")
	}
}

func TestReplay_Open_RejectsUnsupportedFormatVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	bad := append([]byte("PRPL"), 99, 0, 0, 0) // correct magic, version this build cannot read
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("seed file with an unsupported version: %v", err)
	}

	now := uint64(1_000_000)
	_, err := replay.Open(path, replay.Options{PerKeyCapacity: 128, NowMS: func() uint64 { return now }})
	if err == nil {
		t.Fatal("Open on a file with an unsupported format version = nil error, want a rejection")
	}
}

func TestReplay_Reserve_ConcurrentDistinctRequestsAreRaceFree(t *testing.T) {
	// Reserve mutates the byKey and high maps. Distinct goroutines reserving
	// distinct request IDs for the same key must not race on those maps —
	// this is what -race is checking, independent of the outcome of any
	// individual Reserve call.
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 256)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Reserve(res(1, byte(i), uint64(i+1), true, now+3600_000)) //nolint:gosec // G115: i ranges 0..n-1 with n==8, well within byte
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d Reserve: %v", i, err)
		}
	}

	var key [16]byte
	for i := range key {
		key[i] = 1
	}
	if got := s.HighWater(key); got != n {
		t.Fatalf("HighWater = %d, want %d", got, n)
	}
}

func TestReplay_Reserve_ConcurrentSameRequestIDExactlyOneSucceeds(t *testing.T) {
	// The property that matters is stronger than "no data race reported": of
	// N goroutines racing to reserve the identical request_id, exactly one
	// must win and every other caller must see ErrDuplicate. Anything else
	// means the same captured packet could be accepted, and acted on, more
	// than once.
	now := uint64(1_000_000)
	s, _ := newStore(t, &now, 256)

	const n = 32
	var successes int64
	var duplicates int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Reserve(res(9, 9, 1, true, now+3600_000))
			switch {
			case err == nil:
				atomic.AddInt64(&successes, 1)
			case errors.Is(err, replay.ErrDuplicate):
				atomic.AddInt64(&duplicates, 1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	if duplicates != n-1 {
		t.Fatalf("duplicates = %d, want %d", duplicates, n-1)
	}
}
