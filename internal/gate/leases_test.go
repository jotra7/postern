package gate

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return pfx
}

func openStore(t *testing.T, path string) *leaseStore {
	t.Helper()
	s, err := openLeaseStore(path)
	if err != nil {
		t.Fatalf("openLeaseStore: %v", err)
	}
	return s
}

// Recovering the schedule across a restart is the store's only reason to
// exist: without it, an admission whose deadline has not yet passed survives
// the restart with nothing left that knows to withdraw it.
func TestGate_LeaseStore_RecoversLeasesAcrossAReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")

	first := openStore(t, path)
	leases := []Lease{
		{Service: "perimeter", Source: Source{Kind: SourceObserved, Prefix: mustPrefix(t, "203.0.113.5/32")}, ExpiresAtMS: 1700000000000},
		{Service: "perimeter", Source: Source{Kind: SourceAsserted, Prefix: mustPrefix(t, "198.51.100.0/24")}, ExpiresAtMS: 1700000060000},
		{Service: "edge", Source: Source{Kind: SourceObserved, Prefix: mustPrefix(t, "2001:db8::1/128")}, ExpiresAtMS: 1700000120000},
	}
	for _, l := range leases {
		if err := first.Put(l); err != nil {
			t.Fatalf("Put %v: %v", l.Source.Prefix, err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openStore(t, path)
	defer func() { _ = second.Close() }()

	got := second.Live()
	if len(got) != len(leases) {
		t.Fatalf("recovered %d leases, want %d: %+v", len(got), len(leases), got)
	}
	// Live() sorts by service then prefix, so "edge" comes first.
	if got[0].Service != "edge" || got[0].Source.Prefix.String() != "2001:db8::1/128" {
		t.Errorf("first recovered lease = %+v", got[0])
	}
	if got[0].ExpiresAtMS != 1700000120000 {
		t.Errorf("recovered expiry = %d, want 1700000120000", got[0].ExpiresAtMS)
	}
	for _, l := range got {
		if l.Service == "perimeter" && l.Source.Prefix.String() == "198.51.100.0/24" && l.Source.Kind != SourceAsserted {
			t.Errorf("asserted lease came back as %s", l.Source.Kind)
		}
	}
}

// A tombstoned lease must not come back, or a restart would re-acquire a
// responsibility that was already discharged and issue a second withdrawal
// for an admission that is gone.
func TestGate_LeaseStore_DeletedLeaseDoesNotSurviveAReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")

	first := openStore(t, path)
	keep := Lease{Service: "perimeter", Source: Source{Prefix: mustPrefix(t, "203.0.113.5/32")}, ExpiresAtMS: 42}
	drop := Lease{Service: "perimeter", Source: Source{Prefix: mustPrefix(t, "203.0.113.6/32")}, ExpiresAtMS: 42}
	for _, l := range []Lease{keep, drop} {
		if err := first.Put(l); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := first.Delete(drop.Service, drop.Source.Prefix); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openStore(t, path)
	defer func() { _ = second.Close() }()

	got := second.Live()
	if len(got) != 1 || got[0].Source.Prefix != keep.Source.Prefix {
		t.Fatalf("recovered %+v, want only %s", got, keep.Source.Prefix)
	}
}

// The log is append-only, so without this it would grow by a record per knock
// forever in a process that runs for months. Truncating when nothing is live
// is safe precisely because there is no live state in the discarded bytes.
func TestGate_LeaseStore_TruncatesToTheHeaderWhenNothingIsLive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")
	s := openStore(t, path)
	defer func() { _ = s.Close() }()

	l := Lease{Service: "perimeter", Source: Source{Prefix: mustPrefix(t, "203.0.113.5/32")}, ExpiresAtMS: 42}
	for i := 0; i < 20; i++ {
		if err := s.Put(l); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete(l.Service, l.Source.Prefix); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != leaseHeaderSize {
		t.Errorf("file size after 20 open/close cycles = %d, want %d", info.Size(), leaseHeaderSize)
	}
}

// A crash mid-write leaves a partial record. Everything before it is intact,
// and rejecting the whole file over the tail would strand every admission the
// intact part describes.
func TestGate_LeaseStore_TruncatesATornTailRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")

	first := openStore(t, path)
	l := Lease{Service: "perimeter", Source: Source{Prefix: mustPrefix(t, "203.0.113.5/32")}, ExpiresAtMS: 42}
	if err := first.Put(l); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	//nolint:gosec // G304: a path this test created
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.Write(make([]byte, leaseRecordSize/2)); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := openStore(t, path)
	defer func() { _ = second.Close() }()
	if got := second.Live(); len(got) != 1 {
		t.Fatalf("recovered %d leases past a torn tail, want 1: %+v", len(got), got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if want := int64(leaseHeaderSize + leaseRecordSize); info.Size() != want {
		t.Errorf("file size after recovery = %d, want %d (the torn tail should be gone)", info.Size(), want)
	}
}

// An unrecognized file must not read as "no admissions are open". That is the
// answer that silently strands every hole a previous build left behind, which
// is the same reasoning internal/replay's header carries.
func TestGate_LeaseStore_RefusesAFileWithoutTheMagicValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")
	if err := os.WriteFile(path, []byte("not a lease store at all"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := openLeaseStore(path)
	if err == nil {
		t.Fatal("openLeaseStore accepted a file with no magic value")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error does not name the magic value: %v", err)
	}
}

func TestGate_LeaseStore_RefusesAnUnsupportedFormatVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")
	header := []byte{'P', 'G', 'L', 'S', leaseFormatVersion + 1, 0, 0, 0}
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := openLeaseStore(path)
	if err == nil {
		t.Fatal("openLeaseStore accepted a format version this build does not understand")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error does not name the version: %v", err)
	}
}

// Two openers each hold their own view of which admissions are live, and the
// second one's reaper would close leases the first still believes in.
func TestGate_LeaseStore_RefusesASecondOpener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")
	first := openStore(t, path)
	defer func() { _ = first.Close() }()

	if _, err := openLeaseStore(path); err == nil {
		t.Fatal("a second openLeaseStore against the same path succeeded")
	}
}

// Both the reaper and a clean shutdown can reach the same admission; the
// second to arrive has nothing left to do and must not report a failure.
func TestGate_LeaseStore_DeleteOfAnAbsentLeaseIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")
	s := openStore(t, path)
	defer func() { _ = s.Close() }()

	if err := s.Delete("perimeter", mustPrefix(t, "203.0.113.5/32")); err != nil {
		t.Errorf("Delete of an absent lease: %v", err)
	}
}

func TestGate_LeaseStore_DueReturnsOnlyLapsedLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")
	s := openStore(t, path)
	defer func() { _ = s.Close() }()

	lapsed := Lease{Service: "perimeter", Source: Source{Prefix: mustPrefix(t, "203.0.113.5/32")}, ExpiresAtMS: 1000}
	live := Lease{Service: "perimeter", Source: Source{Prefix: mustPrefix(t, "203.0.113.6/32")}, ExpiresAtMS: 3000}
	for _, l := range []Lease{lapsed, live} {
		if err := s.Put(l); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	got := s.Due(2000)
	if len(got) != 1 || got[0].Source.Prefix != lapsed.Source.Prefix {
		t.Fatalf("Due(2000) = %+v, want only %s", got, lapsed.Source.Prefix)
	}
	// The boundary is inclusive: a lease whose deadline is exactly now has
	// lapsed, not "has one millisecond left".
	if got := s.Due(3000); len(got) != 2 {
		t.Errorf("Due at a lease's exact deadline returned %d leases, want 2", len(got))
	}
}

// A lease surviving a reopen with the wrong address family would have the
// reaper ask a script to withdraw an address that was never admitted.
func TestGate_LeaseStore_RoundTripsBothAddressFamilies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate-leases.db")

	first := openStore(t, path)
	v4 := Lease{Service: "s", Source: Source{Prefix: mustPrefix(t, "10.0.0.0/8")}, ExpiresAtMS: 1}
	v6 := Lease{Service: "s", Source: Source{Prefix: mustPrefix(t, "2001:db8::/32")}, ExpiresAtMS: 2}
	for _, l := range []Lease{v4, v6} {
		if err := first.Put(l); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openStore(t, path)
	defer func() { _ = second.Close() }()

	var seen []string
	for _, l := range second.Live() {
		seen = append(seen, l.Source.Prefix.String())
	}
	got := strings.Join(seen, ",")
	if want := "10.0.0.0/8,2001:db8::/32"; got != want {
		t.Errorf("recovered prefixes = %q, want %q", got, want)
	}
}
