package gate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

// Lease is one admission the script backend is answerable for withdrawing.
//
// nftables needs no equivalent: the kernel owns the expiry of every element
// this project inserts, which is what lets the README say the bolt falls even
// if the porter dies. A script backend has no such promise to lean on — most
// targets have no per-entry TTL at all — so the schedule has to live
// somewhere the agent can recover it after a restart, which is this.
type Lease struct {
	Service string
	Source  Source
	// ExpiresAtMS is the wall-clock instant the admission must be withdrawn,
	// in Unix milliseconds. Absolute rather than a remaining duration, so a
	// restart recovers the original deadline instead of restarting the clock
	// — a lease that renewed itself across every agent restart would be a
	// hole that outlives its grant by however many restarts it survives.
	ExpiresAtMS uint64
}

// leaseKey identifies one admission. Service plus prefix, because a source is
// admitted per service and the same operator address can hold leases on two
// script-backed services at once.
type leaseKey struct {
	service string
	prefix  netip.Prefix
}

func (l Lease) key() leaseKey { return leaseKey{service: l.Service, prefix: l.Source.Prefix} }

// Lease store file format. The header mirrors internal/replay's byte for
// byte in shape and for the same reason stated there: a bare fixed-width
// record carries no magic and no version, so a future format change has to
// either break every existing file silently or ship a migration for a file
// that cannot safely be deleted. Deleting this one loses the schedule for
// every admission currently open, which is precisely the state where nothing
// else knows to close them.
//
//	0    4  magic   "PGLS"
//	4    1  version leaseFormatVersion
//	5    3  reserved MUST be zero
//
// Records are fixed width and follow immediately:
//
//	0    1  op: leaseOpOpen or leaseOpClose
//	1    1  source kind: 0 observed, 1 asserted
//	2    1  address family: 4 or 6
//	3    1  prefix bits
//	4   16  address, netip.Addr.As16()
//	20   8  expires_at_ms, big endian
//	28   1  service name length, 1..config.MaxServiceNameLen
//	29  32  service name, zero padded
//	61   3  reserved MUST be zero
const (
	leaseHeaderSize    = 8
	leaseFormatVersion = 1
	leaseRecordSize    = 64
	leaseNameOffset    = 29
	leaseNameMax       = 32
)

const (
	leaseOpOpen  byte = 1
	leaseOpClose byte = 2
)

var leaseMagic = [4]byte{'P', 'G', 'L', 'S'}

// leaseStore is the durable record of which admissions a script backend still
// owes a close to.
//
// It is an append-only log with tombstones, the same write discipline
// internal/replay uses — record, fsync, then act — rather than a second,
// differently-wrong scheme. The one addition is that the file is truncated
// back to its header the moment no lease is live, which is what bounds a log
// whose entries are minutes long inside a process that runs for months.
type leaseStore struct {
	// mu guards the file handle as well as the map, for the reason replay's
	// does: the whole point of the file is that a decision and its durable
	// record cannot diverge, and two writers interleaving records would put
	// the map and the log in different states.
	mu   sync.Mutex
	f    *os.File
	live map[leaseKey]Lease
}

// openLeaseStore loads or creates the lease store at path and recovers the
// schedule from it.
func openLeaseStore(path string) (*leaseStore, error) {
	//nolint:gosec // G304: the operator named this path in a root-owned config,
	// the same way internal/replay opens its store
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("gate: open lease store: %w", err)
	}
	if err := lockExclusive(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("gate: lease store %s: %w", path, err)
	}
	s := &leaseStore{f: f, live: map[leaseKey]Lease{}}
	if err := s.load(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

func (s *leaseStore) load() error {
	info, err := s.f.Stat()
	if err != nil {
		return fmt.Errorf("gate: stat lease store: %w", err)
	}
	if info.Size() == 0 {
		return s.writeHeader()
	}
	if err := s.readHeader(); err != nil {
		return err
	}
	if _, err := s.f.Seek(leaseHeaderSize, io.SeekStart); err != nil {
		return fmt.Errorf("gate: seek past lease header: %w", err)
	}

	buf := make([]byte, leaseRecordSize)
	for {
		_, err := io.ReadFull(s.f, buf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// A torn tail from a crash mid-write. Everything before it is
			// intact; truncate to the last whole record and carry on, exactly
			// as replay does — and reposition the write offset, because
			// Truncate does not move it and the next append would otherwise
			// land past EOF and leave a zero-filled hole.
			off, serr := s.f.Seek(0, io.SeekCurrent)
			if serr != nil {
				return fmt.Errorf("gate: seek after torn lease record: %w", serr)
			}
			whole := leaseHeaderSize + ((off-leaseHeaderSize)/leaseRecordSize)*leaseRecordSize
			if err := s.f.Truncate(whole); err != nil {
				return fmt.Errorf("gate: truncate torn lease record: %w", err)
			}
			if _, err := s.f.Seek(whole, io.SeekStart); err != nil {
				return fmt.Errorf("gate: seek to truncated lease end: %w", err)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("gate: read lease record: %w", err)
		}

		l, op, err := decodeLeaseRecord(buf)
		if err != nil {
			return err
		}
		if op == leaseOpClose {
			delete(s.live, l.key())
			continue
		}
		s.live[l.key()] = l
	}
}

func (s *leaseStore) writeHeader() error {
	var buf [leaseHeaderSize]byte
	copy(buf[0:4], leaseMagic[:])
	buf[4] = leaseFormatVersion

	if _, err := s.f.WriteAt(buf[:], 0); err != nil {
		return fmt.Errorf("gate: write lease header: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("gate: sync lease header: %w", err)
	}
	if _, err := s.f.Seek(leaseHeaderSize, io.SeekStart); err != nil {
		return fmt.Errorf("gate: seek past lease header: %w", err)
	}
	return nil
}

// readHeader rejects a file it does not recognize rather than treating it as
// an empty store. An empty store means "no admissions are open", and
// answering that about a file this build cannot read would silently strand
// every hole the previous one left behind.
func (s *leaseStore) readHeader() error {
	buf := make([]byte, leaseHeaderSize)
	if _, err := s.f.ReadAt(buf, 0); err != nil {
		return fmt.Errorf("gate: lease store is too short to contain a valid %d-byte header: %w", leaseHeaderSize, err)
	}
	if !bytes.Equal(buf[0:4], leaseMagic[:]) {
		return errors.New("gate: lease store does not start with the expected magic value; " +
			"refusing to treat an unrecognized file as a store with no admissions open")
	}
	if buf[4] != leaseFormatVersion {
		return fmt.Errorf("gate: lease store format version %d is not supported by this build (want %d)",
			buf[4], leaseFormatVersion)
	}
	return nil
}

// Put records a lease durably and only then reports success, so a crash
// between the two leaves an admission this store still knows to withdraw
// rather than one nothing remembers. That ordering is the whole reason the
// caller writes here before it invokes the script, not after.
func (s *leaseStore) Put(l Lease) error {
	rec, err := encodeLeaseRecord(l, leaseOpOpen)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.append(rec); err != nil {
		return err
	}
	s.live[l.key()] = l
	return nil
}

// Delete tombstones a lease. It is a no-op, not an error, for a lease that is
// not there: the reaper and a clean shutdown can both reach the same
// admission, and the second one to arrive has nothing left to do.
func (s *leaseStore) Delete(service string, prefix netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := leaseKey{service: service, prefix: prefix}
	l, ok := s.live[key]
	if !ok {
		return nil
	}
	rec, err := encodeLeaseRecord(l, leaseOpClose)
	if err != nil {
		return err
	}
	if err := s.append(rec); err != nil {
		return err
	}
	delete(s.live, key)

	// Truncating back to the header the instant nothing is live is what keeps
	// an append-only log of short-lived entries from growing without bound in
	// a process that runs for months. It is safe precisely because the map is
	// empty: there is no live state in the bytes being discarded.
	if len(s.live) == 0 {
		if err := s.truncateToHeader(); err != nil {
			return err
		}
	}
	return nil
}

func (s *leaseStore) append(rec []byte) error {
	if _, err := s.f.Write(rec); err != nil {
		return fmt.Errorf("gate: write lease record: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("gate: sync lease store: %w", err)
	}
	return nil
}

func (s *leaseStore) truncateToHeader() error {
	if err := s.f.Truncate(leaseHeaderSize); err != nil {
		return fmt.Errorf("gate: truncate lease store: %w", err)
	}
	if _, err := s.f.Seek(leaseHeaderSize, io.SeekStart); err != nil {
		return fmt.Errorf("gate: seek to lease store header: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("gate: sync truncated lease store: %w", err)
	}
	return nil
}

// Live returns every lease currently outstanding, ordered by service then
// prefix so two calls against one store agree, and so a caller closing them
// in a loop does it in a reproducible order.
func (s *leaseStore) Live() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(func(Lease) bool { return true })
}

// Due returns the leases whose deadline has passed at nowMS.
func (s *leaseStore) Due(nowMS uint64) []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(func(l Lease) bool { return l.ExpiresAtMS <= nowMS })
}

// LiveFor returns the leases outstanding for one service.
func (s *leaseStore) LiveFor(service string) []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(func(l Lease) bool { return l.Service == service })
}

func (s *leaseStore) snapshot(keep func(Lease) bool) []Lease {
	out := make([]Lease, 0, len(s.live))
	for _, l := range s.live {
		if keep(l) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Source.Prefix.String() < out[j].Source.Prefix.String()
	})
	return out
}

func (s *leaseStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		return fmt.Errorf("gate: sync lease store on close: %w", err)
	}
	return s.f.Close()
}

func encodeLeaseRecord(l Lease, op byte) ([]byte, error) {
	if len(l.Service) == 0 || len(l.Service) > leaseNameMax {
		return nil, fmt.Errorf("gate: lease service name %q is %d bytes, want 1..%d", l.Service, len(l.Service), leaseNameMax)
	}
	if !l.Source.Prefix.IsValid() {
		return nil, fmt.Errorf("gate: lease for %q has an invalid prefix", l.Service)
	}
	addr := l.Source.Prefix.Addr()
	family := byte(6)
	if addr.Is4() {
		family = 4
	}
	bits := l.Source.Prefix.Bits()
	if bits < 0 || bits > 128 {
		return nil, fmt.Errorf("gate: lease prefix %s has out-of-range length", l.Source.Prefix)
	}

	rec := make([]byte, leaseRecordSize)
	rec[0] = op
	if l.Source.Kind == SourceAsserted {
		rec[1] = 1
	}
	rec[2] = family
	rec[3] = byte(bits)
	a16 := addr.As16()
	copy(rec[4:20], a16[:])
	binary.BigEndian.PutUint64(rec[20:28], l.ExpiresAtMS)
	// Bounded to 1..leaseNameMax (32) by the guard at the top of this
	// function, so the conversion cannot truncate.
	rec[28] = byte(len(l.Service)) //nolint:gosec // G115: see the length guard above
	copy(rec[leaseNameOffset:leaseNameOffset+leaseNameMax], l.Service)
	return rec, nil
}

func decodeLeaseRecord(rec []byte) (Lease, byte, error) {
	op := rec[0]
	if op != leaseOpOpen && op != leaseOpClose {
		return Lease{}, 0, fmt.Errorf("gate: lease record has unknown op %d", op)
	}
	kind := SourceObserved
	if rec[1] == 1 {
		kind = SourceAsserted
	}
	nameLen := int(rec[28])
	if nameLen == 0 || nameLen > leaseNameMax {
		return Lease{}, 0, fmt.Errorf("gate: lease record has service name length %d, want 1..%d", nameLen, leaseNameMax)
	}
	service := string(rec[leaseNameOffset : leaseNameOffset+nameLen])

	var a16 [16]byte
	copy(a16[:], rec[4:20])
	addr := netip.AddrFrom16(a16)
	bits := int(rec[3])
	switch rec[2] {
	case 4:
		addr = addr.Unmap()
		if !addr.Is4() {
			return Lease{}, 0, fmt.Errorf("gate: lease record for %q claims ipv4 but its address is not", service)
		}
		if bits > 32 {
			return Lease{}, 0, fmt.Errorf("gate: lease record for %q claims ipv4 with a /%d", service, bits)
		}
	case 6:
		if bits > 128 {
			return Lease{}, 0, fmt.Errorf("gate: lease record for %q claims ipv6 with a /%d", service, bits)
		}
	default:
		return Lease{}, 0, fmt.Errorf("gate: lease record for %q has address family %d, want 4 or 6", service, rec[2])
	}

	return Lease{
		Service:     service,
		Source:      Source{Kind: kind, Prefix: netip.PrefixFrom(addr, bits)},
		ExpiresAtMS: binary.BigEndian.Uint64(rec[20:28]),
	}, op, nil
}

func nowMS(now func() time.Time) uint64 {
	ms := now().UnixMilli()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}
