//go:build unix

package replay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// Record layout on disk, 49 bytes fixed, immediately following the header:
//
//	0   16  key_id
//	16  16  request_id
//	32   8  counter (big endian)
//	40   8  expires_at_ms (big endian)
//	48   1  flags: bit0 = is_gate
const recordSize = 49

// File header, 8 bytes fixed, at offset 0:
//
//	0    4  magic   "PRPL"
//	4    1  version  formatVersion
//	5    3  reserved MUST be zero
//
// The record format itself has always been versionless: a bare 49-byte
// record carries no magic and no version, so widening it later means either
// breaking every existing store silently (a corrupted-looking file that
// actually just predates the change) or shipping a migration for a file
// that cannot safely be deleted — deleting it reopens the exact replay
// window this store exists to close. The header exists so a future format
// change has somewhere to say "this is what you're reading" instead of
// guessing from length and content alone, and so any other kind of
// corruption at the front of the file is rejected outright rather than
// silently treated as an empty, trustworthy store.
const (
	headerSize    = 8
	formatVersion = 1
)

var magic = [4]byte{'P', 'R', 'P', 'L'}

type entry struct {
	requestID   [16]byte
	expiresAtMS uint64
}

type logStore struct {
	// mu guards every field below, including the file handle itself. Reserve
	// is the store's whole reason to exist — deciding, durably, whether a
	// request_id has been seen before — so two Reserve calls racing on the
	// same maps could both observe "unseen" before either records it, which
	// is a replay hole with extra steps. Close is guarded too, so it cannot
	// tear down the file out from under an in-flight Reserve.
	mu    sync.Mutex
	f     *os.File
	now   func() uint64
	cap   int
	byKey map[[16]byte][]entry
	high  map[[16]byte]uint64
}

// Open loads or creates a replay store at path.
func Open(path string, opts Options) (Store, error) {
	if opts.PerKeyCapacity <= 0 {
		opts.PerKeyCapacity = DefaultPerKeyCapacity
	}
	if opts.NowMS == nil {
		opts.NowMS = func() uint64 { return uint64(time.Now().UnixMilli()) }
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("replay: open store: %w", err)
	}

	// Exclusive, non-blocking: a second Open against this path — a systemd
	// restart race, or a future dump tool alongside a running agent — must
	// fail immediately rather than silently produce two openers with
	// independent offsets and independent in-memory dedup maps, which would
	// let the same request_id be accepted twice. flock ties the lock to this
	// file descriptor's open file description, so it releases automatically
	// when Close (or an unclean exit) closes f — no separate unlock path to
	// get wrong.
	//nolint:gosec // G115: Fd() is a small, non-negative OS file descriptor
	// number (bounded by the process's file-descriptor table, nowhere near
	// the int/uintptr width difference on any platform this builds for), not
	// attacker-controlled input; the conversion cannot overflow in practice.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("replay: store %s is already open by another process: %w", path, err)
	}

	s := &logStore{
		f:     f,
		now:   opts.NowMS,
		cap:   opts.PerKeyCapacity,
		byKey: make(map[[16]byte][]entry),
		high:  make(map[[16]byte]uint64),
	}
	if err := s.load(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

func (s *logStore) load() error {
	info, err := s.f.Stat()
	if err != nil {
		return fmt.Errorf("replay: stat: %w", err)
	}

	if info.Size() == 0 {
		// Freshly created (os.O_CREATE) or previously emptied: write the
		// header before anything else, so every non-empty store on disk
		// always begins with one. This positions the file offset at
		// headerSize, ready for the first Reserve to append at.
		return s.writeHeader()
	}

	if err := s.readHeader(); err != nil {
		return err
	}
	if _, err := s.f.Seek(headerSize, io.SeekStart); err != nil {
		return fmt.Errorf("replay: seek past header: %w", err)
	}

	buf := make([]byte, recordSize)
	for {
		_, err := io.ReadFull(s.f, buf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// A torn tail record from a crash mid-write. Everything before it
			// is intact; truncate to the last whole record and carry on.
			off, serr := s.f.Seek(0, io.SeekCurrent)
			if serr != nil {
				return fmt.Errorf("replay: seek after torn record: %w", serr)
			}
			whole := headerSize + ((off-headerSize)/recordSize)*recordSize
			if err := s.f.Truncate(whole); err != nil {
				return fmt.Errorf("replay: truncate torn record: %w", err)
			}
			// Truncate does not move the file's write offset, which is still
			// past the discarded tail. Leaving it there would make the next
			// Write land past EOF and pad the gap with a zero-filled hole
			// instead of appending. Reposition to the new end of file.
			if _, err := s.f.Seek(whole, io.SeekStart); err != nil {
				return fmt.Errorf("replay: seek to truncated end: %w", err)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("replay: read record: %w", err)
		}

		var keyID, reqID [16]byte
		copy(keyID[:], buf[0:16])
		copy(reqID[:], buf[16:32])
		counter := binary.BigEndian.Uint64(buf[32:40])
		expires := binary.BigEndian.Uint64(buf[40:48])
		isGate := buf[48]&0x01 == 0x01

		s.byKey[keyID] = append(s.byKey[keyID], entry{requestID: reqID, expiresAtMS: expires})
		if isGate && counter > s.high[keyID] {
			s.high[keyID] = counter
		}
	}
}

// writeHeader stamps a brand-new store file with the magic value and format
// version, syncs it durably, and leaves the file offset positioned right
// after the header for the first record append.
func (s *logStore) writeHeader() error {
	var buf [headerSize]byte
	copy(buf[0:4], magic[:])
	buf[4] = formatVersion
	// buf[5:8] stays zero (reserved).

	if _, err := s.f.WriteAt(buf[:], 0); err != nil {
		return fmt.Errorf("replay: write header: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("replay: sync header: %w", err)
	}
	if _, err := s.f.Seek(headerSize, io.SeekStart); err != nil {
		return fmt.Errorf("replay: seek past header: %w", err)
	}
	return nil
}

// readHeader verifies an existing store file's header without moving the
// file offset (it uses ReadAt), rejecting the file outright — rather than
// silently truncating it back to an empty store, which would reopen the
// exact replay window this package exists to close — whenever it is too
// short to contain a header, does not start with the expected magic, or
// declares a format version this build does not understand.
func (s *logStore) readHeader() error {
	buf := make([]byte, headerSize)
	if _, err := s.f.ReadAt(buf, 0); err != nil {
		return fmt.Errorf("replay: store file is too short to contain a valid %d-byte header: %w", headerSize, err)
	}
	if !bytes.Equal(buf[0:4], magic[:]) {
		return fmt.Errorf("replay: store file does not start with the expected magic value; " +
			"refusing to treat an unrecognized file as an empty store")
	}
	if buf[4] != formatVersion {
		return fmt.Errorf("replay: store file format version %d is not supported by this build (want %d)",
			buf[4], formatVersion)
	}
	return nil
}

// prune drops entries whose packets can no longer pass any freshness path.
// This is the only permitted removal: nothing is ever evicted early.
func (s *logStore) prune(keyID [16]byte) {
	now := s.now()
	live := s.byKey[keyID][:0]
	for _, e := range s.byKey[keyID] {
		if e.expiresAtMS > now {
			live = append(live, e)
		}
	}
	s.byKey[keyID] = live
}

func (s *logStore) Reserve(r Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune(r.KeyID)

	for _, e := range s.byKey[r.KeyID] {
		if e.requestID == r.RequestID {
			return ErrDuplicate
		}
	}
	if len(s.byKey[r.KeyID]) >= s.cap {
		return ErrCapacity
	}

	buf := make([]byte, recordSize)
	copy(buf[0:16], r.KeyID[:])
	copy(buf[16:32], r.RequestID[:])
	binary.BigEndian.PutUint64(buf[32:40], r.Counter)
	binary.BigEndian.PutUint64(buf[40:48], r.ExpiresAtMS)
	if r.IsGate {
		buf[48] |= 0x01
	}

	if _, err := s.f.Write(buf); err != nil {
		return fmt.Errorf("replay: write record: %w", err)
	}
	// Commit durably before the caller applies any effect.
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("replay: sync: %w", err)
	}

	s.byKey[r.KeyID] = append(s.byKey[r.KeyID], entry{requestID: r.RequestID, expiresAtMS: r.ExpiresAtMS})
	if r.IsGate && r.Counter > s.high[r.KeyID] {
		// max(existing, counter), never "the last counter seen": storing the
		// packet's counter directly would let the timestamp path lower the
		// mark and re-enable a suppressed higher-counter packet.
		s.high[r.KeyID] = r.Counter
	}
	return nil
}

func (s *logStore) HighWater(keyID [16]byte) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.high[keyID]
}

func (s *logStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		return fmt.Errorf("replay: sync on close: %w", err)
	}
	return s.f.Close()
}
