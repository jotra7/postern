package hub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jotra7/postern/internal/bundle"
)

// hostIDLen is the decoded byte length of a host_id: 16 bytes, 32 hex
// characters. Not reused from internal/bundle or internal/attest — both
// already export the same constant under the name IDSize, but this package
// has no other reason to import either of them just for a number, and doc.go
// is explicit that the value here is the protocol, not a struct layout.
const hostIDLen = 16

var (
	// ErrNoBundle means no bundle file exists for that host_id.
	ErrNoBundle = errors.New("hub: no bundle for that host")
	// ErrNoHostKey means index.json carries no entry for that host_id, so a
	// heartbeat claiming to be from it can never be verified. Distinct from
	// ErrNoBundle: `postern sign` writes both together in the ordinary case,
	// but nothing enforces that the two files agree, and a caller resolving
	// a host's signing key has a different question to answer than a caller
	// fetching its bundle.
	ErrNoHostKey = errors.New("hub: no signing key on file for that host")
	// ErrInvalidHostID means a host_id string is not exactly 32 hex
	// characters: not valid hex at all, or valid hex that does not decode to
	// exactly 16 bytes.
	ErrInvalidHostID = errors.New("hub: host_id is not 32 hex characters")
)

// ParseHostID validates and decodes a host_id path element — the one
// operator- or attacker-controlled string that reaches this package — into
// the fixed array every Store method takes.
//
// This runs before anything touches the filesystem, and it is the only
// place in this package that ever looks at a host_id as a string. Store's
// own methods take [16]byte, not string, so there is no call downstream of
// this function where the original request text could be concatenated into
// a path: whatever built the []byte, Store.Bundle and Store.HostKey re-derive
// the filename by hex-encoding those 16 bytes themselves.
//
// Two independent checks, deliberately not collapsed into one: hex.Decode
// failing (wrong characters, odd length) and the decoded byte count not
// being exactly 16 (an even-length hex string of the wrong size). A string
// built from path-traversal characters like "../" fails the first; a
// same-length-looking hex string that is actually 15 or 17 bytes fails only
// the second. Testing them together would leave either one free to be
// deleted without a test noticing, since most adversarial input happens to
// trip both at once.
func ParseHostID(s string) ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("%w: %v", ErrInvalidHostID, err)
	}
	if len(raw) != hostIDLen {
		return id, fmt.Errorf("%w: decodes to %d bytes, want %d", ErrInvalidHostID, len(raw), hostIDLen)
	}
	copy(id[:], raw)
	return id, nil
}

// Store is the hub's on-disk bundle store: `postern sign` writes
// <dir>/<host_id_hex>.bundle for every host plus <dir>/index.json naming
// each host's signing key, and this type reads exactly that.
//
// Nothing here is cached in memory. Every call re-reads its file, so a
// redeploy that replaces bundles and index.json under a running hub is
// picked up on the very next request — there is no reload path to remember
// to invoke, because there is nothing to invalidate.
type Store struct {
	dir string
}

// OpenStore checks that dir exists and is a directory, and returns a Store
// over it. It does not read index.json or any bundle yet — those reads
// happen per request, not at open time.
func OpenStore(dir string) (*Store, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("hub: open store: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("hub: open store: %s is not a directory", dir)
	}
	return &Store{dir: dir}, nil
}

// Bundle returns the sealed bytes on file for hostID. The filename is built
// by hex-encoding hostID's own bytes, never from anything a caller passed as
// a string — see ParseHostID.
func (s *Store) Bundle(hostID [16]byte) (bundle.Sealed, error) {
	path := filepath.Join(s.dir, hex.EncodeToString(hostID[:])+".bundle")
	//nolint:gosec // G304: path is built from hostID's own 16 bytes,
	// re-encoded to hex here, never from a request string. See ParseHostID
	// and doc.go.
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoBundle
		}
		return nil, fmt.Errorf("hub: read bundle for %x: %w", hostID, err)
	}
	return bundle.Sealed(data), nil
}

// HostKey returns the Ed25519 signing public key index.json records for
// hostID — what a heartbeat claiming to be from this host must verify
// against.
func (s *Store) HostKey(hostID [16]byte) ([32]byte, error) {
	var key [32]byte
	idx, err := loadIndex(s.dir)
	if err != nil {
		return key, err
	}
	entry, ok := idx.Hosts[hex.EncodeToString(hostID[:])]
	if !ok {
		return key, ErrNoHostKey
	}
	raw, err := base64.StdEncoding.DecodeString(entry.Signing)
	if err != nil {
		return key, fmt.Errorf("hub: index.json signing key for %x: %w", hostID, err)
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("hub: index.json signing key for %x is %d bytes, want 32", hostID, len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// Hosts returns the host_id of every host index.json names, in no particular
// order. It is how the hub knows a fleet member exists before that member has
// said anything.
//
// index.json rather than a directory listing of *.bundle files: this is the
// set of hosts whose heartbeats could ever be accepted, since a host with no
// signing key on file is refused at HostKey before a signature is checked at
// all, and a set of hosts that cannot report is not a useful denominator for
// who has reported.
//
// A key that is not a 32-character hex host_id is skipped rather than turned
// into an error. Such an entry names nothing this Store can serve a bundle
// for or verify a beat from, so it is not a fleet member, and one unusable
// line must not deny a caller the rest of the file. A file that does not
// parse as JSON at all is a different matter and is returned as the error
// loadIndex makes it.
func (s *Store) Hosts() ([][16]byte, error) {
	idx, err := loadIndex(s.dir)
	if err != nil {
		return nil, err
	}
	out := make([][16]byte, 0, len(idx.Hosts))
	for key := range idx.Hosts {
		id, err := ParseHostID(key)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

// storeIndex mirrors cmd/postern/cmd_sign.go's bundleIndex — the same
// index.json, read here rather than written. The two are not the same Go
// type because cmd/postern is a different package this one must not import,
// but the JSON shape is the contract between them and has to match exactly.
type storeIndex struct {
	Hosts map[string]storeIndexEntry `json:"hosts"`
}

type storeIndexEntry struct {
	Signing string `json:"signing"`
	Version uint64 `json:"version"`
}

// loadIndex reads dir's index.json fresh on every call — see Store's own
// doc comment for why nothing here is cached.
func loadIndex(dir string) (*storeIndex, error) {
	path := filepath.Join(dir, "index.json")
	//nolint:gosec // G304: dir is the operator-supplied store directory,
	// the same trust boundary as the rest of this file's reads.
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &storeIndex{Hosts: map[string]storeIndexEntry{}}, nil
		}
		return nil, fmt.Errorf("hub: read %s: %w", path, err)
	}
	var idx storeIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("hub: parse %s: %w", path, err)
	}
	if idx.Hosts == nil {
		idx.Hosts = map[string]storeIndexEntry{}
	}
	return &idx, nil
}
