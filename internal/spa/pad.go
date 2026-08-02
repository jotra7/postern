package spa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Pad returns record followed by a random number of random bytes, so the
// datagram that crosses the wire no longer has a constant length an observer
// can fingerprint. The padding is outside the sealed, signed record: it
// carries no meaning, needs no shared secret, and a receiver discards it after
// slicing off the first len(record) bytes. See the variable-length padding
// design for why padding outside the envelope is enough against a size tell.
//
// The scheme is a nested uniform draw over [len(record), MaxDatagram]:
//
//  1. a per-packet ceiling C = CORE + U[0, MaxDatagram-CORE],
//  2. a total length L = CORE + U[0, C-CORE],
//  3. L-CORE bytes from crypto/rand appended after the record.
//
// The nested draw means no single maximum size piles up at a visible edge,
// while MaxDatagram is a common MTU-ish bound postern does not uniquely own.
// L == CORE (no padding at all) is a legal outcome and is not special: what
// matters is that CORE is no longer the only length a datagram can be.
//
// The randomness is crypto/rand because this is security code; the tail is
// high-entropy so it is indistinguishable from the ciphertext ahead of it.
func Pad(record []byte) ([]byte, error) {
	core := len(record)
	if core > MaxDatagram {
		return nil, fmt.Errorf("spa: record is %d bytes, larger than MaxDatagram %d", core, MaxDatagram)
	}
	ceiling, err := uniformInt(MaxDatagram - core)
	if err != nil {
		return nil, err
	}
	total, err := uniformInt(ceiling)
	if err != nil {
		return nil, err
	}
	out := make([]byte, core+total)
	copy(out, record)
	if _, err := rand.Read(out[core:]); err != nil {
		return nil, fmt.Errorf("spa: read padding: %w", err)
	}
	return out, nil
}

// uniformInt returns a uniform integer in [0, n] drawn from crypto/rand.
func uniformInt(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)+1))
	if err != nil {
		return 0, fmt.Errorf("spa: draw padding length: %w", err)
	}
	return int(v.Int64()), nil
}
