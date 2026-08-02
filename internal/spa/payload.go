package spa

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// GatePayload is the source assertion carried by a gate request.
type GatePayload struct {
	SourceKind SourceKind
	// Prefix is meaningful only when SourceKind is SourceAsserted.
	Prefix netip.Prefix
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// EncodeGatePayload renders a source assertion into the 32-byte payload
// union.
func EncodeGatePayload(g GatePayload) ([PayloadLen]byte, error) {
	var out [PayloadLen]byte

	switch g.SourceKind {
	case SourceObserved:
		// Every source byte stays zero: the agent uses the address it saw.
		return out, nil

	case SourceAsserted:
		if !g.Prefix.IsValid() {
			return out, fmt.Errorf("spa: asserted source has an invalid prefix")
		}
		if g.Prefix.Masked() != g.Prefix {
			// One network, one encoding: host bits must not survive into the
			// signed payload.
			return out, fmt.Errorf("spa: asserted prefix %v has non-zero host bits", g.Prefix)
		}
		bits := g.Prefix.Bits()
		if bits < 0 || bits > 128 {
			// netip guarantees 0..32 (v4) or 0..128 (v6) for a valid prefix;
			// this is belt-and-suspenders against the int->byte narrowing.
			return out, fmt.Errorf("spa: asserted prefix %v has an out-of-range prefix length", g.Prefix)
		}
		addr := g.Prefix.Addr()
		out[0] = byte(SourceAsserted)
		out[2] = byte(bits)
		if addr.Is4() {
			out[1] = 4
			b := addr.As4()
			copy(out[3:3+4], b[:])
		} else {
			out[1] = 6
			b := addr.As16()
			copy(out[3:3+16], b[:])
		}
		return out, nil

	default:
		return out, fmt.Errorf("spa: unknown source kind %d", g.SourceKind)
	}
}

// EncodeConfirmPayload binds a confirmation to one pending transaction.
func EncodeConfirmPayload(pendingRevision uint64, deploymentNonce [16]byte) ([PayloadLen]byte, error) {
	var out [PayloadLen]byte
	binary.BigEndian.PutUint64(out[0:8], pendingRevision)
	copy(out[8:24], deploymentNonce[:])
	return out, nil
}

// EncodeDisarmPayload renders the empty disarm payload.
func EncodeDisarmPayload() ([PayloadLen]byte, error) {
	return [PayloadLen]byte{}, nil
}

// EncodeLivenessPayload carries the challenge nonce a pong must echo.
func EncodeLivenessPayload(challenge [16]byte) ([PayloadLen]byte, error) {
	var out [PayloadLen]byte
	copy(out[0:16], challenge[:])
	return out, nil
}

// GatePayload decodes and canonicality-checks the gate variant.
func (r *Request) GatePayload() (GatePayload, error) {
	if r.Kind != KindGate {
		return GatePayload{}, fmt.Errorf("spa: record kind %d is not a gate", r.Kind)
	}
	p := r.Payload[:]

	switch SourceKind(p[0]) {
	case SourceObserved:
		// Every remaining byte is reserved when the source is observed.
		if !allZero(p[1:]) {
			return GatePayload{}, ErrNotCanonical
		}
		return GatePayload{SourceKind: SourceObserved}, nil

	case SourceAsserted:
		// Bytes [19:32) are reserved regardless of address family.
		if !allZero(p[19:]) {
			return GatePayload{}, ErrNotCanonical
		}
		bits := int(p[2])
		var addr netip.Addr
		switch p[1] {
		case 4:
			if bits > 32 {
				return GatePayload{}, ErrNotCanonical
			}
			// Bytes [7:19) are reserved padding in the v4 case: the address
			// slot is 16 bytes wide but v4 only fills the first 4.
			if !allZero(p[7:19]) {
				return GatePayload{}, ErrNotCanonical
			}
			var b4 [4]byte
			copy(b4[:], p[3:7])
			addr = netip.AddrFrom4(b4)
		case 6:
			if bits > 128 {
				return GatePayload{}, ErrNotCanonical
			}
			var b16 [16]byte
			copy(b16[:], p[3:19])
			addr = netip.AddrFrom16(b16)
		default:
			return GatePayload{}, ErrNotCanonical
		}
		pfx := netip.PrefixFrom(addr, bits)
		if !pfx.IsValid() || pfx.Masked() != pfx {
			return GatePayload{}, ErrNotCanonical
		}
		return GatePayload{SourceKind: SourceAsserted, Prefix: pfx}, nil

	default:
		return GatePayload{}, ErrNotCanonical
	}
}

// ConfirmPayload decodes and canonicality-checks the confirm variant.
func (r *Request) ConfirmPayload() (uint64, [16]byte, error) {
	var nonce [16]byte
	if r.Kind != KindAction {
		return 0, nonce, fmt.Errorf("spa: record kind %d is not an action", r.Kind)
	}
	// Bytes [24:32) are reserved.
	if !allZero(r.Payload[24:]) {
		return 0, nonce, ErrNotCanonical
	}
	rev := binary.BigEndian.Uint64(r.Payload[0:8])
	copy(nonce[:], r.Payload[8:24])
	return rev, nonce, nil
}

// DisarmPayload validates the empty disarm variant.
func (r *Request) DisarmPayload() error {
	if r.Kind != KindAction {
		return fmt.Errorf("spa: record kind %d is not an action", r.Kind)
	}
	if !allZero(r.Payload[:]) {
		return ErrNotCanonical
	}
	return nil
}

// LivenessPayload decodes and canonicality-checks the challenge nonce.
func (r *Request) LivenessPayload() ([16]byte, error) {
	var challenge [16]byte
	if r.Kind != KindAction {
		return challenge, fmt.Errorf("spa: record kind %d is not an action", r.Kind)
	}
	// Bytes [16:32) are reserved.
	if !allZero(r.Payload[16:]) {
		return challenge, ErrNotCanonical
	}
	copy(challenge[:], r.Payload[0:16])
	return challenge, nil
}
