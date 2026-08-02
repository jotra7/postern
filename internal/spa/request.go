package spa

import "encoding/binary"

// Request is the decoded inner record. Struct field order follows the
// documented interface, not the wire layout — MarshalSigned and Parse index
// every field by its fixed offset, so this order is cosmetic.
type Request struct {
	Version     uint8
	Alg         uint8
	Kind        Kind
	KeyID       [IDSize]byte
	HostID      [IDSize]byte
	RequestID   [IDSize]byte
	ServiceID   [IDSize]byte
	Counter     uint64
	TimestampMS uint64
	TTLSeconds  uint16
	Payload     [PayloadLen]byte
	Signature   [SigLen]byte
}

// MarshalSigned renders the signed region as it sits on the wire: bytes 0
// through SignedLen-1 of the inner record, every field except the signature.
// The bytes Ed25519 actually covers are SigningInput, which is this region
// behind RequestDomain.
func (r *Request) MarshalSigned() []byte {
	b := make([]byte, SignedLen)
	b[OffVersion] = r.Version
	b[OffAlg] = r.Alg
	b[OffKind] = byte(r.Kind)
	// OffReserved1 stays zero.
	copy(b[OffKeyID:], r.KeyID[:])
	copy(b[OffHostID:], r.HostID[:])
	copy(b[OffRequestID:], r.RequestID[:])
	binary.BigEndian.PutUint64(b[OffCounter:], r.Counter)
	binary.BigEndian.PutUint64(b[OffTimestamp:], r.TimestampMS)
	copy(b[OffServiceID:], r.ServiceID[:])
	binary.BigEndian.PutUint16(b[OffTTL:], r.TTLSeconds)
	copy(b[PayloadOff:], r.Payload[:])
	// OffReserved2 stays zero.
	return b
}

// SigningInput returns the exact byte string a signer signs and a verifier
// checks: RequestDomain followed by the signed region. The tag costs no wire
// bytes, since a receiver reconstructs it from the record type it is already
// parsing.
func (r *Request) SigningInput() []byte {
	b := make([]byte, 0, len(RequestDomain)+SignedLen)
	b = append(b, RequestDomain...)
	return append(b, r.MarshalSigned()...)
}

// Marshal renders the full inner record, signature included.
func (r *Request) Marshal() []byte {
	b := make([]byte, InnerSize)
	copy(b, r.MarshalSigned())
	copy(b[OffSignature:], r.Signature[:])
	return b
}

// Parse decodes and canonicality-checks an inner record. It performs no
// cryptography: the caller verifies the signature after this returns.
//
// Order matters — cheapest rejections first — and every MUST-be-zero byte is
// checked rather than ignored, so a signature covers exactly one meaning.
//
// For an action record, Parse enforces only the invariants shared by every
// action (zero counter, zero TTL). It cannot fully canonicalize the payload,
// because which of confirm/disarm/liveness applies depends on service_id,
// which this package deliberately does not resolve (that needs
// internal/config). The caller resolves the sub-type and then calls the
// matching *Payload accessor, which enforces that variant's own canonical
// form.
func Parse(b []byte) (*Request, error) {
	if len(b) != InnerSize {
		return nil, ErrWrongSize
	}

	r := &Request{
		Version:     b[OffVersion],
		Alg:         b[OffAlg],
		Kind:        Kind(b[OffKind]),
		Counter:     binary.BigEndian.Uint64(b[OffCounter:]),
		TimestampMS: binary.BigEndian.Uint64(b[OffTimestamp:]),
		TTLSeconds:  binary.BigEndian.Uint16(b[OffTTL:]),
	}
	copy(r.KeyID[:], b[OffKeyID:OffKeyID+IDSize])
	copy(r.HostID[:], b[OffHostID:OffHostID+IDSize])
	copy(r.RequestID[:], b[OffRequestID:OffRequestID+IDSize])
	copy(r.ServiceID[:], b[OffServiceID:OffServiceID+IDSize])
	copy(r.Payload[:], b[PayloadOff:PayloadOff+PayloadLen])
	copy(r.Signature[:], b[OffSignature:OffSignature+SigLen])

	if r.Version != Version1 || r.Alg != AlgEd25519X25519 {
		return nil, ErrUnsupportedVersion
	}
	if b[OffReserved1] != 0 || b[OffReserved2] != 0 || b[OffReserved2+1] != 0 {
		return nil, ErrNotCanonical
	}

	switch r.Kind {
	case KindGate:
		if _, err := r.GatePayload(); err != nil {
			return nil, err
		}
	case KindAction:
		// Actions never carry a replay counter and never request a TTL.
		// Leaving either free would give an action an ignored field, and a
		// free counter could raise the operator's high-water mark and
		// silently disable drift tolerance for later gate requests.
		if r.Counter != 0 || r.TTLSeconds != 0 {
			return nil, ErrNotCanonical
		}
	default:
		return nil, ErrUnknownKind
	}

	return r, nil
}
