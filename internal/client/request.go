package client

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

// Builder constructs SPA requests. Every request postern sends is built
// here, and that is the point: the constructor stamps version and alg rather
// than accepting them.
//
// A spa.Request is a plain struct with exported fields, so a caller
// assembling one by hand gets Version = 0 and Alg = 0 by default. Such a
// record signs and seals without complaint — nothing in Seal looks at either
// field — and the far side drops it at spa.Parse's very first check, silently,
// with no reply, because the SPA path never replies. The operator sees a
// packet sent and a connect that times out, which is indistinguishable from
// a dead agent, a dropped datagram, and the CGNAT split. Stamping the two
// bytes in one place is the difference between that and a working knock.
type Builder struct {
	// Signer is the operator's identity. Its public half supplies key_id.
	Signer identity.Signer
	// Rand supplies request_id and challenge nonces. Nil selects crypto/rand.
	Rand io.Reader
}

func (b Builder) rand() io.Reader {
	if b.Rand != nil {
		return b.Rand
	}
	return rand.Reader
}

// base builds the fields every request carries, whatever its kind. Version
// and Alg are set here and nowhere else.
func (b Builder) base(h *Host, kind spa.Kind, service string, nowMS uint64) (*spa.Request, error) {
	if b.Signer == nil {
		return nil, fmt.Errorf("client: no operator identity is loaded")
	}
	if h == nil {
		return nil, fmt.Errorf("client: no host")
	}
	req := &spa.Request{
		Version:     spa.Version1,
		Alg:         spa.AlgEd25519X25519,
		Kind:        kind,
		KeyID:       b.Signer.Public().KeyID(),
		HostID:      h.HostID,
		ServiceID:   ServiceID(service),
		TimestampMS: nowMS,
	}
	if _, err := io.ReadFull(b.rand(), req.RequestID[:]); err != nil {
		return nil, fmt.Errorf("client: mint request_id: %w", err)
	}
	return req, nil
}

// Gate builds a kind:gate request for service on h.
//
// counter comes from the persisted Counter; ttl of zero means "use the
// service default", which the agent resolves — the client does not guess a
// default the host may have changed.
func (b Builder) Gate(h *Host, service string, ttl time.Duration, source *netip.Prefix, counter, nowMS uint64) (*spa.Request, error) {
	req, err := b.base(h, spa.KindGate, service, nowMS)
	if err != nil {
		return nil, err
	}
	req.Counter = counter

	secs := int64(ttl / time.Second)
	if secs < 0 || secs > config.MaxTTLSeconds {
		return nil, fmt.Errorf("client: ttl %s is outside the wire range 0..%ds", ttl, config.MaxTTLSeconds)
	}
	req.TTLSeconds = uint16(secs) //nolint:gosec // bounded immediately above

	payload := spa.GatePayload{SourceKind: spa.SourceObserved}
	if source != nil {
		// Masked here rather than at the flag: an asserted prefix with host
		// bits set has several valid signed encodings, which is the thing
		// canonicalisation exists to prevent, and spa.EncodeGatePayload
		// rejects it outright. Normalising an operator's "203.0.113.9/24"
		// into 203.0.113.0/24 is what they meant; refusing it during an
		// outage is not.
		masked := source.Masked()
		payload = spa.GatePayload{SourceKind: spa.SourceAsserted, Prefix: masked}
	}
	encoded, err := spa.EncodeGatePayload(payload)
	if err != nil {
		return nil, fmt.Errorf("client: encode gate payload: %w", err)
	}
	req.Payload = encoded
	return req, nil
}

// Confirm builds the confirm action bound to one pending transaction.
//
// Both values are required and neither has a default. An unbound confirm
// means "confirm whatever happens to be pending when this lands", which can
// ratify a rollout the operator never approved (design section 5); the agent
// refuses one, and the client must not be able to send one by omission.
func (b Builder) Confirm(h *Host, revision uint64, nonce [16]byte, nowMS uint64) (*spa.Request, error) {
	req, err := b.base(h, spa.KindAction, "confirm", nowMS)
	if err != nil {
		return nil, err
	}
	payload, err := spa.EncodeConfirmPayload(revision, nonce)
	if err != nil {
		return nil, fmt.Errorf("client: encode confirm payload: %w", err)
	}
	req.Payload = payload
	return req, nil
}

// Disarm builds the panic button: one action packet disarms one host, since
// SPA packets are host-bound (design section 7).
func (b Builder) Disarm(h *Host, nowMS uint64) (*spa.Request, error) {
	req, err := b.base(h, spa.KindAction, "disarm", nowMS)
	if err != nil {
		return nil, err
	}
	payload, err := spa.EncodeDisarmPayload()
	if err != nil {
		return nil, fmt.Errorf("client: encode disarm payload: %w", err)
	}
	req.Payload = payload
	return req, nil
}

// Liveness builds the one request that is answered, and only on the
// always-allow path. The returned challenge must be handed to the pong
// verification unchanged: echoing it and request_id together is what stops a
// captured pong answering a later ping.
func (b Builder) Liveness(h *Host, nowMS uint64) (*spa.Request, [16]byte, error) {
	var challenge [16]byte
	req, err := b.base(h, spa.KindAction, "liveness", nowMS)
	if err != nil {
		return nil, challenge, err
	}
	if _, err := io.ReadFull(b.rand(), challenge[:]); err != nil {
		return nil, challenge, fmt.Errorf("client: mint challenge nonce: %w", err)
	}
	payload, err := spa.EncodeLivenessPayload(challenge)
	if err != nil {
		return nil, challenge, fmt.Errorf("client: encode liveness payload: %w", err)
	}
	req.Payload = payload
	return req, challenge, nil
}

// Seal signs and seals a request to the host's encryption key.
func (b Builder) Seal(req *spa.Request, h *Host) ([]byte, error) {
	if b.Signer == nil {
		return nil, fmt.Errorf("client: no operator identity is loaded")
	}
	return spa.Seal(req, b.Signer, h.HostEncrypt)
}
