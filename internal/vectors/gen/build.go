package main

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/jotra7/postern/internal/vectors"
)

// Field values shared by the SPA request vectors. Every one of them is the
// byte pattern internal/spa/golden_test.go already freezes, so the published
// signed regions and the golden fixtures agree byte for byte everywhere
// except key_id, which has to be the real truncated SHA-256 of the operator's
// signing key for a datagram to survive the agent's key_id check.
var (
	vectorHostID    = idPattern(0x11)
	vectorRequestID = idPattern(0x21)
	vectorServiceID = idPattern(0x31)
	confirmNonce    = idPattern(0x51)
	livenessNonce   = idPattern(0x71)
)

const (
	gateCounter   = uint64(0x0102030405060708)
	gateTimestamp = uint64(0x1112131415161718)
	gateTTL       = uint16(0x2122)

	confirmRevision = uint64(0x6162636465666768)
)

var (
	bundleFleetID = idPattern(0xE1)
	bundleHostID  = idPattern(0x11)
)

const (
	bundleVersion  = uint64(7)
	bundleIssuedAt = uint64(1735689600000)

	beatEpoch    = uint64(3)
	beatSequence = uint64(42)
	beatSentAt   = uint64(1735689600000)
)

const bundlePolicy = "version: 7\n" +
	"services:\n" +
	"  - name: ssh\n" +
	"    kind: gate\n" +
	"    proto: tcp\n" +
	"    ports: [22]\n"

const beatBody = `{"agent_version":"1.4.2","bundle_version":7,` +
	`"config_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4","clock_skew_ms":-12,` +
	`"listener_status":{"ssh":"listening"},"gate_elements":{"ssh":3},` +
	`"spa_accepted":9,"spa_rejected":4,"agent_up_healthy":true}`

func build() *vectors.File {
	operator := newKeypair("vector-operator", "signs and seals SPA requests",
		vectors.OperatorSigningSeed, vectors.OperatorEncryptionPrivate)
	host := newKeypair("vector-host", "opens SPA requests and bundles, signs pongs and beats",
		vectors.HostSigningSeed, vectors.HostEncryptionPrivate)
	signer := newKeypair("vector-bundle-signer", "signs bundles",
		vectors.SignerSigningSeed, vectors.SignerEncryptionPrivate)
	untrusted := newKeypair("vector-untrusted", "trusted by nothing in these vectors",
		vectors.UntrustedSigningSeed, vectors.UntrustedEncryptionPrivate)

	pong := buildPong(host)

	f := &vectors.File{
		Schema:    1,
		Protocol:  "postern wire protocol, version 1",
		Spec:      "docs/protocol.md, section 13",
		Generator: "go run ./internal/vectors/gen",
		Warning: "Every private key in this file is published test material and protects nothing. " +
			"The key bytes are ASCII and read \"" + vectors.SeedPrefix + "...\". " +
			"Loading one of these keys into a running agent, operator client or hub would " +
			"hand the door to anyone who has read this file.",
		Notes: []string{
			"Offsets are zero-based byte positions inside the record named. Multi-byte integers are unsigned big-endian.",
			"signing_input_hex is the exact byte string handed to Ed25519: domain_tag_hex followed by signed_region_hex.",
			"The SPA request and the pong do not transmit their tag, so signing_input_hex is longer than the record's signed region. The bundle and the beat carry theirs at offset 0, so their tag is already inside signed_region_hex.",
			"Every rejection vector is signed correctly over the bytes it carries, unless the vector is about the signature, so the field named in its description is the only reason to refuse it.",
			"expect_trial_open of \"accept\" marks a record the wire layer admits: an action payload is canonicalised only once service_id has been resolved, which needs the host's configuration, so those vectors name the payload accessor that refuses them instead.",
		},
		Keys: vectors.Keys{
			Operator:  operator.published(),
			Host:      host.published(),
			Signer:    signer.published(),
			Untrusted: untrusted.published(),
		},
		DomainTags:              buildDomainTags(),
		KeyIDDerivations:        buildKeyIDs(operator, host, signer, untrusted),
		ServiceIDDerivations:    buildServiceIDs(),
		SPARequests:             buildSPARequests(operator, host),
		SPARejections:           buildSPARejections(operator, host, untrusted),
		Pong:                    pong,
		PongRejections:          buildPongRejections(host, pong),
		Bundle:                  buildBundle(signer, host),
		BundleRejections:        buildBundleRejections(signer, host, untrusted),
		Beat:                    buildBeat(host),
		BeatRejections:          buildBeatRejections(host, untrusted),
		CrossProtocolRejections: buildCrossProtocol(operator, host, pong),
	}
	return f
}

func buildDomainTags() []vectors.DomainTag {
	return []vectors.DomainTag{
		{
			Record: "spa_request", ASCII: "postern-spa-request\\0", Hex: hexOf([]byte(requestDomain)),
			Length: len(requestDomain), Transmitted: false,
			Note: "Prepended to the 120-byte signed region for signing only. The datagram stays 224 bytes.",
		},
		{
			Record: "pong", ASCII: "postern-spa-pong\\0", Hex: hexOf([]byte(pongDomain)),
			Length: len(pongDomain), Transmitted: false,
			Note: "Prepended to the 58-byte signed region for signing only. The pong stays 122 bytes.",
		},
		{
			Record: "bundle", ASCII: "postern-bundle\\0", Hex: hexOf([]byte(bundleMagic)),
			Length: len(bundleMagic), Transmitted: true,
			Note: "The record's first field. It separates the signature and lets a parser reject a record of the wrong type first.",
		},
		{
			Record: "beat", ASCII: "postern-beat\\0", Hex: hexOf([]byte(beatMagic)),
			Length: len(beatMagic), Transmitted: true,
			Note: "The record's first field, for the same two jobs as the bundle's.",
		},
	}
}

func buildKeyIDs(keys ...keypair) []vectors.KeyIDVector {
	out := make([]vectors.KeyIDVector, 0, len(keys))
	for _, k := range keys {
		out = append(out, vectors.KeyIDVector{
			Name:             k.name,
			SigningPublicHex: hexOf(k.signPub[:]),
			SHA256Hex:        hexOf(k.sha[:]),
			KeyIDHex:         hexOf(k.keyID[:]),
		})
	}
	return out
}

func buildServiceIDs() []vectors.ServiceIDVector {
	names := []string{"ssh", "confirm", "disarm", "liveness", "postgres-primary"}
	out := make([]vectors.ServiceIDVector, 0, len(names))
	for _, n := range names {
		id, sum := serviceIDOf(n)
		out = append(out, vectors.ServiceIDVector{
			ServiceName:  n,
			NameHex:      hexOf([]byte(n)),
			SHA256Hex:    hexOf(sum[:]),
			ServiceIDHex: hexOf(id[:]),
		})
	}
	return out
}

func gateFields(keyID [idLen]byte, payload [spaPayloadLen]byte) spaFields {
	return spaFields{
		version: versionV1, alg: algV1, kind: kindGate,
		keyID: keyID, hostID: vectorHostID, requestID: vectorRequestID,
		counter: gateCounter, timestamp: gateTimestamp,
		serviceID: vectorServiceID, ttl: gateTTL, payload: payload,
	}
}

func actionFields(keyID [idLen]byte, payload [spaPayloadLen]byte) spaFields {
	return spaFields{
		version: versionV1, alg: algV1, kind: kindAction,
		keyID: keyID, hostID: vectorHostID, requestID: vectorRequestID,
		counter: 0, timestamp: gateTimestamp,
		serviceID: vectorServiceID, ttl: 0, payload: payload,
	}
}

func v6Addr() [16]byte {
	var a [16]byte
	a[0], a[1], a[2], a[3] = 0x20, 0x01, 0x0d, 0xb8
	return a
}

func buildSPARequests(operator, host keypair) []vectors.SPARequestVector {
	cases := []struct {
		name, desc, note string
		fields           spaFields
	}{
		{
			"gate-observed",
			"A gate request with an all-zero payload: the agent gates the address it saw the datagram arrive from.",
			"32 zero bytes. Read with the gate payload accessor.",
			gateFields(operator.keyID, payloadGateObserved()),
		},
		{
			"gate-asserted-v4",
			"A gate request asserting the source prefix 198.51.100.0/24.",
			"source_kind 1, family 4, prefix_bits 24, address 198.51.100.0 in bytes 3..6, bytes 7..31 zero.",
			gateFields(operator.keyID, payloadGateAssertedV4([4]byte{198, 51, 100, 0}, 24)),
		},
		{
			"gate-asserted-v6",
			"A gate request asserting the source prefix 2001:db8::/32.",
			"source_kind 1, family 6, prefix_bits 32, address in bytes 3..18, bytes 19..31 zero.",
			gateFields(operator.keyID, payloadGateAssertedV6(v6Addr(), 32)),
		},
		{
			"confirm",
			"A confirm action naming pending_revision 0x6162636465666768 and its deployment nonce.",
			"pending_revision in bytes 0..7, deployment_nonce in 8..23, bytes 24..31 reserved and zero.",
			actionFields(operator.keyID, payloadConfirm(confirmRevision, confirmNonce)),
		},
		{
			"disarm",
			"A disarm action, whose payload is empty.",
			"32 zero bytes.",
			actionFields(operator.keyID, payloadDisarm()),
		},
		{
			"liveness",
			"A liveness ping carrying the challenge nonce the pong echoes.",
			"challenge_nonce in bytes 0..15, bytes 16..31 reserved and zero.",
			actionFields(operator.keyID, payloadLiveness(livenessNonce)),
		},
	}

	out := make([]vectors.SPARequestVector, 0, len(cases))
	for _, c := range cases {
		region := c.fields.signedRegion()
		input := spaSigningInput(region)
		sig := ed25519.Sign(operator.signPriv, input)
		record := spaRecord(region, sig)
		nonce, nonceSrc := spaNonce(c.name)
		datagram := sealSPA(record, operator.encPriv, host.encPub, nonce)

		out = append(out, vectors.SPARequestVector{
			Name:            c.name,
			Description:     c.desc,
			Fields:          c.fields.published(region, c.note),
			SignedRegionHex: hexOf(region),
			DomainTagHex:    hexOf([]byte(requestDomain)),
			SigningInputHex: hexOf(input),
			SignedBy:        "operator",
			SignatureHex:    hexOf(sig),
			RecordHex:       hexOf(record),
			SealedTo:        "host",
			NonceSource:     nonceSrc,
			NonceHex:        hexOf(nonce[:]),
			DatagramHex:     hexOf(datagram),
		})
	}
	return out
}

// rejection describes one datagram an implementation must refuse.
type rejection struct {
	name, desc string
	fields     spaFields
	// mutate edits the signed region after it is rendered and before it is
	// signed, so the signature is valid over exactly the bytes on the wire.
	mutate func([]byte)
	// corruptSignature flips a bit in the signature after signing.
	corruptSignature bool
	// sealFrom names the operator whose encryption key seals the datagram.
	// Empty means the trusted operator.
	sealFrom *keypair
	// truncate drops this many bytes from the end of the datagram, and pad
	// appends this many zero bytes to it. A padded datagram carries the CORE
	// record plus random padding, so both bounds of the accepted range need a
	// vector: truncate makes a datagram shorter than the record (rejected), and
	// pad makes one longer than MaxDatagram (rejected). Padding that stays
	// within the range is accepted and is exercised by the package tests.
	truncate int
	pad      int

	expectOpen    string
	payloadCall   string
	expectPayload string
}

func buildSPARejections(operator, host, untrusted keypair) []vectors.SPARejectionVector {
	observed := gateFields(operator.keyID, payloadGateObserved())
	liveness := actionFields(operator.keyID, payloadLiveness(livenessNonce))
	confirm := actionFields(operator.keyID, payloadConfirm(confirmRevision, confirmNonce))
	disarm := actionFields(operator.keyID, payloadDisarm())
	assertedV4 := gateFields(operator.keyID, payloadGateAssertedV4([4]byte{198, 51, 100, 0}, 24))

	setPayloadByte := func(i int, v byte) func([]byte) {
		return func(b []byte) { b[spaOffPayload+i] = v }
	}

	wrongKeyID := gateFields(untrusted.keyID, payloadGateObserved())

	unmasked := gateFields(operator.keyID, payloadGateAssertedV4([4]byte{198, 51, 100, 7}, 24))
	badBits := gateFields(operator.keyID, payloadGateAssertedV4([4]byte{198, 51, 100, 0}, 33))
	badFamily := gateFields(operator.keyID, payloadGateAssertedV4([4]byte{198, 51, 100, 0}, 24))
	badFamily.payload[1] = 5

	specs := []rejection{
		{
			name: "datagram-shorter-than-the-record", fields: observed, truncate: 1,
			desc:       "A 223-byte datagram, one short of the 224-byte record. The bounded-length check runs before any key is touched.",
			expectOpen: "wrong_size",
		},
		{
			name: "datagram-longer-than-max", fields: observed, pad: spaMaxDatagram + 1 - spaDatagramLen,
			desc:       "A 1401-byte datagram, one past MaxDatagram. Padding up to MaxDatagram is accepted; beyond it the datagram is rejected on length so a padded packet can never fragment.",
			expectOpen: "wrong_size",
		},
		{
			name: "reserved-byte-at-offset-3", fields: observed,
			desc:       "The reserved byte at offset 3 of the inner record is 1.",
			mutate:     func(b []byte) { b[spaOffReserved1] = 1 },
			expectOpen: "not_canonical",
		},
		{
			name: "reserved-byte-at-offset-118", fields: observed,
			desc:       "The first of the two reserved bytes at offsets 118 and 119 is 1.",
			mutate:     func(b []byte) { b[spaOffReserved2] = 1 },
			expectOpen: "not_canonical",
		},
		{
			name: "reserved-byte-at-offset-119", fields: observed,
			desc:       "The second of the two reserved bytes at offsets 118 and 119 is 1.",
			mutate:     func(b []byte) { b[spaOffReserved2+1] = 1 },
			expectOpen: "not_canonical",
		},
		{
			name: "unknown-version", fields: observed,
			desc:       "version is 2. v1 has exactly one legal value and there is no negotiation.",
			mutate:     func(b []byte) { b[spaOffVersion] = 2 },
			expectOpen: "unsupported_version",
		},
		{
			name: "unknown-alg", fields: observed,
			desc:       "alg is 2. Only 1, ed25519+x25519, exists in v1.",
			mutate:     func(b []byte) { b[spaOffAlg] = 2 },
			expectOpen: "unsupported_version",
		},
		{
			name: "unknown-kind", fields: observed,
			desc:       "kind is 3, which is neither gate nor action.",
			mutate:     func(b []byte) { b[spaOffKind] = 3 },
			expectOpen: "unknown_kind",
		},
		{
			name: "action-with-non-zero-counter", fields: liveness,
			desc:       "An action carrying counter 1. An action has no counter path, and a free counter would raise the operator's high-water mark.",
			mutate:     func(b []byte) { binary.BigEndian.PutUint64(b[spaOffCounter:], 1) },
			expectOpen: "not_canonical",
		},
		{
			name: "action-with-non-zero-ttl", fields: liveness,
			desc:       "An action carrying ttl_seconds 1. An action requests no lease.",
			mutate:     func(b []byte) { binary.BigEndian.PutUint16(b[spaOffTTL:], 1) },
			expectOpen: "not_canonical",
		},
		{
			name: "gate-observed-payload-not-zero", fields: observed,
			desc:       "An observed-source gate whose payload byte 1 is 1. Every byte after source_kind is reserved.",
			mutate:     setPayloadByte(1, 1),
			expectOpen: "not_canonical",
		},
		{
			name: "gate-asserted-unmasked-prefix", fields: unmasked,
			desc:       "An asserted 198.51.100.7/24: host bits survive below prefix_bits. A decoder rejects rather than masking.",
			expectOpen: "not_canonical",
		},
		{
			name: "gate-asserted-v4-padding-not-zero", fields: assertedV4,
			desc:       "A v4 assertion with a non-zero byte at payload offset 7, inside the 7..18 padding the 16-byte address slot leaves.",
			mutate:     setPayloadByte(7, 1),
			expectOpen: "not_canonical",
		},
		{
			name: "gate-asserted-prefix-bits-above-family-max", fields: badBits,
			desc:       "family 4 with prefix_bits 33.",
			expectOpen: "not_canonical",
		},
		{
			name: "gate-asserted-unknown-family", fields: badFamily,
			desc:       "family 5, which is neither 4 nor 6.",
			expectOpen: "not_canonical",
		},
		{
			name: "gate-asserted-reserved-tail-not-zero", fields: assertedV4,
			desc:       "An asserted gate whose reserved payload byte 19 is 1. Bytes 19..31 are reserved for both families.",
			mutate:     setPayloadByte(19, 1),
			expectOpen: "not_canonical",
		},
		{
			name: "confirm-reserved-tail-not-zero", fields: confirm,
			desc: "A confirm whose reserved payload byte 24 is 1. The wire layer admits it: which action variant applies " +
				"depends on service_id, so the reserved tail is checked when the payload is read as a confirm.",
			mutate:        setPayloadByte(24, 1),
			expectOpen:    "accept",
			payloadCall:   "confirm",
			expectPayload: "not_canonical",
		},
		{
			name: "disarm-payload-not-zero", fields: disarm,
			desc:          "A disarm whose payload byte 31 is 1. The whole 32-byte payload is reserved for a disarm.",
			mutate:        setPayloadByte(31, 1),
			expectOpen:    "accept",
			payloadCall:   "disarm",
			expectPayload: "not_canonical",
		},
		{
			name: "liveness-reserved-tail-not-zero", fields: liveness,
			desc:          "A liveness ping whose reserved payload byte 16 is 1. Bytes 16..31 follow the challenge nonce and are reserved.",
			mutate:        setPayloadByte(16, 1),
			expectOpen:    "accept",
			payloadCall:   "liveness",
			expectPayload: "not_canonical",
		},
		{
			name: "key-id-disagrees-with-decrypting-operator", fields: wrongKeyID,
			desc: "A record naming the untrusted key's key_id, correctly signed by the trusted operator and sealed under " +
				"the trusted operator's shared secret. Without this check anyone holding a trusted key could forge audit attribution.",
			expectOpen: "key_id_mismatch",
		},
		{
			name: "corrupted-signature", fields: observed,
			desc:             "A well-formed record whose signature has one bit flipped.",
			corruptSignature: true,
			expectOpen:       "bad_signature",
		},
		{
			name: "sealed-by-an-untrusted-operator", fields: observed,
			desc: "A well-formed, correctly signed record sealed from a key the agent does not trust. No precomputed shared " +
				"secret opens it, which is indistinguishable from garbage and from a forgery by design.",
			sealFrom:   &untrusted,
			expectOpen: "no_operator",
		},
	}

	out := make([]vectors.SPARejectionVector, 0, len(specs))
	for _, s := range specs {
		region := s.fields.signedRegion()
		if s.mutate != nil {
			s.mutate(region)
		}
		sig := ed25519.Sign(operator.signPriv, spaSigningInput(region))
		if s.corruptSignature {
			sig[0] ^= 0x01
		}
		record := spaRecord(region, sig)

		sender := operator
		if s.sealFrom != nil {
			sender = *s.sealFrom
		}
		nonce, _ := spaNonce(s.name)
		datagram := sealSPA(record, sender.encPriv, host.encPub, nonce)
		if s.truncate > 0 {
			datagram = datagram[:len(datagram)-s.truncate]
		}
		if s.pad > 0 {
			datagram = append(datagram, make([]byte, s.pad)...)
		}

		v := vectors.SPARejectionVector{
			Name:            s.name,
			Description:     s.desc,
			RecordHex:       hexOf(record),
			DatagramHex:     hexOf(datagram),
			ExpectTrialOpen: s.expectOpen,
			PayloadCall:     s.payloadCall,
			ExpectPayload:   s.expectPayload,
		}
		if s.truncate > 0 || s.pad > 0 {
			// The inner record is intact; only the datagram's length was
			// changed, so publishing the plaintext would invite an
			// implementer to test the wrong thing.
			v.RecordHex = ""
		}
		out = append(out, v)
	}
	return out
}

func vectorPongFields() pongFields {
	return pongFields{
		version: versionV1, alg: algV1,
		hostID:    idPattern(0x81),
		requestID: idPattern(0x91),
		challenge: idPattern(0xA1),
		timestamp: 0xB1B2B3B4B5B6B7B8,
	}
}

func buildPong(host keypair) vectors.PongVector {
	f := vectorPongFields()
	region := f.signedRegion()
	input := pongSigningInput(region)
	sig := ed25519.Sign(host.signPriv, input)
	record := pongRecord(region, sig)

	return vectors.PongVector{
		Name: "liveness-pong",
		Description: "The one record postern transmits in reply, signed by the host key that also signs heartbeats " +
			"and emitted only on the always-allow path after a liveness ping has fully authenticated.",
		Fields: vectors.PongFields{
			Version:      int(f.version),
			Alg:          int(f.alg),
			HostIDHex:    hexOf(f.hostID[:]),
			RequestIDHex: hexOf(f.requestID[:]),
			ChallengeHex: hexOf(f.challenge[:]),
			TimestampMS:  f.timestamp,
		},
		SignedRegionHex: hexOf(region),
		DomainTagHex:    hexOf([]byte(pongDomain)),
		SigningInputHex: hexOf(input),
		SignedBy:        "host",
		SignatureHex:    hexOf(sig),
		RecordHex:       hexOf(record),
		VerifyNowMS:     f.timestamp,
		VerifyWindowMS:  60000,
	}
}

// buildPongRejections covers the two stages a client runs over a reply. The
// first is structural and needs nothing but the bytes; the second needs the
// ping that was sent, and every field it compares is one an attacker would
// have to get right to pass a captured pong off as an answer to a later ping.
func buildPongRejections(host keypair, pong vectors.PongVector) []vectors.PongRejection {
	base := vectorPongFields()

	type spec struct {
		name, desc   string
		fields       pongFields
		truncate     int
		pad          int
		corruptSig   bool
		expectParse  string
		expectVerify string
	}

	stale := base
	stale.timestamp = pong.VerifyNowMS - pong.VerifyWindowMS - 1

	badVersion := base
	badVersion.version = 2

	badAlg := base
	badAlg.alg = 2

	otherHost := base
	otherHost.hostID = idPattern(0x11)

	otherRequest := base
	otherRequest.requestID = idPattern(0x21)

	otherChallenge := base
	otherChallenge.challenge = idPattern(0x31)

	specs := []spec{
		{
			name: "unknown-version", fields: badVersion,
			desc:        "version is 2. A receiver that reads a version it does not understand answers nothing.",
			expectParse: "unsupported_version",
		},
		{
			name: "unknown-alg", fields: badAlg,
			desc:        "alg is 2. Only 1, ed25519+x25519, exists in v1.",
			expectParse: "unsupported_version",
		},
		{
			name: "shorter-than-the-record", fields: base, truncate: 1,
			desc:        "121 bytes, one short of the 122-byte pong record.",
			expectParse: "wrong_size",
		},
		{
			name: "longer-than-max", fields: base, pad: spaMaxDatagram + 1 - pongLen,
			desc: "1401 bytes, one past MaxDatagram. Padding up to MaxDatagram is accepted and its trailing bytes " +
				"discarded; beyond MaxDatagram the pong is rejected on length so a padded packet can never fragment.",
			expectParse: "wrong_size",
		},
		{
			name: "host-id-does-not-match-the-host-that-was-pinged", fields: otherHost,
			desc: "A correctly signed pong naming a different host_id from the one the client pinged. " +
				"The client compares in constant time against what it sent.",
			expectParse: "accept", expectVerify: "pong_mismatch",
		},
		{
			name: "request-id-does-not-match-the-ping", fields: otherRequest,
			desc: "A correctly signed pong echoing a different request_id. Echoing both request_id and the " +
				"challenge nonce is what closes the replay hole; either alone would let a captured pong answer a later ping.",
			expectParse: "accept", expectVerify: "pong_mismatch",
		},
		{
			name: "challenge-nonce-does-not-match-the-ping", fields: otherChallenge,
			desc:        "A correctly signed pong echoing a different challenge nonce, the other half of the same pairing.",
			expectParse: "accept", expectVerify: "pong_mismatch",
		},
		{
			name: "timestamp-outside-the-freshness-window", fields: stale,
			desc: "A correctly signed pong one millisecond beyond the client's freshness window, whose bound " +
				"the vector publishes as verify_now_ms and verify_window_ms.",
			expectParse: "accept", expectVerify: "pong_mismatch",
		},
		{
			name: "corrupted-signature", fields: base, corruptSig: true,
			desc:        "Every field matches the ping and one bit of the signature is flipped.",
			expectParse: "accept", expectVerify: "pong_mismatch",
		},
	}

	out := make([]vectors.PongRejection, 0, len(specs))
	for _, s := range specs {
		region := s.fields.signedRegion()
		sig := ed25519.Sign(host.signPriv, pongSigningInput(region))
		if s.corruptSig {
			sig[0] ^= 0x01
		}
		record := pongRecord(region, sig)
		if s.truncate > 0 {
			record = record[:len(record)-s.truncate]
		}
		if s.pad > 0 {
			record = append(record, make([]byte, s.pad)...)
		}
		out = append(out, vectors.PongRejection{
			Name:         s.name,
			Description:  s.desc,
			RecordHex:    hexOf(record),
			ExpectParse:  s.expectParse,
			ExpectVerify: s.expectVerify,
		})
	}
	return out
}

func buildBundle(signer, host keypair) vectors.BundleVector {
	policy := []byte(bundlePolicy)
	region := bundleSignedRegion(bundleFleetID, bundleHostID, bundleVersion, bundleIssuedAt, policy, signer.signPub)
	sig := ed25519.Sign(signer.signPriv, region)
	record := append(append([]byte{}, region...), sig...)
	ephemeral, ephemeralSrc := bundleEphemeral("bundle")
	sealed := sealAnonymous(record, host.encPub, ephemeral)

	return vectors.BundleVector{
		Name: "bundle",
		Description: "One policy bundle, signed by a bundle signer and then sealed anonymously to the host's " +
			"encryption key. The seal authenticates nobody, so the signature carries the whole authenticity claim.",
		Fields: vectors.BundleFields{
			FleetIDHex:   hexOf(bundleFleetID[:]),
			HostIDHex:    hexOf(bundleHostID[:]),
			Version:      bundleVersion,
			IssuedAtMS:   bundleIssuedAt,
			PolicyLen:    uint32(len(policy)),
			PolicyUTF8:   bundlePolicy,
			PolicyHex:    hexOf(policy),
			SignerKeyHex: hexOf(signer.signPub[:]),
		},
		DomainTagHex:       hexOf([]byte(bundleMagic)),
		SignedRegionHex:    hexOf(region),
		SignedBy:           "bundle_signer",
		SignatureHex:       hexOf(sig),
		RecordHex:          hexOf(record),
		SealedTo:           "host",
		EphemeralKeySource: ephemeralSrc,
		EphemeralSeedHex:   hexOf(ephemeral[:]),
		SealedHex:          hexOf(sealed),
		Accept: vectors.BundleAccept{
			FleetIDHex:      hexOf(bundleFleetID[:]),
			HostIDHex:       hexOf(bundleHostID[:]),
			EnrollmentFloor: 0,
			HasCurrent:      false,
			CurrentVersion:  0,
		},
	}
}

func buildBundleRejections(signer, host, untrusted keypair) []vectors.RecordRejection {
	policy := []byte(bundlePolicy)

	type spec struct {
		name, desc string
		signWith   keypair
		mutate     func([]byte) []byte
		corruptSig bool
		expect     string
	}
	specs := []spec{
		{
			name: "wrong-magic", desc: "The first byte of the 15-byte magic is not 'p'.",
			signWith: signer, expect: "format",
			mutate: func(b []byte) []byte { b[bundleOffMagic] ^= 0xFF; return b },
		},
		{
			name: "unknown-format", desc: "format is 2. v1 understands only 1.",
			signWith: signer, expect: "format",
			mutate: func(b []byte) []byte { b[bundleOffFormat] = 2; return b },
		},
		{
			name: "policy-len-disagrees-with-record-length",
			desc: "policy_len is one byte longer than the policy actually present, so the record length and the " +
				"prefix disagree. Exact, not at least: trailing bytes would give one meaning two encodings.",
			signWith: signer, expect: "format",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint32(b[bundleOffPolicyLen:], uint32(len(policy))+1)
				return b
			},
		},
		{
			name: "policy-len-above-the-cap",
			desc: "policy_len is 0x00200000, twice the 1 MiB cap. The bound is checked before the prefix sizes " +
				"anything, so a small record can carry an absurd prefix and still be refused cheaply.",
			signWith: signer, expect: "format",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint32(b[bundleOffPolicyLen:], 0x00200000)
				return b
			},
		},
		{
			name:     "shorter-than-the-fixed-length",
			desc:     "163 bytes, one below the 164-byte minimum a record with an empty policy occupies.",
			signWith: signer, expect: "format",
			mutate: func(b []byte) []byte { return b[:len(b)-1] },
		},
		{
			name: "untrusted-signer",
			desc: "A structurally perfect record, correctly signed, naming a signer key outside the trusted set. " +
				"Membership is checked before the signature, so an untrusted party's signature is never verified.",
			signWith: untrusted, expect: "untrusted_signer",
		},
		{
			name:     "corrupted-signature",
			desc:     "A trusted signer's record with one bit flipped in the signature.",
			signWith: signer, corruptSig: true, expect: "bad_signature",
		},
	}

	out := make([]vectors.RecordRejection, 0, len(specs))
	for _, s := range specs {
		region := bundleSignedRegion(bundleFleetID, bundleHostID, bundleVersion, bundleIssuedAt, policy, s.signWith.signPub)
		sig := ed25519.Sign(s.signWith.signPriv, region)
		if s.corruptSig {
			sig[0] ^= 0x01
		}
		record := append(append([]byte{}, region...), sig...)
		if s.mutate != nil {
			record = s.mutate(record)
		}
		ephemeral, _ := bundleEphemeral("rejection-" + s.name)
		out = append(out, vectors.RecordRejection{
			Name:        s.name,
			Description: s.desc,
			RecordHex:   hexOf(record),
			SealedHex:   hexOf(sealAnonymous(record, host.encPub, ephemeral)),
			Expect:      s.expect,
		})
	}
	return out
}

func buildBeat(host keypair) vectors.BeatVector {
	body := []byte(beatBody)
	region := beatSignedRegion(bundleFleetID, bundleHostID, beatEpoch, beatSequence, beatSentAt, body)
	sig := ed25519.Sign(host.signPriv, region)
	record := append(append([]byte{}, region...), sig...)

	return vectors.BeatVector{
		Name: "beat",
		Description: "One signed heartbeat. It is not encrypted: it carries telemetry rather than secrets, and the " +
			"hub checks it against the one signing key already on file for the host named inside.",
		Fields: vectors.BeatFields{
			FleetIDHex: hexOf(bundleFleetID[:]),
			HostIDHex:  hexOf(bundleHostID[:]),
			Epoch:      beatEpoch,
			Sequence:   beatSequence,
			SentAtMS:   beatSentAt,
			BodyLen:    uint32(len(body)),
			BodyUTF8:   beatBody,
			BodyHex:    hexOf(body),
		},
		DomainTagHex:    hexOf([]byte(beatMagic)),
		SignedRegionHex: hexOf(region),
		SignedBy:        "host",
		SignatureHex:    hexOf(sig),
		RecordHex:       hexOf(record),
	}
}

func buildBeatRejections(host, untrusted keypair) []vectors.RecordRejection {
	body := []byte(beatBody)

	type spec struct {
		name, desc string
		signWith   keypair
		mutate     func([]byte) []byte
		corruptSig bool
		expect     string
	}
	specs := []spec{
		{
			name: "wrong-magic", desc: "The first byte of the 13-byte magic is not 'p'.",
			signWith: host, expect: "format",
			mutate: func(b []byte) []byte { b[beatOffMagic] ^= 0xFF; return b },
		},
		{
			name: "unknown-format", desc: "format is 2. v1 understands only 1.",
			signWith: host, expect: "format",
			mutate: func(b []byte) []byte { b[beatOffFormat] = 2; return b },
		},
		{
			name:     "body-len-disagrees-with-record-length",
			desc:     "body_len is one byte longer than the body actually present.",
			signWith: host, expect: "format",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint32(b[beatOffBodyLen:], uint32(len(body))+1)
				return b
			},
		},
		{
			name:     "body-len-above-the-cap",
			desc:     "body_len is 0x00020000, twice the 64 KiB cap, in a record of a few hundred bytes.",
			signWith: host, expect: "format",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint32(b[beatOffBodyLen:], 0x00020000)
				return b
			},
		},
		{
			name:     "shorter-than-the-fixed-length",
			desc:     "137 bytes, one below the 138-byte minimum a record with an empty body occupies.",
			signWith: host, expect: "format",
			mutate: func(b []byte) []byte { return b[:len(b)-1] },
		},
		{
			name: "signed-by-another-key",
			desc: "A structurally perfect record signed by a key that is not the one on file for this host. " +
				"A beat carries no signer key field: the verifier is handed the one key the record must check against.",
			signWith: untrusted, expect: "bad_signature",
		},
		{
			name:     "corrupted-signature",
			desc:     "The host's own record with one bit flipped in the signature.",
			signWith: host, corruptSig: true, expect: "bad_signature",
		},
	}

	out := make([]vectors.RecordRejection, 0, len(specs))
	for _, s := range specs {
		region := beatSignedRegion(bundleFleetID, bundleHostID, beatEpoch, beatSequence, beatSentAt, body)
		sig := ed25519.Sign(s.signWith.signPriv, region)
		if s.corruptSig {
			sig[0] ^= 0x01
		}
		record := append(append([]byte{}, region...), sig...)
		if s.mutate != nil {
			record = s.mutate(record)
		}
		out = append(out, vectors.RecordRejection{
			Name:        s.name,
			Description: s.desc,
			RecordHex:   hexOf(record),
			Expect:      s.expect,
		})
	}
	return out
}

// buildCrossProtocol is the property the tags exist for. Every signature here
// is genuine and made by the key the verifier will check against; the only
// thing wrong with it is which record type's signing input it covers. Without
// a tag, all four would verify.
func buildCrossProtocol(operator, host keypair, pong vectors.PongVector) []vectors.CrossProtocolVector {
	spaRegion := gateFields(operator.keyID, payloadGateObserved()).signedRegion()
	pongRegion, err := pong.SignedRegionHex.Bytes()
	if err != nil {
		fail(err)
	}

	out := []vectors.CrossProtocolVector{}

	add := func(v vectors.CrossProtocolVector) { out = append(out, v) }

	// An SPA request whose signature covers the untagged 120-byte region.
	// This is exactly what a client built before domain separation emits.
	sig := ed25519.Sign(operator.signPriv, spaRegion)
	record := spaRecord(spaRegion, sig)
	nonce, _ := spaNonce("cross-spa-untagged")
	add(vectors.CrossProtocolVector{
		Name:   "spa-request-signed-over-the-untagged-region",
		Record: "spa_request",
		Description: "The signature covers the 120-byte signed region with no tag in front of it. The datagram " +
			"decrypts, parses and matches key_id, so the signature check is the only control that can refuse it.",
		SignedOver:          "the SPA request's signed region, without postern-spa-request\\0",
		SigningInputUsedHex: hexOf(spaRegion),
		SignedBy:            "operator",
		SignatureHex:        hexOf(sig),
		RecordHex:           hexOf(record),
		NonceHex:            hexOf(nonce[:]),
		DatagramHex:         hexOf(sealSPA(record, operator.encPriv, host.encPub, nonce)),
		Expect:              "bad_signature",
	})

	// An SPA request whose signature covers the pong's signing input.
	pongInput := pongSigningInput(pongRegion)
	sig = ed25519.Sign(operator.signPriv, pongInput)
	record = spaRecord(spaRegion, sig)
	nonce, _ = spaNonce("cross-spa-over-pong")
	add(vectors.CrossProtocolVector{
		Name:   "spa-request-signed-over-the-pong-signing-input",
		Record: "spa_request",
		Description: "A genuine operator signature over the pong's signing input, carried in an SPA request. " +
			"The tags make the two sets of signable byte strings disjoint, so it cannot be reused here.",
		SignedOver:          "postern-spa-pong\\0 followed by the pong's 58-byte signed region",
		SigningInputUsedHex: hexOf(pongInput),
		SignedBy:            "operator",
		SignatureHex:        hexOf(sig),
		RecordHex:           hexOf(record),
		NonceHex:            hexOf(nonce[:]),
		DatagramHex:         hexOf(sealSPA(record, operator.encPriv, host.encPub, nonce)),
		Expect:              "bad_signature",
	})

	// A pong whose signature covers the untagged 58-byte region.
	sig = ed25519.Sign(host.signPriv, pongRegion)
	add(vectors.CrossProtocolVector{
		Name:   "pong-signed-over-the-untagged-region",
		Record: "pong",
		Description: "The pong's half of the same check: a host signature over the 58-byte signed region with no " +
			"tag in front of it. Every other field matches the ping, so the signature is the only control in play.",
		SignedOver:          "the pong's signed region, without postern-spa-pong\\0",
		SigningInputUsedHex: hexOf(pongRegion),
		SignedBy:            "host",
		SignatureHex:        hexOf(sig),
		RecordHex:           hexOf(pongRecord(pongRegion, sig)),
		Expect:              "pong_mismatch",
	})

	// A pong whose signature covers the SPA request's signing input.
	spaInput := spaSigningInput(spaRegion)
	sig = ed25519.Sign(host.signPriv, spaInput)
	add(vectors.CrossProtocolVector{
		Name:   "pong-signed-over-the-spa-request-signing-input",
		Record: "pong",
		Description: "A genuine host signature over the SPA request's signing input, carried in a pong. " +
			"Refused for the same reason as its mirror image above.",
		SignedOver:          "postern-spa-request\\0 followed by an SPA request's 120-byte signed region",
		SigningInputUsedHex: hexOf(spaInput),
		SignedBy:            "host",
		SignatureHex:        hexOf(sig),
		RecordHex:           hexOf(pongRecord(pongRegion, sig)),
		Expect:              "pong_mismatch",
	})

	return out
}
