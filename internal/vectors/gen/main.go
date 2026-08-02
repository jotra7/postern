// Command gen writes docs/vectors/postern-v1.json.
//
// Run it by hand, from the repository root:
//
//	go run ./internal/vectors/gen
//
// Nothing runs it automatically. The test suite reads the file it produced
// and never regenerates it, because a vector that is recomputed at test time
// from the code it is meant to check agrees with that code by construction
// and pins nothing.
//
// The same reasoning shapes what this program is allowed to import. It reads
// the key material from internal/vectors and everything else from the
// specification: the offsets, magic strings, domain tags, field widths and
// payload layouts below are written out again here from docs/protocol.md, and
// this file imports neither internal/spa, nor internal/bundle, nor
// internal/attest. So the vectors are the output of a second encoder rather
// than a transcript of the first, and regenerating them after a change to the
// wire code does not make the change disappear: the frozen file would move
// only if the specification did.
//
// What that does not buy is independence from the author. Both encoders were
// written from the same document by the same hand, so a misreading of the
// specification is reproduced faithfully in both. Only review by a third
// party closes that gap, and section 13 of the specification says so.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/jotra7/postern/internal/vectors"
)

// The SPA inner record, from section 5.2 of the specification.
const (
	spaOffVersion   = 0
	spaOffAlg       = 1
	spaOffKind      = 2
	spaOffReserved1 = 3
	spaOffKeyID     = 4
	spaOffHostID    = 20
	spaOffRequestID = 36
	spaOffCounter   = 52
	spaOffTimestamp = 60
	spaOffServiceID = 68
	spaOffTTL       = 84
	spaOffPayload   = 86
	spaOffReserved2 = 118
	spaOffSignature = 120

	spaSignedLen   = 120
	spaPayloadLen  = 32
	spaInnerLen    = 184
	spaNonceLen    = 24
	spaDatagramLen = 224
	// spaMaxDatagram is the upper bound on a padded datagram: the record plus
	// random padding may reach this, and anything longer is rejected.
	spaMaxDatagram = 1400
)

// The liveness pong, from section 7.
const (
	pongOffVersion   = 0
	pongOffAlg       = 1
	pongOffHostID    = 2
	pongOffRequestID = 18
	pongOffChallenge = 34
	pongOffTimestamp = 50
	pongOffSignature = 58

	pongSignedLen = 58
	pongLen       = 122
)

// The bundle record, from section 8.
const (
	bundleOffMagic     = 0
	bundleOffFormat    = 15
	bundleOffFleetID   = 16
	bundleOffHostID    = 32
	bundleOffVersion   = 48
	bundleOffIssuedAt  = 56
	bundleOffPolicyLen = 64
	bundleOffPolicy    = 68

	bundleSignerKeyLen = 32
)

// The heartbeat record, from section 9.
const (
	beatOffMagic    = 0
	beatOffFormat   = 13
	beatOffFleetID  = 14
	beatOffHostID   = 30
	beatOffEpoch    = 46
	beatOffSequence = 54
	beatOffSentAt   = 62
	beatOffBodyLen  = 70
	beatOffBody     = 74
)

// The four domain-separation tags of section 12.
const (
	requestDomain = "postern-spa-request\x00"
	pongDomain    = "postern-spa-pong\x00"
	bundleMagic   = "postern-bundle\x00"
	beatMagic     = "postern-beat\x00"
)

const (
	idLen     = 16
	sigLen    = 64
	formatV1  = 1
	versionV1 = 1
	algV1     = 1

	kindGate   = 1
	kindAction = 2

	sourceObserved = 0
	sourceAsserted = 1
)

func main() {
	out := flag.String("o", vectors.RelPath, "where to write the vector file")
	flag.Parse()

	file := build()
	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		fail(err)
	}
	body = append(body, '\n')

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil { //nolint:gosec // G306: published, non-secret vectors.
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *out, len(body))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}

// keypair is one published identity, derived from the ASCII seeds in
// internal/vectors.
type keypair struct {
	name       string
	role       string
	seedASCII  string
	seed       [32]byte
	signPriv   ed25519.PrivateKey
	signPub    [32]byte
	keyID      [idLen]byte
	sha        [32]byte
	encASCII   string
	encPriv    [32]byte
	encPub     [32]byte
	hasEncrypt bool
}

func newKeypair(name, role, signSeed, encPriv string) keypair {
	k := keypair{name: name, role: role, seedASCII: signSeed, encASCII: encPriv}
	k.seed = mustLen32(signSeed)
	k.signPriv = ed25519.NewKeyFromSeed(k.seed[:])
	copy(k.signPub[:], k.signPriv[32:])
	k.sha = sha256.Sum256(k.signPub[:])
	copy(k.keyID[:], k.sha[:idLen])

	k.encPriv = mustLen32(encPriv)
	pub, err := curve25519.X25519(k.encPriv[:], curve25519.Basepoint)
	if err != nil {
		fail(fmt.Errorf("X25519 public key for %s: %w", name, err))
	}
	copy(k.encPub[:], pub)
	k.hasEncrypt = true
	return k
}

func (k keypair) published() vectors.Key {
	return vectors.Key{
		Name:                   k.name,
		Role:                   k.role,
		SigningSeedASCII:       k.seedASCII,
		SigningSeedHex:         hexOf(k.seed[:]),
		SigningPrivateHex:      hexOf(k.signPriv),
		SigningPublicHex:       hexOf(k.signPub[:]),
		KeyIDHex:               hexOf(k.keyID[:]),
		EncryptionPrivateASCII: k.encASCII,
		EncryptionPrivateHex:   hexOf(k.encPriv[:]),
		EncryptionPublicHex:    hexOf(k.encPub[:]),
	}
}

func mustLen32(s string) [32]byte {
	if len(s) != 32 {
		fail(fmt.Errorf("seed %q is %d bytes, want 32", s, len(s)))
	}
	return [32]byte([]byte(s))
}

func hexOf(b []byte) vectors.Hex { return vectors.Hex(hex.EncodeToString(b)) }

// idPattern reproduces the byte patterns internal/spa/golden_test.go freezes,
// so the published records and the golden fixtures differ in nothing but the
// key_id and the signature.
func idPattern(start byte) [idLen]byte {
	var b [idLen]byte
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// spaFields is one inner SPA record before it is rendered.
type spaFields struct {
	version   byte
	alg       byte
	kind      byte
	keyID     [idLen]byte
	hostID    [idLen]byte
	requestID [idLen]byte
	counter   uint64
	timestamp uint64
	serviceID [idLen]byte
	ttl       uint16
	payload   [spaPayloadLen]byte
}

// signedRegion renders bytes 0 through 119 of the inner record: every field
// except the signature.
func (f spaFields) signedRegion() []byte {
	b := make([]byte, spaSignedLen)
	b[spaOffVersion] = f.version
	b[spaOffAlg] = f.alg
	b[spaOffKind] = f.kind
	b[spaOffReserved1] = 0
	copy(b[spaOffKeyID:], f.keyID[:])
	copy(b[spaOffHostID:], f.hostID[:])
	copy(b[spaOffRequestID:], f.requestID[:])
	binary.BigEndian.PutUint64(b[spaOffCounter:], f.counter)
	binary.BigEndian.PutUint64(b[spaOffTimestamp:], f.timestamp)
	copy(b[spaOffServiceID:], f.serviceID[:])
	binary.BigEndian.PutUint16(b[spaOffTTL:], f.ttl)
	copy(b[spaOffPayload:], f.payload[:])
	b[spaOffReserved2] = 0
	b[spaOffReserved2+1] = 0
	return b
}

func (f spaFields) published(signedRegion []byte, note string) vectors.SPAFields {
	return vectors.SPAFields{
		Version:      int(signedRegion[spaOffVersion]),
		Alg:          int(signedRegion[spaOffAlg]),
		Kind:         int(signedRegion[spaOffKind]),
		KeyIDHex:     hexOf(f.keyID[:]),
		HostIDHex:    hexOf(f.hostID[:]),
		RequestIDHex: hexOf(f.requestID[:]),
		Counter:      f.counter,
		TimestampMS:  f.timestamp,
		ServiceIDHex: hexOf(f.serviceID[:]),
		TTLSeconds:   f.ttl,
		PayloadHex:   hexOf(f.payload[:]),
		PayloadNote:  note,
	}
}

func spaRecord(signedRegion, sig []byte) []byte {
	b := make([]byte, spaInnerLen)
	copy(b, signedRegion)
	copy(b[spaOffSignature:], sig)
	return b
}

func spaSigningInput(signedRegion []byte) []byte {
	return append([]byte(requestDomain), signedRegion...)
}

// sealSPA is section 5.4 step 5: the nonce in the clear, then
// box.SealAfterPrecomputation over the whole inner record.
func sealSPA(record []byte, senderPriv, recipientPub [32]byte, nonce [spaNonceLen]byte) []byte {
	var shared [32]byte
	box.Precompute(&shared, &recipientPub, &senderPriv)
	out := make([]byte, 0, spaDatagramLen)
	out = append(out, nonce[:]...)
	return box.SealAfterPrecomputation(out, record, &nonce, &shared)
}

// spaNonce derives this vector's nonce. A real sender reads 24 bytes from the
// system CSPRNG; a vector needs the same nonce every time it is regenerated,
// and it needs a different one per datagram, since two datagrams under one
// shared secret and one nonce would reuse a keystream.
func spaNonce(name string) ([spaNonceLen]byte, string) {
	src := "sha256(\"" + vectors.SeedPrefix + "spa nonce " + name + "\")[:24]"
	sum := sha256.Sum256([]byte(vectors.SeedPrefix + "spa nonce " + name))
	var n [spaNonceLen]byte
	copy(n[:], sum[:spaNonceLen])
	return n, src
}

// bundleEphemeral derives the ephemeral X25519 private key box.SealAnonymous
// would otherwise draw at random, for the same two reasons spaNonce exists.
func bundleEphemeral(name string) ([32]byte, string) {
	src := "sha256(\"" + vectors.SeedPrefix + "bundle ephemeral " + name + "\")"
	return sha256.Sum256([]byte(vectors.SeedPrefix + "bundle ephemeral " + name)), src
}

// fixedReader hands box.SealAnonymous exactly the 32 bytes it reads for the
// ephemeral private key, and nothing more.
type fixedReader struct {
	b []byte
	i int
}

func (r *fixedReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, errors.New("fixedReader: exhausted")
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func sealAnonymous(message []byte, recipient [32]byte, ephemeral [32]byte) []byte {
	out, err := box.SealAnonymous(nil, message, &recipient, &fixedReader{b: ephemeral[:]})
	if err != nil {
		fail(fmt.Errorf("seal anonymous: %w", err))
	}
	return out
}

// gate payload variants, section 5.3.

func payloadGateObserved() [spaPayloadLen]byte {
	return [spaPayloadLen]byte{}
}

func payloadGateAssertedV4(addr [4]byte, bits byte) [spaPayloadLen]byte {
	var p [spaPayloadLen]byte
	p[0] = sourceAsserted
	p[1] = 4
	p[2] = bits
	copy(p[3:7], addr[:])
	return p
}

func payloadGateAssertedV6(addr [16]byte, bits byte) [spaPayloadLen]byte {
	var p [spaPayloadLen]byte
	p[0] = sourceAsserted
	p[1] = 6
	p[2] = bits
	copy(p[3:19], addr[:])
	return p
}

func payloadConfirm(revision uint64, nonce [idLen]byte) [spaPayloadLen]byte {
	var p [spaPayloadLen]byte
	binary.BigEndian.PutUint64(p[0:8], revision)
	copy(p[8:24], nonce[:])
	return p
}

func payloadDisarm() [spaPayloadLen]byte { return [spaPayloadLen]byte{} }

func payloadLiveness(challenge [idLen]byte) [spaPayloadLen]byte {
	var p [spaPayloadLen]byte
	copy(p[0:16], challenge[:])
	return p
}

// pongFields is the pong before it is rendered.
type pongFields struct {
	version   byte
	alg       byte
	hostID    [idLen]byte
	requestID [idLen]byte
	challenge [idLen]byte
	timestamp uint64
}

func (f pongFields) signedRegion() []byte {
	b := make([]byte, pongSignedLen)
	b[pongOffVersion] = f.version
	b[pongOffAlg] = f.alg
	copy(b[pongOffHostID:], f.hostID[:])
	copy(b[pongOffRequestID:], f.requestID[:])
	copy(b[pongOffChallenge:], f.challenge[:])
	binary.BigEndian.PutUint64(b[pongOffTimestamp:], f.timestamp)
	return b
}

func pongRecord(signedRegion, sig []byte) []byte {
	b := make([]byte, pongLen)
	copy(b, signedRegion)
	copy(b[pongOffSignature:], sig)
	return b
}

func pongSigningInput(signedRegion []byte) []byte {
	return append([]byte(pongDomain), signedRegion...)
}

// bundleSignedRegion is section 8: the header, the policy, and the signer's
// own public key.
func bundleSignedRegion(fleetID, hostID [idLen]byte, version, issuedAt uint64, policy []byte, signerKey [32]byte) []byte {
	b := make([]byte, bundleOffPolicy+len(policy)+bundleSignerKeyLen)
	copy(b[bundleOffMagic:], bundleMagic)
	b[bundleOffFormat] = formatV1
	copy(b[bundleOffFleetID:], fleetID[:])
	copy(b[bundleOffHostID:], hostID[:])
	binary.BigEndian.PutUint64(b[bundleOffVersion:], version)
	binary.BigEndian.PutUint64(b[bundleOffIssuedAt:], issuedAt)
	binary.BigEndian.PutUint32(b[bundleOffPolicyLen:], uint32(len(policy)))
	copy(b[bundleOffPolicy:], policy)
	copy(b[bundleOffPolicy+len(policy):], signerKey[:])
	return b
}

// beatSignedRegion is section 9: the header and the body.
func beatSignedRegion(fleetID, hostID [idLen]byte, epoch, sequence, sentAt uint64, body []byte) []byte {
	b := make([]byte, beatOffBody+len(body))
	copy(b[beatOffMagic:], beatMagic)
	b[beatOffFormat] = formatV1
	copy(b[beatOffFleetID:], fleetID[:])
	copy(b[beatOffHostID:], hostID[:])
	binary.BigEndian.PutUint64(b[beatOffEpoch:], epoch)
	binary.BigEndian.PutUint64(b[beatOffSequence:], sequence)
	binary.BigEndian.PutUint64(b[beatOffSentAt:], sentAt)
	binary.BigEndian.PutUint32(b[beatOffBodyLen:], uint32(len(body)))
	copy(b[beatOffBody:], body)
	return b
}

func serviceIDOf(name string) ([idLen]byte, [32]byte) {
	sum := sha256.Sum256([]byte(name))
	var id [idLen]byte
	copy(id[:], sum[:idLen])
	return id, sum
}
