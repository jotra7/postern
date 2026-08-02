// Package vectors loads the published v1 protocol test vectors and holds the
// fixed key material they are built from.
//
// The vectors themselves live in docs/vectors/postern-v1.json, beside the
// specification they pin, so that an implementation with no access to this
// repository's Go code can read them. Nothing here generates them: the file
// is frozen bytes, and the tests in this module check the implementation
// against it rather than the other way round. internal/vectors/gen holds the
// generator, which is run by hand and never by the test suite.
//
// Every key in this package is published, in this source file and in the
// vector file. See keys.go.
package vectors

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RelPath is where the vector file sits relative to the repository root.
const RelPath = "docs/vectors/postern-v1.json"

// Hex is a lowercase hex string as it appears in the vector file.
type Hex string

// Bytes decodes h.
func (h Hex) Bytes() ([]byte, error) {
	b, err := hex.DecodeString(string(h))
	if err != nil {
		return nil, fmt.Errorf("vectors: %q is not hex: %w", string(h), err)
	}
	return b, nil
}

// Path locates the vector file by walking up from the working directory,
// which is how a test in any package of this module reaches it without
// hard-coding its own depth.
func Path() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("vectors: working directory: %w", err)
	}
	start := dir
	for range 12 {
		candidate := filepath.Join(dir, filepath.FromSlash(RelPath))
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("vectors: %s not found at or above %s", RelPath, start)
}

// Load reads the vector file from its usual place.
func Load() (*File, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	return LoadFile(path)
}

// LoadFile reads the vector file at path. Unknown fields are refused, so the
// file and the types below cannot drift apart silently.
func LoadFile(path string) (*File, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is a test fixture, not user input.
	if err != nil {
		return nil, fmt.Errorf("vectors: open: %w", err)
	}
	defer func() { _ = f.Close() }()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var out File
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("vectors: decode %s: %w", path, err)
	}
	return &out, nil
}

// File is the whole vector file.
type File struct {
	Schema    int      `json:"schema"`
	Protocol  string   `json:"protocol"`
	Spec      string   `json:"spec"`
	Generator string   `json:"generator"`
	Warning   string   `json:"warning"`
	Notes     []string `json:"notes"`

	Keys       Keys        `json:"keys"`
	DomainTags []DomainTag `json:"domain_tags"`

	KeyIDDerivations     []KeyIDVector     `json:"key_id_derivations"`
	ServiceIDDerivations []ServiceIDVector `json:"service_id_derivations"`

	SPARequests   []SPARequestVector   `json:"spa_requests"`
	SPARejections []SPARejectionVector `json:"spa_rejections"`

	Pong           PongVector      `json:"pong"`
	PongRejections []PongRejection `json:"pong_rejections"`

	Bundle           BundleVector      `json:"bundle"`
	BundleRejections []RecordRejection `json:"bundle_rejections"`

	Beat           BeatVector        `json:"beat"`
	BeatRejections []RecordRejection `json:"beat_rejections"`

	CrossProtocolRejections []CrossProtocolVector `json:"cross_protocol_rejections"`
}

// Keys is the fixed key material every vector below is built from.
type Keys struct {
	Operator  Key `json:"operator"`
	Host      Key `json:"host"`
	Signer    Key `json:"bundle_signer"`
	Untrusted Key `json:"untrusted_operator"`
}

// Key is one published identity, private halves included.
type Key struct {
	Name string `json:"name"`
	Role string `json:"role"`

	SigningSeedASCII  string `json:"signing_seed_ascii"`
	SigningSeedHex    Hex    `json:"signing_seed_hex"`
	SigningPrivateHex Hex    `json:"signing_private_hex"`
	SigningPublicHex  Hex    `json:"signing_public_hex"`
	KeyIDHex          Hex    `json:"key_id_hex"`

	EncryptionPrivateASCII string `json:"encryption_private_ascii,omitempty"`
	EncryptionPrivateHex   Hex    `json:"encryption_private_hex,omitempty"`
	EncryptionPublicHex    Hex    `json:"encryption_public_hex,omitempty"`
}

// DomainTag is one of the four byte strings that begin a postern signing
// input.
type DomainTag struct {
	Record      string `json:"record"`
	ASCII       string `json:"ascii"`
	Hex         Hex    `json:"hex"`
	Length      int    `json:"length"`
	Transmitted bool   `json:"transmitted"`
	Note        string `json:"note"`
}

// KeyIDVector pins the truncated SHA-256 that turns a signing key into the
// key_id carried on the wire.
type KeyIDVector struct {
	Name             string `json:"name"`
	SigningPublicHex Hex    `json:"signing_public_hex"`
	SHA256Hex        Hex    `json:"sha256_hex"`
	KeyIDHex         Hex    `json:"key_id_hex"`
}

// ServiceIDVector pins the same derivation over a service name.
type ServiceIDVector struct {
	ServiceName  string `json:"service_name"`
	NameHex      Hex    `json:"name_hex"`
	SHA256Hex    Hex    `json:"sha256_hex"`
	ServiceIDHex Hex    `json:"service_id_hex"`
}

// SPAFields is one inner SPA record's decoded field set.
type SPAFields struct {
	Version      int    `json:"version"`
	Alg          int    `json:"alg"`
	Kind         int    `json:"kind"`
	KeyIDHex     Hex    `json:"key_id_hex"`
	HostIDHex    Hex    `json:"host_id_hex"`
	RequestIDHex Hex    `json:"request_id_hex"`
	Counter      uint64 `json:"counter"`
	TimestampMS  uint64 `json:"timestamp_ms"`
	ServiceIDHex Hex    `json:"service_id_hex"`
	TTLSeconds   uint16 `json:"ttl_seconds"`
	PayloadHex   Hex    `json:"payload_hex"`
	PayloadNote  string `json:"payload_note"`
}

// SPARequestVector is one accepted SPA request, from fields to datagram.
type SPARequestVector struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Fields      SPAFields `json:"fields"`

	SignedRegionHex Hex `json:"signed_region_hex"`
	DomainTagHex    Hex `json:"domain_tag_hex"`
	SigningInputHex Hex `json:"signing_input_hex"`

	SignedBy     string `json:"signed_by"`
	SignatureHex Hex    `json:"signature_hex"`
	RecordHex    Hex    `json:"record_hex"`

	SealedTo    string `json:"sealed_to"`
	NonceSource string `json:"nonce_source"`
	NonceHex    Hex    `json:"nonce_hex"`
	DatagramHex Hex    `json:"datagram_hex"`
}

// SPARejectionVector is one datagram an implementation must refuse, with the
// stage that refuses it.
//
// Two stages exist because the wire layer cannot finish the job on its own.
// Parsing establishes the shared invariants; the payload variant of an action
// is only canonicalised once service_id has been resolved to a service, which
// needs the host's configuration. ExpectTrialOpen of "accept" marks the
// records that reach the second stage.
type SPARejectionVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`

	RecordHex   Hex `json:"record_hex,omitempty"`
	DatagramHex Hex `json:"datagram_hex"`

	ExpectTrialOpen string `json:"expect_trial_open"`
	PayloadCall     string `json:"payload_call,omitempty"`
	ExpectPayload   string `json:"expect_payload,omitempty"`
}

// PongFields is the pong's decoded field set.
type PongFields struct {
	Version      int    `json:"version"`
	Alg          int    `json:"alg"`
	HostIDHex    Hex    `json:"host_id_hex"`
	RequestIDHex Hex    `json:"request_id_hex"`
	ChallengeHex Hex    `json:"challenge_nonce_hex"`
	TimestampMS  uint64 `json:"timestamp_ms"`
}

// PongVector is the liveness pong, the one record postern transmits in reply.
type PongVector struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Fields      PongFields `json:"fields"`

	SignedRegionHex Hex `json:"signed_region_hex"`
	DomainTagHex    Hex `json:"domain_tag_hex"`
	SigningInputHex Hex `json:"signing_input_hex"`

	SignedBy     string `json:"signed_by"`
	SignatureHex Hex    `json:"signature_hex"`
	RecordHex    Hex    `json:"record_hex"`

	VerifyNowMS    uint64 `json:"verify_now_ms"`
	VerifyWindowMS uint64 `json:"verify_window_ms"`
}

// PongRejection is one pong a client must refuse, and the stage that refuses
// it. Parsing establishes the version, the algorithm and the length; every
// other check belongs to Verify, which needs the ping the client sent.
// ExpectParse of "accept" marks the records that reach the second stage.
type PongRejection struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	RecordHex    Hex    `json:"record_hex"`
	ExpectParse  string `json:"expect_parse"`
	ExpectVerify string `json:"expect_verify,omitempty"`
}

// BundleFields is a bundle's decoded field set.
type BundleFields struct {
	FleetIDHex   Hex    `json:"fleet_id_hex"`
	HostIDHex    Hex    `json:"host_id_hex"`
	Version      uint64 `json:"version"`
	IssuedAtMS   uint64 `json:"issued_at_ms"`
	PolicyLen    uint32 `json:"policy_len"`
	PolicyUTF8   string `json:"policy_utf8"`
	PolicyHex    Hex    `json:"policy_hex"`
	SignerKeyHex Hex    `json:"signer_key_hex"`
}

// BundleAccept is what an agent already knows about itself when it opens the
// record.
type BundleAccept struct {
	FleetIDHex      Hex    `json:"fleet_id_hex"`
	HostIDHex       Hex    `json:"host_id_hex"`
	EnrollmentFloor uint64 `json:"enrollment_floor"`
	HasCurrent      bool   `json:"has_current"`
	CurrentVersion  uint64 `json:"current_version"`
}

// BundleVector is one signed and anonymously sealed bundle.
type BundleVector struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Fields      BundleFields `json:"fields"`

	DomainTagHex    Hex `json:"domain_tag_hex"`
	SignedRegionHex Hex `json:"signed_region_hex"`

	SignedBy     string `json:"signed_by"`
	SignatureHex Hex    `json:"signature_hex"`
	RecordHex    Hex    `json:"record_hex"`

	SealedTo           string `json:"sealed_to"`
	EphemeralKeySource string `json:"ephemeral_key_source"`
	EphemeralSeedHex   Hex    `json:"ephemeral_seed_hex"`
	SealedHex          Hex    `json:"sealed_hex"`

	Accept BundleAccept `json:"accept_criteria"`
}

// BeatFields is a beat's decoded field set.
type BeatFields struct {
	FleetIDHex Hex    `json:"fleet_id_hex"`
	HostIDHex  Hex    `json:"host_id_hex"`
	Epoch      uint64 `json:"epoch"`
	Sequence   uint64 `json:"sequence"`
	SentAtMS   uint64 `json:"sent_at_ms"`
	BodyLen    uint32 `json:"body_len"`
	BodyUTF8   string `json:"body_utf8"`
	BodyHex    Hex    `json:"body_hex"`
}

// BeatVector is one signed heartbeat.
type BeatVector struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Fields      BeatFields `json:"fields"`

	DomainTagHex    Hex `json:"domain_tag_hex"`
	SignedRegionHex Hex `json:"signed_region_hex"`

	SignedBy     string `json:"signed_by"`
	SignatureHex Hex    `json:"signature_hex"`
	RecordHex    Hex    `json:"record_hex"`
}

// RecordRejection is one malformed bundle or beat and the error class an
// implementation is expected to reach.
type RecordRejection struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	RecordHex   Hex    `json:"record_hex"`
	SealedHex   Hex    `json:"sealed_hex,omitempty"`
	Expect      string `json:"expect"`
}

// CrossProtocolVector is a record whose signature is genuine, made by the
// right key, over the signing input of a different record type. Each must be
// refused: without the domain tag every one of them would verify.
type CrossProtocolVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Record      string `json:"record"`

	SignedOver          string `json:"signed_over"`
	SigningInputUsedHex Hex    `json:"signing_input_used_hex"`
	SignedBy            string `json:"signed_by"`
	SignatureHex        Hex    `json:"signature_hex"`

	RecordHex   Hex    `json:"record_hex"`
	DatagramHex Hex    `json:"datagram_hex,omitempty"`
	NonceHex    Hex    `json:"nonce_hex,omitempty"`
	Expect      string `json:"expect"`
}
