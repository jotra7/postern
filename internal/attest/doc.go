// Package attest is the signed heartbeat record fleet mode runs on: a host
// asserting, at (epoch, sequence), that it is alive, over its own signing
// key. It is its own package, separate from internal/bundle, because the
// agent writes beats and the hub reads them and neither may import the
// other.
//
// Like internal/spa, this package performs no I/O and reads no clock: it
// parses attacker-controlled bytes as root (Encode runs on the agent, Verify
// on the hub, over whatever transport carries the datagram between them),
// so it has to be fuzzable without a network, an agent, or a hub.
//
// # Wire layout
//
// The signed record, all integers big-endian, no padding:
//
//	offset  size  field
//	0       13    magic "postern-beat\0"
//	13      1     format version (1)
//	14      16    fleet_id
//	30      16    host_id
//	46      8     epoch
//	54      8     sequence
//	62      8     sent_at, unix milliseconds
//	70      4     body_len
//	74      N     body (JSON)
//	74+N    64    Ed25519 signature over bytes [0, 74+N)
//
// Unlike a bundle record, there is no signer key carried in the record.
// Verify takes the one host signing key the caller already has on file for
// the HostID a beat claims — established once, at enrollment, the same way
// a bundle's encryption key is — so there is no trusted set to search and no
// key to re-attribute by rewriting bytes.
//
// # Why the body is lenient where a bundle's policy is strict
//
// A bundle's policy is parsed with config.ParseStandalone, which rejects any
// key it does not recognize. A beat's body is parsed with encoding/json,
// deliberately without DisallowUnknownFields. That asymmetry is the point,
// not an oversight:
//
// A bundle is policy the agent is about to enforce. An unknown key in it
// means a posture the agent cannot honor — the safe response is to refuse
// the whole bundle rather than silently enforce a subset of what an operator
// asked for.
//
// A beat is telemetry the hub will display, and nothing downstream of Verify
// enforces anything because of it. Hosts are upgraded before hubs in the
// ordinary case: a fleet's agents roll forward while its hub lags behind,
// sometimes for a while. Phase B is already documented to add fields to
// Body — ruleset hashes, the always-allow liveness result — that an
// unupgraded hub has never heard of. If Verify rejected a beat for carrying
// a field it does not recognize, the routine act of upgrading one host would
// turn into that host vanishing from the hub's view: the single worst
// outcome for a system whose entire purpose is telling an operator whether a
// host is still there. Tolerating the unknown field costs nothing but an
// ignored key; rejecting it costs the signal the whole package exists to
// carry.
package attest
