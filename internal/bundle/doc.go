// Package bundle turns a fleet inventory into what a host actually receives:
// compile.go resolves the inventory down to one host's policy, and bundle.go
// wraps that policy in the signed, sealed record the hub serves and the agent
// accepts.
//
// Resolution never invents a shape config.Policy cannot already hold. Design
// section 10 puts the agent on a single code path for both modes, so a
// compiled policy is expected to survive the same config.MarshalStandalone /
// config.ParseStandalone round trip a standalone file does.
//
// # Wire layout
//
// The signed record, all integers big-endian, no padding:
//
//	offset  size  field
//	0       15    magic "postern-bundle\0"
//	15      1     format version (1)
//	16      16    fleet_id
//	32      16    host_id
//	48      8     bundle version
//	56      8     issued_at, unix milliseconds
//	64      4     policy_len
//	68      N     policy (standalone YAML)
//	68+N    32    signer Ed25519 public key
//	100+N   64    Ed25519 signature over bytes [0, 100+N)
//
// That record is then sealed with box.SealAnonymous to the host's X25519 key,
// and the sealed form is the only thing the hub ever holds.
//
// # Sign for authenticity, seal for secrecy
//
// The two are deliberately independent. Authenticity comes from the Ed25519
// signature verified against the bundle_signers set the agent already holds;
// the seal supplies confidentiality only, which is what makes a bundle safe
// to serve over an unauthenticated fetch — a signature would give integrity
// without hiding CDN origin addresses, the SPA port, every gated port, fleet
// membership, or operator structure, the very things SPA exists to conceal.
//
// Sealing is anonymous rather than authenticated box.Seal because the
// alternative couples the two halves: authenticated sealing would require
// every agent to hold the signer's X25519 public key, baked in at enrollment,
// and would break bundle delivery fleet-wide the moment a signer rotated that
// encryption key. The SPA path stays on authenticated box.Seal for the
// opposite reason — there the sender's identity is what the precomputed
// shared secret establishes, cheaply, before any signature check runs.
//
// The cost of anonymous sealing is that the seal proves nothing about who
// produced the ciphertext: anyone who learns a host's public encryption key
// can seal something that host will open. The trusted-signer check is what
// stops that from becoming policy.
//
// # Version ordering and the enrollment floor
//
// A correctly signed bundle is still not acceptable on its own. An old
// bundle — one still naming an operator who has since been removed — carries
// a valid signature forever, so only the version ordering rejects it, and
// equal is not newer. A freshly enrolled agent holds no version to order
// against, which is why enrollment stamps a floor: without it, that same old
// bundle replays cleanly against a new host.
package bundle
