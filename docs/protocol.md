# postern wire protocol

The reference for what goes on the wire: the SPA request datagram, the rotating
knock port it is sent to, and the one reply postern ever sends, the liveness
pong. It describes the protocol as implemented in `internal/spa` and
`internal/knockport`, precisely enough to write an independent client.

The protocol has not had an outside cryptographic review. This document is not a
substitute for one.

## Primitives

- Sealing: X25519 with `golang.org/x/crypto/nacl/box` (Curve25519, XSalsa20,
  Poly1305). The request is sealed to the target host's encryption key by the
  operator's encryption key.
- Signing: Ed25519. The request is signed by the operator's signing key; the
  pong is signed by the host's signing key.
- Hashing: SHA-256, used for service ids and for HMAC.

An operator identity is one Ed25519 signing keypair and one X25519 encryption
keypair. A host identity is the same pair. The two roles are kept disjoint: the
opener refuses any operator whose signing key equals the host's own, so an
operator-role signature can never stand in for a host-role one.

## The request datagram

The sealed record is exactly **224 bytes**. The datagram that crosses the wire
is this record followed by a random amount of padding, so the on-wire length is
not constant and cannot be fingerprinted. The sender draws the length per packet
and appends that many bytes from a CSPRNG after the record; the receiver reads
the first 224 bytes and discards the rest.

```
[ 24-byte nonce ][ 200-byte sealed box ][ 0..1176 bytes of random padding ]
```

- The 24-byte nonce is the nacl/box nonce, in the clear.
- The sealed box is `box.Seal` over the 184-byte inner record, which adds the
  16-byte Poly1305 tag: 184 + 16 = 200.
- The padding is outside the sealed record. It carries no meaning, is not signed
  or authenticated, and is never parsed, allocated against, or logged: an on-path
  attacker who strips or rewrites it changes nothing, because the 224-byte record
  is still sealed and signed.

The padding length is drawn with a nested uniform draw so no single maximum piles
up at a visible edge: a per-packet ceiling `C = 224 + U[0, 1400-224]`, then a
total length `L = 224 + U[0, C-224]`, appending `L-224` random bytes. `L == 224`
(no padding) is a legal outcome and is not special. The datagram is bounded at
**1400 bytes** (`MaxDatagram`), which keeps it plus a 28-byte IPv4/UDP header
under a 1500-byte MTU so a padded packet never fragments; fragmentation is its
own tell. A receiver accepts a datagram in `[224, 1400]` and rejects anything
shorter or longer in silence, the same as any malformed input.

Nothing outside the nonce is in the clear, and the random padding is
indistinguishable from the sealed ciphertext ahead of it, so the whole datagram
is high-entropy end to end. There is no magic string and no version byte on the
wire; the version lives inside the box. A passive observer sees a
variable-length run of opaque bytes to a UDP port.

### The inner record

The 184-byte inner record is a 120-byte signed region followed by a 64-byte
Ed25519 signature. All integers are big-endian.

| Field | Offset | Size | Notes |
|-------|-------:|-----:|-------|
| Version | 0 | 1 | `1` |
| Alg | 1 | 1 | `1` = Ed25519 + X25519 |
| Kind | 2 | 1 | `1` gate, `2` action |
| Reserved | 3 | 1 | must be 0 |
| KeyID | 4 | 16 | operator key id |
| HostID | 20 | 16 | target host id |
| RequestID | 36 | 16 | per-request id, the replay key |
| Counter | 52 | 8 | replay counter (gate only) |
| TimestampMS | 60 | 8 | milliseconds since epoch |
| ServiceID | 68 | 16 | first 16 bytes of SHA-256 of the service name |
| TTLSeconds | 84 | 2 | requested gate lease, in seconds |
| Payload | 86 | 32 | union, keyed by Kind and service |
| Reserved | 118 | 2 | must be 0 |
| Signature | 120 | 64 | Ed25519 |

The service name is not sent in the clear. `ServiceID` is the first 16 bytes of
SHA-256 of the name, so a captured packet does not reveal which service was
knocked. For an **action** record (confirm, disarm, liveness), `Counter` and
`TTLSeconds` are both zero: an action carries no lease.

### The payload union

The 32-byte payload is interpreted by `Kind` and, for actions, by the resolved
service.

- **Gate.** Byte 0 is the source kind. `0` (observed): the rest is zero and the
  agent gates the source address it saw the datagram arrive from. `1` (asserted):
  byte 1 is the address family (`4` or `6`), byte 2 is the prefix length, and the
  remaining bytes hold the masked network address. Host bits must be zero and the
  prefix canonical. This is the `--source-cidr` assertion, for a carrier NAT that
  egresses UDP and TCP from different addresses.
- **Confirm action.** Bytes 0:8 are the pending revision (big-endian), bytes 8:24
  are the 16-byte deployment nonce the agent reported, bytes 24:32 are reserved.
- **Disarm action.** All 32 bytes zero.
- **Liveness action.** Bytes 0:16 are a fresh 16-byte challenge nonce, bytes
  16:32 reserved.

### Signing

The signature is Ed25519 over `RequestDomain || signed-region`, where the signed
region is the first 120 bytes of the inner record and

```
RequestDomain = "postern-spa-request\x00"
```

The domain tag is never transmitted; the verifier prepends it. It keeps a
signature over a request from ever validating as any other postern record type.
The domains for the request, the pong, the bundle, and the attestation are
mutually non-prefix, which a test enforces.

### Validation order

Every datagram is attacker-controlled input the agent handles as root, so it runs
the cheapest checks first and reveals nothing on any rejection.

1. **Length.** Outside `[224, 1400]`: drop. Within it, the first 224 bytes are
   the record and any trailing padding is discarded.
2. **Trial-decrypt.** Try `box.Open` against each trusted operator's precomputed
   shared secret. Each attempt is a Poly1305 verify, not a fresh scalar
   multiply. A Poly1305 failure is indistinguishable from random bytes, a
   forgery, or a corrupted tag, and moves on to the next operator. No operator
   opens it: reject, with one sentinel error for every such case.
3. **Parse.** Structure and canonical encoding, including the zero reserved
   bytes and, for actions, that the counter and TTL are zero. No crypto here.
4. **Key id.** The `KeyID` in the record must match the operator whose key
   opened the box. This stops an operator forging audit attribution to another.
5. **Signature.** Ed25519, verified last because it is the most expensive check.

Only after the box opens does the agent check the host id, so a datagram
captured on its way to one host is useless against any other. It then rejects a
timestamp outside the freshness window, looks up the service, checks the operator
holds a grant for it, and records the request id in the replay store before it
acts. That record is written once, and only for a packet that passed every check
above, so the same datagram cannot be used twice. The store is a file on disk,
and the record is committed before the gate opens, so a restart or a crash
between recording and acting does not reopen the window. An entry is retained
until its packet is too old to pass the freshness check and then pruned, never
sooner, since evicting it early would let the timestamp path accept the very
datagram the record exists to refuse.

### No reply

A rejected request produces no datagram. A valid gate request is answered only by
the port opening; a valid confirm or disarm produces no datagram either. The
liveness pong is the sole exception, and it is sent only on the always-allow
path.

## The rotating knock port

By default the UDP port a request is sent to is not fixed. It is derived from a
per-host secret and the current time window, so a network observer cannot find or
predict where to scan. Client and agent derive the same port independently; the
secret never goes on the wire.

### Derivation

Let `K` be the host's 32-byte rotation secret, `[lo, hi]` the inclusive port
range, and `period` the window length. For window number `w`:

```
window(t) = floor( unixSeconds(t) / windowSeconds )
port(w)   = lo + ( uint32( HMAC_SHA256(K, be64(w))[0:4] ) mod (hi - lo + 1) )
```

- `be64(w)` is `w` as 8 big-endian bytes.
- `HMAC_SHA256(K, be64(w))[0:4]` is the first four bytes of the HMAC, read as a
  big-endian uint32.
- The result is reduced modulo the inclusive span `hi - lo + 1` and offset by
  `lo`, so it always lands in `[lo, hi]`.

Defaults: `period` is 600 seconds (ten minutes), and the range is 20000-30000.
The range sits below the kernel ephemeral range (32768-60999) so a fixed bind
never collides with a kernel-assigned outbound source port. The secret is 32
bytes, generated per host at enrollment.

### Windows and skew

The client sends **one** datagram, to `port(w)` for its own current window `w`.
The agent listens on three ports at once: `port(w-1)`, `port(w)`, and
`port(w+1)`, the current window plus each neighbor, deduplicated when two windows
happen to derive the same port. (At window 0 the `w-1` neighbor is omitted to
avoid a uint64 wrap.)

The neighbor windows absorb clock skew and window boundaries: a client up to
about one window out of step with the agent still lands on a port the agent is
listening on. Because the knock gets no reply, nothing corrects a larger skew, so
a rotation host should run NTP. A knock past the tolerance simply misses, in
silence, like any other rejected packet.

## The liveness pong

The pong is the only reply postern ever sends. The agent sends it in response to
a liveness request, and only when that request arrived on the always-allow path;
the binding is checked both where the request is validated and again at the pong
site, since that is the single place postern puts bytes on the wire.

The pong is **signed, not sealed**. The path is already trusted and the pong
carries no secret, so it is Ed25519 over `PongDomain || signed-region`, signed
with the host's signing key (the same key that signs health heartbeats), where

```
PongDomain = "postern-spa-pong\x00"
```

### Pong layout

The pong record is **122 bytes**: a 58-byte signed region and a 64-byte
signature. All integers are big-endian. Like the request, it is padded to a
random length before it goes on the wire, bounded at the same 1400 bytes, so it
is not a second constant size to fingerprint. The client accepts a reply in
`[122, 1400]`, reads the first 122 bytes as the record, and discards the rest.

| Field | Offset | Size | Notes |
|-------|-------:|-----:|-------|
| Version | 0 | 1 | `1` |
| Alg | 1 | 1 | `1` |
| HostID | 2 | 16 | the responding host |
| RequestID | 18 | 16 | echoed from the liveness request |
| Challenge | 34 | 16 | echoed from the request payload |
| TimestampMS | 50 | 8 | milliseconds since epoch |
| Signature | 58 | 64 | Ed25519, host signing key |

### Verification

The client checks, in constant time, that `HostID`, `RequestID`, and `Challenge`
all match what it sent, that the timestamp is within its freshness window, and
that the Ed25519 signature verifies against the host's signing key. Echoing both
the request id and the challenge closes the replay hole: either one alone would
let a captured pong answer a later ping.
