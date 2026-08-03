# postern

A break-glass door for hosts whose usual way in has failed. postern keeps a
service shut behind a default-drop firewall and opens it, for one source
address and a fixed lease, when it receives a single signed UDP datagram. One
static binary is the client, the agent, the hub, and the console; the
subcommand picks the role.

postern's packet is an ordinary single-packet authorization (SPA) knock, a
technique roughly two decades old and done first by
[fwknop](https://www.cipherdyne.org/fwknop/). What postern adds is the
operational treatment around the knock: nothing arms without a proved way back
in, a new ruleset reverts unless you confirm it, the firewall fails shut when
the daemon dies, and no control plane sits in the path of an open. Most of what
follows is about those properties rather than the cryptography.

> postern has not had an outside cryptographic review. Treat it accordingly.

## The problem it exists for

You run a mesh VPN (Tailscale, WireGuard, similar) as the primary path to your
hosts. One day the mesh node credentials expire, or the control plane is down,
and at the same moment the provider's web console is slow, half-broken, or
gated behind an account-recovery flow. Both halves of that sentence are
ordinary: mesh keys expire on a timer, and a browser console is the least
exercised path any operator owns. postern is the independent door for that
intersection.

Opening that door has no external control-plane dependency: no hub, no cloud
API, no DNS lookup in the knock path. It still relies on internet routing, the
host's network, and any statically configured provider-firewall rules;
postern does not claim to move those.

## What makes it more than a knock

- **Confirm-or-revert (dead-man).** Arming a new ruleset stages it as pending.
  If you do not confirm it within the window, the host reverts to how it was
  found. A confirm is checked against the recovery path first, so you cannot
  ratify a configuration you can no longer reach.
- **A recovery path that was proved, not just configured.** postern refuses to
  arm without an always-allow path (your mesh interface) that it has just
  proved works, with an authenticated liveness challenge plus a real connect to
  a recovery service. Expired mesh credentials leave the interface up with its
  address assigned, so a presence check passes while the path is dead; postern
  checks reachability, not presence.
- **Fail-closed in the kernel and the init system.** A boot-time ruleset drops
  the gated traffic before the network comes up, loaded by its own systemd unit
  independent of the agent. If the agent dies, its live table is torn down and
  every open gate is emptied. The thing that keeps you safe is not the daemon
  that just crashed.
- **No control plane in the knock path.** A host with a dead hub, dead DNS, and
  no cloud reachability still opens to a valid knock on its last confirmed
  configuration.
- **Continuous verification.** A break-glass path that silently rotted is worse
  than none, because it displaces the effort that would have built a real one.
  postern verifies the door from the inside (`status`, over the recovery path)
  and from the outside (`probe`, proving the gate is shut and then that a knock
  opens it).

## What crosses the wire

The knock is one UDP datagram. Inside it is a 224-byte record: a 24-byte
nonce and a 200-byte box sealed to the target host (X25519 / NaCl box) wrapping
an Ed25519-signed inner record. The service name is never sent in the clear,
only the first 16 bytes of its SHA-256. The agent trial-decrypts against each
trusted operator, verifies, checks freshness, and records the request id in a
replay store written to disk before the gate opens, so the same datagram cannot
open a door twice, even across an agent restart. Each id is kept only until its
packet is too old to pass the freshness window, then pruned.

Two properties keep a passive observer from fingerprinting the knock:

- **Variable length.** The sealed record is a constant 224 bytes, but the
  sender appends a random amount of padding (drawn per packet, bounded at 1400
  bytes so it never fragments) outside the sealed record. The datagram on the
  wire is a variable-length run of opaque bytes with no magic string and no
  version byte in the clear.
- **A rotating destination port.** By default the port is derived from a
  per-host secret and the current ten-minute time window, so there is no fixed
  port to scan for. Client and agent derive the same port independently; the
  secret never goes on the wire. The agent listens on the current window and
  each neighbor to absorb clock skew. A fixed port is available as an opt-out
  where you need one.

postern sends no reply to a knock: a valid gate request is answered only by the
port opening. The sole datagram it ever sends back is a signed liveness pong,
and only on the always-allow recovery path. See
[`docs/protocol.md`](docs/protocol.md) for the byte-level format, enough to
write an independent client.

## Two deployment modes

- **Standalone.** `postern init-standalone` writes a root-owned config with
  operator public keys and service definitions, and the agent reads it
  directly. No hub, no bundle signing, no pull loop. A complete, permanently
  supported deployment for one box.
- **Fleet.** A hub distributes per-host bundles, each signed and sealed so only
  its own host can open it, to many agents, with drift detection and aggregated
  health. The hub is an upgrade for people running fleets, never a requirement,
  and it is never in the knock path.

## Quickstart (standalone)

Requirements: the client builds on macOS or Linux; the agent is Linux, root,
with nftables and systemd. The public knock path and the always-allow recovery
path must be different networks, or postern protects nothing.

Build the binary on your laptop and each host:

```
CGO_ENABLED=0 go build -o postern ./cmd/postern
install -m 0755 postern /usr/local/bin/postern
```

Mint your operator identity once, on the laptop. It prints the two public keys
you hand to hosts:

```
postern operator init
```

Enroll and arm a host, as root. This writes the config, host identity,
fail-closed boot ruleset, and systemd units, then arms a revision that is
pending your confirmation:

```
sudo postern init-standalone \
  --host-name web-01 \
  --knock-addr 203.0.113.9 \
  --always-allow-iface tailscale0 \
  --recovery-service ssh \
  --operator you=<SIGNING_B64>,<ENCRYPTION_B64> \
  --go-live --export entry.yaml
```

Register the host with your laptop, then confirm over the recovery path within
the window (the arm step prints the exact command):

```
postern host add web-01 --from entry.yaml
postern confirm web-01 --revision 1 --nonce <HEX>
```

Open the door and connect:

```
postern open web-01 ssh
ssh you@203.0.113.9
```

The full walkthrough, including fleets, the console-recovery mode for hosts
with no mesh, disarm and recovery, and metrics, is in
[`docs/operating.md`](docs/operating.md).

## Command surface

One binary, one subcommand per role.

| Command | Role |
|---------|------|
| `operator init` | mint and manage the operator identity (laptop) |
| `host add` | register a host with the laptop |
| `init-standalone` | write a host's config, identity, boot ruleset, and units (on the host) |
| `open` | knock a host and confirm the service became reachable |
| `confirm` | ratify one armed-but-unconfirmed change |
| `status` | prove the always-allow path still works, over the recovery path |
| `probe` | prove from outside that the gate is shut and a knock opens it |
| `disarm` | panic button: remove postern's tables, delete the boot ruleset, disable the units |
| `sign` | compile a fleet inventory into sealed, signed bundles |
| `hub` | serve bundles and ingest signed heartbeats |
| `ui` | optional local web console for fleet management (loopback only) |
| `agent` | run the daemon: bind the port, validate packets, open gates (Linux, root) |
| `gate-flush` / `gate-teardown` | on-host recovery when the agent is wedged (Linux, root) |

## What postern is not

postern controls *reachability*. It is not a VPN, not an SSH certificate
authority, and not a replacement for the authentication of whatever it gates.
Everything behind the gate stays exactly as hardened as it already is. The
disarm grant is the power to strip postern off a host, so treat it as a master
key and keep it on a separate key held offline. In an emergency it is the way
back in when a fail-closed gate has locked you out, run from the host itself; see
[`docs/operating.md`](docs/operating.md) for the disarm and recovery paths.

## Documentation

- [`docs/operating.md`](docs/operating.md): set up and run postern end to end.
- [`docs/protocol.md`](docs/protocol.md): the wire format, byte for byte.

## Building and testing

```
CGO_ENABLED=0 go build -o postern ./cmd/postern
go test ./...              # client, config, and hub code; runs on macOS or Linux
./scripts/linux-test.sh    # the Linux-only agent and gate code, in a container
```

The client, hub, and console build and run on macOS and Linux. The agent and
the nftables gate code are Linux-only and are exercised through the container
harness.
