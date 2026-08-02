# Operating postern

How to set up and run postern, end to end. For what it is and the threat it
addresses, see the README. For the wire format, see `docs/protocol.md`.

## Prerequisites

- One static binary (`CGO_ENABLED=0`). It is the client, the agent, the hub, and
  the console; the subcommand selects the role.
- Client: macOS or Linux. Agent: Linux, root, nftables, systemd. Hub: anywhere.
- The public knock path and the always-allow recovery path (your mesh VPN) must
  be different networks. If they are the same network, postern protects nothing.
- postern manages nftables and expects to be the input firewall authority; a host
  also running a default-deny firewall such as UFW must let the rotation range
  (and the HTTP carrier port, if used) reach postern, or the knocks are dropped
  before they arrive.

## 1. Install

Laptop and each host:

```
CGO_ENABLED=0 go build -o postern ./cmd/postern    # or fetch a release binary
install -m 0755 postern /usr/local/bin/postern
```

## 2. Mint your operator identity (laptop, once)

```
postern operator init
```

Writes `identity.json` (signing and encryption keys), passphrase-protected, under
your user config directory. Guard it like an SSH private key. It prints the two
public keys you give to hosts. Use `--operator NAME` to label it.

## 3. Standalone host (one box)

### 3a. Enroll and arm, on the host, as root

```
sudo postern init-standalone \
  --host-name web-01 \
  --knock-addr 203.0.113.9 \
  --always-allow-iface tailscale0 \
  --recovery-service ssh \
  --operator you=<SIGNING_B64>,<ENCRYPTION_B64> \
  --go-live --export entry.yaml
```

Writes the config, host identity, `boot.nft`, both systemd units, and a flush
drop-in under `/etc/postern`. `--export` captures the host's public entry for step
3b. Key flags:

- `--knock-addr` is an IP literal, not a hostname (postern resolves no names).
- `--always-allow-iface` is your mesh interface, the recovery path. postern
  refuses to arm without a recovery path.
- `--recovery-service` is what arm-time liveness and `status` connect to over the
  always-allow path (default `ssh`).
- `--operator NAME=SIGNING_B64,ENCRYPTION_B64` names an operator and its two
  public keys; repeatable. Append `:svc,svc` to scope it to services.
- `--disarm-operator` puts disarm on a separate key (see 8).
- `--allow-source-cidr NAME`, with `--min-ipv4-prefix` / `--min-ipv6-prefix`,
  lets a named operator assert a source prefix, with a floor on its width.
- `--metrics-listen ADDR` serves Prometheus metrics (loopback or the always-allow
  interface; a wildcard is refused).
- `--go-live` arms the host in this same command and prints the confirm line.
  Without it, the units stage disabled and nothing arms, which is what you want
  when imaging a host to arm later.

Rotation is on by default: the knock port is derived from a per-host secret and
the current time, not fixed. `--port-range LO-HI` sets the band it draws from
(default 20000-30000, below the kernel ephemeral range). `--no-port-rotation`
opts out and binds the fixed `--spa-port` instead (default 62201); use it only
where a fixed port is required. Run NTP on a rotation host: the knock gets no
reply to correct clock skew, and the neighbor-window overlap tolerates only about
one window (ten minutes by default). Past that a knock misses in silence, and the
always-allow path is the backstop.

`--go-live` prints:

```
armed revision 1, pending confirmation.
  postern confirm web-01 --revision 1 --nonce <HEX>
```

### 3b. Register the host with your laptop

Copy `entry.yaml` from the host to the laptop, then:

```
postern host add web-01 --from entry.yaml
```

### 3c. Confirm

Run the confirm command `--go-live` printed, from your laptop, over the
always-allow path:

```
postern confirm web-01 --revision 1 --nonce <HEX>
```

`confirm` runs the same liveness check as `status` and refuses on a dead path,
because confirming a configuration you cannot reach would lock you out.
`--force` skips the pre-check when you are confirming from somewhere the recovery
path does not reach; the dead-man timer still runs, so a confirm that never lands
still reverts the host. A confirm is one UDP datagram and UDP does not guarantee
delivery, so `confirm` sends several copies by default (`--sends`); the agent
refuses a duplicate as a replay, so extra copies cost nothing and a lost one
costs a revert. If you miss the window, the host reverts to as-found, and
starting the agent again will not re-arm the reverted revision.

### 3d. Console-recovery (no mesh)

A host with no mesh interface can still arm. Pass `--console-recovery` with an
out-of-band console URL in place of `--always-allow-iface`:

```
sudo postern init-standalone \
  --host-name web-01 \
  --knock-addr 203.0.113.9 \
  --console-recovery https://provider.example/console \
  --operator you=<SIGNING_B64>,<ENCRYPTION_B64> \
  --go-live --export entry.yaml
```

postern arms with no always-allow path, accepting that it cannot verify a way
back in before arming. A fail-closed service is then reachable only through the
console. `status` and `probe` do not work, because both check remote health over
the always-allow path and there is none. Recovery is the provider console plus
`postern disarm --local` on the host. Register and confirm exactly as in 3b and
3c.

## 4. Fleet (many hosts, a hub)

Hosts pull sealed bundles from a hub instead of trusting a local operator list.

### 4a. Write the inventory

One YAML file lists hosts, services, operators and grants, and fleet-wide
`defaults`. See `examples/inventory.yaml` for a worked one. Rotation is the fleet
default: `defaults.port_rotation` sets the `window` and `range` every host
inherits, but each host's secret is generated per host at enrollment, never
shared, so the fleet never presents the same port at the same instant. A host
that needs a fixed port sets `port_rotation: disabled` and its own `spa_port`,
the same as any other per-host override:

```
defaults:
  port_rotation: { window: 600s, range: 20000-30000 }
  spa_port: 62201
  always_allow_iface: tailscale0
  recovery_service: ssh

hosts:
  - name: web-01
    port_rotation: disabled
    spa_port: 62210
```

### 4b. Sign it (laptop)

```
postern sign --inventory inventory.yaml --out ./bundles --key-file identity.json
```

Writes one `<host_id>.bundle` per host plus `index.json`, each signed by the
inventory's bundle signer and sealed so only its own host can open it. Sign as a
particular operator with `--as NAME`, or re-sign a single host with `--host
NAME`. A signer holds fleet-wide authority: keep the signing key off the everyday
laptop if the recovery-key split is to mean anything.

### 4c. Serve them (hub host)

```
postern hub --store ./bundles --addr :8080 --metrics-addr 127.0.0.1:9099
```

`--addr` is the public listener hosts pull bundles from and post heartbeats to.
`--metrics-addr` is a separate private listener for Prometheus metrics and
per-host heartbeat freshness (at `/beats`); it must not equal `--addr`, and
belongs on loopback or a management network. Add `--tls-cert` / `--tls-key` for
TLS on the public listener. The hub is never in the knock path; a host with a
dead hub keeps serving knocks on its last confirmed config.

### 4d. Enroll each host

Run `init-standalone` as in 3a but without `--go-live`, adding:

```
  --hub-url http://hub.internal:8080 \
  --bundle-signers <SIGNER_SIGNING_KEY_HEX> \
  --fleet-id <FLEET_ID> \
  --enrollment-floor <VERSION>
```

`--bundle-signers` is the raw Ed25519 public key whose bundle signatures this
host accepts. `--fleet-id` joins an existing fleet (an empty one mints a fresh
fleet, which is wrong for the second host of a fleet). `--enrollment-floor` is the
lowest bundle version this host will ever accept, so an old but validly-signed
bundle cannot replay against a freshly enrolled host. Then start the agent:

```
systemctl start posternd.service
```

The agent pulls its bundle, arms it, and logs the confirm command. Confirm as in
3c.

### 4e. Deploy a change

Bump the inventory `version`, re-sign (4b). Each agent pulls, arms, and waits for
a confirm, as at first arm. A bundle at the same version or older is refused as a
replay.

## 5. The two systemd units

`init-standalone` writes both; the arm step enables them, you do not.

- **postern-boot.service** loads `boot.nft` (the fail-closed drops) before the
  network comes up, independent of the agent, so a host with a dead agent stays
  shut across a reboot. `boot.nft` is an enrollment artifact the agent reads to
  arm: leave it in place.
- **posternd.service** is the agent: it binds the SPA port, holds `agent_up`, and
  opens gates. On any exit it deletes its live table and, through the drop-in it
  keeps current, empties every gate grant.

```
systemctl status posternd.service
journalctl -u posternd.service -f
```

## 6. Open a door

```
postern open web-01 ssh
ssh you@203.0.113.9
```

`open` knocks, then checks the service became reachable and warns if it was
already open. With no service named it opens the host's recovery service.

- `--ttl 5m` holds the gate open (default: the host's configured default; the
  agent clamps to the service and grant maximums).
- `--source-cidr 203.0.113.0/24` admits a whole prefix instead of the one source
  address the agent sees, for a carrier NAT that egresses your UDP and TCP from
  different addresses. The host must permit the prefix.
- `--carrier http` sends the same signed packet as an HTTP POST to the host's
  `spa_http_port`, for a network that blocks outbound UDP. The carrier's port is
  fixed, not rotated. The host must run the HTTP carrier, and there is no
  automatic fallback: you name the carrier, so a broken UDP path shows here rather
  than being masked.

## 7. Check the door works

```
postern status web-01           # ask the agent, over the recovery path
postern probe web-01 --once     # from outside: prove it is shut, then knock
```

`status` proves the always-allow path still works: it runs an authenticated
liveness challenge and a recovery-service connect over that path, the same check
`confirm` runs before it ratifies. `probe` confirms the gate is shut, knocks, and
confirms it opened; `--once` returns the verdict as its exit code, and without it
`probe` runs on a schedule and can POST each result to a `--webhook`. Run both: if
the agent reports healthy and the probe cannot get in, the knock path is broken
while your recovery path still works.

## 8. Disarm and recover

```
postern disarm web-01           # from your laptop, over the knock path
postern disarm --local          # on the host itself, as root
```

Both remove postern's two nftables tables, delete `boot.nft`, and disable both
units. `postern disarm web-01` sends a signed packet and so needs a live agent,
which rules it out when a fail-closed gate is what shut you out. `postern disarm
--local`, run on the host over the mesh or a provider console, always works.

Disarming needs a disarm grant, and that grant is the power to strip postern off a
host, so treat it as a master key. Hold it on a separate key kept offline, apart
from the key you knock with day to day; `postern init-standalone
--disarm-operator` sets that up on a standalone host, and on a fleet the inventory
splits it (see `examples/inventory.yaml`).

If the agent is wedged and you are on the host as root:

```
postern gate-teardown           # remove the agent's table and empty gate grants
postern gate-flush              # empty gate grants, leave the drop rules standing
```

## 9. The console (optional)

```
postern ui
```

Loopback only, with no flag to bind it elsewhere: it holds an unlocked operator
key and can knock every host in the fleet, and there is no authentication in
front of it. It authenticates each request with a one-time secret it places in
the URL it opens, and holds no key until you unlock one on the page. It shows each
host's signed version, what the hub serves, and the compiled grants; it can knock,
confirm, run a liveness check, and sign bundles. It cannot disarm. Reach it from
elsewhere by forwarding its port over SSH. Flags: `--listen`, `--inventory`,
`--bundles`, `--hub`, `--sign-key`.

## 10. Metrics

- Agent: `--metrics-listen ADDR` (loopback or the always-allow interface; a
  wildcard is refused, since the endpoint publishes a root daemon's gate state).
  Exposes `agent_up`, per-service armed state, the pending transaction, and the
  applied bundle version.
- Hub: `--metrics-addr ADDR` (private). Exposes distinct hosts that have beaten
  since the hub started, and per-host heartbeat freshness.
- Probe: `--metrics-listen ADDR` on `postern probe`. The probe runs off-host, so
  it is a second scrape target: the agent reports its own health, and the probe
  reports whether the knock path actually opens.
