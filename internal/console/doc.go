// Package console is an optional local web console for fleet management.
//
// It runs on the operator's own machine, reads the client config and the
// fleet inventory, asks the hub what it is serving, and drives the same
// operations the CLI drives. It is a convenience over the CLI and never a
// dependency: everything reachable here is reachable with `postern open`,
// `postern confirm`, `postern status` and `postern sign` alone, and postern
// works with this package never invoked. Nothing on a host imports it,
// nothing in the SPA path imports it, and no knock passes through it.
//
// # Why the security controls here are load-bearing
//
// A local HTTP server that can act on a fleet is reachable from every
// webpage the operator has open. A browser will happily issue a cross-origin
// POST to 127.0.0.1 on behalf of any site in any tab, so an unprotected
// console turns "the operator visited a page" into "a stranger opened a gate
// on a production host". The controls below are therefore refusals in code
// rather than conventions in a document, and each one has a test built to fail
// for that control's own reason: every refusal test sends a request that
// satisfies every other control, so a passing suite cannot mean some second
// control quietly did the rejecting.
//
//   - Loopback only. ResolveBind refuses a wildcard, a hostname, and any
//     literal that is not loopback, and Listen re-checks the socket the
//     kernel actually handed back. See bind.go.
//   - Authentication on every request, read as well as write: a one-time
//     secret minted per process and printed to the operator's terminal at
//     startup, carried into the session by a HttpOnly SameSite=Strict cookie
//     the first request establishes from the token in the printed URL. This is
//     the control that keeps a local PROCESS out, not just a hostile site: the
//     process reaches loopback directly and cannot read another program's
//     cookie jar, so it never learns the secret, and the fleet map is not
//     served to it. See guard.go's authenticate.
//   - A CSRF token on every state-changing request, AND a Sec-Fetch-Site /
//     Origin check. These are same-origin write protection, not
//     authentication: the token is handed out only in a page body, and
//     same-origin policy stops a hostile SITE from reading it — but it does
//     nothing to a local process, which is why authentication above exists
//     separately. Both, never either: the header check stops a cross-origin
//     POST from a browser that never had the token, and the token is what still
//     holds for a client that sends no fetch metadata at all. See guard.go.
//   - A Host header allowlist, which is what a DNS rebinding attack has to
//     get past — it reaches 127.0.0.1 under a name the browser considers
//     same-origin, so the origin checks above do not see it. See guard.go.
//   - No GET performs an action. Every knock, confirm, status probe and
//     signing run is a POST, so a prefetch, a pasted link or a preview
//     crawler cannot open a gate. See server.go.
//
// # disarm is not here, and cannot be
//
// `disarm` removes both tables, deletes boot.nft and disables both units: it
// strips postern from a host. A CSRF hole in a console that could disarm
// would be a fleet-destruction endpoint reachable from any browser tab.
//
// This console routes no disarm, on any path, and loads no recovery key. That
// is the control, and it is a real one: the routes simply do not exist.
//
// It does not rest on a second claim that the everyday key cannot sign a
// disarm, because that claim is not true everywhere. A FLEET following
// examples/inventory.yaml splits disarm onto a separate recovery key and
// grants the everyday key only ssh, confirm and liveness, so there the key
// this console unlocks holds no disarm grant. A STANDALONE host is different:
// `init-standalone --operator` grants disarm to the everyday key by design
// (a single-box operator with no second key must keep a panic button), so on
// such a host that key can sign a disarm. The console still cannot, because it
// offers no route that would. Where it mentions disarm it prints the CLI
// command and nothing more.
//
// # The operator key
//
// The CLI prompts for the key passphrase once per invocation and drops the
// decrypted key when the process exits. This package cannot work that way —
// a web form that re-prompted per action would put the passphrase into a
// browser on every knock — so it holds the decrypted key in process memory
// for a bounded idle window instead. That is a real change in exposure and
// it is stated rather than assumed: see Keyring in keyring.go for what the
// window is, what resets it, and what the key is never allowed to touch.
//
// # What the pages can and cannot say
//
// An operator opens this console mid-outage and scans it. The pages therefore
// carry the fleet's state and nothing about why postern is built the way it
// is; the reasoning the pages used to print lives here instead.
//
//   - Liveness is this console's own measurement. internal/hub keeps the
//     latest heartbeat per host in memory and serves it on no route at all:
//     the public listener carries GET /bundle/{host_id} and POST /heartbeat,
//     and the private listener carries only aggregate metrics, where
//     known_hosts is fleet size rather than per-host freshness. What the fleet
//     page shows is what `postern status` found when the operator last ran it,
//     with the age of that reading, and the column header names whose
//     measurement it is. It is not a feed.
//   - The deploy plan is a version and membership diff, never a diff of policy
//     text. A bundle is sealed ciphertext neither the hub nor this console can
//     read, and the seal is randomised, so two seals of identical bytes do not
//     compare equal. index.json is the only account of what version is on file.
//   - The grants a host page lists come from bundle.Compile rather than from
//     the inventory entry, because the compiled policy is what the host will
//     actually run. A grant written on hosts: ["*"] never names the host it
//     reaches, so reading the inventory by hand would produce a second answer
//     to "what does this host permit", and the second answer is the wrong one.
//   - A source CIDR is the carrier-NAT mitigation. Asserting a prefix admits
//     everyone behind it for as long as the gate is open, and it works only
//     where the host was enrolled to permit one, which the grants table reports
//     per operator.
//   - A confirm takes a revision and a nonce, neither of them defaulted, for
//     the reason `postern confirm` gives: an unbound confirm ratifies whatever
//     happens to be pending when it lands. The agent prints both when it
//     prepares the transaction.
package console
