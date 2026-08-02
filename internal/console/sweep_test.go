package console_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/console"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

// The sweep button runs the liveness check against every knockable host at
// once. Its fixture therefore carries several hosts rather than the one the
// per-host fixture does, and can answer each host's liveness ping with a
// correctly signed pong — otherwise "the sweep reached every host" could not
// be told apart from "the sweep reached the one host there was".

// sweepHost is one host in a multi-host fixture: the identity that signs its
// pong, the host_id that pong carries, and the address the ping is sent to,
// which is what the fake exchange routes on.
type sweepHost struct {
	name   string
	signer identity.Signer
	hostID [16]byte
	addr   netip.Addr
}

// sweepKit answers liveness pings for a fixture's hosts. It plays the agent:
// it opens the sealed ping addressed to a host and replies with a pong that
// host's key signs, which is the only reply client.Status will call healthy.
type sweepKit struct {
	op    identity.Signer
	hosts []sweepHost
}

// exchange returns a client.Exchanger that answers each host's ping at its own
// address. A ping to an address no host owns is an error, not a silent drop:
// a sweep that reached the wrong host is a test bug worth surfacing loudly.
func (k *sweepKit) exchange(t *testing.T) client.Exchanger {
	t.Helper()
	answer := map[netip.Addr]func([]byte) ([]byte, error){}
	for _, h := range k.hosts {
		opener, _, err := spa.NewOpenerFromSigner(h.signer, []identity.PublicIdentity{k.op.Public()})
		if err != nil {
			t.Fatalf("NewOpenerFromSigner(%s): %v", h.name, err)
		}
		hostID := h.hostID
		signer := h.signer
		answer[h.addr] = func(payload []byte) ([]byte, error) {
			req, _, err := opener.TrialOpen(payload)
			if err != nil {
				return nil, err
			}
			challenge, err := req.LivenessPayload()
			if err != nil {
				return nil, err
			}
			// The timestamp is real-now rather than a fixed clock: the console
			// runs client.Status with no injected clock, so the pong has to be
			// fresh against the machine's own time for verification to pass.
			return spa.SignPong(&spa.Pong{
				Version:     spa.Version1,
				Alg:         spa.AlgEd25519X25519,
				HostID:      hostID,
				RequestID:   req.RequestID,
				Challenge:   challenge,
				TimestampMS: uint64(time.Now().UnixMilli()),
			}, signer)
		}
	}
	return func(_ context.Context, to netip.AddrPort, payload []byte, _ time.Duration) ([]byte, error) {
		a, ok := answer[to.Addr()]
		if !ok {
			return nil, fmt.Errorf("no host answering at %s", to)
		}
		return a(payload)
	}
}

// okDial makes the recovery connect succeed: client.Confirm classifies a nil
// error as Connected, and a nil conn is safe because it only closes non-nil
// ones. A host with a verified pong and a reachable recovery service is the
// only combination client.Status reports healthy.
func okDial(_ context.Context, _, _ string) (net.Conn, error) { return nil, nil }

// newSweepFixture builds a console over an inventory and a client config that
// both carry hostNames, giving each host its own identity and address. A name
// in badRecovery gets a recovery_service it does not define, which is what
// makes client.Status return an error for that one host and no other.
func newSweepFixture(t *testing.T, hostNames []string, badRecovery map[string]bool, opts ...func(*console.Config)) (*fixture, *sweepKit) {
	t.Helper()
	dir := t.TempDir()

	op, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("identity.Generate operator: %v", err)
	}
	keyFile := filepath.Join(dir, "identity.json")
	if err := identity.SaveFile(keyFile, op, []byte(testPassphrase)); err != nil {
		t.Fatalf("identity.SaveFile: %v", err)
	}

	kit := &sweepKit{op: op}
	var invHosts, cfgHosts strings.Builder
	for i, name := range hostNames {
		hostSigner, err := identity.Generate(name)
		if err != nil {
			t.Fatalf("identity.Generate host %s: %v", name, err)
		}
		var idBytes [16]byte
		for j := range idBytes {
			idBytes[j] = byte(i*16 + j + 1)
		}
		idHex := hex.EncodeToString(idBytes[:])
		addr := netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", 20+i))
		kit.hosts = append(kit.hosts, sweepHost{name: name, signer: hostSigner, hostID: idBytes, addr: addr})

		pub := hostSigner.Public()
		invHosts.WriteString(fmt.Sprintf(`  - name: %q
    host_id: "%s"
    knock_addr: %s
    ssh: { host: %s.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    "%s"
      encryption: "%s"
    services: [ssh]
    groups: [prod]
`, name, idHex, addr.String(), name, b64(pub.Signing), b64(pub.Encryption)))

		recovery := "ssh"
		if badRecovery[name] {
			// A recovery service the host entry does not define. client.Status
			// resolves it after the pong and returns that lookup's error.
			recovery = "nope"
		}
		cfgHosts.WriteString(fmt.Sprintf(`  - name: %q
    host_id: "%s"
    knock_addr: %s
    knock_port: 62201
    host_encryption: "%s"
    host_signing: "%s"
    recovery_service: %s
    ssh: { host: %s.example.com, user: ops }
    services:
      ssh: { port: 22, ttl: 120s }
`, name, idHex, addr.String(), b64(pub.Encryption), b64(pub.Signing), recovery, name))
	}

	invPath := filepath.Join(dir, "inventory.yaml")
	writeFile(t, invPath, fmt.Sprintf(`fleet_id: "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"
version: 47
bundle_signers: [laptop-primary]
operators:
  - name: laptop-primary
    alg: ed25519+x25519
    signing:    "%s"
    encryption: "%s"
    grants:
      - hosts: ["*"]
        services: ["ssh", "confirm", "liveness"]
        max_ttl: 300s
        allow_source_cidr: true
        min_ipv4_prefix: 24
        min_ipv6_prefix: 64
breakglass_services: [ssh]
services:
  ssh:      { kind: gate, proto: tcp, ports: [22], default_ttl: 120s, max_ttl: 300s, listener_expectation: present }
  confirm:  { kind: action }
  liveness: { kind: action }
defaults:
  spa_port: 62201
  always_allow_iface: tailscale0
  recovery_service: ssh
hosts:
%s`, b64(op.Public().Signing), b64(op.Public().Encryption), invHosts.String()))

	cfgPath := filepath.Join(dir, "config.yaml")
	writeFile(t, cfgPath, fmt.Sprintf(`operator: laptop-primary
key_file: %q
hosts:
%s`, keyFile, cfgHosts.String()))
	cfg, err := client.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("client.LoadConfig: %v", err)
	}

	sends := &sendLog{}
	cc := console.Config{
		Listen:          testListen,
		InventoryPath:   invPath,
		OutDir:          filepath.Join(dir, "bundles"),
		ClientConfig:    cfg,
		OperatorKeyFile: keyFile,
		SignerKeyFile:   keyFile,
		Send:            sends.send,
		Dial:            okDial,
		Exchange:        kit.exchange(t),
	}
	for _, o := range opts {
		o(&cc)
	}
	srv, err := console.New(cc)
	if err != nil {
		t.Fatalf("console.New: %v", err)
	}
	return &fixture{
		Server:        srv,
		Dir:           dir,
		InventoryPath: invPath,
		BundleDir:     cc.OutDir,
		KeyFile:       keyFile,
		HostName:      hostNames[0],
		sends:         sends,
	}, kit
}

func TestConsole_StatusSweep_ChecksEveryClientHostAndRecordsLiveness(t *testing.T) {
	f, _ := newSweepFixture(t, []string{"web-01", "web-02", "web-03"}, nil)

	// The fleet page must offer the sweep, and offer it as a real form the CSRF
	// token rides: a fetch would be refused by this console's fetch-metadata
	// guard, so the auto-refresh has to submit this form rather than call an API.
	page := f.do(f.wellFormedGet("/")).Body.String()
	if !strings.Contains(page, `action="/status-all"`) || !strings.Contains(page, "sweep liveness") {
		t.Fatalf("the fleet page carries no sweep-liveness form:\n%s", page)
	}
	if !strings.Contains(page, `id="auto-sweep"`) {
		t.Fatalf("the fleet page carries no auto-refresh opt-in:\n%s", page)
	}
	if !strings.Contains(page, `name="csrf_token" value="`+f.Server.Token()+`"`) {
		t.Fatalf("the sweep form does not carry this console's CSRF token, so a real submit would be refused:\n%s", page)
	}

	f.unlock(t, "operator")

	w := f.do(f.wellFormedPost("/status-all", url.Values{"return_to": {"/"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /status-all = %d, want 303: %s", w.Code, w.Body.String())
	}
	body := f.do(f.wellFormedGet("/")).Body.String()

	// Every host must carry a reading now. A sweep that stopped after the
	// first host would leave the rest reported as never checked, which is the
	// exact false quiet this button exists to clear.
	if strings.Contains(body, `is-mute">never checked`) {
		t.Fatalf("a host is still 'never checked' after a sweep, so it did not reach every host:\n%s", body)
	}
	if n := strings.Count(body, `is-ok">healthy`); n != 3 {
		t.Fatalf("healthy hosts after the sweep = %d, want 3:\n%s", n, body)
	}
	if !strings.Contains(body, "swept 3 hosts") || !strings.Contains(body, "3 healthy, 0 unhealthy") {
		t.Fatalf("the sweep summary is missing or wrong:\n%s", body)
	}
}

func TestConsole_StatusSweep_LockedOperatorKeyIsRefusedWithoutChecking(t *testing.T) {
	f, _ := newSweepFixture(t, []string{"web-01", "web-02", "web-03"}, nil)
	// No unlock. A sweep signs a liveness ping per host with the operator key,
	// so a locked key must refuse the whole operation before it signs anything.
	w := f.do(f.wellFormedPost("/status-all", url.Values{"return_to": {"/"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /status-all with a locked key = %d, want a 303 carrying the refusal: %s", w.Code, w.Body.String())
	}
	body := f.do(f.wellFormedGet("/")).Body.String()

	if !strings.Contains(body, "operator key") {
		t.Fatalf("the refusal does not name the locked operator key:\n%s", body)
	}
	// Nothing was measured, so every host must still read never checked. A
	// sweep that checked even one host before noticing the lock would have
	// tried to sign a ping with a key it does not hold.
	if n := strings.Count(body, `is-mute">never checked`); n != 3 {
		t.Fatalf("hosts still never checked = %d, want 3 (a locked-key sweep must record nothing):\n%s", n, body)
	}
}

func TestConsole_StatusSweep_OneHostFailureDoesNotAbortTheRest(t *testing.T) {
	// web-01 is first in config order and names a recovery_service it does not
	// define, so client.Status returns an error for it. If the sweep treated
	// that the way the per-host handler treats a status error — fail and stop —
	// the two hosts after it would never be measured.
	f, _ := newSweepFixture(t, []string{"web-01", "web-02", "web-03"}, map[string]bool{"web-01": true})
	f.unlock(t, "operator")

	w := f.do(f.wellFormedPost("/status-all", url.Values{"return_to": {"/"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /status-all = %d, want 303: %s", w.Code, w.Body.String())
	}
	body := f.do(f.wellFormedGet("/")).Body.String()

	if strings.Contains(body, `is-mute">never checked`) {
		t.Fatalf("a host after the failing one was never checked, so the failure aborted the sweep:\n%s", body)
	}
	if n := strings.Count(body, `is-ok">healthy`); n != 2 {
		t.Fatalf("healthy hosts = %d, want 2 (the two hosts whose recovery service resolves):\n%s", n, body)
	}
	if n := strings.Count(body, `is-bad">unhealthy`); n != 1 {
		t.Fatalf("unhealthy hosts = %d, want 1 (the host whose recovery service does not resolve):\n%s", n, body)
	}
	if !strings.Contains(body, "swept 3 hosts") || !strings.Contains(body, "2 healthy, 1 unhealthy") {
		t.Fatalf("the sweep summary should report the mix and still complete:\n%s", body)
	}
}
