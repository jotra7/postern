package console_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/console"
	"github.com/jotra7/postern/internal/identity"
)

// testPort is the port every fixture console claims to be bound to. The guard
// builds its Host and Origin allowlists around the bound port, so tests have
// to agree on one; nothing is actually listening on it.
const testPort = 8177

var testListen = fmt.Sprintf("127.0.0.1:%d", testPort)

const testPassphrase = "correct horse battery staple"

// fixture is a console wired against generated key material, a real
// inventory file, a real client config, and network seams that record what
// was sent instead of sending it.
type fixture struct {
	Server *console.Server
	Dir    string

	// InventoryPath, BundleDir and KeyFile are the paths the console reads.
	InventoryPath string
	BundleDir     string
	KeyFile       string

	// HostName is the one host in both the inventory and the client config.
	HostName string

	sends *sendLog
}

// sendLog records every datagram a handler put on the wire. It is what makes
// "a GET cannot open a gate" an assertion about the packet rather than about
// a status code.
type sendLog struct {
	mu sync.Mutex
	to []netip.AddrPort
}

func (l *sendLog) send(_ context.Context, to netip.AddrPort, _ []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.to = append(l.to, to)
	return nil
}

func (l *sendLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.to)
}

// refusedDial stands in for the confirmation connect. A refusal is a
// definitive outcome, so client.Confirm stops after one attempt and no test
// waits on a timeout.
func refusedDial(_ context.Context, _, address string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: dummyAddr(address), Err: errConnRefused}
}

type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }

// newFixture builds a console over freshly generated identities.
func newFixture(t *testing.T, opts ...func(*console.Config)) *fixture {
	t.Helper()
	return newFixtureNamed(t, "web-01", opts...)
}

func newFixtureNamed(t *testing.T, hostName string, opts ...func(*console.Config)) *fixture {
	t.Helper()
	dir := t.TempDir()

	op, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("identity.Generate operator: %v", err)
	}
	hostID, err := identity.Generate(hostName)
	if err != nil {
		t.Fatalf("identity.Generate host: %v", err)
	}

	keyFile := filepath.Join(dir, "identity.json")
	if err := identity.SaveFile(keyFile, op, []byte(testPassphrase)); err != nil {
		t.Fatalf("identity.SaveFile: %v", err)
	}

	var hostIDBytes [16]byte
	for i := range hostIDBytes {
		hostIDBytes[i] = byte(i + 1)
	}
	hostIDHex := hex.EncodeToString(hostIDBytes[:])

	invPath := filepath.Join(dir, "inventory.yaml")
	writeFile(t, invPath, inventoryYAML(hostName, hostIDHex, op.Public(), hostID.Public()))

	cfgPath := filepath.Join(dir, "config.yaml")
	writeFile(t, cfgPath, clientConfigYAML(hostName, hostIDHex, keyFile, hostID.Public()))
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
		Dial:            refusedDial,
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
		HostName:      hostName,
		sends:         sends,
	}
}

// do executes one request against the console's handler.
func (f *fixture) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.Server.Handler().ServeHTTP(w, r)
	return w
}

// wellFormedPost builds the request a browser on this console's own page
// actually sends: the right Host, the fetch metadata a same-origin form POST
// carries, and the CSRF token from the page.
//
// Every refusal test starts from this and breaks exactly one thing, which is
// what makes the failure attributable to the control under test rather than
// to whichever other control happened to fire first.
func (f *fixture) wellFormedPost(path string, form url.Values) *http.Request {
	if form == nil {
		form = url.Values{}
	}
	// Not Set: a caller that supplied its own token is testing what happens
	// to a wrong one, and overwriting it would quietly turn that test into a
	// second copy of the happy path.
	if form.Get("csrf_token") == "" {
		form.Set("csrf_token", f.Server.Token())
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Host = testListen
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+testListen)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(f.Server.AuthCookie())
	return r
}

// wellFormedGet is the read-side equivalent. Like a browser that has already
// made its first visit with the startup token, it carries the session cookie:
// reads now require authentication too, so a request without it is refused
// before the fleet map is served.
func (f *fixture) wellFormedGet(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = testListen
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(f.Server.AuthCookie())
	return r
}

// unlock puts the operator key in the keyring the way the page does.
func (f *fixture) unlock(t *testing.T, slot string) {
	t.Helper()
	w := f.do(f.wellFormedPost("/unlock", url.Values{
		"slot":       {slot},
		"passphrase": {testPassphrase},
	}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unlock %s = %d, want 303: %s", slot, w.Code, w.Body.String())
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func b64(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

func inventoryYAML(hostName, hostIDHex string, op, host identity.PublicIdentity) string {
	return fmt.Sprintf(`fleet_id: "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"
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
  - name: %q
    host_id: "%s"
    knock_addr: 203.0.113.9
    ssh: { host: host.example.com, user: ops }
    host_identity:
      alg: ed25519+x25519
      signing:    "%s"
      encryption: "%s"
    services: [ssh]
    groups: [prod]
`, b64(op.Signing), b64(op.Encryption), hostName, hostIDHex, b64(host.Signing), b64(host.Encryption))
}

func clientConfigYAML(hostName, hostIDHex, keyFile string, host identity.PublicIdentity) string {
	return fmt.Sprintf(`operator: laptop-primary
key_file: %q
hosts:
  - name: %q
    host_id: "%s"
    knock_addr: 203.0.113.9
    knock_port: 62201
    host_encryption: "%s"
    host_signing: "%s"
    recovery_service: ssh
    ssh: { host: host.example.com, user: ops }
    services:
      ssh: { port: 22, ttl: 120s }
`, keyFile, hostName, hostIDHex, b64(host.Encryption), b64(host.Signing))
}

// errConnRefused is syscall.ECONNREFUSED, which client.Classify matches with
// errors.Is. Declared here so refusedDial stays a two-line helper.
var errConnRefused = syscall.ECONNREFUSED
