package client_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/knockport"
)

const minimalConfig = `
operator: laptop-primary
hosts:
  - name: web-01
    host_id: 3a713a713a713a713a713a713a713a71
    knock_addr: 203.0.113.9
    host_encryption: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    services:
      ssh: { port: 22 }
`

// The knock address is the one field in this file that must not be a name.
// This runs when the operator is locked out, and a resolver is one of the
// things that may be down with everything else; on a CDN-fronted host the
// name resolves to an edge rather than to the origin the gate protects.
//
// Mutation verified: accepting a hostname (falling back to a net.Resolver
// lookup) fails this test.
func TestClient_ParseConfig_RefusesAKnockAddrThatIsNotAnIPLiteral(t *testing.T) {
	bad := strings.Replace(minimalConfig, "knock_addr: 203.0.113.9", "knock_addr: web-01.example.com", 1)
	_, err := client.ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("a hostname was accepted as knock_addr; an emergency open would depend on DNS")
	}
	if !strings.Contains(err.Error(), "resolves no names") {
		t.Fatalf("the error does not explain why a name is refused: %v", err)
	}
}

// Renaming a key no longer fails via unknown-field rejection — ParseConfig
// deliberately does not do that anymore, see
// TestClient_ParseConfig_IgnoresUnknownHostFields below. But knock_addr is
// still required, so a typo'd "knock_addres:" leaves the real knock_addr
// unset and validateHost's own required-field check catches it. This pins
// that fallback in place: the safety net for a misspelled required field is
// now "the field is missing", not "the field is unknown", and the error
// must say so.
func TestClient_ParseConfig_MisspelledRequiredFieldStillFailsAsMissing(t *testing.T) {
	bad := strings.Replace(minimalConfig, "knock_addr:", "knock_addres:", 1)
	_, err := client.ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("a config with knock_addr renamed away by a typo parsed cleanly; the host would be knocked at the zero address")
	}
	if !strings.Contains(err.Error(), "no knock_addr") {
		t.Fatalf("ParseConfig() = %v, want it to name the missing knock_addr, not an unknown-field rejection", err)
	}
}

// A client binary older than the host that enrolled it must still be able to
// knock. This is the M1 bug, verbatim: a host enrolled by a newer postern
// wrote a field into the client's copy of its entry.yaml that an older
// client refused outright, with `field ... not found in type client.Host`.
// The whole product is the ability to get in on the day everything else is
// stale, so an unknown key in derived data is ignored rather than fatal.
func TestClient_ParseConfig_IgnoresUnknownHostFields(t *testing.T) {
	data := strings.Replace(minimalConfig, "knock_addr: 203.0.113.9",
		"knock_addr: 203.0.113.9\n    a_field_from_a_later_version: true", 1)
	cfg, err := client.ParseConfig([]byte(data))
	if err != nil {
		t.Fatalf("ParseConfig with an unknown host field: %v", err)
	}
	if _, err := cfg.Host("web-01"); err != nil {
		t.Fatalf("host web-01: %v", err)
	}
}

func TestClient_ParseConfig_RejectsAServiceWithNoPort(t *testing.T) {
	bad := strings.Replace(minimalConfig, "ssh: { port: 22 }", "ssh: {}", 1)
	if _, err := client.ParseConfig([]byte(bad)); err == nil {
		t.Fatal("a service with no port was accepted; the confirmation connect would dial port 0")
	}
}

// A host entry carrying port_rotation decodes to Host.PortRotation with the
// 32-byte secret, the window, and the range; a bad secret length is refused
// by validateHost rather than silently truncated or padded.
func TestClient_Config_ParsesThePortRotationBlock(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(rotationSecret())
	data := strings.Replace(minimalConfig, "knock_addr: 203.0.113.9",
		"knock_addr: 203.0.113.9\n    port_rotation:\n      secret: "+secret+
			"\n      window: 10m\n      range: 20000-30000", 1)
	cfg, err := client.ParseConfig([]byte(data))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if h.PortRotation == nil {
		t.Fatal("port_rotation block did not decode into Host.PortRotation")
	}
	if !bytes.Equal(h.PortRotation.Secret, rotationSecret()) {
		t.Fatal("the decoded secret does not match the configured value")
	}
	if h.PortRotation.Window != 10*time.Minute {
		t.Fatalf("window = %s, want 10m", h.PortRotation.Window)
	}
	if h.PortRotation.RangeLo != 20000 || h.PortRotation.RangeHi != 30000 {
		t.Fatalf("range = %d-%d, want 20000-30000", h.PortRotation.RangeLo, h.PortRotation.RangeHi)
	}

	badSecret := base64.StdEncoding.EncodeToString(rotationSecret()[:knockport.SecretSize-1])
	bad := strings.Replace(minimalConfig, "knock_addr: 203.0.113.9",
		"knock_addr: 203.0.113.9\n    port_rotation:\n      secret: "+badSecret+
			"\n      window: 10m\n      range: 20000-30000", 1)
	if _, err := client.ParseConfig([]byte(bad)); err == nil {
		t.Fatal("a port_rotation secret of the wrong length was accepted")
	}
}

func TestClient_ParseConfig_ReportsEveryProblemAtOnce(t *testing.T) {
	bad := `
operator: ""
hosts:
  - name: web-01
    host_id: "not-hex"
    knock_addr: nope
    host_encryption: "!!!"
    services: {}
`
	_, err := client.ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("an invalid config parsed cleanly")
	}
	for _, want := range []string{"operator", "host_id", "knock_addr", "host_encryption", "services"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not mention %q, so an operator fixes one field per run:\n%v", want, err)
		}
	}
}

func TestClient_ParseConfig_DefaultsTheKnockPortToTheDocumentedSPAPort(t *testing.T) {
	cfg, err := client.ParseConfig([]byte(minimalConfig))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if got := h.KnockAddrPort().String(); got != "203.0.113.9:62201" {
		t.Fatalf("knock address = %s, want the default SPA port", got)
	}
}

// always_allow_addr answers a question knock_addr cannot: `open` knocks the
// public address and `status` has to reach the always-allow one, and on a host
// reached over a mesh those are two addresses.
func TestClient_ParseConfig_ReadsTheAlwaysAllowAddress(t *testing.T) {
	data := strings.Replace(minimalConfig,
		"knock_addr: 203.0.113.9", "knock_addr: 203.0.113.9\n    always_allow_addr: 198.51.100.4", 1)
	cfg, err := client.ParseConfig([]byte(data))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if got := h.StatusAddr().String(); got != "198.51.100.4" {
		t.Errorf("StatusAddr() = %s, want the recorded always-allow address 198.51.100.4", got)
	}
	if got := h.KnockAddrPort().String(); got != "203.0.113.9:62201" {
		t.Errorf("KnockAddrPort() = %s, want the public address; always_allow_addr must not move the knock", got)
	}
}

// The entry every operator enrolled before this field existed is holding.
// Refusing it, or leaving StatusAddr invalid, would turn a client that could
// still check its hosts into one that could not.
func TestClient_ParseConfig_StatusAddrFallsBackToKnockAddrWhenTheEntryHasNone(t *testing.T) {
	cfg, err := client.ParseConfig([]byte(minimalConfig))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if got := h.StatusAddr().String(); got != "203.0.113.9" {
		t.Fatalf("StatusAddr() = %s, want the knock address as the fallback", got)
	}
}

// Refused for knock_addr's reason and one more: `status` is what answers
// whether the always-allow path still carries anyone, so a resolver on it
// could report success about an address the host no longer holds.
func TestClient_ParseConfig_RefusesAnAlwaysAllowAddrThatIsNotAnIPLiteral(t *testing.T) {
	data := strings.Replace(minimalConfig,
		"knock_addr: 203.0.113.9", "knock_addr: 203.0.113.9\n    always_allow_addr: web-01.mesh", 1)
	_, err := client.ParseConfig([]byte(data))
	if err == nil {
		t.Fatal("a hostname was accepted as always_allow_addr")
	}
	if !strings.Contains(err.Error(), "always_allow_addr") {
		t.Fatalf("the error does not name the field an operator has to fix: %v", err)
	}
}

// Relative paths anchor against the config file's own directory, so a whole
// postern directory can be moved or synced as a unit — and, more to the
// point here, so nothing in this package hardcodes ~/.config/postern.
func TestClient_LoadConfig_AnchorsRelativePathsAgainstTheConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := minimalConfig + "key_file: keys/identity.json\ncounter_file: state/counter.json\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := client.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if want := filepath.Join(dir, "keys", "identity.json"); cfg.KeyFilePath() != want {
		t.Fatalf("KeyFilePath = %q, want %q", cfg.KeyFilePath(), want)
	}
	if want := filepath.Join(dir, "state", "counter.json"); cfg.CounterFilePath() != want {
		t.Fatalf("CounterFilePath = %q, want %q", cfg.CounterFilePath(), want)
	}
}

func TestClient_LoadConfig_LeavesAbsolutePathsAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := minimalConfig + "key_file: /etc/postern/operator.json\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := client.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.KeyFilePath() != "/etc/postern/operator.json" {
		t.Fatalf("KeyFilePath = %q", cfg.KeyFilePath())
	}
}
