package client_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/jotra7/postern/internal/client"
)

// refusingDialer stands in for a gate that did not open. These tests are
// about which carrier the knock left by, so the confirmation connect is
// deliberately a failure with no network in it.
func refusingDialer(context.Context, string, string) (net.Conn, error) {
	return nil, io.ErrUnexpectedEOF
}

// carrierHost is testHost plus a knock_http_port, so the two host entries
// differ in exactly the field under test.
func carrierHost(t *testing.T, httpPort string) *client.Host {
	t.Helper()
	// Real keys: a fixed-byte array is a low-order X25519 point, which Seal
	// refuses, and Open seals before it sends.
	hostID := mustGenerate(t, "web-01").Public()
	enc, sign := hostID.Encryption, hostID.Signing
	yaml := "" +
		"operator: laptop-primary\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: " + hex.EncodeToString(bytes16(0x3a)) + "\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		httpPort +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(enc[:]) + "\n" +
		"    host_signing: " + base64.StdEncoding.EncodeToString(sign[:]) + "\n" +
		"    recovery_service: ssh\n" +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n"
	cfg, err := client.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

func TestClient_ParseCarrier_AcceptsTheTwoCarriersAndRefusesTherest(t *testing.T) {
	for in, want := range map[string]client.Carrier{
		"":     client.CarrierUDP,
		"udp":  client.CarrierUDP,
		"http": client.CarrierHTTP,
	} {
		got, err := client.ParseCarrier(in)
		if err != nil {
			t.Errorf("ParseCarrier(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseCarrier(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"https", "tcp", "UDP", "dns"} {
		if _, err := client.ParseCarrier(in); err == nil {
			t.Errorf("ParseCarrier(%q) was accepted", in)
		}
	}
}

// A carrier the host entry cannot address is a refusal, not a guess.
//
// There is no well-known port to fall back on, and a knock sent to a guessed
// port produces silence — which on the SPA path is indistinguishable from a
// knock that arrived and was rejected, from a dead agent, and from a blocked
// network. During an outage that difference is the whole diagnosis.
func TestClient_CarrierAddrPort_RefusesHTTPWhenTheHostEntryNamesNoPort(t *testing.T) {
	h := carrierHost(t, "")

	if _, err := h.CarrierAddrPort(client.CarrierHTTP); err == nil {
		t.Fatal("an http knock was addressed against a host entry with no knock_http_port")
	}
	// The UDP carrier is unaffected, so the refusal above is attributable to
	// the missing port rather than to a host entry that addresses nothing.
	udp, err := h.CarrierAddrPort(client.CarrierUDP)
	if err != nil {
		t.Fatalf("the udp carrier was refused too: %v", err)
	}
	if udp.Port() != 62201 {
		t.Fatalf("udp knock port = %d, want the entry's knock_port", udp.Port())
	}
}

// The two carriers address the same host on different ports, and the HTTP one
// comes from knock_http_port rather than from knock_port — a carrier that
// reused the SPA port would knock a UDP socket over TCP and be silent forever.
func TestClient_CarrierAddrPort_UsesTheCarriersOwnPort(t *testing.T) {
	h := carrierHost(t, "    knock_http_port: 62443\n")

	got, err := h.CarrierAddrPort(client.CarrierHTTP)
	if err != nil {
		t.Fatalf("CarrierAddrPort: %v", err)
	}
	if got.Port() != 62443 {
		t.Fatalf("http knock port = %d, want 62443", got.Port())
	}
	if got.Addr().String() != "203.0.113.9" {
		t.Fatalf("http knock addr = %s, want the entry's knock_addr", got.Addr())
	}
}

// HTTPSend puts the sealed datagram in the body unchanged. The packet does not
// change between carriers — same bytes, same signature, same seal — so
// anything this function added, wrapped, or encoded would be a second wire
// format for one payload.
func TestClient_HTTPSend_PutsTheDatagramInTheBodyUnchanged(t *testing.T) {
	var mu sync.Mutex
	var gotBody []byte
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody, gotMethod = body, r.Method
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	payload := bytes.Repeat([]byte{0xAB}, 224)
	to := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	if err := client.HTTPSend(context.Background(), to, payload); err != nil {
		t.Fatalf("HTTPSend: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Errorf("body is %d bytes and does not match the datagram; the carrier must not transform the packet",
			len(gotBody))
	}
}

// The agent answers every request identically on purpose, so a status code
// carries no information about whether the knock was valid. Treating one as
// failure would invent a signal the protocol does not have — and would report
// a knock that in fact landed as a knock that did not.
func TestClient_HTTPSend_DoesNotTreatAnyStatusAsFailure(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK, http.StatusBadRequest,
		http.StatusForbidden, http.StatusInternalServerError, http.StatusTeapot} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		to := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
		err := client.HTTPSend(context.Background(), to, []byte("knock"))
		srv.Close()
		if err != nil {
			t.Errorf("HTTPSend reported failure on a %d response: %v", status, err)
		}
	}
}

// A transport failure is still a failure, so the rule above is not "never
// report anything". Nothing is listening on this port.
func TestClient_HTTPSend_ReportsATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	to := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	srv.Close() // and now nothing is there

	if err := client.HTTPSend(context.Background(), to, []byte("knock")); err == nil {
		t.Fatal("HTTPSend reported success against a closed port")
	}
}

// The knock is not steerable by the thing it is knocking. A redirect must not
// send a packet addressed and sealed to this host anywhere else.
func TestClient_HTTPSend_DoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	elsewhere := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		elsewhere++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	to := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	if err := client.HTTPSend(context.Background(), to, []byte("knock")); err != nil {
		t.Fatalf("HTTPSend: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if elsewhere != 0 {
		t.Fatalf("the knock followed a redirect and was delivered elsewhere %d time(s)", elsewhere)
	}
}

// Open sends over the carrier it was asked for, to that carrier's port, and
// does not fall back to the other one. The absence of a fallback is a
// deliberate design decision (see OpenOptions.Carrier), so it is asserted
// rather than left to the implementation's current shape.
func TestClient_Open_SendsOverTheChosenCarrierOnly(t *testing.T) {
	h := carrierHost(t, "    knock_http_port: 62443\n")
	signer := mustGenerate(t, "laptop-primary")

	var sent []netip.AddrPort
	record := func(_ context.Context, to netip.AddrPort, _ []byte) error {
		sent = append(sent, to)
		return nil
	}

	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder:         client.Builder{Signer: signer},
		Host:            h,
		Service:         "ssh",
		Carrier:         client.CarrierHTTP,
		Send:            record,
		Dial:            refusingDialer,
		ConnectAttempts: 1,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("the knock left this machine %d times; there is no fallback carrier", len(sent))
	}
	if sent[0].Port() != 62443 {
		t.Fatalf("the knock went to port %d, want the http carrier's 62443", sent[0].Port())
	}
	if rep.Carrier != client.CarrierHTTP {
		t.Fatalf("the report says carrier %q", rep.Carrier)
	}
}

// An unaddressable carrier is refused before the packet is built, so a failed
// `open --carrier http` does not consume a counter value or mint a request_id
// for a knock that was never going anywhere.
func TestClient_Open_RefusesAnUnaddressableCarrierBeforeSending(t *testing.T) {
	h := carrierHost(t, "")
	signer := mustGenerate(t, "laptop-primary")

	sends := 0
	_, err := client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: signer},
		Host:    h,
		Service: "ssh",
		Carrier: client.CarrierHTTP,
		Send: func(context.Context, netip.AddrPort, []byte) error {
			sends++
			return nil
		},
		Dial:            refusingDialer,
		ConnectAttempts: 1,
	})
	if err == nil {
		t.Fatal("Open accepted a carrier the host entry cannot address")
	}
	if sends != 0 {
		t.Fatalf("it sent %d knock(s) anyway", sends)
	}
}
