package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/metrics"
)

// testHub wires a *server the same way Serve does, fronted by an
// httptest.Server so tests get a real address without racing Serve's own
// listener setup. Both listeners are real and separate, exactly as Serve
// arranges them: the public mux on PublicURL, and metrics.Serve carrying
// /metrics plus privateRoutes on PrivateURL.
type testHub struct {
	PublicURL  string
	PrivateURL string
	Store      *Store
	Beats      *Beats
	Metrics    *Metrics

	dir    string
	signer identity.Signer
	hostID [16]byte
}

// startTestHub writes one host's bundle and signing key into a fresh store
// directory and serves it over httptest. opts run against the *server before
// either listener opens, so a test can pin the clock without writing to
// fields a live handler is reading.
func startTestHub(t *testing.T, opts ...func(*server)) *testHub {
	t.Helper()
	signer, err := identity.Generate("host-01")
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	var hostID [16]byte
	hostID[0] = 0x42

	dir := t.TempDir()
	sealed := []byte("opaque sealed bundle bytes, not a policy")
	idHex := hex.EncodeToString(hostID[:])
	if err := os.WriteFile(filepath.Join(dir, idHex+".bundle"), sealed, 0o600); err != nil {
		t.Fatalf("write bundle fixture: %v", err)
	}
	signingKey := signer.Public().Signing
	index := `{"hosts":{"` + idHex + `":{"signing":"` +
		base64.StdEncoding.EncodeToString(signingKey[:]) + `","version":1}}}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o600); err != nil {
		t.Fatalf("write index.json fixture: %v", err)
	}

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	beats := NewBeats()
	m := NewMetrics(beats)
	srv := &server{store: store, beats: beats, metrics: m, now: time.Now, since: time.Now()}
	for _, o := range opts {
		o(srv)
	}

	ts := httptest.NewServer(newMux(srv))
	t.Cleanup(ts.Close)

	privateLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the private listener: %v", err)
	}
	privateSrv := metrics.Serve(privateLn, m.Handler(), privateRoutes(srv)...)
	t.Cleanup(func() { _ = privateSrv.Close() })

	return &testHub{
		PublicURL:  ts.URL,
		PrivateURL: "http://" + privateLn.Addr().String(),
		Store:      store,
		Beats:      beats,
		Metrics:    m,
		dir:        dir,
		signer:     signer,
		hostID:     hostID,
	}
}

// beat builds and signs a well-formed beat for this hub's one enrolled host.
func (h *testHub) beat(t *testing.T, epoch, sequence uint64) []byte {
	t.Helper()
	b := &attest.Beat{
		HostID:   h.hostID,
		Epoch:    epoch,
		Sequence: sequence,
		SentAt:   time.Now(),
		Body:     attest.Body{AgentVersion: "0.0.0-test"},
	}
	data, err := attest.Encode(b, h.signer)
	if err != nil {
		t.Fatalf("attest.Encode: %v", err)
	}
	return data
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func post(t *testing.T, url string, body []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(body)) //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// --- the two-route surface -------------------------------------------------

// The public listener serves two things. Anything else on it is surface on
// the one component with a public address, and /metrics there would publish
// fleet size and per-host health to anyone who asked.
func TestHub_Server_PublicListenerServesOnlyBundlesAndHeartbeat(t *testing.T) {
	h := startTestHub(t)
	for _, path := range []string{"/metrics", BeatsPath, "/", "/debug/pprof/", "/index.html", "/bundles/"} {
		resp := get(t, h.PublicURL+path)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s on the public listener: status %d, want 404", path, resp.StatusCode)
		}
	}
}

// An unauthenticated fetch of the right path returns ciphertext, and that is
// by design — section 6 bounds the claim to contents, not metadata. This
// test pins the bound: what comes back must not be readable policy, and
// must be exactly the bytes on file.
func TestHub_Server_BundleFetchReturnsCiphertextToAnyone(t *testing.T) {
	h := startTestHub(t)
	resp := get(t, h.PublicURL+"/bundle/"+hex.EncodeToString(h.hostID[:]))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	want := "opaque sealed bundle bytes, not a policy"
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if bytes.Contains(got, []byte("ssh")) || bytes.Contains(got, []byte("operators")) {
		t.Errorf("fetched bundle looks like readable policy, not ciphertext: %q", got)
	}
}

func TestHub_Server_BundleFetch_ReturnsNotFoundForAnUnenrolledHost(t *testing.T) {
	h := startTestHub(t)
	var other [16]byte
	other[0] = 0x99
	resp := get(t, h.PublicURL+"/bundle/"+hex.EncodeToString(other[:]))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHub_Server_BundleFetch_ReturnsNotFoundForAMalformedHostID(t *testing.T) {
	h := startTestHub(t)
	resp := get(t, h.PublicURL+"/bundle/not-hex-at-all")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHub_Server_BundleFetch_RejectsPOST(t *testing.T) {
	h := startTestHub(t)
	resp := post(t, h.PublicURL+"/bundle/"+hex.EncodeToString(h.hostID[:]), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHub_Server_Heartbeat_RejectsGET(t *testing.T) {
	h := startTestHub(t)
	resp := get(t, h.PublicURL+"/heartbeat")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// --- heartbeat ingest -------------------------------------------------------

func TestHub_Server_Heartbeat_AcceptsAWellSignedBeat(t *testing.T) {
	h := startTestHub(t)
	resp := post(t, h.PublicURL+"/heartbeat", h.beat(t, 1, 1))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	beat, _, ok := h.Beats.Latest(h.hostID)
	if !ok {
		t.Fatal("Beats has no record after a well-signed heartbeat")
	}
	if beat.Sequence != 1 {
		t.Errorf("recorded sequence = %d, want 1", beat.Sequence)
	}
}

func TestHub_Server_Heartbeat_RejectsAReplayedBeat(t *testing.T) {
	h := startTestHub(t)
	first := h.beat(t, 1, 5)
	if resp := post(t, h.PublicURL+"/heartbeat", first); resp.StatusCode != http.StatusNoContent {
		_ = resp.Body.Close()
		t.Fatalf("first beat: status = %d, want 204", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}

	resp := post(t, h.PublicURL+"/heartbeat", first)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("a replayed beat was accepted a second time")
	}
}

// A beat naming a host with no key on file must be rejected without ever
// touching the sequence store — there is nothing to verify it against, and
// the response must not tell the caller whether the host_id is simply
// unknown or the signature was wrong.
// The unknown-host branch, isolated by which control refused the beat rather
// than by the fact that something did.
//
// Status and body are deliberately identical for every rejection this route
// makes, so an unauthenticated caller cannot tell them apart — which means
// the response says nothing about WHICH check fired. Deleting the
// unknown-host branch and falling through to attest.Verify with a zero key
// still rejects, via signature failure, so a test asserting only "not 204"
// would pass under exactly the mutation it exists to catch.
//
// The metric is the one place the hub does distinguish them, and it is the
// same place an operator would look to tell "a host I have never enrolled is
// beating at me" from "an enrolled host's key no longer matches".
//
// Mutation verified: removing the s.store.HostKey error branch turns this
// into result="bad_signature" and fails here rather than silently passing.
func TestHub_Server_Heartbeat_RejectsAnUnknownHost(t *testing.T) {
	h := startTestHub(t)
	stranger, err := identity.Generate("not-enrolled")
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	var strangerID [16]byte
	strangerID[0] = 0x77
	b := &attest.Beat{HostID: strangerID, Epoch: 1, Sequence: 1, SentAt: time.Now()}
	data, err := attest.Encode(b, stranger)
	if err != nil {
		t.Fatalf("attest.Encode: %v", err)
	}

	resp := post(t, h.PublicURL+"/heartbeat", data)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("a beat from an unenrolled host was accepted")
	}
	if got := h.Beats.Count(); got != 0 {
		t.Fatalf("Beats.Count() = %d after rejecting an unknown host, want 0", got)
	}
	assertHeartbeatResult(t, h, "unknown_host", 1)
	assertHeartbeatResult(t, h, "bad_signature", 0)
}

// scrapeHub renders the hub's own metrics registry, the way its separate
// metrics listener would.
func scrapeHub(t *testing.T, h *testHub) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scraping the hub registry returned %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// assertHeartbeatResult checks one result label's counter. A label that has
// never been incremented does not appear in the exposition at all, which is
// how want == 0 is expressed.
func assertHeartbeatResult(t *testing.T, h *testHub, result string, want int) {
	t.Helper()
	body := scrapeHub(t, h)
	series := `postern_hub_heartbeats_total{result="` + result + `"}`
	var got int
	found := false
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != series {
			continue
		}
		found = true
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("%s has non-numeric value %q", series, fields[1])
		}
		got = int(v)
	}
	if !found && want == 0 {
		return
	}
	if got != want {
		t.Fatalf("%s = %d, want %d; the response body and status are identical for every rejection "+
			"this route makes, so this counter is the only thing that says which control fired"+
			"\n--- scrape ---\n%s", series, got, want, body)
	}
}

func TestHub_Server_Heartbeat_RejectsAnOversizedBody(t *testing.T) {
	h := startTestHub(t)
	oversized := make([]byte, maxHeartbeatBody+1)
	resp := post(t, h.PublicURL+"/heartbeat", oversized)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if got := h.Beats.Count(); got != 0 {
		t.Fatalf("Beats.Count() = %d after an oversized body, want 0", got)
	}
}

// A body too short to be a beat is refused, and this asserts exactly that
// and no more.
//
// It used to claim it exercised handleHeartbeat's own length guard. It does
// not: that guard is genuinely redundant against attest.Verify's own
// `len(data) < FixedLen`, so a body this short is refused either way and the
// status code cannot tell which. The guard is kept as defence in depth —
// handleHeartbeat slices host_id out of the unverified prefix before Verify
// runs, and a bounds check standing right next to that slice is worth having
// whether or not something downstream would also catch it — but a test cannot
// attribute the refusal to it, so this one no longer says it does.
//
// The metric is asserted because it is the only part of the response that
// distinguishes anything: "malformed" is what the local guard records, and a
// body that got past it and died at Verify would record "bad_signature".
func TestHub_Server_Heartbeat_RejectsABodyTooShortToBeABeat(t *testing.T) {
	h := startTestHub(t)
	resp := post(t, h.PublicURL+"/heartbeat", []byte("too short to be a beat"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("a truncated body was accepted as a beat")
	}
	assertHeartbeatResult(t, h, "malformed", 1)
}

// A beat that fails signature verification must never reach the sequence
// store, or an attacker could park a host's epoch at the maximum and lock
// out every real beat that follows. Sending a tampered beat claiming the
// maximum epoch and sequence, and then confirming a legitimately signed,
// far lower (epoch, sequence) beat still succeeds afterward, is the only
// way to observe that the tampered one was never recorded — checking only
// the tampered request's own status code would pass even if Accept were
// called before verification failed to reject it for some other reason.
func TestHub_Server_RejectsAnUnsignedBeatBeforeRecordingIt(t *testing.T) {
	h := startTestHub(t)

	tampered := h.beat(t, ^uint64(0), ^uint64(0)) // maximum epoch and sequence
	// Flip a bit inside the signature itself so the record is exactly the
	// right shape and length but fails ed25519.Verify.
	tampered[len(tampered)-1] ^= 0x01

	resp := post(t, h.PublicURL+"/heartbeat", tampered)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("a beat with a tampered signature was accepted")
	}
	if _, _, ok := h.Beats.Latest(h.hostID); ok {
		t.Fatal("a beat with a tampered signature reached the sequence store")
	}

	// If the tampered beat had been recorded, this host's epoch would now
	// be pinned at the maximum and every real beat below it would read as
	// stale forever. A legitimately signed, low (epoch, sequence) beat must
	// still succeed.
	legit := h.beat(t, 1, 1)
	resp2 := post(t, h.PublicURL+"/heartbeat", legit)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("legitimate beat after a rejected tampered one: status = %d, want 204 "+
			"(the tampered beat's claimed epoch/sequence must never have been recorded)", resp2.StatusCode)
	}
}

// --- Serve: config validation and the public server's own hardening -------

func TestHub_Serve_RefusesACertWithoutAKey(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	cfg := Config{Addr: "127.0.0.1:0", StoreDir: dir, TLSCertFile: "/tmp/does-not-matter.pem"}
	if err := Serve(context.Background(), cfg); err == nil {
		t.Fatal("Serve accepted a cert file with no key file")
	}
}

func TestHub_Serve_RefusesAKeyWithoutACert(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	cfg := Config{Addr: "127.0.0.1:0", StoreDir: dir, TLSKeyFile: "/tmp/does-not-matter.pem"}
	if err := Serve(context.Background(), cfg); err == nil {
		t.Fatal("Serve accepted a key file with no cert file")
	}
}

func TestHub_Serve_RefusesMetricsAddrEqualToAddr(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	cfg := Config{Addr: "127.0.0.1:9999", MetricsAddr: "127.0.0.1:9999", StoreDir: dir}
	if err := Serve(context.Background(), cfg); err == nil {
		t.Fatal("Serve accepted MetricsAddr == Addr")
	}
}

func TestHub_Serve_RefusesAMissingStoreDir(t *testing.T) {
	cfg := Config{Addr: "127.0.0.1:0", StoreDir: filepath.Join(t.TempDir(), "nope")}
	if err := Serve(context.Background(), cfg); err == nil {
		t.Fatal("Serve accepted a store directory that does not exist")
	}
}

func TestHub_Serve_StartsPlainHTTPWithNoTLSConfigured(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	addr := freeAddr(t)
	cfg := Config{Addr: addr, StoreDir: dir}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v after a clean cancellation", err)
		}
	})

	// A plain http.Get succeeding at all proves the listener speaks HTTP,
	// not TLS: a client speaking plaintext to a TLS listener gets a
	// connection-level failure, never a parsed HTTP response.
	resp := waitForHTTP(t, "http://"+addr+"/heartbeat")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /heartbeat over what should be plain HTTP: status = %d, want 405", resp.StatusCode)
	}
}

func TestHub_Serve_ServesTLSWhenBothFilesAreConfigured(t *testing.T) {
	dir := writeStore(t, []byte("x"), randomSigningKey(t))
	certFile, keyFile := writeSelfSignedCert(t)
	addr := freeAddr(t)
	cfg := Config{Addr: addr, StoreDir: dir, TLSCertFile: certFile, TLSKeyFile: keyFile}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v after a clean cancellation", err)
		}
	})

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only, self-signed fixture
	}}
	var resp *http.Response
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get("https://" + addr + "/heartbeat") //nolint:gosec // test-controlled URL
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS GET never succeeded: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}

	// A plaintext request to the same address must not get our handler's
	// response. Go's http.Server has a courtesy behaviour for exactly this
	// case — crypto/tls detects a plaintext ClientHello and the server
	// writes back a diagnostic 400 before closing the connection — so
	// plainErr is not itself the signal; what matters is that our own
	// mux never ran, which a 405 (the handler's answer for a wrong method)
	// would prove wrongly.
	if plainResp, plainErr := http.Get("http://" + addr + "/heartbeat"); plainErr == nil { //nolint:gosec // test URL
		defer func() { _ = plainResp.Body.Close() }()
		if plainResp.StatusCode == http.StatusMethodNotAllowed {
			t.Fatal("a plaintext request to a TLS-configured listener reached our handler")
		}
	}
}

func TestHub_Serve_PublicServerSetsTimeoutsAndMaxHeaderBytes(t *testing.T) {
	srv := newPublicServer(http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is not set")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("ReadTimeout is not set")
	}
	if srv.WriteTimeout <= 0 {
		t.Error("WriteTimeout is not set")
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes is not set")
	}
}

// --- test helpers ------------------------------------------------------

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}

func waitForHTTP(t *testing.T, url string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // test-controlled URL
		if err == nil {
			return resp
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s never succeeded: %v", url, lastErr)
	return nil
}

// writeSelfSignedCert generates a throwaway ECDSA certificate for the TLS
// tests above and writes it to two PEM files in a temp directory.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}
