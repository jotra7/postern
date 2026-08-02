package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func freeHubAddr(t *testing.T) string {
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

// writeHubStoreFixture writes one host's bundle and signing key, exactly the
// shape `postern sign` produces (see cmd_sign.go's bundleIndex), so this
// command's own flags are what is under test here — not internal/hub's
// store format, which internal/hub/server_test.go already covers directly.
func writeHubStoreFixture(t *testing.T, dir string, hostID [16]byte, sealed []byte, signingPub [32]byte) {
	t.Helper()
	idHex := hex.EncodeToString(hostID[:])
	if err := os.WriteFile(filepath.Join(dir, idHex+".bundle"), sealed, 0o600); err != nil {
		t.Fatalf("write bundle fixture: %v", err)
	}
	index := `{"hosts":{"` + idHex + `":{"signing":"` +
		base64.StdEncoding.EncodeToString(signingPub[:]) + `","version":1}}}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o600); err != nil {
		t.Fatalf("write index.json fixture: %v", err)
	}
}

// TestMain_Hub_RequiresStoreAndAddr proves the two required flags are
// checked before anything else runs: neither reaches hub.Serve, so this
// returns instantly rather than needing a listener or a cancellable context.
func TestMain_Hub_RequiresStoreAndAddr(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no --store", []string{"hub", "--addr", "127.0.0.1:0"}},
		{"no --addr", []string{"hub", "--store", t.TempDir()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, errBuf := envWithHome(t, t.TempDir())
			if code := runCLI(t, e, tc.args...); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (usage); stderr: %s", code, exitUsage, errBuf.String())
			}
		})
	}
}

// TestMain_Hub_ServesBundleAndKeepsMetricsOffThePublicListener runs the real
// dispatcher against the shipped binary's own code path — runHub, not
// hub.Serve directly — so what is proven is that this command's five flags
// actually reach a working hub.Config. The two assertions mirror design
// section 6's own two-listener requirement: a bundle fetch answers, and
// /metrics — a route the public mux never registers at all (see
// internal/hub/server.go's newMux) — 404s rather than being silently
// present.
func TestMain_Hub_ServesBundleAndKeepsMetricsOffThePublicListener(t *testing.T) {
	dir := t.TempDir()
	var hostID [16]byte
	hostID[0] = 0x42
	sealed := []byte("opaque sealed bundle bytes, not a readable policy")
	writeHubStoreFixture(t, dir, hostID, sealed, [32]byte{1, 2, 3})

	addr := freeHubAddr(t)
	e, _, _ := envWithHome(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runHub(ctx, e, []string{"--store", dir, "--addr", addr}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runHub returned %v after a clean cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("runHub did not return within 5s of context cancellation")
		}
	})

	url := "http://" + addr + "/bundle/" + hex.EncodeToString(hostID[:])
	var resp *http.Response
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get(url) //nolint:gosec // test-controlled URL
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s never succeeded: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, sealed) {
		t.Fatalf("GET %s = %d %q, want 200 with the sealed bytes %q", url, resp.StatusCode, body, sealed)
	}

	mresp, err := http.Get("http://" + addr + "/metrics") //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	_ = mresp.Body.Close()
	if mresp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /metrics on the public listener = %d, want 404 — /metrics must never be reachable "+
			"without --metrics-addr naming a separate listener", mresp.StatusCode)
	}
}

// TestMain_Hub_PropagatesHalfConfiguredTLSAsAFailure proves this command does
// not swallow hub.Serve's own configuration refusals: half-configured TLS is
// caught before any listener opens, so this returns promptly against an
// uncancelled background context.
func TestMain_Hub_PropagatesHalfConfiguredTLSAsAFailure(t *testing.T) {
	dir := t.TempDir()
	writeHubStoreFixture(t, dir, [16]byte{9}, []byte("x"), [32]byte{1})
	addr := freeHubAddr(t)
	e, _, _ := envWithHome(t, t.TempDir())

	code := runCLI(t, e, "hub", "--store", dir, "--addr", addr, "--tls-cert", "/tmp/does-not-matter.pem")
	if code == exitOK {
		t.Fatal("hub with only --tls-cert set exited 0; half-configured TLS must be refused")
	}
}

// TestMain_Hub_RefusesPositionalArguments keeps the flag surface exactly
// what the brief specifies: five flags, nothing else.
func TestMain_Hub_RefusesPositionalArguments(t *testing.T) {
	e, _, _ := envWithHome(t, t.TempDir())
	if code := runCLI(t, e, "hub", "--store", t.TempDir(), "--addr", "127.0.0.1:0", "extra"); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (usage)", code, exitUsage)
	}
}

// TestMain_Hub_ServesBeatsOnTheMetricsListenerOnly runs the shipped command's
// own path with --metrics-addr set, and asserts the freshness document from
// both sides of the split: it answers on the private address and 404s on the
// public one.
//
// Both halves use the same path against the same running hub, and the private
// half checks the body rather than only the status. A public-listener 404 on
// its own would pass just as well if the route had been renamed or dropped.
func TestMain_Hub_ServesBeatsOnTheMetricsListenerOnly(t *testing.T) {
	dir := t.TempDir()
	var hostID [16]byte
	hostID[0] = 0x42
	writeHubStoreFixture(t, dir, hostID, []byte("sealed"), [32]byte{1, 2, 3})

	addr := freeHubAddr(t)
	metricsAddr := freeHubAddr(t)
	e, _, errBuf := envWithHome(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runHub(ctx, e, []string{"--store", dir, "--addr", addr, "--metrics-addr", metricsAddr})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runHub returned %v after a clean cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("runHub did not return within 5s of context cancellation")
		}
	})

	private := waitForOK(t, "http://"+metricsAddr+"/beats")
	body, err := io.ReadAll(private.Body)
	_ = private.Body.Close()
	if err != nil {
		t.Fatalf("read /beats body: %v", err)
	}
	if !bytes.Contains(body, []byte(`"hosts"`)) || !bytes.Contains(body, []byte(hex.EncodeToString(hostID[:]))) {
		t.Fatalf("GET /beats on the metrics listener returned %q, want the freshness document naming the "+
			"enrolled host", body)
	}
	// observed_since comes from the real clock at startup here rather than
	// from a test hook, so a hub that left it at the zero time would report
	// every host as quiet since the year 1 and no unit test would notice.
	var doc struct {
		ObservedSince time.Time `json:"observed_since"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode /beats body %q: %v", body, err)
	}
	if age := time.Since(doc.ObservedSince); age < 0 || age > time.Minute {
		t.Errorf("observed_since = %v, which is %v ago; want the moment this hub process started keeping beats",
			doc.ObservedSince, age)
	}

	public, err := http.Get("http://" + addr + "/beats") //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("GET /beats on the public listener: %v", err)
	}
	_ = public.Body.Close()
	if public.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /beats on the public listener = %d, want 404. Which hosts exist and which have "+
			"gone quiet is for this hub's operator, not for anyone who can reach the bundle route",
			public.StatusCode)
	}

	if got := errBuf.String(); !strings.Contains(got, "/metrics and /beats on "+metricsAddr) {
		t.Errorf("startup output %q does not say what --metrics-addr now serves", got)
	}
}

// waitForOK polls url until it answers 200, which is how these tests wait for
// a listener the command opened in a goroutine.
func waitForOK(t *testing.T, url string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // test-controlled URL
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp
		}
		if err == nil {
			lastErr = errStatus(resp.StatusCode)
			_ = resp.Body.Close()
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s never returned 200: %v", url, lastErr)
	return nil
}

type errStatus int

func (e errStatus) Error() string { return "status " + strconv.Itoa(int(e)) }
