package console

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxHubBundleRead bounds how much of a bundle response the console will read
// before giving up. A bundle's plaintext is capped at bundle.MaxPolicyLen
// (1 MiB) and the seal adds a fixed overhead, so 2 MiB is generous; the point
// is that a hub the console does not control cannot make it allocate without
// limit.
const maxHubBundleRead = 2 << 20

// hubTimeout bounds one hub request. The hub is a management convenience and
// is never in the path of a knock, so a slow or dead hub must degrade the
// fleet view rather than hang it.
const hubTimeout = 5 * time.Second

// HubState is what the console could learn about one host from the hub.
//
// The hub serves exactly two routes (internal/hub/server.go): a per-host
// sealed bundle, and heartbeat ingest. So this is everything there is to
// learn from it about a host, and it is deliberately little: the bundle is
// ciphertext the hub itself cannot read, which is the property the whole
// bundle plane rests on. Presence and size are the metadata design section 6
// already says a hub leaks; nothing here tries to infer more.
type HubState struct {
	// Queried is false when no hub URL was configured, which is the ordinary
	// case for an operator running standalone hosts.
	Queried bool
	// Serving reports that the hub returned a bundle for this host.
	Serving bool
	// Bytes is the sealed bundle's size.
	Bytes int
	// Err is why the question could not be answered. A hub that is down
	// leaves every other column of the fleet view intact.
	Err string
}

// HubClient asks a hub what it is serving.
type HubClient struct {
	// BaseURL is the hub's public listener, e.g. "https://hub.example:8443".
	// Empty means no hub is configured and Bundle is never called.
	BaseURL string
	// HTTP is the client used. Nil selects a plain client with hubTimeout.
	HTTP *http.Client
}

// Bundle reports whether the hub is serving a bundle for hostID.
//
// It reads the body rather than issuing a HEAD: internal/hub's handler writes
// the sealed bytes with no Content-Length of its own, so a HEAD would answer
// "present" and nothing about size, and size is the only other thing the
// route can honestly report.
func (c HubClient) Bundle(ctx context.Context, hostID [16]byte) HubState {
	if c.BaseURL == "" {
		return HubState{}
	}
	st := HubState{Queried: true}
	url := strings.TrimSuffix(c.BaseURL, "/") + "/bundle/" + hex.EncodeToString(hostID[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: hubTimeout}
	}
	resp, err := hc.Do(req)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// The hub answers 404 both for "no bundle on file" and for a host_id
		// it could not parse. The console never sends an unparseable one — it
		// hex-encodes 16 bytes here — so from this side a 404 means the hub
		// is not serving this host.
		return st
	default:
		st.Err = fmt.Sprintf("hub answered %s", resp.Status)
		return st
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxHubBundleRead))
	if err != nil {
		st.Err = err.Error()
		return st
	}
	st.Serving = true
	st.Bytes = int(n)
	return st
}
