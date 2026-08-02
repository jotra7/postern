package console_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/console"
	"github.com/jotra7/postern/internal/hub"
)

// TestConsole_Post_StatusRecordsWhatItObserved is at the top of this file's
// action tests because the fleet view's live column has no other source: the
// hub serves no per-host heartbeat on any route, so what the page shows is
// what this console measured.
func TestConsole_Post_StatusRecordsWhatItObserved(t *testing.T) {
	// The exchange never answers, so the pong fails and the recovery connect
	// is refused. That is the interesting case: the fleet view has to record
	// an unhealthy reading rather than nothing, because "checked and bad" and
	// "never checked" point at different next actions.
	f := newFixture(t, func(c *console.Config) {
		c.Exchange = func(_ context.Context, _ netip.AddrPort, _ []byte, _ time.Duration) ([]byte, error) {
			return nil, os.ErrDeadlineExceeded
		}
	})
	f.unlock(t, "operator")

	if w := f.do(f.wellFormedPost("/status", url.Values{"host": {f.HostName}})); w.Code != http.StatusSeeOther {
		t.Fatalf("POST /status = %d, want 303: %s", w.Code, w.Body.String())
	}
	body := f.do(f.wellFormedGet("/host/" + f.HostName)).Body.String()
	if strings.Contains(body, "Nothing observed yet") {
		t.Fatalf("POST /status recorded nothing; the host page still says it has never been checked:\n%s", body)
	}
	if !strings.Contains(body, "FAIL") {
		t.Fatalf("a failed liveness exchange was not recorded as a failure:\n%s", body)
	}
}

// nastyHost is a host name carrying markup. Nothing validates a host name's
// character set — the inventory is a hand-edited file and the client config is
// derived from a host's own entry — so this is input the page has to survive
// rather than input that cannot occur.
const nastyHost = `web<script>alert("pwned")</script>-01`

func TestConsole_Render_EscapesAHostNameContainingHTML(t *testing.T) {
	f := newFixtureNamed(t, nastyHost)

	w := f.do(f.wellFormedGet("/"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Fatalf("the fleet page rendered a host name's markup verbatim. html/template escapes per "+
			"context and text/template does not, which is the entire reason this package uses the "+
			"former; body:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("the fleet page does not contain the escaped host name at all, so this test is not "+
			"looking at the thing it claims to check; body:\n%s", body)
	}
}

func TestConsole_Render_EscapesErrorTextFromOffMachine(t *testing.T) {
	// The error string comes back from a hub this console does not control,
	// and it reaches the page. A hub — or anything sitting in front of one —
	// choosing its own reason phrase is enough to put markup in it.
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer hostile.Close()

	f := newFixture(t, func(c *console.Config) { c.HubURL = hostile.URL })
	w := f.do(f.wellFormedGet("/"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "418") {
		t.Fatalf("the hub's status did not reach the page, so the escaping claim is untested; body:\n%s", w.Body.String())
	}
}

func TestConsole_Fleet_MarksAnUnsignedHostStale(t *testing.T) {
	f := newFixture(t)
	body := f.do(f.wellFormedGet("/")).Body.String()
	if !strings.Contains(body, "never signed") {
		t.Fatalf("a host with no bundle on file is not reported stale. An agent pulling right now would "+
			"get nothing, which is exactly what this column exists to say; body:\n%s", body)
	}
}

func TestConsole_Fleet_RendersTheGrantsThatApplyToAHost(t *testing.T) {
	f := newFixture(t)
	body := f.do(f.wellFormedGet("/host/" + f.HostName)).Body.String()
	// The fixture's one grant is on hosts: ["*"], which never names this host
	// in the inventory. It appears here because the view compiles the policy
	// rather than reading the inventory entry.
	if !strings.Contains(body, "laptop-primary") {
		t.Fatalf("the host page does not show the operator whose wildcard grant reaches it; body:\n%s", body)
	}
}

func TestConsole_Deploy_SignsBundlesTheHubStoreCanRead(t *testing.T) {
	f := newFixture(t)
	f.unlock(t, "signer")

	w := f.do(f.wellFormedPost("/sign", url.Values{}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /sign = %d, want 303: %s", w.Code, w.Body.String())
	}

	// index.json's shape is a contract between three packages that cannot
	// import each other: cmd/postern writes it, internal/hub reads it, and
	// this package writes it too. Reading what the console wrote with the
	// hub's own Store is what holds the three copies together.
	store, err := hub.OpenStore(f.BundleDir)
	if err != nil {
		t.Fatalf("hub.OpenStore(%s): %v", f.BundleDir, err)
	}
	var hostID [16]byte
	for i := range hostID {
		hostID[i] = byte(i + 1)
	}
	if _, err := store.HostKey(hostID); err != nil {
		t.Fatalf("hub.Store.HostKey after a console signing run: %v — the index this console wrote is "+
			"not the index a hub reads", err)
	}
	sealed, err := store.Bundle(hostID)
	if err != nil {
		t.Fatalf("hub.Store.Bundle after a console signing run: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("the console wrote an empty bundle")
	}
	if _, err := os.Stat(filepath.Join(f.BundleDir, hex.EncodeToString(hostID[:])+".bundle")); err != nil {
		t.Fatalf("stat the bundle the console wrote: %v", err)
	}
}

func TestConsole_Deploy_RefusesASecondRunAtTheSameVersion(t *testing.T) {
	f := newFixture(t)
	f.unlock(t, "signer")
	if w := f.do(f.wellFormedPost("/sign", url.Values{})); w.Code != http.StatusSeeOther {
		t.Fatalf("first POST /sign = %d, want 303", w.Code)
	}
	if w := f.do(f.wellFormedPost("/sign", url.Values{})); w.Code != http.StatusSeeOther {
		t.Fatalf("second POST /sign = %d, want 303 carrying the refusal", w.Code)
	}
	body := f.do(f.wellFormedGet("/deploy")).Body.String()
	if !strings.Contains(body, "not newer") {
		t.Fatalf("re-signing at a version that is not newer was not refused. Those bundles are rejected "+
			"by every agent as not-newer, which an operator discovers at rollout; body:\n%s", body)
	}
}

func TestConsole_Deploy_RefusesToSignWhileTheSignerKeyIsLocked(t *testing.T) {
	f := newFixture(t)
	// The operator slot is unlocked; the signer slot is not. Bundle-signing
	// authority is transitively door-opening authority for the whole fleet,
	// so it is its own slot and unlocking one must not unlock the other.
	f.unlock(t, "operator")
	if w := f.do(f.wellFormedPost("/sign", url.Values{})); w.Code != http.StatusSeeOther {
		t.Fatalf("POST /sign with a locked signer = %d, want a 303 carrying the failure", w.Code)
	}
	if _, err := os.Stat(filepath.Join(f.BundleDir, "index.json")); !os.IsNotExist(err) {
		t.Fatalf("a signing run with a locked signer key wrote %s/index.json (stat err %v)", f.BundleDir, err)
	}
}

func TestConsole_Deploy_PlanIsComputedWithoutAKey(t *testing.T) {
	f := newFixture(t)
	// The deploy page is a GET, so it must produce the whole plan with
	// nothing unlocked: a page that needed a key to show what would change
	// would push an operator into unlocking one in order to look.
	body := f.do(f.wellFormedGet("/deploy")).Body.String()
	if !strings.Contains(body, "laptop-primary") || !strings.Contains(body, f.HostName) {
		t.Fatalf("the deploy plan is incomplete with no key unlocked; body:\n%s", body)
	}
}

func TestConsole_DeployView_ShowsEachHostsResolvedKnockPort(t *testing.T) {
	f := newFixture(t)
	// The deploy preview shows the address:port a knock is sent to for each
	// host, resolved from the host's own spa_port if set and defaults.spa_port
	// otherwise, so a per-host knock-port override can be confirmed before the
	// run is signed rather than by hand-reading the sealed bundle.
	body := f.do(f.wellFormedGet("/deploy")).Body.String()
	if !strings.Contains(body, "203.0.113.9:62201") {
		t.Fatalf("the deploy view does not show %s's resolved knock address:port; an operator cannot "+
			"confirm a per-host knock port before signing. body:\n%s", f.HostName, body)
	}
}
