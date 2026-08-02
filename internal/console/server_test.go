package console_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/console"
)

// Every refusal below starts from wellFormedPost — the request a browser on
// this console's own page actually sends — and breaks exactly one thing. That
// is the point: if a test broke two controls at once it would still pass with
// the control under test deleted, which is how a suite ends up green while
// the thing it claims to check is gone.
//
// TestConsole_Post_WellFormedRequestIsAccepted is what makes the rest
// meaningful. Without it, every refusal test would also pass against a
// console that refused everything.

func TestConsole_Post_WellFormedRequestIsAccepted(t *testing.T) {
	f := newFixture(t)
	w := f.do(f.wellFormedPost("/lock", url.Values{}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("well-formed POST /lock = %d, want 303. Every refusal test in this file is "+
			"worthless if the request they mutate does not itself get through: body %s", w.Code, w.Body.String())
	}
}

func TestConsole_Post_RefusedWhenCrossSite(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/open", url.Values{"host": {f.HostName}})
	// The one thing broken: the browser's own account of who started this.
	// The token is still valid and the Host header is still this console's,
	// so only the fetch-metadata check can refuse it.
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://evil.example")

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST /open = %d, want 403: any page the operator has open can issue this "+
			"request, and without the fetch-metadata check it would knock a production host", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrCrossSite.Error()) {
		t.Fatalf("cross-site POST refused with %q, want ErrCrossSite — a refusal from some other control "+
			"would mean this test is not checking the one it names", w.Body.String())
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("a refused cross-site POST put %d datagrams on the wire, want 0", n)
	}
}

func TestConsole_Post_RefusedWhenOriginIsForeignAndFetchMetadataAbsent(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/open", url.Values{"host": {f.HostName}})
	// Sec-Fetch-Site removed entirely, standing in for a browser that never
	// sends it. Origin alone has to carry the refusal.
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Origin", "https://evil.example")

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign-Origin POST /open = %d, want 403: Origin is set on every cross-origin POST by "+
			"browsers that predate Sec-Fetch-Site, and it is the half of the header check that still works there", w.Code)
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("a refused foreign-Origin POST put %d datagrams on the wire, want 0", n)
	}
}

// An opaque origin is not a foreign one, and the difference cost a real
// operator a refusal on a button that does nothing but drop a key from memory.
//
// A browser sends the literal "null" when the document has no nameable origin:
// a sandboxed iframe, a page from data: or file:, a request that crossed
// origins on a redirect. That is exactly as much information as no Origin
// header at all, which the guard already lets through, and it is stopped by
// exactly the same control, since none of those contexts can read the token
// out of a page it has no same-origin access to.
//
// The token here is valid and deliberately so. Without it the request would be
// refused by the token check and this test would pass against a guard that
// still rejected every opaque origin, proving nothing.
func TestConsole_Post_AcceptedWithAnOpaqueOrigin(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/lock", url.Values{"slot": {"operator"}})
	r.Header.Set("Origin", "null")

	w := f.do(r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /lock with an opaque origin = %d, want 303: %q. \"null\" says no more than a "+
			"missing Origin does, and refusing it turns away an operator whose browser produced an "+
			"opaque origin while stopping nobody who could not already be stopped by the token",
			w.Code, w.Body.String())
	}
}

// The counterpart, so the acceptance above cannot be satisfied by a guard that
// stopped reading Origin altogether: a named foreign origin is still refused
// on the same route, with the same valid token.
func TestConsole_Post_StillRefusesANamedForeignOriginOnTheSameRoute(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/lock", url.Values{"slot": {"operator"}})
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Origin", "https://evil.example")

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST /lock from a named foreign origin = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrCrossSite.Error()) {
		t.Fatalf("refused with %q, want ErrCrossSite", w.Body.String())
	}
}

func TestConsole_Post_RefusedWithoutCSRFToken(t *testing.T) {
	f := newFixture(t)
	// Built by hand rather than by mutating wellFormedPost, because the
	// token is the field wellFormedPost exists to add. Everything else the
	// guard checks is present and correct: this console's own Host, its own
	// Origin, same-origin fetch metadata, and the session cookie that
	// authenticates the request. Only the CSRF token is missing, so only the
	// token check can refuse it.
	form := url.Values{"host": {f.HostName}}
	r := httptest.NewRequest(http.MethodPost, "/open", strings.NewReader(form.Encode()))
	r.Host = testListen
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+testListen)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(f.Server.AuthCookie())

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tokenless POST /open = %d, want 403: the token is what still holds for a client that "+
			"sends no fetch metadata at all", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrBadCSRFToken.Error()) {
		t.Fatalf("tokenless POST refused with %q, want ErrBadCSRFToken", w.Body.String())
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("a refused tokenless POST put %d datagrams on the wire, want 0", n)
	}
}

// #53. A read is authenticated too, so the fleet map -- every host, address and
// grant -- is not served to a caller that cannot prove the session. A local
// process reaching loopback has the right Host and same-origin metadata but no
// session; it used to be able to GET the page and read the CSRF token out of
// its body, and now it cannot.
func TestConsole_Get_RefusedWithoutASession(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testListen
	r.Header.Set("Sec-Fetch-Site", "same-origin") // correct Host and origin: only the session is missing
	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("sessionless GET / = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrUnauthenticated.Error()) {
		t.Fatalf("sessionless GET / refused with %q, want ErrUnauthenticated", w.Body.String())
	}
	if strings.Contains(w.Body.String(), f.HostName) {
		t.Fatal("the fleet map was served to a request with no session; it names hosts the caller " +
			"has no business reading")
	}
}

// #53. The startup token in the URL query authenticates the first request and
// establishes the session cookie, so the operator's browser carries no token on
// later navigation. The cookie is HttpOnly and SameSite=Strict.
func TestConsole_Get_StartupTokenAuthenticatesAndSetsTheSessionCookie(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/?token="+f.Server.StartupToken(), nil)
	r.Host = testListen
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := f.do(r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET with the startup token = %d, want 200\n%s", w.Code, w.Body.String())
	}

	var set *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == f.Server.AuthCookie().Name {
			set = c
		}
	}
	if set == nil {
		t.Fatal("a valid startup token did not establish the session cookie, so every later request " +
			"would have to carry the token in its URL")
	}
	if !set.HttpOnly || set.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie is not HttpOnly+SameSite=Strict, so script could read it or a "+
			"cross-site request could send it: %+v", set)
	}
}

// #53. A wrong startup token is refused. The secret is what a caller must know;
// the right Host and same-origin metadata, which a local process also has, are
// not enough.
func TestConsole_Get_RefusesAWrongStartupToken(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/?token=not-the-startup-secret", nil)
	r.Host = testListen
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET with a wrong startup token = %d, want 403\n%s", w.Code, w.Body.String())
	}
}

func TestConsole_Post_RefusedWithAWrongCSRFToken(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/open", url.Values{
		"host":       {f.HostName},
		"csrf_token": {"not-the-token"},
	})
	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong-token POST /open = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrBadCSRFToken.Error()) {
		t.Fatalf("wrong-token POST refused with %q, want ErrBadCSRFToken", w.Body.String())
	}
}

func TestConsole_Get_RefusedWhenHostHeaderIsForeign(t *testing.T) {
	f := newFixture(t)
	// A GET, deliberately. Only the Host allowlist applies to a read, so a
	// refusal here can have come from nothing else — which is exactly the
	// attribution a rebinding test needs, since the whole point of DNS
	// rebinding is that the browser considers the request same-origin and
	// every origin check is therefore satisfied.
	r := f.wellFormedGet("/")
	r.Host = "rebound.evil.example:8177"

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET / with a foreign Host = %d, want 403: a hostile site that rebinds its own name to "+
			"127.0.0.1 reaches this console past the same-origin policy, and the Host header is the only "+
			"thing left that still carries its name", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrForeignHost.Error()) {
		t.Fatalf("foreign-Host GET refused with %q, want ErrForeignHost", w.Body.String())
	}
}

func TestConsole_Post_RefusedWhenHostHeaderIsForeign(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/open", url.Values{"host": {f.HostName}})
	// A rebound page believes it is same-origin, so it sends no Origin the
	// guard would reject — the header is removed here to model that, leaving
	// the Host allowlist as the only control that can refuse.
	r.Header.Del("Origin")
	r.Host = "rebound.evil.example:8177"

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST /open with a foreign Host = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrForeignHost.Error()) {
		t.Fatalf("foreign-Host POST refused with %q, want ErrForeignHost — a refusal from the Origin or "+
			"token check would mean this test is not exercising the rebinding defence", w.Body.String())
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("a refused foreign-Host POST put %d datagrams on the wire, want 0", n)
	}
}

func TestConsole_Get_CannotOpenAGate(t *testing.T) {
	f := newFixture(t)
	f.unlock(t, "operator")

	// Everything the guard checks is correct, including a valid token in the
	// query string, and the key is unlocked. The only thing wrong is the
	// method — which is what a prefetch, a pasted link, a link-preview
	// crawler and a browser's back button all produce.
	q := url.Values{"host": {f.HostName}, "service": {"ssh"}, "csrf_token": {f.Server.Token()}}
	r := f.wellFormedGet("/open?" + q.Encode())

	w := f.do(r)
	// The datagram count is asserted first, deliberately. It is the property
	// that matters — a GET must not open a gate — and the status code is only
	// evidence for it. Asserting the code first would let a mutation that
	// merely changed which refusal fired look like the same failure as one
	// that put a packet on the wire.
	if n := f.sends.count(); n != 0 {
		t.Fatalf("GET /open put %d datagrams on the wire, want 0: a prefetch, a pasted link or a link "+
			"preview crawler must not be able to open a gate", n)
	}
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /open = %d, want 405", w.Code)
	}
}

func TestConsole_Post_OpenSendsExactlyOneDatagram(t *testing.T) {
	f := newFixture(t)
	f.unlock(t, "operator")

	w := f.do(f.wellFormedPost("/open", url.Values{"host": {f.HostName}, "service": {"ssh"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /open = %d, want 303: %s", w.Code, w.Body.String())
	}
	if n := f.sends.count(); n != 1 {
		t.Fatalf("POST /open put %d datagrams on the wire, want exactly 1", n)
	}
}

func TestConsole_Post_OpenRefusedWhileTheKeyIsLocked(t *testing.T) {
	f := newFixture(t)
	// No unlock. The request is otherwise perfect.
	w := f.do(f.wellFormedPost("/open", url.Values{"host": {f.HostName}, "service": {"ssh"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /open with no key = %d, want a 303 carrying the failure", w.Code)
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("POST /open with no unlocked key put %d datagrams on the wire, want 0", n)
	}
}

func TestConsole_Routes_ExposeNoDisarm(t *testing.T) {
	f := newFixture(t)
	f.unlock(t, "operator")
	for _, path := range []string{"/disarm", "/action/disarm", "/host/" + f.HostName + "/disarm"} {
		w := f.do(f.wellFormedPost(path, url.Values{"host": {f.HostName}}))
		if w.Code != http.StatusNotFound {
			t.Fatalf("POST %s = %d, want 404: a console that could disarm would be a fleet-destruction "+
				"endpoint reachable from any browser tab", path, w.Code)
		}
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("the disarm probes put %d datagrams on the wire, want 0", n)
	}
}

func TestConsole_New_RefusesANonLoopbackBind(t *testing.T) {
	_, err := console.New(console.Config{Listen: "0.0.0.0:8177"})
	if err == nil {
		t.Fatal("console.New(0.0.0.0) succeeded, want a refusal: an unauthenticated fleet-control " +
			"endpoint on every interface is the mistake that actually happens")
	}
}

// Sec-Fetch-Site is a control in its own right, not a spare copy of the Origin
// check, and this is the test that proves it. A request with Sec-Fetch-Site:
// none carries no Origin at all, so the Origin branch cannot refuse it: only
// the Sec-Fetch-Site branch can.
//
// Browsers send Sec-Fetch-Site: none for a request no site initiated, which
// includes an extension acting on the operator's page. The token here is
// valid and the Host is this console's own, so a refusal can only be the
// fetch-metadata check doing its job. Removing that branch makes this request
// succeed, which is what the older RefusedWhenCrossSite test could not show,
// because it also set a foreign Origin and the Origin branch did the work.
func TestConsole_Post_RefusedWhenSecFetchSiteIsNoneWithNoOrigin(t *testing.T) {
	f := newFixture(t)
	r := f.wellFormedPost("/open", url.Values{"host": {f.HostName}})
	r.Header.Del("Origin")
	r.Header.Set("Sec-Fetch-Site", "none")

	w := f.do(r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST /open with Sec-Fetch-Site: none and no Origin = %d, want 403: this request has a "+
			"valid token and this console's own Host, so nothing but the Sec-Fetch-Site check can refuse "+
			"it, and an extension issuing it must not be able to knock a production host", w.Code)
	}
	if !strings.Contains(w.Body.String(), console.ErrCrossSite.Error()) {
		t.Fatalf("refused with %q, want ErrCrossSite", w.Body.String())
	}
	if n := f.sends.count(); n != 0 {
		t.Fatalf("a refused Sec-Fetch-Site: none POST put %d datagrams on the wire, want 0", n)
	}
}
