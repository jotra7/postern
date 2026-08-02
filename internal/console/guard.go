package console

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// The five refusals below are the whole reason this file exists, and each one
// stops a different attack. They are checked in a fixed order and none of them
// substitutes for another — a test that removes any single one, leaving the
// other four in place, has to see the request get through.
var (
	// ErrForeignHost means the Host header named something outside the
	// allowlist. This is the DNS rebinding refusal: a hostile site rebinds
	// its own name to 127.0.0.1, the browser then treats requests to that
	// name as same-origin, and every origin check below sees a request it is
	// happy with. The Host header is the one thing that still carries the
	// attacker's name, so it is the one thing that can refuse them.
	ErrForeignHost = errors.New("console: request Host is not this console's own address")

	// ErrCrossSite means Sec-Fetch-Site said this request came from another
	// site, or Origin named one. Browsers set these; a page on evil.example
	// cannot suppress or forge them.
	ErrCrossSite = errors.New("console: refusing a cross-site state-changing request")

	// ErrBadCSRFToken means the per-session token was missing or wrong. This
	// is what still holds when a client sends no fetch metadata at all —
	// an older browser, a non-browser client — because the token is minted
	// per console process and only ever handed out in a page body, which the
	// same-origin policy stops a hostile site from reading.
	ErrBadCSRFToken = errors.New("console: missing or incorrect CSRF token")

	// ErrActionNeedsPOST means a state-changing route was reached with a
	// method that must never change state. A prefetch, a pasted link, a link
	// preview crawler and a browser's back button all issue GETs.
	ErrActionNeedsPOST = errors.New("console: this action is POST-only")

	// ErrUnauthenticated means the request carried neither the session cookie
	// nor the one-time startup token. It is the authentication the CSRF token
	// is not: the token is only ever handed out in a page body and same-origin
	// policy keeps a hostile SITE from reading it, but that does nothing to a
	// local PROCESS, which reaches loopback directly and can GET the same body.
	// The startup secret closes that: it is printed once to the operator's
	// terminal and nothing on the machine but the operator's own browser (which
	// the operator hands it to) ever learns it. It gates reads as well as
	// writes, so the fleet map is not served to a caller that cannot prove it.
	ErrUnauthenticated = errors.New("console: no valid session; open the URL postern printed, which carries the one-time startup token")
)

// csrfHeader is where a fetch() caller puts the token; csrfField is where a
// form puts it. Both are accepted and both are checked the same way.
const (
	csrfHeader = "X-Postern-CSRF"
	csrfField  = "csrf_token"

	// sessionCookie holds the startup secret once the operator's browser has
	// presented it. HttpOnly keeps script from reading it and SameSite=Strict
	// keeps a cross-site request from carrying it; a local process cannot read
	// another program's cookie jar, so it never obtains the value at all.
	sessionCookie = "postern_console_session"
	// authTokenParam is where the operator's browser first presents the startup
	// secret: the query string of the URL postern printed. A match establishes
	// the session cookie, so it appears in the URL once and not on every click.
	authTokenParam = "token"

	// maxFormBytes bounds a state-changing request body before it is parsed.
	maxFormBytes = 64 << 10

	// opaqueOrigin is what a browser puts in Origin when the document has no
	// origin it can name. See checkFetchMetadata for why it is read as
	// absence rather than as a foreign site.
	opaqueOrigin = "null"
)

// guard applies every request-level refusal. It is built once, at startup,
// around the port the console actually bound — the allowlist has to name that
// port, or a rebinding attack that guessed a different one would be waved
// through on the name alone.
type guard struct {
	// token is the CSRF token, minted once per console process. It is
	// same-origin write protection, not authentication: see ErrBadCSRFToken and
	// ErrUnauthenticated for the difference and why both exist.
	token string
	// secret is the authentication token, minted once per console process and
	// printed to the operator's terminal at startup. It gates every request,
	// read or write. See ErrUnauthenticated.
	secret string
	// hosts is the set of Host header values this console answers to.
	hosts map[string]bool
	// origins is the set of Origin header values it accepts.
	origins map[string]bool
}

// newGuard builds the guard for a console bound to port.
func newGuard(port uint16) (*guard, error) {
	token, err := mintToken()
	if err != nil {
		return nil, err
	}
	secret, err := mintToken()
	if err != nil {
		return nil, err
	}
	p := strconv.Itoa(int(port))
	g := &guard{
		token:   token,
		secret:  secret,
		hosts:   map[string]bool{},
		origins: map[string]bool{},
	}
	// Exactly the three spellings of "this machine" a browser can produce for
	// a loopback bind, each with the console's own port. Anything else — a
	// name that resolves here, a bare address with no port, a different port
	// — is refused, because a rebinding attack arrives as a name that
	// resolves here.
	for _, h := range []string{"127.0.0.1", "localhost", "[::1]"} {
		g.hosts[h+":"+p] = true
		g.origins["http://"+h+":"+p] = true
		g.origins["https://"+h+":"+p] = true
	}
	return g, nil
}

// mintToken draws a 256-bit CSRF token.
func mintToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("console: mint CSRF token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// checkHost applies the Host allowlist. It runs on every request, not only on
// the state-changing ones: a rebound page that could merely READ the fleet
// view would still have read every host name, address and grant in the fleet.
func (g *guard) checkHost(r *http.Request) error {
	if g.hosts[r.Host] {
		return nil
	}
	// Normalise a Host that carries no port: net.SplitHostPort fails on it,
	// and a bare "localhost" is not in the allowlist on purpose — the
	// allowlist is port-qualified. Reported with the value so an operator who
	// has genuinely proxied the console can see what arrived.
	return fmt.Errorf("%w: %q", ErrForeignHost, r.Host)
}

// checkFetchMetadata applies the browser's own account of where the request
// came from.
//
// Two headers, deliberately, because they fail in different places. A browser
// that sets Sec-Fetch-Site tells us directly that the initiator was another
// site, which catches a cross-origin form POST even though a form POST is not
// subject to CORS preflight and would otherwise be delivered. Origin is set
// on every cross-origin POST by every browser that has existed for a decade,
// including ones with no fetch metadata at all.
//
// Absence is not refused here, and that is the whole reason this is not the
// only control: a client that sends neither header is refused by the token
// instead. Refusing on absence would break nothing an operator does and
// protect nothing an attacker cannot already do — a hostile page cannot
// suppress these headers — while a token a hostile page cannot read is what
// actually closes the case.
//
// The literal string "null" is treated as absence for the same reason. It is
// what a browser sends when the document's origin is opaque: a sandboxed
// iframe, a page from data: or file:, or a request that crossed origins on a
// redirect. It says no more than a missing header does, and it is stopped by
// the same thing, since none of those contexts has same-origin access to the
// page carrying the token. Refusing it while letting absence through would
// refuse a real operator whose browser produced an opaque origin and would
// stop nobody, which is what it did the first time an operator met it.
func (g *guard) checkFetchMetadata(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return fmt.Errorf("%w: Sec-Fetch-Site: %s", ErrCrossSite, site)
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != opaqueOrigin && !g.origins[origin] {
		return fmt.Errorf("%w: Origin: %s", ErrCrossSite, origin)
	}
	return nil
}

// authenticate proves the request came from the operator this console was
// started for, and it runs on every request rather than only the
// state-changing ones: a caller that cannot authenticate must not READ the
// fleet map either, since it names every host, address and grant in the fleet.
//
// The established session is a cookie holding the startup secret. The first
// request instead presents the secret in the URL's query string, the one
// postern printed, and a match sets the cookie so later navigation carries no
// token. The cookie is HttpOnly and SameSite=Strict: script cannot read it and
// a cross-site request cannot send it, and a local process cannot reach another
// program's cookie jar, so none of the three ways the threat model cares about
// obtains the secret.
func (g *guard) authenticate(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(sessionCookie); err == nil &&
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(g.secret)) == 1 {
		return nil
	}
	if tok := r.URL.Query().Get(authTokenParam); tok != "" &&
		subtle.ConstantTimeCompare([]byte(tok), []byte(g.secret)) == 1 {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    g.secret,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		return nil
	}
	return ErrUnauthenticated
}

// checkToken compares the request's token against this process's own, in
// constant time.
func (g *guard) checkToken(r *http.Request) error {
	got := r.Header.Get(csrfHeader)
	if got == "" {
		got = r.PostFormValue(csrfField)
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(g.token)) != 1 {
		return ErrBadCSRFToken
	}
	return nil
}

// check runs every refusal that applies to r.
//
// The order is host, then authentication, then method, then fetch metadata,
// then token. It matters only for which error an operator sees first; each
// check is independent, and none of them is reached by a request the one before
// it should have stopped. Host precedes authentication so a rebinding attempt
// is named as one rather than as a missing session.
func (g *guard) check(w http.ResponseWriter, r *http.Request, stateChanging bool) error {
	if err := g.checkHost(r); err != nil {
		return err
	}
	// Authentication, before reads are served and before writes are considered:
	// the fleet map is not handed to a caller that cannot prove the session.
	if err := g.authenticate(w, r); err != nil {
		return err
	}
	if !stateChanging {
		return nil
	}
	if r.Method != http.MethodPost {
		return fmt.Errorf("%w: got %s", ErrActionNeedsPOST, r.Method)
	}
	// Bounded before it is parsed. Every field this console reads is a host
	// name, a duration, a prefix or a passphrase, so maxFormBytes is orders of
	// magnitude more than any real request — the cap is here so a body that is
	// not a real request cannot make this process allocate without limit.
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	// ParseForm before the token check so a form-encoded token is visible to
	// it, and after the method check so a GET's query string can never supply
	// one. r.PostFormValue reads only the body.
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("console: parse form: %w", err)
	}
	if err := g.checkFetchMetadata(r); err != nil {
		return err
	}
	return g.checkToken(r)
}

// status maps a refusal to the response code it gets. 405 for a wrong method
// so a browser's own error is accurate; 403 for everything else, with no
// detail beyond the reason, because the caller being refused is by definition
// not the operator.
func refusalStatus(err error) int {
	if errors.Is(err, ErrActionNeedsPOST) {
		return http.StatusMethodNotAllowed
	}
	return http.StatusForbidden
}

// originOf renders the console's own origin, for the line `postern ui`
// prints so an operator has a URL to click. net.JoinHostPort re-brackets an
// IPv6 literal that SplitHostPort stripped.
func originOf(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	return u.String()
}
