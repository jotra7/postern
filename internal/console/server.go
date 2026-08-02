package console

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

// Server timeouts. The console is local and its requests are small, but a
// knock's confirmation connect can legitimately take several seconds
// (client.DefaultConnectTimeout times client.DefaultConnectAttempts), so the
// write timeout is the one bound that has to be generous.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 1 << 16
	shutdownTimeout   = 5 * time.Second
)

// Config is everything a console needs from outside itself. Every path is
// supplied by the caller: nothing under internal/ knows where an operator
// keeps their files.
type Config struct {
	// Listen is the --listen value, checked by ResolveBind.
	Listen string
	// InventoryPath is the fleet inventory YAML.
	InventoryPath string
	// OutDir is where `postern sign` writes bundles and index.json.
	OutDir string
	// HubURL is a hub's public listener, empty when there is none.
	HubURL string
	// ClientConfig is the operator's own config, or nil. A console with no
	// client config can still show the fleet and sign; it cannot knock.
	ClientConfig *client.Config
	// OperatorKeyFile and SignerKeyFile are the two key files the unlock form
	// may open. OperatorKeyFile defaults to the client config's own.
	OperatorKeyFile string
	SignerKeyFile   string

	// IdleTimeout bounds how long an unlocked key is held. Zero selects
	// DefaultIdleTimeout.
	IdleTimeout time.Duration
	// LiveMaxAge is how old a status observation may be before the fleet view
	// calls it cold. Zero selects DefaultLiveMaxAge.
	LiveMaxAge time.Duration

	// HTTP is the client used to reach the hub. Nil selects a default.
	HTTP *http.Client
	// Send, Dial and Exchange are the network seams internal/client already
	// exposes, injected so every handler is testable without a socket. Nil
	// selects the production implementation.
	Send     client.Sender
	Dial     client.Dialer
	Exchange client.Exchanger
	// Now is the clock. Nil selects time.Now.
	Now func() time.Time
}

// Server is the console. It is built by New and served by Serve; a test can
// hand Handler() to httptest instead.
type Server struct {
	cfg   Config
	src   *sources
	keys  *Keyring
	guard *guard
	live  *liveStore
	mux   *http.ServeMux

	mu    sync.Mutex
	flash *Flash
}

// Flash is the result of the last state-changing request, held so a POST can
// redirect to a GET that renders it.
//
// Post/redirect/get rather than rendering the result straight from the POST,
// because the POST here sends real datagrams: a rendered POST response turns
// the browser's reload button into a second knock, and on the confirm route
// into a second ratification of a transaction the operator approved once.
type Flash struct {
	// OK is false when the operation failed. It drives nothing but styling.
	OK bool
	// Title is one line, e.g. "knock sent to web-01".
	Title string
	// Lines is the body: the diagnosis `postern open` prints, one line each.
	Lines []string
	// Next and Verify are the two commands the client's own Advice carries.
	Next   string
	Verify string
}

// New builds a console. It resolves the bind address first, because the port
// is what the CSRF guard's Host and Origin allowlists are built around: a
// guard that did not know the port could not tell this console's own origin
// from a rebinding attack that guessed another one.
func New(cfg Config) (*Server, error) {
	addr, err := ResolveBind(cfg.Listen)
	if err != nil {
		return nil, err
	}
	g, err := newGuard(addr.Port())
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:   cfg,
		keys:  NewKeyring(cfg.IdleTimeout, cfg.Now),
		guard: g,
		live:  newLiveStore(),
		src: &sources{
			inventoryPath: cfg.InventoryPath,
			outDir:        cfg.OutDir,
			clientCfg:     cfg.ClientConfig,
			hub:           HubClient{BaseURL: cfg.HubURL, HTTP: cfg.HTTP},
			liveMaxAge:    cfg.LiveMaxAge,
			now:           cfg.Now,
		},
	}
	s.mux = s.routes()
	return s, nil
}

// Handler returns the console's http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Token returns this process's CSRF token. Exported for tests, which have to
// send a valid one in order to prove that some OTHER control is the thing
// doing the rejecting.
func (s *Server) Token() string { return s.guard.token }

// StartupToken returns the one-time authentication secret. `postern ui` puts it
// in the URL it prints, and a browser presenting it establishes the session
// cookie (see guard.authenticate). It is not the CSRF token: this is what a
// request must carry to be served at all, read or write.
func (s *Server) StartupToken() string { return s.guard.secret }

// AuthCookie returns a session cookie that authenticates a request, so a test
// (or any caller already holding StartupToken) can drive the console the way a
// browser does after its first visit, without threading the token through
// every request's query string.
func (s *Server) AuthCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookie, Value: s.guard.secret}
}

// Keys exposes the keyring so the caller can lock everything on shutdown.
func (s *Server) Keys() *Keyring { return s.keys }

// routes registers every path.
//
// The split between GET and POST here is a security control, not a
// convention: every route that sends a datagram, ratifies a change, or writes
// a bundle is registered POST-only, so a prefetch, a pasted link, a link
// preview crawler or a browser's back button cannot reach one. The
// method-qualified patterns mean an unmatched method is refused by the mux
// before any handler runs, and stateChanging() refuses it again at the guard
// — the second check is what would still catch a route registered without a
// method one day.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", s.read(s.handleFleet))
	mux.Handle("GET /host/{name}", s.read(s.handleHost))
	mux.Handle("GET /deploy", s.read(s.handleDeploy))
	mux.Handle("GET /assets/{file}", s.read(s.handleAsset))

	mux.Handle("POST /unlock", s.act(s.handleUnlock))
	mux.Handle("POST /lock", s.act(s.handleLock))
	mux.Handle("POST /open", s.act(s.handleOpen))
	mux.Handle("POST /confirm", s.act(s.handleConfirm))
	mux.Handle("POST /status", s.act(s.handleStatus))
	mux.Handle("POST /status-all", s.act(s.handleStatusSweep))
	mux.Handle("POST /sign", s.act(s.handleSign))

	// Every state-changing path is also registered for every other method, so
	// a GET to one is refused by this console's own guard with a reason
	// rather than by the mux with a bare 405 that says nothing about why.
	for _, p := range []string{"/unlock", "/lock", "/open", "/confirm", "/status", "/status-all", "/sign"} {
		mux.Handle(p, s.act(nil))
	}
	return mux
}

// read wraps a handler that changes nothing. The Host allowlist still
// applies: a rebound page that could merely read the fleet view would have
// read every host name, address and grant in the fleet.
func (s *Server) read(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.guard.check(w, r, false); err != nil {
			s.refuse(w, err)
			return
		}
		h(w, r)
	})
}

// act wraps a handler that changes something. A nil handler is the
// wrong-method case: the guard refuses it before anything else looks at the
// request.
func (s *Server) act(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.guard.check(w, r, true); err != nil {
			s.refuse(w, err)
			return
		}
		if h == nil {
			s.refuse(w, fmt.Errorf("%w: got %s", ErrActionNeedsPOST, r.Method))
			return
		}
		h(w, r)
	})
}

// refuse writes a refusal. The body is the reason and nothing else: the
// caller being refused is by definition not the operator, and the operator
// sees the same reason in the console's own log line.
func (s *Server) refuse(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), refusalStatus(err))
}

func (s *Server) setFlash(f *Flash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flash = f
}

// takeFlash returns the pending flash and clears it, so a reload of the page
// it redirected to does not show a stale result as if it were new.
func (s *Server) takeFlash() *Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flash
	s.flash = nil
	return f
}

func (s *Server) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// ---- read handlers ----

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	v := s.src.fleet(r.Context(), s.live)
	s.render(w, "fleet.html", s.page("fleet", v, nil))
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v := s.src.fleet(r.Context(), s.live)
	for i := range v.Hosts {
		if v.Hosts[i].Name == name {
			s.render(w, "host.html", s.page("host "+name, v, &v.Hosts[i]))
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	s.render(w, "fleet.html", s.page("fleet", v, nil))
}

func (s *Server) handleDeploy(w http.ResponseWriter, _ *http.Request) {
	p := s.src.planDeploy()
	pg := s.page("deploy", FleetView{InventoryPath: s.cfg.InventoryPath, OutDir: s.cfg.OutDir, HubURL: s.cfg.HubURL}, nil)
	pg.Plan = &p
	s.render(w, "deploy.html", pg)
}

// ---- action handlers ----

// handleUnlock decrypts one key file into the keyring.
//
// The passphrase arrives in a form body and is used once. It is not stored,
// not echoed back into the page, and not put into a flash — the flash for a
// successful unlock names the slot and the operator, both of which are public
// material `postern operator init` already prints.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	slot := Slot(r.PostForm.Get("slot"))
	path, err := s.keyPath(slot)
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	pass := []byte(r.PostForm.Get("passphrase"))
	if err := s.keys.Unlock(slot, path, pass); err != nil {
		if errors.Is(err, identity.ErrIncorrectPassphrase) {
			s.fail(w, r, fmt.Sprintf("the passphrase for %s is wrong (or the file is corrupt)", path))
			return
		}
		s.fail(w, r, err.Error())
		return
	}
	s.setFlash(&Flash{OK: true, Title: fmt.Sprintf("%s key unlocked from %s", slot, path),
		Lines: []string{fmt.Sprintf("it is held in memory only and is dropped after %s idle", s.idleWindow())}})
	s.back(w, r)
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	if slot := Slot(r.PostForm.Get("slot")); slot != "" {
		s.keys.Lock(slot)
		s.setFlash(&Flash{OK: true, Title: string(slot) + " key locked"})
	} else {
		s.keys.LockAll()
		s.setFlash(&Flash{OK: true, Title: "every key locked"})
	}
	s.back(w, r)
}

// handleOpen knocks a host and confirms, exactly as `postern open` does.
func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	host, err := s.clientHost(r.PostForm.Get("host"))
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	service := r.PostForm.Get("service")
	if service == "" {
		service = host.RecoveryService
	}
	if service == "" {
		s.fail(w, r, fmt.Sprintf("host %q has no recovery_service, so there is no default service to open — name one", host.Name))
		return
	}
	var asserted *netip.Prefix
	if raw := strings.TrimSpace(r.PostForm.Get("source_cidr")); raw != "" {
		p, perr := netip.ParsePrefix(raw)
		if perr != nil {
			s.fail(w, r, fmt.Sprintf("source CIDR %q: %v", raw, perr))
			return
		}
		asserted = &p
	}
	var ttl time.Duration
	if raw := strings.TrimSpace(r.PostForm.Get("ttl")); raw != "" {
		d, derr := time.ParseDuration(raw)
		if derr != nil {
			s.fail(w, r, fmt.Sprintf("ttl %q: %v", raw, derr))
			return
		}
		ttl = d
	}
	signer, err := s.keys.Signer(SlotOperator)
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}

	var counter *client.Counter
	if s.cfg.ClientConfig != nil {
		counter = client.NewCounter(s.cfg.ClientConfig.CounterFilePath())
	}
	rep, err := client.Open(r.Context(), client.OpenOptions{
		Builder: client.Builder{Signer: signer},
		Host:    host,
		Service: service,
		TTL:     ttl,
		// SourceCIDR is the CGNAT mitigation and the only thing on this form
		// that changes what the packet asserts.
		SourceCIDR: asserted,
		Counter:    counter,
		Send:       s.cfg.Send,
		Dial:       s.cfg.Dial,
	})

	f := &Flash{OK: err == nil && rep.Result.Outcome == client.Connected}
	if rep.KnockAddr.IsValid() {
		verb := "sent"
		if !rep.Sent.Delivered {
			verb = "NOT sent"
		}
		f.Title = fmt.Sprintf("knock %s to %s (%s/%s, ttl %s)", verb, rep.KnockAddr, rep.Sent.Host, rep.Sent.Service, rep.Sent.TTL)
	} else {
		f.Title = "the knock was not built"
	}
	if err != nil {
		f.Lines = append(f.Lines, err.Error())
	}
	if rep.Advice.Summary != "" {
		f.Lines = append(f.Lines, string(rep.Result.Outcome)+": "+rep.Advice.Summary)
	}
	if rep.Advice.Detail != "" {
		f.Lines = append(f.Lines, rep.Advice.Detail)
	}
	f.Next = rep.Advice.Hint
	f.Verify = rep.Advice.Verify
	if f.OK && host.SSH.Host != "" {
		f.Lines = append(f.Lines, "then: "+clientSSHCommand(host))
	}
	s.setFlash(f)
	s.back(w, r)
}

// handleConfirm ratifies one pending transaction. Both the revision and the
// nonce are required and neither has a default, for the reason `postern
// confirm` spells out: an unbound confirm ratifies whatever happens to be
// pending when it lands, which is the wrong thing by construction.
func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	host, err := s.clientHost(r.PostForm.Get("host"))
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	revRaw := strings.TrimSpace(r.PostForm.Get("revision"))
	if revRaw == "" {
		s.fail(w, r, "a revision is required: it is half the binding, and a confirm carrying the wrong "+
			"revision is refused by the agent in silence")
		return
	}
	revision, perr := strconv.ParseUint(revRaw, 10, 64)
	if perr != nil {
		s.fail(w, r, fmt.Sprintf("revision %q: %v", revRaw, perr))
		return
	}
	nonce, nerr := decodeNonce(strings.TrimSpace(r.PostForm.Get("nonce")))
	if nerr != nil {
		s.fail(w, r, nerr.Error())
		return
	}
	signer, err := s.keys.Signer(SlotOperator)
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	b := client.Builder{Signer: signer}
	rep, err := client.SendAction(r.Context(), client.ActionOptions{
		Builder: b, Host: host, Sends: client.DefaultActionSends, Send: s.cfg.Send,
	}, func(nowMS uint64) (*spa.Request, error) { return b.Confirm(host, revision, nonce, nowMS) })
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	s.setFlash(&Flash{
		OK:    rep.Sent > 0,
		Title: fmt.Sprintf("confirm sent to %s (%s, revision %d), %d of %d datagrams", rep.To, host.Name, revision, rep.Sent, rep.Attempted),
		Lines: []string{
			"the SPA path never answers, so this reports only that the datagrams left. " +
				"The confirmation landed if the agent's dead-man timer does not revert the change.",
		},
	})
	s.back(w, r)
}

// liveness runs the two status assertions against one host and reduces the
// result to a LiveState, which is what the fleet view's live column reads.
//
// A client.Status error — a host with no host_signing key, a recovery service
// the entry does not define, a transport failure the client surfaces as an
// error — becomes an unhealthy reading rather than an abort. The per-host
// handler observes one host and can report the error directly; the sweep has
// other hosts to reach, and "checked and bad" is a reading it must still
// record. Folding the error in here is what lets both callers share the walk.
func (s *Server) liveness(ctx context.Context, signer identity.Signer, host *client.Host) LiveState {
	rep, err := client.Status(ctx, client.StatusOptions{
		Builder:  client.Builder{Signer: signer},
		Host:     host,
		Exchange: s.cfg.Exchange,
		Dial:     s.cfg.Dial,
	})
	if err != nil {
		return LiveState{Checked: s.now(), PongErr: err.Error()}
	}
	st := LiveState{
		Checked:         s.now(),
		Pong:            rep.Pong,
		PongRTT:         rep.PongRTT,
		ClockSkew:       rep.ClockSkew,
		RecoveryService: rep.RecoveryService,
		Recovery:        string(rep.Recovery.Outcome),
		Healthy:         rep.Healthy(),
	}
	if rep.PongErr != nil {
		st.PongErr = rep.PongErr.Error()
	}
	return st
}

// handleStatus runs the two liveness assertions against one host and records
// the result, then reports the same detailed diagnosis `postern status`
// prints. It reads the reading back out of the recorded LiveState rather than
// from the report, so the page and the flash can never disagree about what was
// observed.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	host, err := s.clientHost(r.PostForm.Get("host"))
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	signer, err := s.keys.Signer(SlotOperator)
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	st := s.liveness(r.Context(), signer, host)
	s.live.set(host.Name, st)

	f := &Flash{OK: st.Healthy, Title: "status " + host.Name}
	if st.Pong {
		f.Lines = append(f.Lines, fmt.Sprintf("liveness ok: signed pong in %s, host clock skew %s", st.PongRTT, st.ClockSkew))
	} else {
		f.Lines = append(f.Lines, "liveness FAIL: "+st.PongErr)
	}
	switch {
	case st.RecoveryService == "":
		f.Lines = append(f.Lines, "recovery: no recovery_service configured for this host")
	case st.Recovery == string(client.Connected):
		f.Lines = append(f.Lines, "recovery ok: "+st.RecoveryService+" reachable on the always-allow path")
	default:
		f.Lines = append(f.Lines,
			fmt.Sprintf("recovery FAIL: %s: %s", st.RecoveryService, st.Recovery),
			"a pong proves the mesh routes UDP to the agent; it says nothing about the port you would "+
				"actually recover with. Mesh ACLs are routinely written per port.")
	}
	s.setFlash(f)
	s.back(w, r)
}

// handleStatusSweep runs the liveness check against every knockable host at
// once, so an operator watching a rollout does not have to walk the fleet a
// row at a time.
//
// The operator key is fetched once and refused up front: a sweep signs a
// liveness ping per host with it, so a locked key means there is nothing to
// do, and refusing before the walk is what keeps it from recording a wall of
// identical failures. Past that, no single host aborts the rest — a host that
// cannot be reached is a reading the fleet view still wants — and the flash is
// a count rather than a diagnosis, because the per-host rows carry the detail.
func (s *Server) handleStatusSweep(w http.ResponseWriter, r *http.Request) {
	signer, err := s.keys.Signer(SlotOperator)
	if err != nil {
		s.fail(w, r, "unlock the operator key to sweep liveness")
		return
	}
	if s.cfg.ClientConfig == nil {
		s.fail(w, r, "no client config is loaded, so there is no fleet to sweep")
		return
	}
	hosts := s.cfg.ClientConfig.Hosts
	healthy := 0
	for i := range hosts {
		st := s.liveness(r.Context(), signer, &hosts[i])
		s.live.set(hosts[i].Name, st)
		if st.Healthy {
			healthy++
		}
	}
	n := len(hosts)
	s.setFlash(&Flash{
		OK:    n > 0 && healthy == n,
		Title: fmt.Sprintf("swept %d hosts", n),
		Lines: []string{fmt.Sprintf("%d healthy, %d unhealthy", healthy, n-healthy)},
	})
	s.back(w, r)
}

// handleSign compiles the inventory and writes sealed bundles.
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	signer, err := s.keys.Signer(SlotSigner)
	if err != nil {
		s.fail(w, r, err.Error())
		return
	}
	res := s.src.runDeploy(signer)
	if res.Err != "" {
		s.fail(w, r, res.Err)
		return
	}
	s.setFlash(&Flash{
		OK:    true,
		Title: fmt.Sprintf("%d bundles written to %s at version %d, signed as %s", len(res.Hosts), res.OutDir, res.Version, res.Signer),
		Lines: []string{"nothing is deployed until an agent pulls", strings.Join(res.Hosts, ", ")},
	})
	s.back(w, r)
}

// ---- helpers ----

func (s *Server) idleWindow() time.Duration {
	if s.cfg.IdleTimeout > 0 {
		return s.cfg.IdleTimeout
	}
	return DefaultIdleTimeout
}

func (s *Server) keyPath(slot Slot) (string, error) {
	switch slot {
	case SlotOperator:
		if s.cfg.OperatorKeyFile != "" {
			return s.cfg.OperatorKeyFile, nil
		}
		if s.cfg.ClientConfig != nil {
			return s.cfg.ClientConfig.KeyFilePath(), nil
		}
		return "", errors.New("no operator key file is configured and there is no client config to take one from")
	case SlotSigner:
		if s.cfg.SignerKeyFile != "" {
			return s.cfg.SignerKeyFile, nil
		}
		return "", errors.New("no bundle-signing key file is configured; pass --sign-key")
	default:
		return "", fmt.Errorf("unknown key slot %q", slot)
	}
}

func (s *Server) clientHost(name string) (*client.Host, error) {
	if s.cfg.ClientConfig == nil {
		return nil, errors.New("no client config is loaded, so there is nothing to knock")
	}
	return s.cfg.ClientConfig.Host(name)
}

// fail records a failed action and redirects, so every outcome reaches the
// operator the same way.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, msg string) {
	s.setFlash(&Flash{Title: msg})
	s.back(w, r)
}

// back redirects to the page the form was on. The target comes from a form
// field this console rendered, and is checked against the shape of a console
// path — a redirect target taken from a request is how an open redirect gets
// built, even on a page nobody else can reach.
func (s *Server) back(w http.ResponseWriter, r *http.Request) {
	target := "/"
	if v := r.PostForm.Get("return_to"); strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") &&
		!strings.ContainsAny(v, "\\\r\n") {
		target = v
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func clientSSHCommand(h *client.Host) string {
	target := h.SSH.Host
	if h.SSH.User != "" {
		target = h.SSH.User + "@" + target
	}
	if h.SSH.Port != 0 && h.SSH.Port != 22 {
		return fmt.Sprintf("ssh -p %d %s", h.SSH.Port, target)
	}
	return "ssh " + target
}

func decodeNonce(s string) ([16]byte, error) {
	var out [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("nonce %q is not hex: %w", s, err)
	}
	if len(raw) != 16 {
		return out, fmt.Errorf("nonce is %d bytes, want 16 (32 hex characters)", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// Serve runs the console until ctx is cancelled, and locks every key on the
// way out.
func Serve(ctx context.Context, cfg Config) (string, func() error, error) {
	s, err := New(cfg)
	if err != nil {
		return "", nil, err
	}
	addr, err := ResolveBind(cfg.Listen)
	if err != nil {
		return "", nil, err
	}
	ln, err := Listen(addr)
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()
	wait := func() error {
		var runErr error
		cancelled := false
		select {
		case <-ctx.Done():
			cancelled = true
		case runErr = <-serveErr:
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		// The decrypted keys go before this function returns, whichever way
		// it is leaving.
		s.keys.LockAll()
		if cancelled {
			<-serveErr
			return nil
		}
		return runErr
	}
	// The token is in the printed URL, not just the origin: the first click
	// authenticates and sets the session cookie, so the operator never has to
	// copy a secret by hand. base64url is URL-safe, so it needs no escaping.
	url := originOf(ln.Addr().String()) + "/?" + authTokenParam + "=" + s.StartupToken()
	return url, wait, nil
}
