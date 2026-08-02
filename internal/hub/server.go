package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jotra7/postern/internal/attest"
	"github.com/jotra7/postern/internal/metrics"
)

// Config configures Serve.
type Config struct {
	// Addr is the public bundle-and-heartbeat listener.
	Addr string
	// MetricsAddr is a separate address for the private listener: /metrics
	// and the per-host freshness document on BeatsPath, neither of which the
	// public listener may ever carry. It must never equal
	// Addr — Serve refuses to start if it does — and, unlike Addr, is
	// resolved through internal/metrics's bind rules: an empty host means
	// loopback, a wildcard or a hostname is refused. A hub's metrics
	// endpoint has no "always-allow interface" to prefer the way an agent's
	// does, so it uses metrics.ResolveProbeBind rather than
	// metrics.ResolveBind — the same rule `postern probe --metrics-listen`
	// uses, for the same reason: there is no host-specific interface to
	// consult, only the operator's own mistake to catch.
	MetricsAddr string
	// TLSCertFile and TLSKeyFile, both set, turn on TLS for the public
	// listener. Both empty means plain HTTP. Exactly one set is a startup
	// error — see Serve.
	TLSCertFile string
	TLSKeyFile  string
	// StoreDir is passed to OpenStore.
	StoreDir string
	// BeatMaxAge is how old a host's last accepted beat may be before it is
	// no longer fresh. Nothing in this package enforces it — Beats.Latest
	// returns the age-bearing timestamp and leaves the comparison to the
	// caller — but it is carried on Config because it is exactly the kind
	// of fleet-wide policy a hub's own operator sets, and a later consumer
	// of Beats.Latest (a status command, a metrics gauge) needs it from
	// somewhere. The freshness document on BeatsPath is not that consumer
	// either: it publishes each host's age and leaves the threshold with
	// whatever is reading, so one operator's idea of stale is not baked into
	// the only answer the hub gives.
	BeatMaxAge time.Duration
}

// Public listener timeouts. This listener has no authentication in front of
// it by design (design section 6: the bundle fetch is meant to work
// unauthenticated), so it is public in the fullest sense, and every bound
// below exists so a stuck or hostile client cannot pin a file descriptor or
// a goroutine on the hub indefinitely.
const (
	publicReadHeaderTimeout = 5 * time.Second
	publicReadTimeout       = 10 * time.Second
	publicWriteTimeout      = 10 * time.Second
	publicMaxHeaderBytes    = 1 << 16 // 64 KiB
	publicShutdownTimeout   = 5 * time.Second

	// maxHeartbeatBody bounds the request body http.MaxBytesReader admits
	// for POST /heartbeat: attest.FixedLen covers the fixed header and
	// signature, attest.MaxBodyLen the JSON body it wraps. A request over
	// this can never decode as a beat regardless, so it is rejected before
	// a single byte past the limit is read into memory.
	maxHeartbeatBody = int64(attest.FixedLen + attest.MaxBodyLen)
)

// server holds what the handlers on both listeners need. It has no lock of
// its own beyond what Store and Beats already carry, since every field here is
// either immutable after construction or already safe for concurrent use.
type server struct {
	store   *Store
	beats   *Beats
	metrics *Metrics
	now     func() time.Time
	// since is when this process started keeping beats, published by
	// handleBeats so a reader can tell a quiet host from a hub that has only
	// just come back. Beats holds nothing across a restart (see doc.go), so
	// without it every host looks like it has never reported for the first
	// interval after one.
	since time.Time
}

// newMux builds the public listener's routes: exactly these two patterns,
// and nothing else. There is no catch-all handler registered on this mux —
// http.ServeMux's own default response to an unmatched pattern is 404, which
// is what design section 8's "the public listener serves only per-host
// sealed bundles and heartbeat ingest" requires for every other path.
//
// BeatsPath is the one to keep an eye on when this list is next edited. It
// answers the same question a bundle fetch does, which host_ids exist, and it
// also says which of them stopped answering. That second half is why it
// belongs to privateRoutes.
func newMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /bundle/{host_id}", s.handleBundle)
	mux.HandleFunc("POST /heartbeat", s.handleHeartbeat)
	return mux
}

// handleBundle serves the sealed bytes on file for the host_id path element,
// to anyone who asks — see doc.go for why that is safe.
func (s *server) handleBundle(w http.ResponseWriter, r *http.Request) {
	hostID, err := ParseHostID(r.PathValue("host_id"))
	if err != nil {
		s.metrics.BundleFetch("invalid_host_id")
		http.NotFound(w, r)
		return
	}
	sealed, err := s.store.Bundle(hostID)
	if err != nil {
		if errors.Is(err, ErrNoBundle) {
			s.metrics.BundleFetch("not_found")
			http.NotFound(w, r)
			return
		}
		// A read error that is not "absent" (permissions, disk I/O) is the
		// hub's own problem, not the caller's, but the response tells an
		// unauthenticated caller nothing beyond "internal error" — the same
		// opacity the not-found path already gives.
		s.metrics.BundleFetch("error")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.metrics.BundleFetch("ok")
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// handleHeartbeat verifies and records one signed beat.
//
// Order matters and mirrors doc.go's "signature before sequence": the body
// is size-capped before it is read, host_id is read out of the unverified
// prefix only to select which key to check the signature against (the same
// role a JWT's unverified "kid" header plays), attest.Verify runs next, and
// Beats.Accept is the last step — reached only once a beat has already
// proven it was signed by the key on file for the host_id it claims.
func (s *server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHeartbeatBody)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.metrics.Heartbeat("too_large")
		http.Error(w, "beat too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(data) < attest.OffHostID+attest.IDSize {
		s.metrics.Heartbeat("malformed")
		http.Error(w, "malformed beat", http.StatusBadRequest)
		return
	}

	var hostID [16]byte
	copy(hostID[:], data[attest.OffHostID:attest.OffHostID+attest.IDSize])

	hostKey, err := s.store.HostKey(hostID)
	if err != nil {
		// Deliberately the same response, status, and body as every other
		// rejection below: this route must not let an unauthenticated
		// caller distinguish "not a host we know" from "signature did not
		// verify" from "replayed sequence" by status code or message.
		s.metrics.Heartbeat("unknown_host")
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}

	beat, err := attest.Verify(data, hostKey)
	if err != nil {
		s.metrics.Heartbeat("bad_signature")
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}

	// Only now — after Verify has already succeeded — does anything reach
	// the sequence store. See doc.go: an unverified beat let in here could
	// park a real host's epoch at attacker-chosen values forever.
	if err := s.beats.Accept(beat, s.now()); err != nil {
		s.metrics.Heartbeat("stale")
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	s.metrics.Heartbeat("ok")
	w.WriteHeader(http.StatusNoContent)
}

// newPublicServer builds the *http.Server the public listener runs on, with
// every bound this listener's public-by-definition status requires (see
// doc.go). Split out from Serve so a test can inspect these fields directly,
// without opening a socket.
func newPublicServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: publicReadHeaderTimeout,
		ReadTimeout:       publicReadTimeout,
		WriteTimeout:      publicWriteTimeout,
		MaxHeaderBytes:    publicMaxHeaderBytes,
	}
}

// Serve runs the hub until ctx is cancelled: the public bundle-and-heartbeat
// listener on cfg.Addr, and, when cfg.MetricsAddr is set, a separate private
// listener carrying /metrics and BeatsPath. It returns nil on a clean,
// context-driven shutdown and
// a non-nil error for anything else, including every configuration mistake
// below — all of which are checked before either listener opens.
func Serve(ctx context.Context, cfg Config) error {
	if cfg.MetricsAddr != "" && cfg.MetricsAddr == cfg.Addr {
		return fmt.Errorf("hub: MetricsAddr must not equal the public Addr (%s); "+
			"that would publish /metrics and %s, so fleet size and which hosts have gone quiet, "+
			"to anyone who can reach the public listener",
			cfg.Addr, BeatsPath)
	}
	// Half-configured TLS is refused rather than silently falling back to
	// plaintext: an operator who set one of the two almost certainly meant
	// to turn TLS on, and serving plaintext instead is a worse surprise than
	// a startup failure.
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("hub: half-configured TLS: cert file %q, key file %q; set both or neither",
			cfg.TLSCertFile, cfg.TLSKeyFile)
	}

	store, err := OpenStore(cfg.StoreDir)
	if err != nil {
		return err
	}
	beats := NewBeats()
	m := NewMetrics(beats)
	srv := &server{store: store, beats: beats, metrics: m, now: time.Now, since: time.Now()}

	publicLn, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("hub: listen %s: %w", cfg.Addr, err)
	}
	publicSrv := newPublicServer(newMux(srv))

	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		addr, err := metrics.ResolveProbeBind(cfg.MetricsAddr)
		if err != nil {
			_ = publicLn.Close()
			return fmt.Errorf("hub: metrics bind: %w", err)
		}
		metricsLn, err := metrics.Listen(addr)
		if err != nil {
			_ = publicLn.Close()
			return fmt.Errorf("hub: metrics listen: %w", err)
		}
		metricsSrv = metrics.Serve(metricsLn, m.Handler(), privateRoutes(srv)...)
	}

	serveErrc := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSCertFile != "" {
			err = publicSrv.ServeTLS(publicLn, cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = publicSrv.Serve(publicLn)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrc <- fmt.Errorf("hub: public listener: %w", err)
			return
		}
		serveErrc <- nil
	}()

	var runErr error
	cancelledFirst := false
	select {
	case <-ctx.Done():
		cancelledFirst = true
	case runErr = <-serveErrc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), publicShutdownTimeout)
	defer cancel()
	_ = publicSrv.Shutdown(shutdownCtx)
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutdownCtx)
	}
	if cancelledFirst {
		// Drain the goroutine's result so it does not leak past Serve
		// returning. Shutdown above guarantees Serve/ServeTLS has already
		// returned by the time we get here, so this never blocks.
		<-serveErrc
		return nil
	}
	return runErr
}
