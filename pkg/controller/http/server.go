// Package http exposes the range's six pseudo-vulnerable endpoints and serves
// the embedded SPA. The /api routes are grouped into one subrouter, the single
// seam where the semgate guard middleware is inserted (see WithGuard).
package http

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/semgate-example/pkg/usecase"
)

// handlers bundles the usecase for the HTTP layer.
type handlers struct {
	sim *usecase.Simulator
}

// Option configures optional behavior of the handler built by New.
type Option func(*options)

type options struct {
	rateLimit  int
	rateWindow time.Duration
	now        func() time.Time
	guard      func(http.Handler) http.Handler
}

// WithRateLimit allows each client IP at most limit requests to /api per
// fixed window. Without this option /api is not rate limited.
func WithRateLimit(limit int, window time.Duration) Option {
	return func(o *options) {
		o.rateLimit = limit
		o.rateWindow = window
	}
}

// WithGuard inserts guard on the /api subrouter, after the input size bound and
// before the handlers. Without this option /api is not guarded and every attack
// payload reaches its handler. Build the semgate guard with NewGuard.
func WithGuard(guard func(http.Handler) http.Handler) Option {
	return func(o *options) { o.guard = guard }
}

func withClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// New builds the HTTP handler: the /api subrouter (the guard seam, where the
// rate limit, input size bounds, and per-request logging are applied) and the
// embedded SPA.
func New(sim *usecase.Simulator, staticFS fs.FS, logger *slog.Logger, opts ...Option) (http.Handler, error) {
	o := options{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}

	var limiter *ipRateLimiter
	if o.rateLimit != 0 || o.rateWindow != 0 {
		if o.rateLimit <= 0 || o.rateWindow <= 0 {
			return nil, goerr.New("rate limit and window must be positive",
				goerr.V("rate_limit", o.rateLimit), goerr.V("rate_window", o.rateWindow))
		}
		limiter = newIPRateLimiter(o.rateLimit, o.rateWindow, o.now)
	}

	h := &handlers{sim: sim}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(withLogger(logger))
	r.Use(accessLogger)
	r.Use(middleware.Recoverer)

	// The API subrouter is the single seam the guard middleware wraps. Every
	// attack-carrying request passes through here.
	r.Route("/api", func(api chi.Router) {
		// The rate limit applies only here, so SPA static files are never
		// counted.
		if limiter != nil {
			api.Use(limiter.middleware)
		}
		// Query values and headers are bounded before the guard; the body is
		// bounded after it, because the guard refuses an oversized body itself
		// rather than evaluating its first kilobyte (see boundBody).
		api.Use(boundInputs)
		if o.guard != nil {
			api.Use(o.guard)
		}
		api.Use(boundBody)
		api.Post("/login", h.login)
		api.Get("/ping", h.ping)
		api.Get("/files", h.files)
		api.Get("/greet", h.greet)
		api.Get("/fetch", h.fetch)
		api.Get("/track", h.track)
	})

	if staticFS != nil {
		r.Get("/*", spaHandler(staticFS))
	}

	return r, nil
}

// spaHandler serves static assets and falls back to index.html for client-side
// routes.
func spaHandler(staticFS fs.FS) http.HandlerFunc {
	fileServer := http.FileServer(http.FS(staticFS))
	return func(w http.ResponseWriter, r *http.Request) {
		urlPath := r.URL.Path
		if urlPath == "/" || urlPath == "" {
			serveIndex(w, r, staticFS)
			return
		}
		trimmed := urlPath
		if len(trimmed) > 0 && trimmed[0] == '/' {
			trimmed = trimmed[1:]
		}
		if f, err := staticFS.Open(trimmed); err != nil {
			serveIndex(w, r, staticFS)
			return
		} else {
			_ = f.Close()
		}
		fileServer.ServeHTTP(w, r)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request, staticFS fs.FS) {
	f, err := staticFS.Open("index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusNotFound)
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "failed to read index.html", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
