// Package http exposes the range's six pseudo-vulnerable endpoints and serves
// the embedded SPA. The /api routes are grouped into one subrouter so a guard
// middleware (semgate) can later be inserted at a single seam.
package http

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/m-mizutani/semgate-example/pkg/usecase"
)

// handlers bundles the usecase for the HTTP layer.
type handlers struct {
	sim *usecase.Simulator
}

// New builds the HTTP handler: the /api subrouter (the guard seam, where input
// size bounds and per-request logging are applied) and the embedded SPA.
func New(sim *usecase.Simulator, staticFS fs.FS, logger *slog.Logger) (http.Handler, error) {
	h := &handlers{sim: sim}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(withLogger(logger))
	r.Use(accessLogger)
	r.Use(middleware.Recoverer)

	// The API subrouter is the single seam a guard middleware would wrap. Every
	// attack-carrying request passes through here.
	r.Route("/api", func(api chi.Router) {
		// Input size is bounded first, so a guard middleware inserted after this
		// (api.Use(guard)) only ever inspects bounded input.
		api.Use(boundInputs)
		// A guard middleware (semgate) would be inserted here with api.Use(...).
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
