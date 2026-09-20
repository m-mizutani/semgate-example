package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/m-mizutani/semgate-example/pkg/utils/logging"
)

// maxInputBytes bounds every attack-carrying input. A guard cannot inspect a
// large body effectively, so the range refuses anything above this.
const maxInputBytes = 1024

// boundInputs enforces the 1KB limit on every query value and on the X-Log-Tag
// header. It runs before the guard, so the guard only ever sees bounded values
// there. The body is bounded separately by boundBody, which runs after the
// guard.
func boundInputs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, values := range r.URL.Query() {
			for _, v := range values {
				if len(v) > maxInputBytes {
					writeError(w, r, http.StatusRequestEntityTooLarge,
						"query parameter "+key+" exceeds 1KB limit")
					return
				}
			}
		}
		if len(r.Header.Get("X-Log-Tag")) > maxInputBytes {
			writeError(w, r, http.StatusRequestEntityTooLarge, "X-Log-Tag header exceeds 1KB limit")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// boundBody caps the request body at maxInputBytes for the handlers. It runs
// after the guard rather than before it: http.MaxBytesReader stops the body
// mid-read instead of refusing the request up front, so a guard behind it would
// evaluate — and send to its provider — the first 1KB of a body the range means
// to refuse. With the guard installed, the guard refuses an oversized body
// itself (413) and this bound never fires.
func boundBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
		next.ServeHTTP(w, r)
	})
}

// withLogger stores the base logger (plus the request id) in the request
// context so handlers log through logging.From(ctx).
func withLogger(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := base.With("request_id", middleware.GetReqID(r.Context()))
			ctx := logging.With(r.Context(), logger)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// accessLogger records one transport-level line per request (method, path,
// status, latency). Attack details are logged separately by each handler.
func accessLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			logging.From(r.Context()).Info("access",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_addr", r.RemoteAddr,
			)
		}()
		next.ServeHTTP(ww, r)
	})
}
