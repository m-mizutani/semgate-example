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

// boundInputs enforces the 1KB limit on the body, every query value, and the
// X-Log-Tag header. It is registered first on the /api subrouter so it runs
// before any guard middleware inserted at that seam — the guard then only ever
// sees bounded input.
func boundInputs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)

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
