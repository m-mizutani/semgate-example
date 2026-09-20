package http

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
)

// Body statuses recorded next to the logged body. They state how much of the
// body the record holds, so a record never leaves that ambiguous.
const (
	bodyStatusNone       = "none"       // the request carries no body
	bodyStatusUnread     = "unread"     // nothing had read the body when the record was written
	bodyStatusRead       = "read"       // the body was read to its end
	bodyStatusPartial    = "partial"    // read so far; the rest had not arrived
	bodyStatusTruncated  = "truncated"  // more than maxInputBytes was read; the record holds the first maxInputBytes
	bodyStatusReadError  = "read_error" // reading the body failed; the record holds what was read
	bodyStatusUncaptured = "uncaptured" // captureRequest did not run for this request
)

// capturedBody is the body a log record shows, together with the status that
// says how much of it the record holds.
type capturedBody struct {
	content string
	status  string
}

// bodyRecorder keeps what other readers take from the request body, so that
// the guard's decision record and the handler's detection record can show the
// payload their verdict was made on.
//
// It never starts a read of its own. The guard bounds how long it waits for a
// body and the handlers read only what they answer with, while a read started
// here would wait on the client with no bound at all: this range serves one
// request at a time (see terraform/main.tf) and net/http bounds the header
// read only, so one stalled body would hold the whole range.
//
// The guard reads the body in its own goroutine, so the recorded state is
// taken under a mutex.
type bodyRecorder struct {
	src   io.ReadCloser
	limit int

	mu        sync.Mutex
	buf       []byte
	started   bool
	truncated bool
	err       error
}

type bodyRecorderKey struct{}

// captureRequest puts a recorder for the request body in the request context,
// so that requestAttrs can show the body without reading it. A request that
// carries no body records nothing and is logged as such.
func captureRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorder *bodyRecorder
		if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
			recorder = &bodyRecorder{src: r.Body, limit: maxInputBytes}
		}

		// Only the context and the body are replaced, so the caller's request
		// is left untouched.
		captured := r.WithContext(context.WithValue(r.Context(), bodyRecorderKey{}, recorder))
		if recorder != nil {
			captured.Body = recorder
		}
		next.ServeHTTP(w, captured)
	})
}

func (b *bodyRecorder) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)

	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = true
	if room := b.limit - len(b.buf); n > room {
		b.truncated = true
		b.buf = append(b.buf, p[:room]...)
	} else {
		b.buf = append(b.buf, p[:n]...)
	}
	if err != nil {
		b.err = err
	}
	return n, err
}

func (b *bodyRecorder) Close() error { return b.src.Close() }

func (b *bodyRecorder) snapshot() capturedBody {
	b.mu.Lock()
	defer b.mu.Unlock()

	body := capturedBody{content: string(b.buf)}
	switch {
	case !b.started:
		body.status = bodyStatusUnread
	case b.truncated:
		body.status = bodyStatusTruncated
	case b.err == nil:
		body.status = bodyStatusPartial
	case errors.Is(b.err, io.EOF):
		body.status = bodyStatusRead
	default:
		body.status = bodyStatusReadError
	}
	return body
}

func bodyFrom(ctx context.Context) capturedBody {
	recorder, ok := ctx.Value(bodyRecorderKey{}).(*bodyRecorder)
	switch {
	case !ok:
		return capturedBody{status: bodyStatusUncaptured}
	case recorder == nil:
		return capturedBody{status: bodyStatusNone}
	}
	return recorder.snapshot()
}

// requestAttrs returns the whole request a verdict was made on: the fields the
// guard sends to its provider (method, path, query, headers, body) together
// with the transport fields that identify the caller. Reading a verdict record
// then needs no second record and no correlation.
//
// No header is withheld. This range exists to be attacked, and its records are
// the material a visitor inspects afterwards, so a record shows the request
// exactly as it arrived — including the credential headers the guard itself
// withholds from its provider (see NewGuard).
func requestAttrs(r *http.Request) slog.Attr {
	body := bodyFrom(r.Context())
	return slog.Group("request",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("raw_query", r.URL.RawQuery),
		fieldGroup("query", r.URL.Query()),
		fieldGroup("headers", r.Header),
		slog.String("body", body.content),
		slog.String("body_status", body.status),
		slog.Int64("content_length", r.ContentLength),
		slog.String("proto", r.Proto),
		slog.String("host", r.Host),
		slog.String("remote_addr", r.RemoteAddr),
	)
}

// fieldGroup renders a multi-valued field map with its keys in a stable order.
func fieldGroup(name string, fields map[string][]string) slog.Attr {
	attrs := make([]any, 0, len(fields))
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		attrs = append(attrs, slog.Any(key, fields[key]))
	}
	return slog.Group(name, attrs...)
}
