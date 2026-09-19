package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m-mizutani/gt"
	httpctrl "github.com/m-mizutani/semgate-example/pkg/controller/http"
)

// fakeClock lets a test move time across window boundaries deterministically.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func newRateLimitedServer(t *testing.T, limit int, clock *fakeClock) http.Handler {
	t.Helper()
	return newTestServer(t, nil,
		httpctrl.WithRateLimit(limit, time.Minute),
		httpctrl.WithClock(clock.Now),
	)
}

func serve(h http.Handler, path, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const apiPath = "/api/greet?name=Alice"

func TestRateLimit(t *testing.T) {
	t.Run("requests over the limit in one window are rejected with 429", func(t *testing.T) {
		clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
		h := newRateLimitedServer(t, 15, clock)

		for i := 0; i < 15; i++ {
			gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)
		}

		rec := serve(h, apiPath, "192.0.2.1:40000")
		gt.Number(t, rec.Code).Equal(http.StatusTooManyRequests)
		gt.String(t, rec.Header().Get("Retry-After")).Equal("50")
		var body struct {
			Error string `json:"error"`
		}
		gt.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
		gt.String(t, body.Error).Equal("rate limit exceeded")
	})

	t.Run("concurrent requests never exceed the limit", func(t *testing.T) {
		clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
		h := newRateLimitedServer(t, 15, clock)

		var wg sync.WaitGroup
		var allowed atomic.Int32
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if serve(h, apiPath, "192.0.2.1:40000").Code == http.StatusOK {
					allowed.Add(1)
				}
			}()
		}
		wg.Wait()
		gt.Number(t, allowed.Load()).Equal(15)
	})

	t.Run("counts are kept per client IP regardless of source port", func(t *testing.T) {
		clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
		h := newRateLimitedServer(t, 2, clock)

		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)
		gt.Number(t, serve(h, apiPath, "192.0.2.1:40001").Code).Equal(http.StatusOK)
		gt.Number(t, serve(h, apiPath, "192.0.2.1:40002").Code).Equal(http.StatusTooManyRequests)

		gt.Number(t, serve(h, apiPath, "192.0.2.2:40000").Code).Equal(http.StatusOK)
		gt.Number(t, serve(h, apiPath, "[2001:db8::1]:40000").Code).Equal(http.StatusOK)
	})

	t.Run("the count resets when the next window starts", func(t *testing.T) {
		clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 58, 0, time.UTC)}
		h := newRateLimitedServer(t, 1, clock)

		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)
		rec := serve(h, apiPath, "192.0.2.1:40000")
		gt.Number(t, rec.Code).Equal(http.StatusTooManyRequests)
		gt.String(t, rec.Header().Get("Retry-After")).Equal("2")

		clock.now = time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)
	})

	t.Run("a clock that steps back into an earlier window does not reset the count", func(t *testing.T) {
		clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}
		h := newRateLimitedServer(t, 1, clock)

		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)

		clock.now = time.Date(2026, 1, 1, 0, 0, 59, 0, time.UTC)
		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusTooManyRequests)
	})

	t.Run("static files are neither counted nor limited", func(t *testing.T) {
		clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
		h := newRateLimitedServer(t, 1, clock)

		for i := 0; i < 5; i++ {
			gt.Number(t, serve(h, "/", "192.0.2.1:40000").Code).Equal(http.StatusOK)
		}
		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)
		gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusTooManyRequests)
		gt.Number(t, serve(h, "/hints", "192.0.2.1:40000").Code).Equal(http.StatusOK)
	})

	t.Run("no limit is applied without the option", func(t *testing.T) {
		h := newTestServer(t, nil)
		for i := 0; i < 30; i++ {
			gt.Number(t, serve(h, apiPath, "192.0.2.1:40000").Code).Equal(http.StatusOK)
		}
	})

	t.Run("a non-positive limit or window is rejected", func(t *testing.T) {
		_, err := httpctrl.New(nil, nil, nil, httpctrl.WithRateLimit(0, time.Minute))
		gt.Error(t, err)
		_, err = httpctrl.New(nil, nil, nil, httpctrl.WithRateLimit(15, 0))
		gt.Error(t, err)
	})
}
