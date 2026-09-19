package http

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ipRateLimiter counts API requests per client IP in fixed windows: time is
// divided into consecutive, epoch-aligned slots of one window each, and every
// count is discarded when a request arrives in a new slot. Counts live in the
// memory of one process, so each server process enforces its own limit.
type ipRateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	slot   int64
	counts map[string]int
}

func newIPRateLimiter(limit int, window time.Duration, now func() time.Time) *ipRateLimiter {
	return &ipRateLimiter{
		limit:  limit,
		window: window,
		now:    now,
		counts: make(map[string]int),
	}
}

// allow records one request from ip and reports whether it is within the
// limit. A rejected request is not counted; for it, allow also returns the time
// remaining until the current slot ends.
func (l *ipRateLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// The clock is read under the lock so that a request which read the time
	// just before a slot boundary cannot acquire the lock after one from the new
	// slot and roll the counts back.
	now := l.now()
	slot := now.UnixNano() / int64(l.window)
	if slot < l.slot {
		// The wall clock stepped backwards; keep counting in the current slot
		// rather than resetting.
		slot = l.slot
	}

	if slot != l.slot {
		// Replacing the whole map instead of expiring entries one by one keeps
		// memory bounded to the IPs seen in the current slot without a
		// background sweeper.
		l.slot = slot
		l.counts = make(map[string]int)
	}
	if l.counts[ip] >= l.limit {
		return false, time.Duration((slot+1)*int64(l.window) - now.UnixNano())
	}
	l.counts[ip]++
	return true, 0
}

// middleware rejects a request with 429 and Retry-After once its client IP has
// used up the limit for the current slot.
func (l *ipRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, retryAfter := l.allow(clientIP(r))
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
			writeError(w, r, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the host part of the TCP peer address. X-Forwarded-For is
// ignored: the range is not deployed behind a trusted proxy, and any client
// could set that header to an arbitrary value to evade the limit.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
