package app

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/time/rate"
)

// rateLimiterEntry holds a per-IP rate limiter and the last time it was used.
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiterMap manages per-IP rate limiters with automatic cleanup of
// stale entries. Safe for concurrent use.
type rateLimiterMap struct {
	entries sync.Map // map[string]*rateLimiterEntry
	rps     rate.Limit
	burst   int
}

func newRateLimiterMap(rps float64, burst int) *rateLimiterMap {
	return &rateLimiterMap{
		rps:   rate.Limit(rps),
		burst: burst,
	}
}

// get returns the rate limiter for the given IP, creating one if needed.
func (m *rateLimiterMap) get(ip string) *rate.Limiter {
	now := time.Now()
	if val, ok := m.entries.Load(ip); ok {
		entry := val.(*rateLimiterEntry)
		entry.lastSeen = now
		return entry.limiter
	}
	// Fiber's c.Get() returns strings backed by fasthttp's reusable buffer
	// (UnsafeString). Clone before storing as a map key to prevent silent
	// corruption when the RequestCtx is recycled via sync.Pool.
	ip = strings.Clone(ip)
	entry := &rateLimiterEntry{
		limiter:  rate.NewLimiter(m.rps, m.burst),
		lastSeen: now,
	}
	if actual, loaded := m.entries.LoadOrStore(ip, entry); loaded {
		return actual.(*rateLimiterEntry).limiter
	}
	return entry.limiter
}

// cleanup removes entries that haven't been seen since the given cutoff.
func (m *rateLimiterMap) cleanup(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	m.entries.Range(func(key, value any) bool {
		if value.(*rateLimiterEntry).lastSeen.Before(cutoff) {
			m.entries.Delete(key)
		}
		return true
	})
}

// rateLimitMiddleware returns a Fiber middleware that rate-limits edge
// requests (those without an XFCC header, indicating no client cert).
// Over-limit requests are stalled (blocked) up to stallTimeout before
// receiving a 429 response. The cleanup goroutine for stale per-IP
// entries is started separately via startRateLimitCleanup.
func (s *Server) rateLimitMiddleware() fiber.Handler {
	s.rateLimiters = newRateLimiterMap(s.cfg.RateLimitRPS, s.cfg.RateLimitBurst)
	stallTimeout := s.cfg.RateLimitStallTimeout

	return func(c *fiber.Ctx) error {
		// Skip rate limiting for mTLS clients (service-to-service traffic).
		if c.Get("x-forwarded-client-cert") != "" {
			return c.Next()
		}

		ip := extractClientIP(c)
		if ip == "" {
			return c.Next()
		}

		limiter := s.rateLimiters.get(ip)

		ctx, cancel := context.WithTimeout(s.shutdownCtx(), stallTimeout)
		defer cancel()

		if err := limiter.Wait(ctx); err != nil {
			c.Set("Retry-After", "1")
			return fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded")
		}

		return c.Next()
	}
}

// runRateLimitCleanup periodically removes stale per-IP limiter entries.
func (s *Server) runRateLimitCleanup(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.rateLimiters.cleanup(2 * s.cfg.RateLimitStallTimeout)
		}
	}
}

// extractClientIP extracts the client IP address from proxy headers or
// the connection. Priority: X-Envoy-Original-IP > first X-Forwarded-For
// entry > c.IP(). Returns empty string if the extracted value is not a
// valid IP (prevents header injection from creating unbounded map entries).
func extractClientIP(c *fiber.Ctx) string {
	if ip := c.Get("x-envoy-original-ip"); ip != "" {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	if xff := c.Get("x-forwarded-for"); xff != "" {
		// Use the first (leftmost) entry — the original client IP.
		ip, _, _ := strings.Cut(xff, ",")
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	ip := c.IP()
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}
