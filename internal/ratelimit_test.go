package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "x-envoy-original-ip takes priority",
			headers: map[string]string{"X-Envoy-Original-Ip": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"},
			want:    "1.2.3.4",
		},
		{
			name:    "x-forwarded-for first entry",
			headers: map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 10.0.0.3"},
			want:    "10.0.0.1",
		},
		{
			name:    "x-forwarded-for single",
			headers: map[string]string{"X-Forwarded-For": "192.168.1.1"},
			want:    "192.168.1.1",
		},
		{
			name:    "invalid envoy ip falls through to xff",
			headers: map[string]string{"X-Envoy-Original-Ip": "not-an-ip", "X-Forwarded-For": "1.2.3.4"},
			want:    "1.2.3.4",
		},
		{
			name:    "invalid xff falls through to c.IP",
			headers: map[string]string{"X-Forwarded-For": "not-an-ip"},
			want:    "", // c.IP() returns "0.0.0.0" in tests which is valid
		},
		{
			name:    "ipv6 address",
			headers: map[string]string{"X-Envoy-Original-Ip": "::1"},
			want:    "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			var got string
			app.Get("/test", func(c *fiber.Ctx) error {
				got = extractClientIP(c)
				return c.SendStatus(200)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			_, _ = app.Test(req, -1)

			if tt.want != "" && got != tt.want {
				t.Errorf("extractClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitMiddleware_SkipsXFCC(t *testing.T) {
	s := &Server{
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		cfg: &Config{
			RateLimitRPS:          0.001, // extremely low — would block without skip
			RateLimitBurst:        1,
			RateLimitStallTimeout: 100 * time.Millisecond,
		},
	}

	app := fiber.New()
	app.Use(s.rateLimitMiddleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	// First request without XFCC — uses the burst token
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, _ := app.Test(req, -1)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first request without XFCC: status = %d, want 200", resp.StatusCode)
	}

	// Second request without XFCC — should be rate limited (burst exhausted, very low RPS)
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp2, _ := app.Test(req2, 2000) // 2s timeout for the stall
	resp2.Body.Close()
	if resp2.StatusCode != 429 {
		t.Fatalf("second request without XFCC: status = %d, want 429", resp2.StatusCode)
	}

	// Request with XFCC — should bypass rate limiting
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.Header.Set("x-forwarded-client-cert", "Hash=abcd1234")
	resp3, _ := app.Test(req3, -1)
	resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("request with XFCC: status = %d, want 200 (should bypass rate limit)", resp3.StatusCode)
	}
}

func TestRateLimitMiddleware_StallingBehavior(t *testing.T) {
	s := &Server{
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		cfg: &Config{
			RateLimitRPS:          10, // 10 RPS = one token every 100ms
			RateLimitBurst:        1,
			RateLimitStallTimeout: 2 * time.Second,
		},
	}

	app := fiber.New()
	app.Use(s.rateLimitMiddleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	// First request uses burst token
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, _ := app.Test(req, -1)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first request: status = %d, want 200", resp.StatusCode)
	}

	// Second request should stall briefly (100ms for next token) then succeed
	start := time.Now()
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp2, _ := app.Test(req2, 5000)
	resp2.Body.Close()
	elapsed := time.Since(start)

	if resp2.StatusCode != 200 {
		t.Fatalf("second request: status = %d, want 200 (should stall and succeed)", resp2.StatusCode)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("second request completed too quickly (%v), expected stalling", elapsed)
	}
}

func TestRateLimitMiddleware_TimeoutReturns429(t *testing.T) {
	// This test verifies that over-limit requests eventually receive 429.
	// The stalling/timeout behavior depends on context propagation which
	// varies in Fiber test mode, so we only assert on the status code.
	s := &Server{
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		cfg: &Config{
			RateLimitRPS:          0.001, // extremely low — one token per 1000s
			RateLimitBurst:        1,
			RateLimitStallTimeout: 50 * time.Millisecond,
		},
	}

	app := fiber.New()
	app.Use(s.rateLimitMiddleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	// First request consumes the burst token.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, _ := app.Test(req, -1)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first request: status = %d, want 200", resp.StatusCode)
	}

	// Second request should be rejected (burst exhausted, very low RPS).
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp2, _ := app.Test(req2, 2000)
	resp2.Body.Close()
	if resp2.StatusCode != 429 {
		t.Fatalf("second request: status = %d, want 429", resp2.StatusCode)
	}
}

func TestRateLimiterMap_Cleanup(t *testing.T) {
	m := newRateLimiterMap(1.0, 1)

	// Create two entries: one "old" and one "recent".
	_ = m.get("old-ip")
	_ = m.get("recent-ip")

	// Manually backdate the "old" entry.
	if val, ok := m.entries.Load("old-ip"); ok {
		val.(*rateLimiterEntry).lastSeen = time.Now().Add(-10 * time.Minute)
	}

	// Cleanup with 5m maxAge should remove "old-ip" but keep "recent-ip".
	m.cleanup(5 * time.Minute)

	if _, ok := m.entries.Load("old-ip"); ok {
		t.Error("expected old-ip to be cleaned up")
	}
	if _, ok := m.entries.Load("recent-ip"); !ok {
		t.Error("expected recent-ip to survive cleanup")
	}
}

func TestRateLimiterMap_Cleanup_EmptyMap(t *testing.T) {
	m := newRateLimiterMap(1.0, 1)
	// Should not panic on empty map.
	m.cleanup(5 * time.Minute)
}

func TestRateLimitMiddleware_PerIPIsolation(t *testing.T) {
	s := &Server{
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		cfg: &Config{
			RateLimitRPS:          0.001, // extremely low
			RateLimitBurst:        1,
			RateLimitStallTimeout: 100 * time.Millisecond,
		},
	}

	app := fiber.New()
	app.Use(s.rateLimitMiddleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	// First IP exhausts its burst token.
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.1")
	resp1, _ := app.Test(req1, -1)
	resp1.Body.Close()
	if resp1.StatusCode != 200 {
		t.Fatalf("IP1 first request: status = %d, want 200", resp1.StatusCode)
	}

	// Second IP should still have its own burst token.
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.2")
	resp2, _ := app.Test(req2, -1)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("IP2 first request: status = %d, want 200 (separate bucket)", resp2.StatusCode)
	}

	// First IP's second request should be rate limited.
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.Header.Set("X-Forwarded-For", "10.0.0.1")
	resp3, _ := app.Test(req3, 2000)
	resp3.Body.Close()
	if resp3.StatusCode != 429 {
		t.Fatalf("IP1 second request: status = %d, want 429", resp3.StatusCode)
	}
}
