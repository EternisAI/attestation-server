package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"

	// The x509roots/fallback blank import embeds Mozilla's root CA bundle
	// as a fallback when the system trust store is unavailable (e.g. minimal
	// container images without ca-certificates). This ensures endorsement
	// HTTPS fetches always have a reasonable set of trusted roots.
	_ "golang.org/x/crypto/x509roots/fallback"
)

// Endorsement/cosign HTTP client hardening constants. Per-phase timeouts
// prevent a misbehaving or malicious server from holding connections open
// indefinitely. The body limit prevents memory exhaustion.
const (
	fetchDialTimeout           = 3 * time.Second
	fetchTLSHandshakeTimeout   = 5 * time.Second
	fetchResponseHeaderTimeout = 5 * time.Second
	fetchMaxResponseBytes      = 1 << 20 // 1 MiB

	fetchRetryInitial = 500 * time.Millisecond
	fetchRetryMax     = 5 * time.Second

	fetchDefaultTTL = 30 * time.Minute
	fetchMaxTTL     = 24 * time.Hour
)

// fetcherCache is a generic ristretto cache keyed by URL strings. It stores
// both *EndorsementDocument and *cosignResult values — endorsement URLs and
// signature URLs (with .sig suffix) never collide, so a single cache works.
type fetcherCache struct {
	cache *ristretto.Cache[string, any]
}

func newFetcherCache(maxBytes int64) (*fetcherCache, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, any]{
		NumCounters: 10000,
		MaxCost:     maxBytes,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("creating fetcher cache: %w", err)
	}
	return &fetcherCache{cache: cache}, nil
}

func (fc *fetcherCache) get(url string) (any, bool) {
	return fc.cache.Get(url)
}

// setGroup stores the same pointer under all URL keys (multiple endorsement
// URLs resolve to the same document by design). Cost is charged only on the
// first key — all keys reference the same underlying memory, so charging
// each would over-count and prematurely evict entries.
func (fc *fetcherCache) setGroup(urls []string, value any, rawSize int, ttl time.Duration) {
	for i, u := range urls {
		cost := int64(0)
		if i == 0 {
			cost = int64(rawSize)
		}
		fc.cache.SetWithTTL(u, value, cost, ttl)
	}
	fc.cache.Wait()
}

// fetchHTTPClient builds an HTTPS client for fetching endorsement documents
// and cosign signature bundles from public URLs. Uses system/Mozilla root
// CAs (via the x509roots/fallback blank import). If a DNSSEC resolver is
// configured, it is wired into the transport so DNS queries go through the
// same upstream servers used for DNSSEC validation.
func (s *Server) fetchHTTPClient() *http.Client {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}

	dialer := &net.Dialer{
		Timeout: fetchDialTimeout,
	}
	if s.dnssecResolver != nil {
		dialer.Resolver = s.dnssecResolver.NetResolver()
	}

	transport := &http.Transport{
		// TLS 1.2 minimum for public CDN/endorsement fetches (some
		// public servers may not support TLS 1.3). The dependency mTLS
		// client uses TLS 1.3 minimum (see dependencyHTTPClient).
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   fetchTLSHandshakeTimeout,
		ResponseHeaderTimeout: fetchResponseHeaderTimeout,
		DialContext:           dialer.DialContext,
		// Disable keep-alives: each fetch is a one-shot request during
		// endorsement validation, and re-using connections would tie up
		// sockets across the TTL-driven refetch interval.
		DisableKeepAlives: true,
	}
	if s.cfg.HTTPAllowProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}

	return &http.Client{
		Timeout:   s.cfg.EndorsementClientTimeout,
		Transport: transport,
	}
}

// parseCacheTTL extracts a TTL from HTTP response headers. It checks
// Cache-Control for max-age and no-cache/no-store, falls back to the
// Expires header, and defaults to 30 minutes. TTL is capped at 24 hours.
func parseCacheTTL(header http.Header) time.Duration {
	if cc := header.Get("Cache-Control"); cc != "" {
		lower := strings.ToLower(cc)
		if strings.Contains(lower, "no-cache") || strings.Contains(lower, "no-store") {
			return 0
		}
		for _, directive := range strings.Split(lower, ",") {
			directive = strings.TrimSpace(directive)
			if strings.HasPrefix(directive, "max-age=") {
				if secs, err := strconv.Atoi(strings.TrimPrefix(directive, "max-age=")); err == nil && secs > 0 {
					ttl := time.Duration(secs) * time.Second
					if ttl > fetchMaxTTL {
						ttl = fetchMaxTTL
					}
					return ttl
				}
			}
		}
	}

	if exp := header.Get("Expires"); exp != "" {
		if t, err := http.ParseTime(exp); err == nil {
			now := time.Now()
			if dateStr := header.Get("Date"); dateStr != "" {
				if d, err := http.ParseTime(dateStr); err == nil {
					now = d
				}
			}
			ttl := t.Sub(now)
			if ttl <= 0 {
				return 0
			}
			if ttl > fetchMaxTTL {
				ttl = fetchMaxTTL
			}
			return ttl
		}
	}

	return fetchDefaultTTL
}

// fetchResult holds the result of fetching a single URL.
type fetchResult struct {
	body   []byte
	header http.Header
}

// fetchWithRetry fetches a URL with exponential backoff retry until the
// context deadline. Each failed attempt is logged at WARN level so that
// the underlying cause (DNS, TLS, HTTP status, etc.) is visible even
// when the final error is just "context deadline exceeded".
func fetchWithRetry(ctx context.Context, client *http.Client, u *url.URL, logger *slog.Logger) ([]byte, http.Header, error) {
	backoff := fetchRetryInitial
	var lastErr error
	attempt := 0

	for {
		attempt++
		start := time.Now()
		body, header, err := fetchOnce(ctx, client, u)
		dur := time.Since(start)
		if err == nil {
			if logger != nil {
				logger.Debug("fetch attempt succeeded", "url", u.String(), "attempt", attempt, "duration_ms", dur.Milliseconds())
			}
			return body, header, nil
		}
		lastErr = err

		if logger != nil {
			logger.Warn("fetch attempt failed", "url", u.String(), "attempt", attempt, "duration_ms", dur.Milliseconds(), "error", err)
		}

		if ctx.Err() != nil {
			return nil, nil, lastErr
		}

		select {
		case <-ctx.Done():
			return nil, nil, lastErr
		case <-time.After(backoff):
		}

		backoff = time.Duration(math.Min(float64(backoff)*2, float64(fetchRetryMax)))
	}
}

// fetchOnce performs a single HTTP GET and returns the response body and
// headers. Non-200 status codes are treated as errors. The response body
// is capped at fetchMaxResponseBytes.
func fetchOnce(ctx context.Context, client *http.Client, u *url.URL) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, classifyNetError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchMaxResponseBytes))
	if err != nil {
		return nil, nil, classifyNetError(fmt.Errorf("reading response: %w", err))
	}

	return body, resp.Header, nil
}

// cachedHTTPSGetterEntry stores a cached (header, body) pair from an
// HTTPSGetter response, keyed by URL in the shared fetcherCache.
type cachedHTTPSGetterEntry struct {
	header map[string][]string
	body   []byte
}

// cachedHTTPSGetter implements trust.HTTPSGetter with URL-keyed caching
// backed by the shared ristretto fetcherCache. On cache hit the network is
// skipped entirely. On miss the inner getter is called and the response is
// cached with a TTL derived from the response headers (defaulting to 30 min
// when no Cache-Control is present, which is the case for Intel PCS).
type cachedHTTPSGetter struct {
	inner  *simpleHTTPSGetter
	cache  *fetcherCache
	logger *slog.Logger
}

// simpleHTTPSGetter is a proxy-aware replacement for trust.SimpleHTTPSGetter.
// The go-tdx-guest default getter uses bare http.Get (http.DefaultTransport),
// which always honours proxy env vars. When http.allow_proxy is false we want
// to suppress that, so this getter uses the server's fetchHTTPClient which
// only sets Proxy when explicitly allowed.
type simpleHTTPSGetter struct {
	client *http.Client
}

func (g *simpleHTTPSGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	resp, err := g.client.Get(rawURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("failed to retrieve %s, status code %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchMaxResponseBytes))
	if err != nil {
		return nil, nil, err
	}

	return resp.Header, body, nil
}

func (g *cachedHTTPSGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	if val, ok := g.cache.get(rawURL); ok {
		if entry, ok := val.(*cachedHTTPSGetterEntry); ok {
			if g.logger != nil {
				g.logger.Debug("tdx collateral cache hit", "url", rawURL)
			}
			return entry.header, entry.body, nil
		}
	}

	header, body, err := g.inner.Get(rawURL)
	if err != nil {
		return nil, nil, err
	}

	ttl := parseCacheTTL(http.Header(header))
	entry := &cachedHTTPSGetterEntry{header: header, body: body}
	g.cache.setGroup([]string{rawURL}, entry, len(body), ttl)

	if g.logger != nil {
		g.logger.Debug("tdx collateral cached", "url", rawURL, "size", len(body), "ttl", ttl.String())
	}

	return header, body, nil
}
