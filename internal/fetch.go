package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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

// setGroup stores the same value under all URL keys. Cost is charged only
// on the first key to avoid double-counting identical documents.
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

	return &http.Client{
		Timeout: s.cfg.EndorsementClientTimeout,
		Transport: &http.Transport{
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
		},
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
// context deadline.
func fetchWithRetry(ctx context.Context, client *http.Client, u *url.URL) ([]byte, http.Header, error) {
	backoff := fetchRetryInitial
	var lastErr error

	for {
		body, header, err := fetchOnce(ctx, client, u)
		if err == nil {
			return body, header, nil
		}
		lastErr = err

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
