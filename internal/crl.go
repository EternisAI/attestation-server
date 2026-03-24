package app

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// AMD KDS CRL URL templates. {product} is the SEV-SNP product line
// (Milan, Genoa, Turin). These return DER-encoded X.509 CRLs.
const (
	amdVCEKCRLTemplate = "https://kdsintf.amd.com/vcek/v1/%s/crl"
	amdVLEKCRLTemplate = "https://kdsintf.amd.com/vlek/v1/%s/crl"
)

// crlMaxResponseBytes limits the CRL response body size.
const crlMaxResponseBytes = 4 << 20 // 4 MiB

// amdProductLines lists the SEV-SNP product lines for which CRLs are fetched.
var amdProductLines = []string{"Milan", "Genoa", "Turin"}

// crlEntry holds a parsed CRL with metadata.
type crlEntry struct {
	crl       *x509.RevocationList
	fetchedAt time.Time
}

// crlCache manages background-fetched certificate revocation lists for TEE
// endorsement key verification. Thread-safe via sync.RWMutex.
type crlCache struct {
	mu      sync.RWMutex
	entries map[string]*crlEntry // keyed by CRL URL
	logger  *slog.Logger
}

func newCRLCache(logger *slog.Logger) *crlCache {
	return &crlCache{
		entries: make(map[string]*crlEntry),
		logger:  logger,
	}
}

// CheckRevocation checks if a certificate's serial number appears in any
// cached CRL. Returns nil if the certificate is not revoked or if no CRL
// data is available yet (fail-open until first successful fetch).
func (c *crlCache) CheckRevocation(cert *x509.Certificate, now time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.entries) == 0 {
		return nil // no CRL data yet — fail-open
	}

	for url, entry := range c.entries {
		if entry.crl == nil {
			continue
		}
		for _, revoked := range entry.crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate serial %s is revoked (CRL: %s)", cert.SerialNumber, url)
			}
		}
	}

	return nil
}

// fetchCRL fetches and parses a DER-encoded CRL from the given URL.
func fetchCRL(ctx context.Context, client *http.Client, url string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL fetch %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, crlMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL from %s: %w", url, err)
	}

	return crl, nil
}

// crlURLsForEvidence returns the CRL URLs that should be fetched based on
// which evidence types are enabled.
func crlURLsForEvidence(cfg *Config) []string {
	var urls []string

	if cfg.ReportEvidence.SEVSNP {
		for _, prod := range amdProductLines {
			urls = append(urls, fmt.Sprintf(amdVCEKCRLTemplate, prod))
			urls = append(urls, fmt.Sprintf(amdVLEKCRLTemplate, prod))
		}
	}

	// TDX CRL checking is handled by go-tdx-guest's verify.Options
	// (CheckRevocations/GetCollateral), not through this cache.

	// NitroNSM/NitroTPM: AWS Nitro uses ephemeral certificate chains
	// with no CRL mechanism.

	return urls
}

// refreshAll fetches all configured CRL URLs and updates the cache.
// Errors are logged but do not prevent other CRLs from being fetched.
func (c *crlCache) refreshAll(ctx context.Context, client *http.Client, urls []string) {
	for _, url := range urls {
		crl, err := fetchCRL(ctx, client, url)
		if err != nil {
			c.logger.Warn("crl fetch failed", "url", url, "error", err)
			continue
		}

		c.mu.Lock()
		c.entries[url] = &crlEntry{crl: crl, fetchedAt: time.Now()}
		c.mu.Unlock()

		c.logger.Debug("crl fetched", "url", url, "entries", len(crl.RevokedCertificateEntries))
	}
}

// runCRLRefresh runs the background CRL refresh loop.
func (s *Server) runCRLRefresh(ctx context.Context) {
	urls := crlURLsForEvidence(s.cfg)
	if len(urls) == 0 {
		return
	}

	client := s.fetchHTTPClient()

	// Initial fetch.
	s.crlCache.refreshAll(ctx, client, urls)

	ticker := time.NewTicker(s.cfg.RevocationRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.crlCache.refreshAll(ctx, client, urls)
		}
	}
}
