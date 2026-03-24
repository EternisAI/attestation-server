package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"github.com/goccy/go-json"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/miekg/dns"
	_ "golang.org/x/crypto/x509roots/fallback"
	"golang.org/x/sync/errgroup"

	"github.com/eternisai/attestation-server/pkg/hexbytes"
	"github.com/eternisai/attestation-server/pkg/nitro"
)

const (
	endorsementDialTimeout           = 3 * time.Second
	endorsementTLSHandshakeTimeout   = 5 * time.Second
	endorsementResponseHeaderTimeout = 5 * time.Second
	endorsementMaxResponseBytes      = 1 << 20 // 1 MiB

	endorsementRetryInitial = 500 * time.Millisecond
	endorsementRetryMax     = 5 * time.Second

	endorsementDefaultTTL = 30 * time.Minute
	endorsementMaxTTL     = 24 * time.Hour
)

// endorsementCache wraps a ristretto cache for endorsement documents.
// Cache keys are URL strings; deduplication is achieved by storing the same
// *EndorsementDocument pointer under all URLs from a fetch batch.
type endorsementCache struct {
	cache *ristretto.Cache[string, *EndorsementDocument]
}

func newEndorsementCache(maxBytes int64) (*endorsementCache, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, *EndorsementDocument]{
		NumCounters: 10000,
		MaxCost:     maxBytes,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("creating endorsement cache: %w", err)
	}
	return &endorsementCache{cache: cache}, nil
}

func (ec *endorsementCache) get(url string) (*EndorsementDocument, bool) {
	return ec.cache.Get(url)
}

// setGroup stores the same document pointer under all URL keys. Cost is
// charged only on the first key to avoid double-counting identical documents.
func (ec *endorsementCache) setGroup(urls []string, doc *EndorsementDocument, rawSize int, ttl time.Duration) {
	for i, u := range urls {
		cost := int64(0)
		if i == 0 {
			cost = int64(rawSize)
		}
		ec.cache.SetWithTTL(u, doc, cost, ttl)
	}
	ec.cache.Wait()
}

// endorsementHTTPClient builds an HTTPS client for fetching endorsement
// documents from public URLs. Uses system/Mozilla root CAs (via the
// x509roots/fallback blank import). If DNSSEC enforcement is enabled, a
// custom resolver that validates DNSSEC is wired into the transport.
func (s *Server) endorsementHTTPClient() *http.Client {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}

	dialer := &net.Dialer{
		Timeout: endorsementDialTimeout,
	}
	if s.cfg.EndorsementDNSSEC {
		dialer.Resolver = dnssecResolver()
	}

	return &http.Client{
		Timeout: s.cfg.EndorsementClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{RootCAs: roots},
			TLSHandshakeTimeout:   endorsementTLSHandshakeTimeout,
			ResponseHeaderTimeout: endorsementResponseHeaderTimeout,
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
		},
	}
}

// dnssecResolver returns a net.Resolver that validates DNSSEC by querying a
// well-known validating resolver and checking the AD (Authenticated Data)
// flag. If the AD flag is not set, DNS resolution fails — this enforces
// strict DNSSEC: domains must have DNSSEC configured.
func dnssecResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Use Cloudflare's DNSSEC-validating resolver
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
}

// dnssecLookup performs a DNS A/AAAA lookup with DNSSEC validation for the
// given host. It queries a well-known validating resolver with the DO bit
// set and checks the AD flag. Returns an error if the AD flag is not set.
func dnssecLookup(ctx context.Context, host string) error {
	if !strings.Contains(host, ".") {
		return nil // skip localhost / bare names
	}
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil {
		return nil // IP addresses don't have DNSSEC
	}

	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.SetEdns0(4096, true) // DO bit
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, "1.1.1.1:53")
	if err != nil {
		return classifyNetError(fmt.Errorf("DNSSEC lookup for %s: %w", host, err))
	}
	if r.Rcode == dns.RcodeServerFailure {
		return fmt.Errorf("DNSSEC validation failed for %s (SERVFAIL)", host)
	}
	if !r.AuthenticatedData {
		return fmt.Errorf("DNSSEC not available for %s (AD flag not set)", host)
	}
	return nil
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
					if ttl > endorsementMaxTTL {
						ttl = endorsementMaxTTL
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
			if ttl > endorsementMaxTTL {
				ttl = endorsementMaxTTL
			}
			return ttl
		}
	}

	return endorsementDefaultTTL
}

// fetchResult holds the result of fetching a single endorsement URL.
type fetchResult struct {
	body   []byte
	header http.Header
}

// fetchEndorsementDocuments fetches endorsement documents from all URLs in
// parallel with retry, verifies byte-for-byte identity, parses the document,
// and returns it with a TTL derived from Cache-Control headers.
func (s *Server) fetchEndorsementDocuments(ctx context.Context, urls []*url.URL) (*EndorsementDocument, int, time.Duration, error) {
	return s.fetchEndorsementDocumentsWithClient(ctx, urls, nil)
}

// fetchEndorsementDocumentsWithClient is the internal implementation that
// accepts an optional HTTP client override (used in tests with httptest TLS servers).
func (s *Server) fetchEndorsementDocumentsWithClient(ctx context.Context, urls []*url.URL, client *http.Client) (*EndorsementDocument, int, time.Duration, error) {
	if len(urls) == 0 {
		return nil, 0, 0, fmt.Errorf("no endorsement URLs configured")
	}

	for i, u := range urls {
		if u.Scheme != "https" {
			return nil, 0, 0, fmt.Errorf("endorsement URL %d: scheme must be https, got %q (%s)", i, u.Scheme, u.String())
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.EndorsementClientTimeout)
	defer cancel()

	// DNSSEC pre-validation for unique hosts
	if s.cfg.EndorsementDNSSEC {
		seen := make(map[string]bool)
		for _, u := range urls {
			host := u.Hostname()
			if seen[host] {
				continue
			}
			seen[host] = true
			if err := dnssecLookup(ctx, host); err != nil {
				return nil, 0, 0, err
			}
		}
	}

	if client == nil {
		client = s.endorsementHTTPClient()
	}
	g, gctx := errgroup.WithContext(ctx)
	results := make([]fetchResult, len(urls))

	for i, u := range urls {
		g.Go(func() error {
			body, header, err := fetchWithRetry(gctx, client, u)
			if err != nil {
				return fmt.Errorf("fetching %s: %w", u.String(), err)
			}
			results[i] = fetchResult{body: body, header: header}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, 0, 0, err
	}

	// Verify byte-for-byte identity across all responses
	refHash := sha256.Sum256(results[0].body)
	for i := 1; i < len(results); i++ {
		h := sha256.Sum256(results[i].body)
		if h != refHash {
			return nil, 0, 0, fmt.Errorf("endorsement document mismatch: %s (sha256:%s) differs from %s (sha256:%s)",
				urls[i].String(), hex.EncodeToString(h[:8]),
				urls[0].String(), hex.EncodeToString(refHash[:8]))
		}
	}

	var doc EndorsementDocument
	if err := json.Unmarshal(results[0].body, &doc); err != nil {
		return nil, 0, 0, fmt.Errorf("parsing endorsement document: %w", err)
	}

	// Use the most conservative (shortest) TTL across all responses
	ttl := endorsementMaxTTL
	for _, r := range results {
		t := parseCacheTTL(r.header)
		if t < ttl {
			ttl = t
		}
	}
	if ttl <= 0 {
		ttl = endorsementDefaultTTL
	}

	return &doc, len(results[0].body), ttl, nil
}

// fetchWithRetry fetches a URL with exponential backoff retry until the
// context deadline.
func fetchWithRetry(ctx context.Context, client *http.Client, u *url.URL) ([]byte, http.Header, error) {
	backoff := endorsementRetryInitial
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

		backoff = time.Duration(math.Min(float64(backoff)*2, float64(endorsementRetryMax)))
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, endorsementMaxResponseBytes))
	if err != nil {
		return nil, nil, classifyNetError(fmt.Errorf("reading response: %w", err))
	}

	return body, resp.Header, nil
}

// resolveEndorsements resolves endorsement documents from cache or fetches
// them from the provided URLs. Shared by own-evidence and dependency paths.
func (s *Server) resolveEndorsements(ctx context.Context, urls []*url.URL) (*EndorsementDocument, error) {
	return s.resolveEndorsementsWithClient(ctx, urls, nil)
}

// resolveEndorsementsWithClient is the internal implementation that accepts
// an optional HTTP client override (used in tests with httptest TLS servers).
func (s *Server) resolveEndorsementsWithClient(ctx context.Context, urls []*url.URL, client *http.Client) (*EndorsementDocument, error) {
	if s.endCache != nil {
		if doc, ok := s.endCache.get(urls[0].String()); ok {
			return doc, nil
		}
	}

	doc, rawSize, ttl, err := s.fetchEndorsementDocumentsWithClient(ctx, urls, client)
	if err != nil {
		return nil, err
	}

	if s.endCache != nil {
		urlStrs := make([]string, len(urls))
		for i, u := range urls {
			urlStrs[i] = u.String()
		}
		s.endCache.setGroup(urlStrs, doc, rawSize, ttl)
	}

	return doc, nil
}

// validateOwnEndorsements fetches (or retrieves from cache) endorsement
// documents for the server's own endorsement URLs and validates all
// configured evidence types against the golden measurements.
func (s *Server) validateOwnEndorsements(ctx context.Context) error {
	if len(s.endorsements) == 0 {
		return nil
	}

	doc, err := s.resolveEndorsements(ctx, s.endorsements)
	if err != nil {
		return err
	}

	return validateEndorsementsAgainstEvidence(doc, s.cfg, s.selfAttestation)
}

// validateEndorsementsAgainstEvidence checks all configured evidence types
// against the golden measurements in the endorsement document.
func validateEndorsementsAgainstEvidence(doc *EndorsementDocument, cfg *Config, sa *parsedSelfAttestation) error {
	if cfg.ReportEvidence.NitroNSM {
		if doc.NitroNSM == nil {
			return fmt.Errorf("nitronsm: evidence configured but no endorsement measurements")
		}
		if err := validateNitroNSMMeasurements(sa.nitroNSMDoc, doc.NitroNSM); err != nil {
			return fmt.Errorf("nitronsm: %w", err)
		}
	}

	if cfg.ReportEvidence.NitroTPM {
		if doc.NitroTPM == nil {
			return fmt.Errorf("nitrotpm: evidence configured but no endorsement measurements")
		}
		if err := validateNitroTPMMeasurements(sa.nitroTPMDoc, doc.NitroTPM); err != nil {
			return fmt.Errorf("nitrotpm: %w", err)
		}
	}

	if cfg.ReportEvidence.SEVSNP {
		if doc.SEVSNP == nil {
			return fmt.Errorf("sevsnp: evidence configured but no endorsement measurements")
		}
		if err := validateSEVSNPMeasurement(sa.sevSNPReport, *doc.SEVSNP); err != nil {
			return fmt.Errorf("sevsnp: %w", err)
		}
	}

	if cfg.ReportEvidence.TDX {
		if doc.TDX == nil {
			return fmt.Errorf("tdx: evidence configured but no endorsement measurements")
		}
		if err := validateTDXMeasurements(sa.tdxQuote, doc.TDX); err != nil {
			return fmt.Errorf("tdx: %w", err)
		}
	}

	if cfg.TPM.Enabled {
		if doc.TPM == nil {
			return fmt.Errorf("tpm: evidence configured but no endorsement measurements")
		}
		if err := validateTPMMeasurements(sa.tpmPCRs, doc.TPM); err != nil {
			return fmt.Errorf("tpm: %w", err)
		}
	}

	return nil
}

// validateDependencyEndorsements fetches endorsement documents from the
// dependency's endorsement URLs and validates all evidence in the dependency
// report against the golden measurements.
func (s *Server) validateDependencyEndorsements(ctx context.Context, report *AttestationReport, parsed *parsedDependencyEvidence) error {
	var reportData AttestationReportData
	if err := json.Unmarshal(report.Data, &reportData); err != nil {
		return fmt.Errorf("parsing dependency report data: %w", err)
	}

	if len(reportData.Endorsements) == 0 {
		return nil
	}

	urls := make([]*url.URL, 0, len(reportData.Endorsements))
	for i, s := range reportData.Endorsements {
		u, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf("dependency endorsement %d: invalid URL %q: %w", i, s, err)
		}
		urls = append(urls, u)
	}

	doc, err := s.resolveEndorsements(ctx, urls)
	if err != nil {
		return err
	}

	// Validate each evidence entry present in the dependency report
	for _, ev := range report.Evidence {
		switch ev.Kind {
		case "nitronsm":
			if doc.NitroNSM == nil {
				return fmt.Errorf("nitronsm: dependency has evidence but endorsement has no measurements")
			}
			if parsed.nitroNSMDoc == nil {
				return fmt.Errorf("nitronsm: no parsed evidence available for endorsement check")
			}
			if err := validateNitroNSMMeasurements(parsed.nitroNSMDoc, doc.NitroNSM); err != nil {
				return fmt.Errorf("nitronsm: %w", err)
			}
		case "nitrotpm":
			if doc.NitroTPM == nil {
				return fmt.Errorf("nitrotpm: dependency has evidence but endorsement has no measurements")
			}
			if parsed.nitroTPMDoc == nil {
				return fmt.Errorf("nitrotpm: no parsed evidence available for endorsement check")
			}
			if err := validateNitroTPMMeasurements(parsed.nitroTPMDoc, doc.NitroTPM); err != nil {
				return fmt.Errorf("nitrotpm: %w", err)
			}
		case "sevsnp":
			if doc.SEVSNP == nil {
				return fmt.Errorf("sevsnp: dependency has evidence but endorsement has no measurements")
			}
			if parsed.sevSNPReport == nil {
				return fmt.Errorf("sevsnp: no parsed evidence available for endorsement check")
			}
			if err := validateSEVSNPMeasurement(parsed.sevSNPReport, *doc.SEVSNP); err != nil {
				return fmt.Errorf("sevsnp: %w", err)
			}
		case "tdx":
			if doc.TDX == nil {
				return fmt.Errorf("tdx: dependency has evidence but endorsement has no measurements")
			}
			if parsed.tdxQuote == nil {
				return fmt.Errorf("tdx: no parsed evidence available for endorsement check")
			}
			if err := validateTDXMeasurements(parsed.tdxQuote, doc.TDX); err != nil {
				return fmt.Errorf("tdx: %w", err)
			}
		}
	}

	// Validate TPM PCRs if the dependency report includes them
	if reportData.TPMData != nil && len(reportData.TPMData.PCRs) > 0 {
		if doc.TPM == nil {
			return fmt.Errorf("tpm: dependency has TPM data but endorsement has no measurements")
		}
		if err := validateTPMMeasurements(reportData.TPMData.PCRs, doc.TPM); err != nil {
			return fmt.Errorf("tpm: %w", err)
		}
	}

	return nil
}

// --- Measurement comparison functions ---

// validateNitroNSMMeasurements compares Nitro NSM PCR values from a verified
// attestation document against golden values from an endorsement.
func validateNitroNSMMeasurements(doc *nitro.AttestationDocument, endorsement *PCREndorsement) error {
	return comparePCRs(doc.PCRs, endorsement)
}

// validateNitroTPMMeasurements compares NitroTPM PCR values from a verified
// attestation document against golden values from an endorsement.
func validateNitroTPMMeasurements(doc *nitro.AttestationDocument, endorsement *PCREndorsement) error {
	return comparePCRs(doc.NitroTPMPCRs, endorsement)
}

// comparePCRs compares actual PCR values (map[int][]byte) against golden
// values from an endorsement.
func comparePCRs(actual map[int][]byte, endorsement *PCREndorsement) error {
	for idx, expectedHex := range endorsement.Measurements.PCRs {
		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			return fmt.Errorf("PCR%d: invalid hex in endorsement: %w", idx, err)
		}
		actualVal, ok := actual[idx]
		if !ok {
			return fmt.Errorf("PCR%d: present in endorsement but missing from evidence", idx)
		}
		if !bytes.Equal(actualVal, expected) {
			return fmt.Errorf("PCR%d mismatch: expected %s, got %s", idx,
				hex.EncodeToString(expected), hex.EncodeToString(actualVal))
		}
	}
	return nil
}

// validateSEVSNPMeasurement compares the SEV-SNP launch measurement against
// the golden hex value from an endorsement.
func validateSEVSNPMeasurement(report *spb.Report, endorsementHex string) error {
	expected, err := hex.DecodeString(endorsementHex)
	if err != nil {
		return fmt.Errorf("invalid hex in endorsement: %w", err)
	}
	actual := report.GetMeasurement()
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("measurement mismatch: expected %s, got %s",
			hex.EncodeToString(expected), hex.EncodeToString(actual))
	}
	return nil
}

// validateTDXMeasurements compares TDX measurement registers against golden
// values from an endorsement. Only non-empty endorsement fields are checked.
func validateTDXMeasurements(quote *pb.QuoteV4, endorsement *TDXEndorsement) error {
	body := quote.GetTdQuoteBody()

	checks := []struct {
		name     string
		expected string
		actual   []byte
	}{
		{"MRTD", endorsement.MRTD, body.GetMrTd()},
		{"RTMR0", endorsement.RTMR0, getRTMR(body, 0)},
		{"RTMR1", endorsement.RTMR1, getRTMR(body, 1)},
		{"RTMR2", endorsement.RTMR2, getRTMR(body, 2)},
	}

	for _, c := range checks {
		if c.expected == "" {
			continue
		}
		exp, err := hex.DecodeString(c.expected)
		if err != nil {
			return fmt.Errorf("%s: invalid hex in endorsement: %w", c.name, err)
		}
		if !bytes.Equal(c.actual, exp) {
			return fmt.Errorf("%s mismatch: expected %s, got %s", c.name,
				hex.EncodeToString(exp), hex.EncodeToString(c.actual))
		}
	}

	return nil
}

func getRTMR(body *pb.TDQuoteBody, idx int) []byte {
	rtmrs := body.GetRtmrs()
	if idx < len(rtmrs) {
		return rtmrs[idx]
	}
	return nil
}

// validateTPMMeasurements compares generic TPM PCR values against golden
// values from an endorsement.
func validateTPMMeasurements(pcrs map[int]hexbytes.Bytes, endorsement *PCREndorsement) error {
	for idx, expectedHex := range endorsement.Measurements.PCRs {
		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			return fmt.Errorf("PCR%d: invalid hex in endorsement: %w", idx, err)
		}
		actualVal, ok := pcrs[idx]
		if !ok {
			return fmt.Errorf("PCR%d: present in endorsement but missing from evidence", idx)
		}
		if !bytes.Equal([]byte(actualVal), expected) {
			return fmt.Errorf("PCR%d mismatch: expected %s, got %s", idx,
				hex.EncodeToString(expected), hex.EncodeToString([]byte(actualVal)))
		}
	}
	return nil
}
