package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/goccy/go-json"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"golang.org/x/sync/errgroup"

	"github.com/eternisai/attestation-server/pkg/hexbytes"
	"github.com/eternisai/attestation-server/pkg/nitro"
)

// fetchEndorsementDocumentsWithClient fetches endorsement documents from all
// URLs in parallel with retry, verifies byte-for-byte identity, parses the
// document, and returns it alongside the raw bytes (needed for cosign
// verification) and TTL derived from Cache-Control headers.
//
// The caller must set a context timeout — this function does not create one
// internally so that the same deadline can cover both endorsement document
// and cosign signature fetches.
func (s *Server) fetchEndorsementDocumentsWithClient(ctx context.Context, urls []*url.URL, client *http.Client) (*EndorsementDocument, []byte, int, time.Duration, error) {
	if len(urls) == 0 {
		return nil, nil, 0, 0, fmt.Errorf("no endorsement URLs configured")
	}

	for i, u := range urls {
		if u.Scheme != "https" {
			return nil, nil, 0, 0, fmt.Errorf("endorsement URL %d: scheme must be https, got %q (%s)", i, u.Scheme, u.String())
		}
		if err := CheckEndorsementDomain(u.Hostname(), s.cfg.EndorsementAllowedDomains); err != nil {
			return nil, nil, 0, 0, fmt.Errorf("endorsement URL %d: %w", i, err)
		}
	}

	// DNSSEC pre-validation for unique hosts
	if s.dnssecResolver != nil {
		seen := make(map[string]bool)
		for _, u := range urls {
			host := u.Hostname()
			if seen[host] {
				continue
			}
			seen[host] = true
			if err := s.dnssecResolver.Validate(ctx, host); err != nil {
				return nil, nil, 0, 0, err
			}
		}
	}

	if client == nil {
		client = s.fetchHTTPClient()
	}
	g, gctx := errgroup.WithContext(ctx)
	results := make([]fetchResult, len(urls))

	for i, u := range urls {
		g.Go(func() error {
			body, header, err := fetchWithRetry(gctx, client, u, s.logger)
			if err != nil {
				return fmt.Errorf("fetching %s: %w", u.String(), err)
			}
			results[i] = fetchResult{body: body, header: header}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, nil, 0, 0, err
	}

	// Verify byte-for-byte identity across all responses
	refHash := sha256.Sum256(results[0].body)
	for i := 1; i < len(results); i++ {
		h := sha256.Sum256(results[i].body)
		if h != refHash {
			return nil, nil, 0, 0, fmt.Errorf("endorsement document mismatch: %s (sha256:%s) differs from %s (sha256:%s)",
				urls[i].String(), hex.EncodeToString(h[:8]),
				urls[0].String(), hex.EncodeToString(refHash[:8]))
		}
	}

	var doc EndorsementDocument
	if err := json.Unmarshal(results[0].body, &doc); err != nil {
		return nil, nil, 0, 0, fmt.Errorf("parsing endorsement document: %w", err)
	}

	// Use the most conservative (shortest) TTL across all responses
	ttl := fetchMaxTTL
	for _, r := range results {
		t := parseCacheTTL(r.header)
		if t < ttl {
			ttl = t
		}
	}
	if ttl <= 0 {
		ttl = fetchDefaultTTL
	}

	return &doc, results[0].body, len(results[0].body), ttl, nil
}

// resolveEndorsements resolves endorsement documents from cache or fetches
// them from the provided URLs. When cosign verification is enabled, it also
// fetches and verifies the cosign signature bundle. Shared by own-evidence
// and dependency paths.
func (s *Server) resolveEndorsements(ctx context.Context, urls []*url.URL) (*EndorsementDocument, *cosignResult, error) {
	return s.resolveEndorsementsWithClient(ctx, urls, nil)
}

// resolveEndorsementsWithClient is the internal implementation that accepts
// an optional HTTP client override (used in tests with httptest TLS servers).
func (s *Server) resolveEndorsementsWithClient(ctx context.Context, urls []*url.URL, client *http.Client) (*EndorsementDocument, *cosignResult, error) {
	// Fast path: check caches
	if s.httpCache != nil {
		if val, ok := s.httpCache.get(urls[0].String()); ok {
			if doc, ok := val.(*EndorsementDocument); ok {
				if !s.cfg.CosignVerify || s.sigstoreVerifier == nil {
					return doc, nil, nil
				}
				sigURL := urls[0].String() + s.cfg.CosignURLSuffix
				if crVal, crOk := s.httpCache.get(sigURL); crOk {
					if cr, ok := crVal.(*cosignResult); ok {
						return doc, cr, nil
					}
				}
				// Cosign cache miss → need raw bytes → fall through to re-fetch
			}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.EndorsementClientTimeout)
	defer cancel()

	doc, rawBody, rawSize, ttl, err := s.fetchEndorsementDocumentsWithClient(ctx, urls, client)
	if err != nil {
		return nil, nil, err
	}

	urlStrs := make([]string, len(urls))
	for i, u := range urls {
		urlStrs[i] = u.String()
	}

	if s.httpCache != nil {
		s.httpCache.setGroup(urlStrs, doc, rawSize, ttl)
		if s.logger != nil {
			s.logger.Debug("cached endorsement document", "url", urlStrs[0], "ttl", ttl.String())
		}
	}

	var cr *cosignResult
	if s.cfg.CosignVerify && s.sigstoreVerifier != nil {
		bundleBytes, sigRawSize, sigTTL, fetchErr := s.fetchCosignSignatures(ctx, urls, client)
		if fetchErr != nil {
			return nil, nil, fmt.Errorf("cosign signature fetch: %w", fetchErr)
		}

		cr, err = s.verifyCosignBundle(bundleBytes, rawBody)
		if err != nil {
			return nil, nil, fmt.Errorf("cosign verification: %w", err)
		}

		cosignTTL := min(ttl, sigTTL)
		sigURLStrs := make([]string, len(urls))
		for i, u := range urls {
			sigURLStrs[i] = u.String() + s.cfg.CosignURLSuffix
		}
		if s.httpCache != nil {
			s.httpCache.setGroup(sigURLStrs, cr, sigRawSize, cosignTTL)
			if s.logger != nil {
				s.logger.Debug("cached cosign signature", "url", sigURLStrs[0], "ttl", cosignTTL.String())
			}
		}
	}

	return doc, cr, nil
}

// validateOwnEndorsements fetches (or retrieves from cache) endorsement
// documents for the server's own endorsement URLs and validates all
// configured evidence types against the golden measurements.
func (s *Server) validateOwnEndorsements(ctx context.Context) error {
	if len(s.endorsements) == 0 {
		return nil
	}

	doc, cr, err := s.resolveEndorsements(ctx, s.endorsements)
	if err != nil {
		return err
	}

	if cr != nil {
		if err := s.validateCosignOIDs(cr, s.buildInfo); err != nil {
			return fmt.Errorf("cosign: %w", err)
		}
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
		if s.cfg.CosignVerify {
			return fmt.Errorf("cosign verification enabled but dependency has no endorsement URLs")
		}
		return nil
	}

	urls := make([]*url.URL, 0, len(reportData.Endorsements))
	for i, rawURL := range reportData.Endorsements {
		u, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("dependency endorsement %d: invalid URL %q: %w", i, rawURL, err)
		}
		if err := CheckEndorsementDomain(u.Hostname(), s.cfg.EndorsementAllowedDomains); err != nil {
			return fmt.Errorf("dependency endorsement %d: %w", i, err)
		}
		urls = append(urls, u)
	}

	doc, cr, err := s.resolveEndorsements(ctx, urls)
	if err != nil {
		return err
	}

	if cr != nil {
		if err := s.validateCosignOIDs(cr, reportData.BuildInfo); err != nil {
			return fmt.Errorf("cosign: %w", err)
		}
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
		if expectedHex == "" {
			return fmt.Errorf("PCR%d: empty value in endorsement", idx)
		}
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
	if endorsementHex == "" {
		return fmt.Errorf("empty measurement in endorsement")
	}
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
// values from an endorsement. Individual fields are optional, but at least
// one must be set — an endorsement with all fields empty would accept any
// TDX quote.
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

	var checked int
	for _, c := range checks {
		if c.expected == "" {
			continue
		}
		checked++
		exp, err := hex.DecodeString(c.expected)
		if err != nil {
			return fmt.Errorf("%s: invalid hex in endorsement: %w", c.name, err)
		}
		if !bytes.Equal(c.actual, exp) {
			return fmt.Errorf("%s mismatch: expected %s, got %s", c.name,
				hex.EncodeToString(exp), hex.EncodeToString(c.actual))
		}
	}

	if checked == 0 {
		return fmt.Errorf("TDX endorsement has no measurements (all fields empty)")
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
		if expectedHex == "" {
			return fmt.Errorf("PCR%d: empty value in endorsement", idx)
		}
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
