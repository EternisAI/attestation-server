// Package app implements the attestation server: configuration, HTTP
// handler, TEE evidence collection, transitive dependency verification,
// endorsement validation, TLS certificate management, and cosign
// signature verification.
package app

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"

	"github.com/eternisai/attestation-server/pkg/nitro"
	"github.com/eternisai/attestation-server/pkg/sevsnp"
	"github.com/eternisai/attestation-server/pkg/tdx"
	"github.com/eternisai/attestation-server/pkg/tpm"
)

const (
	// nonceHeader carries the hex-encoded nonce that the caller wants bound
	// into the attestation evidence. Dependency servers receive this from
	// their parent so the entire chain shares one nonce.
	nonceHeader = "x-attestation-nonce"

	// pathHeader carries a comma-separated list of service instance IDs
	// visited along the dependency chain, used for cycle detection.
	pathHeader = "x-attestation-path"
)

// handleAttestation serves GET /api/v1/attestation. It collects server
// metadata into AttestationReportData, hashes it with SHA-512, then uses
// that digest as the nonce for the configured TEE attestation mechanism(s).
// The response pairs the raw evidence blob(s) with the report data so that
// a verifier can recompute the digest and check it against the evidence.
func (s *Server) handleAttestation(c *fiber.Ctx) error {
	requestID, _ := c.Locals("requestid").(string)

	// Detect dependency cycles via X-Attestation-Path. The header carries
	// a comma-separated list of instance IDs visited along the dependency
	// chain. If our own ID appears, a cycle exists.
	attestationPath := c.Get(pathHeader)
	if attestationPath != "" {
		for _, id := range strings.Split(attestationPath, ",") {
			if strings.TrimSpace(id) == s.instanceID {
				return fiber.NewError(fiber.StatusConflict, "dependency cycle detected")
			}
		}
	}

	// Resolve nonce: query param > header; left empty if not provided.
	// The nonce is a hex-encoded byte slice of up to 64 bytes (128 hex digits).
	var nonce string
	if n := c.Query("nonce"); n != "" {
		nonce = n
	} else if n := c.Get(nonceHeader); n != "" {
		nonce = n
	}
	if nonce != "" {
		if len(nonce) > 128 {
			return fiber.NewError(fiber.StatusBadRequest, "nonce exceeds 64 bytes")
		}
		if _, err := hex.DecodeString(nonce); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "nonce is not valid hex")
		}
	}

	// Build endorsement URL strings
	endorsements := make([]string, len(s.endorsements))
	for i, u := range s.endorsements {
		endorsements[i] = u.String()
	}

	// Build user data
	userData := make(map[string]any)
	if len(s.cfg.ReportEnvVars) > 0 {
		envMap := make(map[string]string)
		for _, name := range s.cfg.ReportEnvVars {
			if val, ok := os.LookupEnv(name); ok {
				envMap[name] = val
			}
		}
		userData["env"] = envMap
	}

	// Build TLS certificate data
	tlsData := &TLSReportData{}
	s.certs.mu.RLock()
	if s.certs.public != nil {
		tlsData.Public = &TLSCertificateData{
			CertificateFingerprint: s.certs.public.certFingerprint,
			PublicKeyFingerprint:   s.certs.public.pubKeyFingerprint,
		}
	}
	if s.certs.private != nil {
		tlsData.Private = &TLSCertificateData{
			CertificateFingerprint: s.certs.private.certFingerprint,
			PublicKeyFingerprint:   s.certs.private.pubKeyFingerprint,
		}
	}
	s.certs.mu.RUnlock()

	// Extract client certificate fingerprint from XFCC header.
	// Multiple entries (comma-separated) indicate proxy intermediaries,
	// which break the direct e2e encryption guarantee.
	if xfcc := c.Get("x-forwarded-client-cert"); xfcc != "" {
		if strings.Contains(xfcc, ",") {
			s.logger.Error("multiple XFCC entries detected, direct e2e encryption required without intermediaries", "request_id", requestID)
			return fiber.NewError(fiber.StatusBadRequest, "multiple client certificate entries not supported")
		}
		if fp := extractXFCCHash(xfcc); fp != "" {
			tlsData.Client = &TLSCertificateData{
				CertificateFingerprint: fp,
			}
		}
	}

	var tpmData *TPMData
	if s.cfg.TPM.Enabled {
		start := time.Now()
		pcrs, err := tpm.ReadPCRs(s.cfg.TPM.Algorithm)
		if err != nil {
			s.logger.Error("tpm pcr read failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		s.logger.Debug("tpm pcr read complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		tpmData = &TPMData{
			Digest: s.cfg.TPM.AlgorithmName,
			PCRs:   pcrs,
		}
	}

	// Every attestation response must prove end-to-end encryption. The
	// client certificate fingerprint (from XFCC) covers service-to-service
	// mTLS within the dependency chain. The public certificate covers
	// external clients at the Internet-facing ingress. At least one must
	// be present; otherwise the response cannot be trusted as e2e encrypted.
	if tlsData.Client == nil && tlsData.Public == nil {
		s.logger.Error("attestation request has neither client certificate (XFCC) nor public certificate, cannot prove end-to-end encryption", "request_id", requestID)
		return fiber.NewError(fiber.StatusBadRequest, "end-to-end encryption proof required: provide a client certificate or configure a public certificate")
	}

	reportData := &AttestationReportData{
		RequestID:    requestID,
		Nonce:        nonce,
		BuildInfo:    s.buildInfo,
		TLS:          tlsData,
		Endorsements: endorsements,
		UserData:     userData,
		SecureBoot:   s.secureBoot,
		TPMData:      tpmData,
	}

	reportDataJSON, err := json.MarshalWithOption(reportData, json.DisableHTMLEscape())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to marshal report data")
	}

	digest := sha512.Sum512(reportDataJSON)

	// Fetch and verify dependency attestation reports in parallel.
	nonceHex := hex.EncodeToString(digest[:])
	deps, err := s.fetchDependencies(nonceHex, requestID, attestationPath)
	if err != nil {
		if errors.Is(err, errDependencyCycle) {
			return fiber.NewError(fiber.StatusConflict, "dependency cycle detected")
		}
		s.logger.Error("dependency attestation failed", "error", err, "request_id", requestID)
		return fiber.NewError(upstreamErrorCode(err), "dependency attestation failed")
	}

	// Validate own endorsements (cached fast-path or re-fetch on TTL expiry).
	// Use the server's shutdown context so that backoff sleeps in
	// fetchWithRetry are interrupted on graceful shutdown. Fiber's
	// c.UserContext() is context.Background() and is never cancelled.
	if len(s.endorsements) > 0 {
		if err := s.validateOwnEndorsements(s.shutdownCtx()); err != nil {
			s.logger.Error("endorsement validation failed", "request_id", requestID, "error", err)
			return fiber.NewError(upstreamErrorCode(err), "endorsement validation failed")
		}
	}

	// Collect attestation evidence. Each Attest method self-verifies the
	// evidence using the same verification function that external verifiers
	// use, catching corrupted device output or driver bugs before they
	// reach callers. The verified parsed result is returned alongside the
	// raw blob.
	//
	// NitroNSM and TDX are exclusive and return immediately.
	if s.cfg.ReportEvidence.NitroNSM {
		start := time.Now()
		blob, doc, err := s.nitroNSM.Attest(digest[:])
		if err != nil {
			s.logger.Error("nitronsm attestation failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		s.logger.Debug("nitronsm attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{
				{Kind: "nitronsm", Blob: blob, Data: nitro.NewAttestationData(doc)},
			},
			Dependencies: deps,
		}
		return sendReport(c, report, reportDataJSON)
	}

	if s.cfg.ReportEvidence.TDX {
		start := time.Now()
		blob, err := s.tdxDev.GetEvidence(digest)
		if err != nil {
			s.logger.Error("tdx attestation failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		quote, err := tdx.VerifyEvidence(blob, digest, time.Now(), s.tdxVerifyOpt())
		if err != nil {
			s.logger.Error("tdx verification failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		s.logger.Debug("tdx attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{
				{Kind: "tdx", Blob: blob, Data: tdx.NewAttestationData(quote)},
			},
			Dependencies: deps,
		}
		return sendReport(c, report, reportDataJSON)
	}

	// Non-exclusive evidence types can be combined.
	var evidence []*AttestationEvidence

	var nitroTPMBlob []byte
	if s.cfg.ReportEvidence.NitroTPM {
		start := time.Now()
		blob, doc, err := s.nitroTPM.Attest(digest[:])
		if err != nil {
			s.logger.Error("nitrotpm attestation failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		s.logger.Debug("nitrotpm attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		nitroTPMBlob = blob
		evidence = append(evidence, &AttestationEvidence{Kind: "nitrotpm", Blob: blob, Data: nitro.NewAttestationData(doc)})
	}

	if s.cfg.ReportEvidence.SEVSNP {
		start := time.Now()
		// When NitroTPM evidence is also present, chain the two proofs by
		// hashing the NitroTPM blob into the SEV-SNP report data. This lets
		// a verifier confirm that both evidence blobs belong to the same request.
		var snpReportData [64]byte
		if nitroTPMBlob != nil {
			snpReportData = sha512.Sum512(nitroTPMBlob)
		} else {
			snpReportData = digest
		}
		blob, err := s.sevSNP.GetEvidence(snpReportData, s.cfg.ReportEvidence.SEVSNPVMPL)
		if err != nil {
			s.logger.Error("sevsnp attestation failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		snpReport, err := sevsnp.VerifyEvidence(blob, snpReportData, time.Now(), s.sevsnpRevocationChecker())
		if err != nil {
			s.logger.Error("sevsnp verification failed", "error", err, "request_id", requestID)
			return fiber.NewError(fiber.StatusInternalServerError, "attestation failed")
		}
		s.logger.Debug("sevsnp attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		evidence = append(evidence, &AttestationEvidence{Kind: "sevsnp", Blob: blob, Data: sevsnp.NewAttestationData(snpReport)})
	}

	if len(evidence) == 0 {
		return fiber.ErrNotImplemented
	}

	report := &AttestationReport{
		Evidence:     evidence,
		Dependencies: deps,
	}
	return sendReport(c, report, reportDataJSON)
}

// upstreamErrorCode returns the appropriate HTTP status code for an upstream
// error: 504 for timeouts, 503 for connection errors, 500 for everything else.
func upstreamErrorCode(err error) int {
	var te *errTimeout
	if errors.As(err, &te) {
		return fiber.StatusGatewayTimeout
	}
	var ce *errConnection
	if errors.As(err, &ce) {
		return fiber.StatusServiceUnavailable
	}
	return fiber.StatusInternalServerError
}

// sendReport marshals the AttestationReport with the same settings used
// for the nonce digest (DisableHTMLEscape) and writes it as the response
// body. The reportDataJSON is the pre-marshaled AttestationReportData
// that was hashed into the attestation nonce; it is embedded directly as
// the "data" field so that verifiers see byte-for-byte identical JSON.
func sendReport(c *fiber.Ctx, report *AttestationReport, reportDataJSON []byte) error {
	report.Data = json.RawMessage(reportDataJSON)
	body, err := json.MarshalWithOption(report, json.DisableHTMLEscape())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to marshal attestation report")
	}
	c.Set("Content-Type", "application/json")
	return c.Send(body)
}

// extractXFCCHash extracts the Hash field from a single
// x-forwarded-client-cert header entry as populated by Envoy proxy.
// The entry format is: key=value;key=value
// Multiple entries (comma-separated) must be rejected by the caller
// before invoking this function.
func extractXFCCHash(xfcc string) string {
	for _, field := range strings.Split(xfcc, ";") {
		field = strings.TrimSpace(field)
		if !strings.HasPrefix(field, "Hash=") {
			continue
		}
		hash := field[len("Hash="):]
		if isValidHexFingerprint(hash) {
			return hash
		}
		return ""
	}
	return ""
}

// sevsnpRevocationChecker returns a RevocationChecker for SEV-SNP evidence
// if CRL checking is enabled, or nil otherwise.
func (s *Server) sevsnpRevocationChecker() sevsnp.RevocationChecker {
	if s.crlCache == nil {
		return nil
	}
	return s.crlCache.CheckRevocation
}

// tdxVerifyOpt returns a VerifyOpt for TDX evidence. When revocation checking
// is enabled, it includes the cached collateral getter (if available) to
// avoid per-request Intel PCS round-trips.
func (s *Server) tdxVerifyOpt() tdx.VerifyOpt {
	if !s.cfg.RevocationEnabled {
		return tdx.VerifyOpt{}
	}
	return tdx.VerifyOpt{
		CheckRevocations: true,
		Getter:           s.tdxGetter,
	}
}

func isValidHexFingerprint(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
