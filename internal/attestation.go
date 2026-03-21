package app

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
)

func (s *Server) handleAttestation(c *fiber.Ctx) error {
	requestID, _ := c.Locals("requestid").(string)

	// Resolve nonce: query param > header; left empty if not provided.
	// The nonce is a hex-encoded byte slice of up to 64 bytes (128 hex digits).
	var nonce string
	if n := c.Query("nonce"); n != "" {
		nonce = n
	} else if n := c.Get("x-attestation-nonce"); n != "" {
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

	// Extract client certificate fingerprint from XFCC header
	if xfcc := c.Get("x-forwarded-client-cert"); xfcc != "" {
		if fp := extractXFCCHash(xfcc); fp != "" {
			tlsData.Client = &TLSCertificateData{
				CertificateFingerprint: fp,
			}
		}
	}

	var tpmPCRs map[string]string
	if s.cfg.TPM.Enabled {
		start := time.Now()
		var err error
		tpmPCRs, err = ReadTPMPCRs(s.cfg.TPM.Algorithm)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("tpm: %v", err))
		}
		s.logger.Debug("tpm pcr read complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
	}

	reportData := &AttestationReportData{
		RequestID:    requestID,
		Nonce:        nonce,
		BuildInfo:    s.buildInfo,
		TLS:          tlsData,
		Endorsements: endorsements,
		UserData:     userData,
		SecureBoot:   s.secureBoot,
		TPMPCRs:      tpmPCRs,
	}

	data, err := json.MarshalWithOption(reportData, json.DisableHTMLEscape())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to marshal report data")
	}

	digest := sha512.Sum512(data)

	// Collect attestation evidence.
	// NitroNSM and TDX are exclusive and return immediately.
	if s.cfg.ReportEvidence.NitroNSM {
		start := time.Now()
		blob, err := s.nitroNSM.Attest(digest[:])
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("nitronsm: %v", err))
		}
		doc, err := verifyNitroAttestation(blob, digest[:])
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("nitronsm: %v", err))
		}
		s.logger.Debug("nitronsm attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		report := &AttestationReport{
			Data: reportData,
			Evidence: []*AttestationEvidence{
				{Kind: "nitronsm", Blob: blob, Data: nitroAttestationData(doc)},
			},
		}
		c.Set("Content-Type", "application/json")
		return c.JSON(report)
	}

	if s.cfg.ReportEvidence.TDX {
		start := time.Now()
		blob, quote, err := s.tdx.Attest(digest)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("tdx: %v", err))
		}
		s.logger.Debug("tdx attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		report := &AttestationReport{
			Data: reportData,
			Evidence: []*AttestationEvidence{
				{Kind: "tdx", Blob: blob, Data: tdxAttestationData(quote)},
			},
		}
		c.Set("Content-Type", "application/json")
		return c.JSON(report)
	}

	// Non-exclusive evidence types can be combined.
	var evidence []*AttestationEvidence

	var nitroTPMBlob []byte
	if s.cfg.ReportEvidence.NitroTPM {
		start := time.Now()
		blob, err := s.attestNitroTPM(digest[:])
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("nitrotpm: %v", err))
		}
		doc, err := verifyNitroAttestation(blob, digest[:])
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("nitrotpm: %v", err))
		}
		s.logger.Debug("nitrotpm attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		nitroTPMBlob = blob
		evidence = append(evidence, &AttestationEvidence{Kind: "nitrotpm", Blob: blob, Data: nitroAttestationData(doc)})
	}

	if s.cfg.ReportEvidence.SEVSNP {
		start := time.Now()
		var snpReportData [64]byte
		if nitroTPMBlob != nil {
			snpReportData = sha512.Sum512(nitroTPMBlob)
		} else {
			snpReportData = digest
		}
		blob, report, err := s.sevSNP.Attest(snpReportData, s.cfg.ReportEvidence.SEVSNPVMPL)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("sevsnp: %v", err))
		}
		s.logger.Debug("sevsnp attestation complete", "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
		evidence = append(evidence, &AttestationEvidence{Kind: "sevsnp", Blob: blob, Data: sevsnpAttestationData(report)})
	}

	if len(evidence) == 0 {
		return fiber.ErrNotImplemented
	}

	report := &AttestationReport{
		Data:     reportData,
		Evidence: evidence,
	}
	c.Set("Content-Type", "application/json")
	return c.JSON(report)
}

func (s *Server) attestNitroTPM(nonce []byte) ([]byte, error) {
	doc, err := s.nitroTPM.Attest(nonce)
	if err != nil {
		return nil, fmt.Errorf("tpm attestation request failed: %w", err)
	}
	return doc, nil
}

// extractXFCCHash extracts the Hash field from an x-forwarded-client-cert
// header value as populated by Envoy proxy. The header format is:
//
//	key=value;key=value[,key=value;key=value]
//
// where commas separate multiple client certificates and semicolons separate
// fields within a certificate entry.
func extractXFCCHash(xfcc string) string {
	// Use the rightmost certificate entry (closest proxy's client cert)
	if idx := strings.LastIndexByte(xfcc, ','); idx >= 0 {
		xfcc = xfcc[idx+1:]
	}
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

func isValidHexFingerprint(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
