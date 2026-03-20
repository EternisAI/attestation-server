package app

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/hf/nsm/request"
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

	reportData := &AttestationReportData{
		RequestID:    requestID,
		Nonce:        nonce,
		BuildInfo:    s.buildInfo,
		TLS:          tlsData,
		Endorsements: endorsements,
		UserData:     userData,
	}

	data, err := json.MarshalWithOption(reportData, json.DisableHTMLEscape())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to marshal report data")
	}

	digest := sha512.Sum512(data)

	// Collect attestation evidence.
	// NitroNSM is exclusive and returns immediately.
	if s.cfg.ReportEvidence.NitroNSM {
		doc, err := s.attestNitroNSM(digest[:])
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("nitro nsm attestation: %v", err))
		}
		report := &AttestationReport{
			Data: reportData,
			Evidence: []*AttestationEvidence{
				{Kind: "nitronsm", Data: doc},
			},
		}
		c.Set("Content-Type", "application/json")
		return c.JSON(report)
	}

	// Non-exclusive evidence types can be combined.
	var evidence []*AttestationEvidence

	if s.cfg.ReportEvidence.NitroTPM {
		doc, err := s.attestNitroTPM(digest[:])
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("nitro tpm attestation: %v", err))
		}
		evidence = append(evidence, &AttestationEvidence{Kind: "nitrotpm", Data: doc})
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

func (s *Server) attestNitroNSM(nonce []byte) ([]byte, error) {
	// The nsm library's Send uses sync.Pool for serialization buffers but does
	// not synchronize the underlying ioctl syscall on the shared /dev/nsm fd.
	// Concurrent ioctls could interleave request/response pairings, so we
	// serialize all NSM device access.
	s.nsmMu.Lock()
	res, err := s.nsm.Send(&request.Attestation{
		Nonce: nonce,
	})
	s.nsmMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("nsm attestation request failed: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("nsm returned error: %s", res.Error)
	}
	if res.Attestation == nil {
		return nil, fmt.Errorf("nsm response missing attestation field")
	}
	if res.Attestation.Document == nil {
		return nil, fmt.Errorf("nsm response missing attestation document")
	}
	return res.Attestation.Document, nil
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
