package app

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/go-sev-guest/abi"
	"golang.org/x/sync/errgroup"

	"github.com/eternisai/attestation-server/pkg/nitro"
	"github.com/eternisai/attestation-server/pkg/sevsnp"
	"github.com/eternisai/attestation-server/pkg/tdx"
)

// errDependencyCycle indicates that a dependency endpoint reported a cycle
// (HTTP 409). The handler uses this to propagate 409 to the caller instead
// of returning a generic 500.
var errDependencyCycle = errors.New("dependency cycle detected")

const (
	// depClientTimeout is the overall timeout for a single dependency request,
	// covering DNS, connect, TLS handshake, headers, and body transfer.
	depClientTimeout = 30 * time.Second

	// depTLSHandshakeTimeout caps the TLS negotiation phase so a peer
	// cannot stall indefinitely during the handshake.
	depTLSHandshakeTimeout = 10 * time.Second

	// depResponseHeaderTimeout caps how long we wait for the server to
	// send response headers after the request is fully written.
	depResponseHeaderTimeout = 15 * time.Second

	// depMaxResponseBytes limits the response body size to prevent a
	// misbehaving peer from exhausting memory.
	depMaxResponseBytes = 4 << 20 // 4 MiB
)

// fetchDependencies fetches and verifies attestation reports from all
// configured dependency endpoints in parallel. The nonceHex is sent as
// the x-attestation-nonce header and the requestID is forwarded as
// X-Request-Id for dependency loop detection.
func (s *Server) fetchDependencies(nonceHex, requestID, attestationPath string) ([]json.RawMessage, error) {
	if len(s.cfg.DependencyEndpoints) == 0 {
		return nil, nil
	}

	// Append our instance ID to the attestation path so downstream
	// servers can detect cycles back to us.
	outboundPath := s.instanceID
	if attestationPath != "" {
		outboundPath = attestationPath + "," + s.instanceID
	}

	start := time.Now()
	client := s.dependencyHTTPClient()

	g, gctx := errgroup.WithContext(s.ctx)
	results := make([]json.RawMessage, len(s.cfg.DependencyEndpoints))

	for i, ep := range s.cfg.DependencyEndpoints {
		g.Go(func() error {
			depStart := time.Now()
			raw, err := s.fetchAndVerifyDependency(gctx, client, ep, nonceHex, requestID, outboundPath)
			if err != nil {
				dur := time.Since(depStart).Milliseconds()
				if gctx.Err() != nil {
					s.logger.Debug("dependency attestation cancelled", "endpoint", ep.String(), "error", err, "duration_ms", dur, "request_id", requestID)
				} else {
					s.logger.Error("dependency attestation failed", "endpoint", ep.String(), "error", err, "duration_ms", dur, "request_id", requestID)
				}
				if errors.Is(err, errDependencyCycle) {
					return errDependencyCycle
				}
				return fmt.Errorf("dependency attestation failed")
			}
			s.logger.Debug("dependency attestation complete", "endpoint", ep.String(), "duration_ms", time.Since(depStart).Milliseconds(), "request_id", requestID)
			results[i] = raw
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	s.logger.Debug("all dependency attestations complete", "count", len(results), "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
	return results, nil
}

// dependencyHTTPClient builds an HTTP client hardened against slowloris-like
// attacks and misbehaving peers. It sets timeouts at every phase (dial, TLS
// handshake, response headers) and an overall request deadline.
//
// The client presents the private certificate as the TLS client cert (mTLS)
// and verifies the dependency's server certificate against the same CA
// bundle used for the private certificate. All private certificates in the
// dependency chain must be issued by the same CA — Envoy only populates the
// XFCC header when the client cert passes CA verification.
//
// Plain HTTP endpoints are expected to be reachable only through a local
// mTLS-enabling proxy (e.g. Envoy, SPIRE Agent) that terminates TLS on the
// loopback interface.
func (s *Server) dependencyHTTPClient() *http.Client {
	tlsCfg := &tls.Config{}

	s.certs.mu.RLock()
	tlsCfg.Certificates = []tls.Certificate{*s.certs.private.cert}
	if s.certs.privateCA != nil {
		tlsCfg.RootCAs = s.certs.privateCA.roots
	}
	s.certs.mu.RUnlock()

	return &http.Client{
		Timeout: depClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   depTLSHandshakeTimeout,
			ResponseHeaderTimeout: depResponseHeaderTimeout,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			DisableKeepAlives: true,
		},
	}
}

// fetchAndVerifyDependency sends a GET request to the dependency endpoint
// with the nonce header and request ID, parses the response, verifies all
// evidence entries and nonce binding, and checks that the dependency saw
// our private certificate as the client cert (end-to-end encryption proof).
// Returning raw bytes (json.RawMessage) instead of a parsed struct avoids
// re-marshaling through goccy/go-json, which can crash when serialising
// values that were decoded into any-typed fields (zero-copy string refs).
func (s *Server) fetchAndVerifyDependency(ctx context.Context, client *http.Client, endpoint *url.URL, nonceHex, requestID, attestationPath string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set(nonceHeader, nonceHex)
	req.Header.Set("X-Request-Id", requestID)
	req.Header.Set(pathHeader, attestationPath)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusConflict {
			return nil, errDependencyCycle
		}
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, depMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var report AttestationReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	s.certs.mu.RLock()
	privFP := s.certs.private.certFingerprint
	s.certs.mu.RUnlock()

	if err := verifyDependencyReport(&report, nonceHex, privFP, time.Now()); err != nil {
		if isE2EError(err) {
			s.logger.Error("dependency end-to-end encryption verification failed",
				"endpoint", endpoint.String(), "request_id", requestID, "error", err)
			return nil, fmt.Errorf("dependency end-to-end encryption verification failed")
		}
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return json.RawMessage(body), nil
}

// errE2E is a sentinel type for end-to-end encryption verification failures.
// The caller uses isE2EError to distinguish these from cryptographic
// verification failures so it can log a descriptive message while returning
// an opaque error to the user.
type errE2E struct{ msg string }

func (e *errE2E) Error() string { return e.msg }

func isE2EError(err error) bool {
	var e *errE2E
	return errors.As(err, &e)
}

// verifyDependencyReport verifies that a dependency's attestation report
// has a matching nonce, that all evidence entries are cryptographically
// valid, and that the dependency acknowledged our client certificate
// (proving end-to-end encryption). It handles NitroTPM→SEV-SNP chaining
// the same way the handler does. The data JSON is compacted before hashing
// to ensure the digest matches regardless of whitespace formatting.
//
// clientCertFP is the SHA-256 hex fingerprint of the private certificate
// we presented as the TLS client cert when connecting to the dependency.
// The dependency must include this in data.tls.client.certificate.
func verifyDependencyReport(report *AttestationReport, expectedNonce, clientCertFP string, now time.Time) error {
	if len(report.Evidence) == 0 {
		return fmt.Errorf("no evidence in report")
	}

	var reportData AttestationReportData
	if err := json.Unmarshal(report.Data, &reportData); err != nil {
		return fmt.Errorf("parsing report data: %w", err)
	}
	if reportData.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}

	// Verify that the dependency recorded our client certificate fingerprint.
	// Without this, the connection may have been intercepted by a proxy that
	// strips or replaces the client cert, breaking the end-to-end encryption
	// guarantee bound to the TEE attestation.
	if reportData.TLS == nil || reportData.TLS.Client == nil || reportData.TLS.Client.CertificateFingerprint == "" {
		return &errE2E{msg: "dependency response missing client certificate fingerprint in attestation data"}
	}
	if reportData.TLS.Client.CertificateFingerprint != clientCertFP {
		return &errE2E{msg: fmt.Sprintf("client certificate fingerprint mismatch: expected %s, got %s",
			clientCertFP, reportData.TLS.Client.CertificateFingerprint)}
	}

	// Compact the data JSON before hashing. The attestation handler
	// marshals with json.Marshal (producing compact output), so the
	// digest must be computed over the compact form.
	var compactData bytes.Buffer
	if err := json.Compact(&compactData, report.Data); err != nil {
		return fmt.Errorf("compacting report data: %w", err)
	}
	digest := sha512.Sum512(compactData.Bytes())

	var nitroTPMBlob []byte
	for _, ev := range report.Evidence {
		switch ev.Kind {
		case "nitronsm":
			if _, err := nitro.VerifyAttestation(ev.Blob, digest[:], now); err != nil {
				return fmt.Errorf("nitronsm verification: %w", err)
			}
		case "nitrotpm":
			if _, err := nitro.VerifyAttestation(ev.Blob, digest[:], now); err != nil {
				return fmt.Errorf("nitrotpm verification: %w", err)
			}
			nitroTPMBlob = ev.Blob
		case "sevsnp":
			var snpReportData [64]byte
			if nitroTPMBlob != nil {
				snpReportData = sha512.Sum512(nitroTPMBlob)
			} else {
				snpReportData = digest
			}
			if len(ev.Blob) < abi.ReportSize {
				return fmt.Errorf("sevsnp blob too short: %d < %d", len(ev.Blob), abi.ReportSize)
			}
			rawReport := ev.Blob[:abi.ReportSize]
			certTable := ev.Blob[abi.ReportSize:]
			if _, err := sevsnp.VerifyAttestation(rawReport, certTable, snpReportData, nil, now); err != nil {
				return fmt.Errorf("sevsnp verification: %w", err)
			}
		case "tdx":
			if _, err := tdx.VerifyQuote(ev.Blob, digest, now); err != nil {
				return fmt.Errorf("tdx verification: %w", err)
			}
		default:
			return fmt.Errorf("unknown evidence kind %q", ev.Kind)
		}
	}

	return nil
}
