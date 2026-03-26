package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/eternisai/attestation-server/pkg/dnssec"
	"github.com/eternisai/attestation-server/pkg/nitro"
	"github.com/eternisai/attestation-server/pkg/sevsnp"
	"github.com/eternisai/attestation-server/pkg/tdx"
	"github.com/eternisai/attestation-server/pkg/tpm"
)

// Server wraps a Fiber application with its dependencies.
type Server struct {
	ctx              context.Context
	app              *fiber.App
	cfg              *Config
	logger           *slog.Logger
	buildInfo        *BuildInfo
	endorsements     []*url.URL
	certs            tlsCertificates
	nitroNSM         *nitro.NSM
	nitroTPM         *nitro.TPM
	sevSNP           *sevsnp.Device
	tdxDev           *tdx.Device
	secureBoot       *bool
	instanceID       string // deterministic ID for dependency cycle detection via X-Attestation-Path
	selfAttestation  *parsedSelfAttestation
	httpCache        *fetcherCache
	sigstoreVerifier *verify.Verifier
	rateLimitHandler fiber.Handler
	rateLimiters     *rateLimiterMap
	crlCache         *crlCache
	tdxGetter        *cachedHTTPSGetter
	dnssecResolver   *dnssec.Resolver
	ready            atomic.Bool
}

// NewServer constructs a Server with middleware and routes configured.
// The initialization order is significant:
//  1. Load build info and endorsement URLs (static config)
//  2. Load and verify TLS certificates
//  3. Open TEE devices and perform self-attestation (captures parsed
//     results for endorsement validation; primes SEV-SNP cert cache)
//  4. Validate endorsements against self-attestation evidence
//  5. Configure HTTP routes and middleware
//
// Steps 3–4 exit the process on failure, ensuring the server never
// starts with unverified evidence or stale endorsements.
func NewServer(cfg *Config, logger *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, logger: logger}

	bi, err := loadBuildInfo(cfg.BuildInfoPath)
	if err != nil {
		return nil, fmt.Errorf("loading build info: %w", err)
	}
	s.buildInfo = bi
	logger.Debug("loaded build info",
		"build_signer_uri", bi.BuildSignerURI,
		"build_signer_digest", bi.BuildSignerDigest,
		"runner_environment", bi.RunnerEnvironment,
		"source_repository_uri", bi.SourceRepositoryURI,
		"source_repository_digest", bi.SourceRepositoryDigest,
		"source_repository_ref", bi.SourceRepositoryRef,
		"source_repository_identifier", bi.SourceRepositoryIdentifier,
		"source_repository_owner_uri", bi.SourceRepositoryOwnerURI,
		"source_repository_owner_identifier", bi.SourceRepositoryOwnerIdentifier,
		"build_config_uri", bi.BuildConfigURI,
		"build_config_digest", bi.BuildConfigDigest,
		"build_trigger", bi.BuildTrigger,
		"run_invocation_uri", bi.RunInvocationURI,
		"source_repository_visibility", bi.SourceRepositoryVisibility,
		"deployment_environment", bi.DeploymentEnvironment,
	)

	endorsements, err := loadEndorsements(cfg.EndorsementsPath)
	if err != nil {
		return nil, fmt.Errorf("loading endorsements: %w", err)
	}
	if cfg.CosignVerify && len(endorsements) == 0 {
		return nil, fmt.Errorf("endorsements.cosign.verify is enabled but no endorsement URLs are configured")
	}
	s.endorsements = endorsements
	endorsementStrs := make([]string, len(endorsements))
	for i, u := range endorsements {
		endorsementStrs[i] = u.String()
	}
	logger.Debug("loaded endorsements", "count", len(endorsements), "urls", strings.Join(endorsementStrs, ","))

	if cfg.EndorsementSkipValidation {
		logger.Warn("endorsement validation is disabled, attestation will proceed without endorsement verification — security is weakened")
	}

	if len(endorsements) > 0 {
		if !cfg.CosignVerify {
			logger.Warn("cosign verification is disabled, endorsement documents are not cryptographically authenticated")
		}
		if len(cfg.EndorsementAllowedDomains) == 0 {
			logger.Warn("endorsements.allowed_domains is empty, endorsement documents will be fetched from any domain including attacker-controlled URLs in dependency reports")
		}
	}

	if cfg.HTTPAllowProxy {
		logger.Warn("http.allow_proxy is enabled, outbound HTTP clients will honour HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables")
	}

	if err := validateTLSConfig(cfg); err != nil {
		return nil, fmt.Errorf("TLS configuration: %w", err)
	}
	if err := s.loadCertificates(); err != nil {
		return nil, err
	}
	if cfg.PrivateTLSCertPath == "" {
		logger.Warn("running without private TLS certificate, dependency mTLS and XFCC client certificate proof are unavailable")
	}

	if cfg.EndorsementDNSSEC {
		dr, drErr := dnssec.New(5 * time.Second)
		if drErr != nil {
			return nil, fmt.Errorf("creating DNSSEC resolver: %w", drErr)
		}
		s.dnssecResolver = dr
		logger.Info("initialized dnssec resolver", "servers", strings.Join(dr.Servers(), ","))
	}

	s.instanceID = s.deriveServiceIdentity()

	// Skip UEFI secure boot detection in Nitro Enclaves: the enclave kernel
	// has no EFI firmware so the sysfs variable does not exist, and boot
	// integrity is proven by the NSM attestation document (PCR measurements).
	if cfg.ReportEvidence.NitroNSM {
		if cfg.SecureBootEnforce {
			logger.Warn("secure_boot.enforce ignored in nitro enclave, boot integrity is proven by nsm attestation")
		}
		logger.Debug("skipping uefi secure boot detection in nitro enclave")
	} else {
		sbState, sbErr := readSecureBootState()
		if sbErr != nil {
			if cfg.SecureBootEnforce {
				return nil, fmt.Errorf("secure boot: %w", sbErr)
			}
			logger.Warn("could not read secure boot state", "error", sbErr)
		} else {
			if cfg.SecureBootEnforce && !*sbState {
				return nil, fmt.Errorf("secure boot is not enabled")
			}
			s.secureBoot = sbState
			logger.Info("read secure boot state", "enabled", *sbState)
		}
	}

	if cfg.TPM.Enabled {
		if cfg.ReportEvidence.NitroNSM {
			logger.Warn("tpm pcr reading disabled because nitronsm attestation document includes pcr values")
			cfg.TPM.Enabled = false
		} else if cfg.ReportEvidence.NitroTPM {
			logger.Warn("tpm pcr reading disabled because nitrotpm evidence already includes pcr values")
			cfg.TPM.Enabled = false
		}
	}

	s.selfAttestation = &parsedSelfAttestation{}

	if cfg.ReportEvidence.NitroNSM {
		nsmDev, err := nitro.OpenNSM()
		if err != nil {
			return nil, fmt.Errorf("opening nitro nsm: %w", err)
		}
		start := time.Now()
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating random nonce: %w", err)
		}
		_, doc, err := nsmDev.Attest(nonce)
		if err != nil {
			return nil, fmt.Errorf("nitro nsm self-attestation: %w", err)
		}
		s.nitroNSM = nsmDev
		s.selfAttestation.nitroNSMDoc = doc
		logger.Info("opened and verified nitro nsm session", "duration_ms", time.Since(start).Milliseconds())
	}

	if cfg.ReportEvidence.NitroTPM {
		tpmDev, err := nitro.OpenTPM()
		if err != nil {
			return nil, fmt.Errorf("opening nitro tpm: %w", err)
		}
		start := time.Now()
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating random nonce: %w", err)
		}
		_, doc, err := tpmDev.Attest(nonce)
		if err != nil {
			return nil, fmt.Errorf("nitro tpm self-attestation: %w", err)
		}
		s.nitroTPM = tpmDev
		s.selfAttestation.nitroTPMDoc = doc
		logger.Info("opened and verified nitro tpm device", "duration_ms", time.Since(start).Milliseconds())
	}

	if cfg.ReportEvidence.SEVSNP {
		snp, err := sevsnp.Open()
		if err != nil {
			return nil, fmt.Errorf("opening sev-snp device: %w", err)
		}
		start := time.Now()
		var reportData [64]byte
		if _, err := rand.Read(reportData[:]); err != nil {
			return nil, fmt.Errorf("generating random report data: %w", err)
		}
		_, report, err := snp.Attest(reportData, cfg.ReportEvidence.SEVSNPVMPL)
		if err != nil {
			return nil, fmt.Errorf("sev-snp self-attestation: %w", err)
		}
		s.sevSNP = snp
		s.selfAttestation.sevSNPReport = report
		logger.Info("opened and verified sev-snp guest device", "duration_ms", time.Since(start).Milliseconds())
	}

	if cfg.ReportEvidence.TDX {
		tdxDev, err := tdx.Open()
		if err != nil {
			return nil, fmt.Errorf("opening tdx device: %w", err)
		}
		start := time.Now()
		var reportData [64]byte
		if _, err := rand.Read(reportData[:]); err != nil {
			return nil, fmt.Errorf("generating random report data: %w", err)
		}
		_, quote, err := tdxDev.Attest(reportData)
		if err != nil {
			return nil, fmt.Errorf("tdx self-attestation: %w", err)
		}
		s.tdxDev = tdxDev
		s.selfAttestation.tdxQuote = quote
		logger.Info("opened and verified tdx guest device", "duration_ms", time.Since(start).Milliseconds())
	}

	if cfg.TPM.Enabled {
		pcrs, err := tpm.ReadPCRs(cfg.TPM.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("reading tpm pcrs for self-attestation: %w", err)
		}
		s.selfAttestation.tpmPCRs = pcrs
	}

	if len(s.endorsements) > 0 {
		cache, err := newFetcherCache(cfg.HTTPCacheSize)
		if err != nil {
			return nil, err
		}
		s.httpCache = cache

		if cfg.CosignVerify {
			v, err := initSigstoreVerifier(logger, cfg.CosignTUFCachePath)
			if err != nil {
				return nil, fmt.Errorf("cosign initialization: %w", err)
			}
			s.sigstoreVerifier = v
		}

		if err := s.validateOwnEndorsements(context.Background()); err != nil {
			return nil, fmt.Errorf("endorsement validation: %w", err)
		}
		logger.Info("validated endorsements against self-attestation evidence")
	}

	if cfg.RevocationEnabled {
		crlURLs := crlURLsForEvidence(cfg)
		if len(crlURLs) > 0 {
			s.crlCache = newCRLCache(logger)
			logger.Info("certificate revocation checking enabled", "crl_urls", len(crlURLs), "refresh_interval", cfg.RevocationRefreshInterval.String())
		}
		if cfg.ReportEvidence.TDX || len(cfg.DependencyEndpoints) > 0 {
			if s.httpCache == nil {
				cache, err := newFetcherCache(cfg.HTTPCacheSize)
				if err != nil {
					return nil, err
				}
				s.httpCache = cache
			}
			s.tdxGetter = &cachedHTTPSGetter{
				inner:      &simpleHTTPSGetter{client: s.fetchHTTPClient()},
				cache:      s.httpCache,
				defaultTTL: cfg.HTTPCacheDefaultTTL,
				logger:     logger,
			}
			logger.Info("tdx collateral caching enabled")
		}
	} else {
		logger.Warn("certificate revocation checking is disabled, revoked TEE endorsement keys will be accepted")
	}

	if len(cfg.DependencyEndpoints) > 0 {
		depStrs := make([]string, len(cfg.DependencyEndpoints))
		for i, u := range cfg.DependencyEndpoints {
			depStrs[i] = u.String()
		}
		logger.Info("configured dependency endpoints", "count", len(cfg.DependencyEndpoints), "urls", strings.Join(depStrs, ","), "instance_id", s.instanceID)
	}

	s.app = fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler:          s.errorHandler,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
	})

	s.app.Use(requestid.New(requestid.Config{
		Generator: func() string { return uuid.NewString() },
	}))
	if cfg.RateLimitEnabled {
		s.rateLimitHandler = s.rateLimitMiddleware()
		logger.Info("rate limiting enabled for attestation endpoint",
			"rps", cfg.RateLimitRPS,
			"burst", cfg.RateLimitBurst,
			"stall_timeout", cfg.RateLimitStallTimeout.String())
	}
	s.app.Use(s.accessLog())
	s.setupRoutes()

	return s, nil
}

// loadBuildInfo reads and parses the JSON build information file (SLSA
// provenance fields from sigstore/fulcio) at the given path.
func loadBuildInfo(path string) (*BuildInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	var bi BuildInfo
	if err := json.Unmarshal(data, &bi); err != nil {
		return nil, fmt.Errorf("unmarshalling build info: %w", err)
	}
	return &bi, nil
}

// loadEndorsements reads a JSON array of HTTPS URLs from the given path.
// Each URL must have an https scheme and a non-empty host and path.
func loadEndorsements(path string) ([]*url.URL, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshalling endorsements: %w", err)
	}
	urls := make([]*url.URL, 0, len(raw))
	for i, s := range raw {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("endorsement %d: invalid URL %q: %w", i, s, err)
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("endorsement %d: scheme must be https, got %q", i, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("endorsement %d: missing host in %q", i, s)
		}
		if u.Path == "" || u.Path == "/" {
			return nil, fmt.Errorf("endorsement %d: missing path in %q", i, s)
		}
		urls = append(urls, u)
	}
	return urls, nil
}

// shutdownCtx returns the server's lifecycle context. It falls back to
// context.Background() when called before Run (e.g. during unit tests
// that construct Server directly).
func (s *Server) shutdownCtx() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// Run starts the HTTP listener and blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx

	if s.cfg.PublicTLSCertPath != "" {
		if err := s.watchCertDir(ctx, filepath.Dir(s.cfg.PublicTLSCertPath), "public", s.reloadPublicCert); err != nil {
			return fmt.Errorf("public certificate watcher: %w", err)
		}
	}
	if s.cfg.PrivateTLSCertPath != "" {
		if err := s.watchCertDir(ctx, filepath.Dir(s.cfg.PrivateTLSCertPath), "private", s.reloadPrivateCert); err != nil {
			return fmt.Errorf("private certificate watcher: %w", err)
		}
	}

	if s.rateLimiters != nil {
		go s.runRateLimitCleanup(ctx)
	}
	if s.crlCache != nil {
		go s.runCRLRefresh(ctx)
	} else {
		s.ready.Store(true)
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.BindHost, s.cfg.BindPort)

	listenErr := make(chan error, 1)
	go func() {
		s.logger.Info("listening for requests", "addr", addr)
		if err := s.app.Listen(addr); err != nil {
			listenErr <- err
		}
		close(listenErr)
	}()

	select {
	case <-ctx.Done():
		if err := s.app.Shutdown(); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		return nil
	case err := <-listenErr:
		if err != nil {
			return fmt.Errorf("server listen: %w", err)
		}
		return nil
	}
}

// errorHandler returns JSON-formatted error responses for all handler errors.
// For fiber.Error values the handler-controlled message is returned as-is for
// both 4xx and 5xx. This is safe because handler code only puts opaque
// descriptions into fiber.NewError (e.g. "attestation failed", "dependency
// attestation failed") — internal details (device errors, file paths,
// firmware codes) are never included; they are only logged. Unhandled errors
// (plain error values without fiber.Error wrapping) fall back to a generic
// "internal error" message. The real error is always logged at ERROR level
// with request_id for debugging.
func (s *Server) errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := "internal error"
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		code = fiberErr.Code
		msg = fiberErr.Message
	}
	if code >= 500 {
		requestID, _ := c.Locals("requestid").(string)
		s.logger.Error("request failed", "status", code, "error", err, "request_id", requestID)
	}
	return c.Status(code).JSON(fiber.Map{"error": msg})
}

// accessLog is a middleware that logs each request with method, path, status,
// duration, and request-id. 4xx responses are logged at WARN, 5xx at ERROR.
func (s *Server) accessLog() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		chainErr := c.Next()

		duration := time.Since(start)

		// When the handler returned an error the Fiber error handler has not
		// run yet, so c.Response().StatusCode() is still 200. Derive the
		// intended status from the error instead.
		status := c.Response().StatusCode()
		if chainErr != nil {
			var fiberErr *fiber.Error
			if errors.As(chainErr, &fiberErr) {
				status = fiberErr.Code
			} else {
				status = fiber.StatusInternalServerError
			}
		}

		requestID, _ := c.Locals("requestid").(string)

		attrs := []any{
			"method", c.Method(),
			"path", c.Path(),
			"status", status,
			"duration_ms", duration.Milliseconds(),
			"request_id", requestID,
		}
		if chainErr != nil {
			attrs = append(attrs, "error", chainErr.Error())
		}

		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}

		s.logger.Log(context.Background(), level, "http request", attrs...)

		return chainErr
	}
}

// setupRoutes registers the attestation endpoint. Rate limiting, when
// enabled, is chained as middleware on this endpoint only — it is scoped
// to /api/v1/attestation because attestation involves blocking TEE
// hardware operations. Future lightweight endpoints should not inherit it.
func (s *Server) setupRoutes() {
	s.app.Get("/healthz/live", s.handleLive)
	s.app.Get("/healthz/ready", s.handleReady)

	handlers := []fiber.Handler{}
	if s.rateLimitHandler != nil {
		handlers = append(handlers, s.rateLimitHandler)
	}
	handlers = append(handlers, s.handleAttestation)
	s.app.Get("/api/v1/attestation", handlers...)
}

// readSecureBootState reads the UEFI SecureBoot variable from sysfs.
// The file contains a 4-byte EFI variable attributes header followed by
// a single byte: 0x01 = enabled, 0x00 = disabled.
func readSecureBootState() (*bool, error) {
	const path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 5 {
		return nil, fmt.Errorf("secure boot efi variable too short: %d bytes", len(data))
	}
	enabled := data[4] != 0
	return &enabled, nil
}

// deriveServiceIdentity computes a deterministic identity for this service
// for dependency cycle detection. The identity is SHA-256 of the marshaled
// build info concatenated with the leaf certificate's subject and SANs
// (private cert preferred, public cert as fallback). SANs are included
// because SPIFFE SVIDs typically have an empty subject and carry the
// service identity in a URI SAN instead. Replicas of the same service
// share the same build info and cert, so they produce the same identity —
// which is the desired behavior since cycles are between services, not
// processes.
func (s *Server) deriveServiceIdentity() string {
	h := sha256.New()

	if s.buildInfo != nil {
		biJSON, _ := json.Marshal(s.buildInfo)
		h.Write(biJSON)
	}

	s.certs.mu.RLock()
	cb := s.certs.private
	if cb == nil {
		cb = s.certs.public
	}
	s.certs.mu.RUnlock()

	if cb != nil && len(cb.cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cb.cert.Certificate[0]); err == nil {
			h.Write([]byte(leaf.Subject.String()))
			h.Write([]byte(joinSANs(leaf.DNSNames, leaf.IPAddresses, leaf.URIs)))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}
