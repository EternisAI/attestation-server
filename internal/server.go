package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"github.com/hf/nsm"
)

// Server wraps a Fiber application with its dependencies.
type Server struct {
	app          *fiber.App
	cfg          *Config
	logger       *slog.Logger
	buildInfo    *BuildInfo
	endorsements []*url.URL
	certs        tlsCertificates
	nsm          *nsm.Session
	nsmMu        sync.Mutex
	nitroTPM     *NitroTPM
}

// NewServer constructs a Server with middleware and routes configured.
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
	s.endorsements = endorsements
	endorsementStrs := make([]string, len(endorsements))
	for i, u := range endorsements {
		endorsementStrs[i] = u.String()
	}
	logger.Debug("loaded endorsements", "count", len(endorsements), "urls", strings.Join(endorsementStrs, ","))

	if err := validateTLSConfig(cfg); err != nil {
		return nil, fmt.Errorf("TLS configuration: %w", err)
	}
	if err := s.loadCertificates(); err != nil {
		return nil, err
	}

	if cfg.ReportEvidence.NitroNSM {
		sess, err := nsm.OpenDefaultSession()
		if err != nil {
			return nil, fmt.Errorf("opening nitro nsm session: %w", err)
		}
		s.nsm = sess
		logger.Info("opened nitro nsm session")
	}

	if cfg.ReportEvidence.NitroTPM {
		tpm, err := OpenNitroTPM()
		if err != nil {
			return nil, fmt.Errorf("opening nitro tpm: %w", err)
		}
		s.nitroTPM = tpm
		logger.Info("opened nitro tpm device")
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
	s.app.Use(s.accessLog())
	s.setupRoutes()

	return s, nil
}

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

// Run starts the HTTP listener and blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
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
func (s *Server) errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		code = fiberErr.Code
	}
	return c.Status(code).JSON(fiber.Map{"error": err.Error()})
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

func (s *Server) setupRoutes() {
	s.app.Get("/api/v1/attestation", s.handleAttestation)
}
