package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

// Server wraps a Fiber application with its dependencies.
type Server struct {
	app    *fiber.App
	cfg    *Config
	logger *slog.Logger
}

// NewServer constructs a Server with middleware and routes configured.
func NewServer(cfg *Config, logger *slog.Logger) *Server {
	s := &Server{cfg: cfg, logger: logger}

	s.app = fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler:          s.errorHandler,
	})

	s.app.Use(requestid.New())
	s.app.Use(s.accessLog())
	s.setupRoutes()

	return s
}

// Run starts the HTTP listener and blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
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
	s.app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
}
