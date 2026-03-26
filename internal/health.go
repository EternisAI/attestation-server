package app

import (
	"github.com/gofiber/fiber/v2"
)

// handleLive returns 200 if the HTTP server is accepting requests.
// If the handler runs, the process is alive.
func (s *Server) handleLive(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok"})
}

// handleReady returns 200 once startup initialization is complete:
// self-attestation, endorsement validation, and initial CRL fetch
// (when certificate revocation is configured). Returns 503 while the
// server is still initializing.
//
// Readiness is a one-way transition. No runtime condition (certificate
// hot-reload failure, CRL refresh failure) flips it back to not-ready
// because all background processes use fail-safe semantics: stale
// certificates remain in use and CRL checking is fail-open.
func (s *Server) handleReady(c *fiber.Ctx) error {
	if !s.ready.Load() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"status": "not ready"})
	}
	return c.JSON(fiber.Map{"status": "ok"})
}
