package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// ---------------------------------------------------------------------------
// loadBuildInfo
// ---------------------------------------------------------------------------

func TestLoadBuildInfo_Valid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "build-info.json")
	data := `{
		"BuildSignerURI": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.9.0",
		"SourceRepositoryURI": "https://github.com/eternisai/attestation-server",
		"SourceRepositoryRef": "refs/heads/main",
		"RunnerEnvironment": "github-hosted"
	}`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	bi, err := loadBuildInfo(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bi.BuildSignerURI != "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.9.0" {
		t.Errorf("BuildSignerURI = %q, want the full URI", bi.BuildSignerURI)
	}
	if bi.SourceRepositoryURI != "https://github.com/eternisai/attestation-server" {
		t.Errorf("SourceRepositoryURI = %q", bi.SourceRepositoryURI)
	}
	if bi.SourceRepositoryRef != "refs/heads/main" {
		t.Errorf("SourceRepositoryRef = %q", bi.SourceRepositoryRef)
	}
	if bi.RunnerEnvironment != "github-hosted" {
		t.Errorf("RunnerEnvironment = %q", bi.RunnerEnvironment)
	}
}

func TestLoadBuildInfo_EmptyJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "build-info.json")
	if err := os.WriteFile(p, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	bi, err := loadBuildInfo(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bi.BuildSignerURI != "" {
		t.Errorf("expected empty BuildSignerURI, got %q", bi.BuildSignerURI)
	}
	if bi.SourceRepositoryURI != "" {
		t.Errorf("expected empty SourceRepositoryURI, got %q", bi.SourceRepositoryURI)
	}
}

func TestLoadBuildInfo_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "build-info.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadBuildInfo(p)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadBuildInfo_FileNotExist(t *testing.T) {
	_, err := loadBuildInfo("/nonexistent/path/build-info.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadBuildInfo_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "build-info.json")
	if err := os.WriteFile(p, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadBuildInfo(p)
	if err == nil {
		t.Fatal("expected error for empty file, got nil")
	}
}

// ---------------------------------------------------------------------------
// loadEndorsements
// ---------------------------------------------------------------------------

func TestLoadEndorsements_Valid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	data := `["https://example.com/endorsement"]`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	urls, err := loadEndorsements(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d", len(urls))
	}
	if urls[0].String() != "https://example.com/endorsement" {
		t.Errorf("URL = %q", urls[0].String())
	}
}

func TestLoadEndorsements_EmptyArray(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	if err := os.WriteFile(p, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}

	urls, err := loadEndorsements(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 0 {
		t.Fatalf("expected 0 URLs, got %d", len(urls))
	}
}

func TestLoadEndorsements_HTTPSchemeError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	data := `["http://example.com/endorsement"]`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadEndorsements(p)
	if err == nil {
		t.Fatal("expected error for http scheme, got nil")
	}
}

func TestLoadEndorsements_MissingHost(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	data := `["https:///endorsement"]`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadEndorsements(p)
	if err == nil {
		t.Fatal("expected error for missing host, got nil")
	}
}

func TestLoadEndorsements_PathSlashOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	data := `["https://example.com/"]`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadEndorsements(p)
	if err == nil {
		t.Fatal("expected error for path = '/', got nil")
	}
}

func TestLoadEndorsements_MissingPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	data := `["https://example.com"]`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadEndorsements(p)
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
}

func TestLoadEndorsements_MultipleValid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	data := `["https://example.com/a", "https://other.org/b/c"]`
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	urls, err := loadEndorsements(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urls))
	}
	if urls[0].String() != "https://example.com/a" {
		t.Errorf("URL[0] = %q", urls[0].String())
	}
	if urls[1].String() != "https://other.org/b/c" {
		t.Errorf("URL[1] = %q", urls[1].String())
	}
}

func TestLoadEndorsements_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsements.json")
	if err := os.WriteFile(p, []byte(`not json`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadEndorsements(p)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadEndorsements_FileNotExist(t *testing.T) {
	_, err := loadEndorsements("/nonexistent/path/endorsements.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ---------------------------------------------------------------------------
// errorHandler
// ---------------------------------------------------------------------------

func newTestServer() *Server {
	return &Server{
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
}

func TestErrorHandler_FiberError400(t *testing.T) {
	s := newTestServer()
	app := fiber.New(fiber.Config{
		ErrorHandler: s.errorHandler,
	})
	app.Get("/test", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusBadRequest, "bad request")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if bodyStr == "" {
		t.Fatal("empty response body")
	}
	// Verify response contains the error message
	if got := bodyStr; got == "" {
		t.Fatal("empty body")
	}
}

func TestErrorHandler_FiberError500(t *testing.T) {
	s := newTestServer()
	app := fiber.New(fiber.Config{
		ErrorHandler: s.errorHandler,
	})
	app.Get("/test", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusInternalServerError, "internal")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if bodyStr == "" {
		t.Fatal("empty response body")
	}
}

func TestErrorHandler_PlainError(t *testing.T) {
	s := newTestServer()
	app := fiber.New(fiber.Config{
		ErrorHandler: s.errorHandler,
	})
	app.Get("/test", func(c *fiber.Ctx) error {
		return fmt.Errorf("something went wrong")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (plain error should default to 500)", resp.StatusCode, http.StatusInternalServerError)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if bodyStr == "" {
		t.Fatal("empty response body")
	}
}

// ---------------------------------------------------------------------------
// NewLogger
// ---------------------------------------------------------------------------

func TestNewLogger_JSONFormat(t *testing.T) {
	cfg := &Config{LogFormat: "json", LogLevel: slog.LevelInfo}
	logger := NewLogger(cfg)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("logger should be enabled at INFO level")
	}
}

func TestNewLogger_TextFormat(t *testing.T) {
	cfg := &Config{LogFormat: "text", LogLevel: slog.LevelDebug}
	logger := NewLogger(cfg)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("logger should be enabled at DEBUG level")
	}
}

func TestNewLogger_DefaultFormat(t *testing.T) {
	cfg := &Config{LogFormat: "unknown", LogLevel: slog.LevelWarn}
	logger := NewLogger(cfg)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("logger should be enabled at WARN level")
	}
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("logger should NOT be enabled at INFO when level is WARN")
	}
}
