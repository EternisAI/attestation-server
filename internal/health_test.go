package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestHandleLive_Returns200(t *testing.T) {
	s := newTestServer()
	app := fiber.New()
	app.Get("/healthz/live", s.handleLive)

	req := httptest.NewRequest(http.MethodGet, "/healthz/live", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), `"ok"`) {
		t.Errorf("body = %s, want ok status", body)
	}
}

func TestHandleReady_NotReady(t *testing.T) {
	s := newTestServer()
	// ready is false by default (zero value of atomic.Bool)
	app := fiber.New()
	app.Get("/healthz/ready", s.handleReady)

	req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), `"not ready"`) {
		t.Errorf("body = %s, want not ready status", body)
	}
}

func TestHandleReady_Ready(t *testing.T) {
	s := newTestServer()
	s.ready.Store(true)
	app := fiber.New()
	app.Get("/healthz/ready", s.handleReady)

	req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), `"ok"`) {
		t.Errorf("body = %s, want ok status", body)
	}
}
