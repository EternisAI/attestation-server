package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCRLCache_CheckRevocation_Empty(t *testing.T) {
	cache := newCRLCache(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	// Empty cache should pass (fail-open).
	cert := &x509.Certificate{SerialNumber: big.NewInt(42)}
	if err := cache.CheckRevocation(cert, time.Now()); err != nil {
		t.Fatalf("empty cache should not reject certificates: %v", err)
	}
}

// testCRLCA creates a self-signed CA certificate suitable for CRL signing.
func testCRLCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CRL CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestCRLCache_CheckRevocation_Revoked(t *testing.T) {
	cache := newCRLCache(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	revokedSerial := big.NewInt(12345)
	caCert, key := testCRLCA(t)

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now()},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, caCert, key)
	if err != nil {
		t.Fatal(err)
	}

	parsedCRL, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatal(err)
	}

	cache.mu.Lock()
	cache.entries["test-url"] = &crlEntry{crl: parsedCRL, fetchedAt: time.Now()}
	cache.mu.Unlock()

	// Revoked cert should be rejected.
	revokedCert := &x509.Certificate{SerialNumber: revokedSerial}
	if err := cache.CheckRevocation(revokedCert, time.Now()); err == nil {
		t.Fatal("expected error for revoked certificate, got nil")
	}

	// Non-revoked cert should pass.
	goodCert := &x509.Certificate{SerialNumber: big.NewInt(99999)}
	if err := cache.CheckRevocation(goodCert, time.Now()); err != nil {
		t.Fatalf("non-revoked certificate should pass: %v", err)
	}
}

func TestFetchCRL(t *testing.T) {
	caCert, key := testCRLCA(t)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, caCert, key)
	if err != nil {
		t.Fatalf("creating CRL: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer srv.Close()

	crl, err := fetchCRL(t.Context(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchCRL error: %v", err)
	}
	if crl == nil {
		t.Fatal("expected non-nil CRL")
	}
}

func TestCRLURLsForEvidence(t *testing.T) {
	t.Run("sevsnp enabled", func(t *testing.T) {
		cfg := &Config{ReportEvidence: EvidenceConfig{SEVSNP: true}}
		urls := crlURLsForEvidence(cfg)
		// 3 product lines × 2 signer types = 6 URLs
		if len(urls) != 6 {
			t.Errorf("expected 6 CRL URLs for SEV-SNP, got %d", len(urls))
		}
	})

	t.Run("tdx only", func(t *testing.T) {
		cfg := &Config{ReportEvidence: EvidenceConfig{TDX: true}}
		urls := crlURLsForEvidence(cfg)
		if len(urls) != 0 {
			t.Errorf("expected 0 CRL URLs for TDX (handled by library), got %d", len(urls))
		}
	})

	t.Run("nitro only", func(t *testing.T) {
		cfg := &Config{ReportEvidence: EvidenceConfig{NitroNSM: true}}
		urls := crlURLsForEvidence(cfg)
		if len(urls) != 0 {
			t.Errorf("expected 0 CRL URLs for Nitro, got %d", len(urls))
		}
	})

	t.Run("none enabled", func(t *testing.T) {
		cfg := &Config{}
		urls := crlURLsForEvidence(cfg)
		if len(urls) != 0 {
			t.Errorf("expected 0 CRL URLs, got %d", len(urls))
		}
	})
}
