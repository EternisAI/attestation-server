package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func generateTestCertECDSA(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: key}
}

func generateTestCertRSA(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: key}
}

func TestValidateTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "no certs at all",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "public cert only, no key",
			cfg: Config{
				PublicTLSCertPath: "/tmp/certs/cert.pem",
			},
			wantErr: true,
		},
		{
			name: "public key only, no cert",
			cfg: Config{
				PublicTLSKeyPath: "/tmp/certs/key.pem",
			},
			wantErr: true,
		},
		{
			name: "valid public pair same dir",
			cfg: Config{
				PublicTLSCertPath: "/tmp/certs/cert.pem",
				PublicTLSKeyPath:  "/tmp/certs/key.pem",
			},
			wantErr: false,
		},
		{
			name: "valid private pair same dir",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
			},
			wantErr: false,
		},
		{
			name: "both valid pairs",
			cfg: Config{
				PublicTLSCertPath:  "/tmp/public/cert.pem",
				PublicTLSKeyPath:   "/tmp/public/key.pem",
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
			},
			wantErr: false,
		},
		{
			name: "public cert and key in different dirs",
			cfg: Config{
				PublicTLSCertPath: "/tmp/certs/cert.pem",
				PublicTLSKeyPath:  "/tmp/keys/key.pem",
			},
			wantErr: true,
		},
		{
			name: "private cert and key in different dirs",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/certs/cert.pem",
				PrivateTLSKeyPath:  "/tmp/keys/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTLSConfig(&tt.cfg)
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestCertKeyType(t *testing.T) {
	t.Run("ECDSA", func(t *testing.T) {
		cert := generateTestCertECDSA(t)
		got := certKeyType(&cert)
		if got != "ECDSA" {
			t.Errorf("expected ECDSA, got %s", got)
		}
	})

	t.Run("RSA", func(t *testing.T) {
		cert := generateTestCertRSA(t)
		got := certKeyType(&cert)
		if got != "RSA" {
			t.Errorf("expected RSA, got %s", got)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		cert := &tls.Certificate{PrivateKey: "not-a-key"}
		got := certKeyType(cert)
		// Should return the Go type string, not "ECDSA" or "RSA"
		if got == "ECDSA" || got == "RSA" {
			t.Errorf("expected unknown type string, got %s", got)
		}
	})
}

func TestComputeFingerprints(t *testing.T) {
	t.Run("valid ECDSA cert", func(t *testing.T) {
		cert := generateTestCertECDSA(t)
		certFP, pubKeyFP, err := computeFingerprints(&cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certFP) != 64 {
			t.Errorf("expected cert fingerprint of length 64, got %d", len(certFP))
		}
		if len(pubKeyFP) != 64 {
			t.Errorf("expected pubkey fingerprint of length 64, got %d", len(pubKeyFP))
		}
		// Fingerprints should be valid hex
		for _, c := range certFP {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("cert fingerprint contains non-hex char: %c", c)
			}
		}
		for _, c := range pubKeyFP {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("pubkey fingerprint contains non-hex char: %c", c)
			}
		}
	})

	t.Run("valid RSA cert", func(t *testing.T) {
		cert := generateTestCertRSA(t)
		certFP, pubKeyFP, err := computeFingerprints(&cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certFP) != 64 {
			t.Errorf("expected cert fingerprint of length 64, got %d", len(certFP))
		}
		if len(pubKeyFP) != 64 {
			t.Errorf("expected pubkey fingerprint of length 64, got %d", len(pubKeyFP))
		}
	})

	t.Run("cert and pubkey fingerprints differ", func(t *testing.T) {
		cert := generateTestCertECDSA(t)
		certFP, pubKeyFP, err := computeFingerprints(&cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if certFP == pubKeyFP {
			t.Error("cert and pubkey fingerprints should differ")
		}
	})

	t.Run("empty cert returns error", func(t *testing.T) {
		cert := &tls.Certificate{}
		_, _, err := computeFingerprints(cert)
		if err == nil {
			t.Error("expected error for empty certificate, got nil")
		}
	})
}

func TestJoinSANs(t *testing.T) {
	tests := []struct {
		name     string
		dnsNames []string
		ips      []net.IP
		uris     []*url.URL
		want     string
	}{
		{
			name: "all empty",
			want: "",
		},
		{
			name:     "DNS only",
			dnsNames: []string{"example.com", "www.example.com"},
			want:     "example.com,www.example.com",
		},
		{
			name: "IPs only",
			ips:  []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
			want: "10.0.0.1,::1",
		},
		{
			name: "URIs only",
			uris: []*url.URL{
				{Scheme: "spiffe", Host: "trust.example.com", Path: "/workload"},
			},
			want: "spiffe://trust.example.com/workload",
		},
		{
			name:     "mixed",
			dnsNames: []string{"example.com"},
			ips:      []net.IP{net.ParseIP("192.168.1.1")},
			uris: []*url.URL{
				{Scheme: "https", Host: "id.example.com"},
			},
			want: "example.com,192.168.1.1,https://id.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinSANs(tt.dnsNames, tt.ips, tt.uris)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
