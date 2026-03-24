package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
			name: "public only without private is rejected",
			cfg: Config{
				PublicTLSCertPath: "/tmp/certs/cert.pem",
				PublicTLSKeyPath:  "/tmp/certs/key.pem",
			},
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
			name: "private cert only, no key",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/private/cert.pem",
			},
			wantErr: true,
		},
		{
			name: "private key only, no cert",
			cfg: Config{
				PrivateTLSKeyPath: "/tmp/private/key.pem",
			},
			wantErr: true,
		},
		{
			name: "private pair without CA is rejected",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
			},
			wantErr: true,
		},
		{
			name: "valid private pair with CA same dir",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
				PrivateTLSCAPath:   "/tmp/private/ca.pem",
			},
			wantErr: false,
		},
		{
			name: "both valid pairs with CA",
			cfg: Config{
				PublicTLSCertPath:  "/tmp/public/cert.pem",
				PublicTLSKeyPath:   "/tmp/public/key.pem",
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
				PrivateTLSCAPath:   "/tmp/private/ca.pem",
			},
			wantErr: false,
		},
		{
			name: "public cert and key in different dirs",
			cfg: Config{
				PublicTLSCertPath:  "/tmp/certs/cert.pem",
				PublicTLSKeyPath:   "/tmp/keys/key.pem",
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
				PrivateTLSCAPath:   "/tmp/private/ca.pem",
			},
			wantErr: true,
		},
		{
			name: "private cert and key in different dirs",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/certs/cert.pem",
				PrivateTLSKeyPath:  "/tmp/keys/key.pem",
				PrivateTLSCAPath:   "/tmp/certs/ca.pem",
			},
			wantErr: true,
		},
		{
			name: "private CA in different dir from cert",
			cfg: Config{
				PrivateTLSCertPath: "/tmp/private/cert.pem",
				PrivateTLSKeyPath:  "/tmp/private/key.pem",
				PrivateTLSCAPath:   "/tmp/other/ca.pem",
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

// generateTestCA creates a self-signed CA certificate and returns the CA
// cert, key, and a PEM-encoded bundle suitable for loadCABundle.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	return caCert, key
}

// generateSignedCertECDSA creates an ECDSA leaf certificate signed by the given CA.
func generateSignedCertECDSA(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: leafKey}
}

// writeCABundle writes a CA certificate as PEM to a temp file and returns the path.
func writeCABundle(t *testing.T, dir string, caCert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, "ca.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCABundle(t *testing.T) {
	caCert, _ := generateTestCA(t)
	dir := t.TempDir()
	caPath := writeCABundle(t, dir, caCert)

	bundle, err := loadCABundle(caPath)
	if err != nil {
		t.Fatalf("loadCABundle() error: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
}

func TestLoadCABundle_NoPEMCerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte("not a PEM file\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadCABundle(path)
	if err == nil {
		t.Fatal("expected error for file with no PEM certs")
	}
}

func TestLoadCABundle_RejectsFakeSelfsigned(t *testing.T) {
	// Create a certificate with matching issuer == subject but signed by a
	// different key. This should be rejected by CheckSignatureFrom.
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Self-Signed CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	// Sign with key2 but embed key1's public key — issuer matches subject
	// but the signature is from a different key.
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key1.PublicKey, key2)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	pemPath := filepath.Join(dir, "fake-ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(pemPath, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = loadCABundle(pemPath)
	if err == nil {
		t.Fatal("expected error for certificate with mismatched self-signature")
	}
	if !contains(err.Error(), "signature verification failed") {
		t.Errorf("error %q does not mention signature verification", err)
	}
}

func TestLoadCABundle_FileNotFound(t *testing.T) {
	_, err := loadCABundle("/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestVerifyCertAgainstCA_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	cert := generateSignedCertECDSA(t, caCert, caKey)

	bundle := &caBundle{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
	}
	bundle.roots.AddCert(caCert)

	if err := verifyCertAgainstCA(&cert, bundle); err != nil {
		t.Fatalf("verifyCertAgainstCA() error: %v", err)
	}
}

func TestVerifyCertAgainstCA_WrongCA(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	cert := generateSignedCertECDSA(t, caCert, caKey)

	// Create a different CA that did NOT sign the cert.
	otherCA, _ := generateTestCA(t)
	bundle := &caBundle{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
	}
	bundle.roots.AddCert(otherCA)

	err := verifyCertAgainstCA(&cert, bundle)
	if err == nil {
		t.Fatal("expected error for cert signed by different CA")
	}
}

func TestVerifyCertAgainstCA_SelfSigned(t *testing.T) {
	// A self-signed cert that's not in the CA pool should fail.
	cert := generateTestCertECDSA(t)

	caCert, _ := generateTestCA(t)
	bundle := &caBundle{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
	}
	bundle.roots.AddCert(caCert)

	err := verifyCertAgainstCA(&cert, bundle)
	if err == nil {
		t.Fatal("expected error for self-signed cert not in CA pool")
	}
}

// generateTestIntermediateCA creates an intermediate CA cert signed by the given parent.
func generateTestIntermediateCA(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestVerifyCertAgainstCA_IntermediateChainInBundle(t *testing.T) {
	// root -> intermediate1 -> intermediate2 -> leaf
	// All CAs in the bundle, leaf only in the TLS cert file.
	rootCert, rootKey := generateTestCA(t)
	inter1Cert, inter1Key := generateTestIntermediateCA(t, rootCert, rootKey, "Intermediate 1")
	inter2Cert, inter2Key := generateTestIntermediateCA(t, inter1Cert, inter1Key, "Intermediate 2")
	leaf := generateSignedCertECDSA(t, inter2Cert, inter2Key)

	// Write all three CAs into a single bundle file.
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "ca-bundle.pem")
	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*x509.Certificate{rootCert, inter1Cert, inter2Cert} {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	bundle, err := loadCABundle(bundlePath)
	if err != nil {
		t.Fatalf("loadCABundle() error: %v", err)
	}

	if err := verifyCertAgainstCA(&leaf, bundle); err != nil {
		t.Fatalf("verifyCertAgainstCA() should succeed with full chain in bundle: %v", err)
	}
}

func TestVerifyCertAgainstCA_IntermediateChainPartialBundle(t *testing.T) {
	// root -> intermediate1 -> intermediate2 -> leaf
	// Only root and intermediate1 in bundle (missing intermediate2).
	// Leaf cert file has no intermediates. Should fail.
	rootCert, rootKey := generateTestCA(t)
	inter1Cert, inter1Key := generateTestIntermediateCA(t, rootCert, rootKey, "Intermediate 1")
	inter2Cert, inter2Key := generateTestIntermediateCA(t, inter1Cert, inter1Key, "Intermediate 2")
	leaf := generateSignedCertECDSA(t, inter2Cert, inter2Key)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "ca-bundle.pem")
	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	// Only root + intermediate1, missing intermediate2.
	for _, c := range []*x509.Certificate{rootCert, inter1Cert} {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	bundle, err := loadCABundle(bundlePath)
	if err != nil {
		t.Fatalf("loadCABundle() error: %v", err)
	}

	err = verifyCertAgainstCA(&leaf, bundle)
	if err == nil {
		t.Fatal("expected error when intermediate2 is missing from bundle")
	}
}

func TestVerifyCertAgainstCA_IntermediateInCertFile(t *testing.T) {
	// root -> intermediate -> leaf
	// Root in bundle, intermediate bundled in the TLS cert file.
	rootCert, rootKey := generateTestCA(t)
	interCert, interKey := generateTestIntermediateCA(t, rootCert, rootKey, "Intermediate")
	leafCert := generateSignedCertECDSA(t, interCert, interKey)

	// Bundle the intermediate in the cert file (cert.Certificate[1]).
	leafCert.Certificate = append(leafCert.Certificate, interCert.Raw)

	bundle := &caBundle{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
	}
	bundle.roots.AddCert(rootCert)

	if err := verifyCertAgainstCA(&leafCert, bundle); err != nil {
		t.Fatalf("verifyCertAgainstCA() should succeed with intermediate in cert file: %v", err)
	}
}

func TestVerifyCertAgainstCA_FederationBundle(t *testing.T) {
	// Federation bundle with two independent trust chains:
	//   RootA -> InterA1 -> InterA2 -> leafA
	//   RootB -> InterB1
	// All CAs in a single bundle. Leaf signed by InterA2.
	rootA, rootAKey := generateTestCA(t)
	interA1, interA1Key := generateTestIntermediateCA(t, rootA, rootAKey, "Inter A1")
	interA2, interA2Key := generateTestIntermediateCA(t, interA1, interA1Key, "Inter A2")
	leaf := generateSignedCertECDSA(t, interA2, interA2Key)

	rootB, rootBKey := generateTestCA(t)
	interB1, _ := generateTestIntermediateCA(t, rootB, rootBKey, "Inter B1")

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "federation.pem")
	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*x509.Certificate{rootA, interA1, interA2, rootB, interB1} {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	bundle, err := loadCABundle(bundlePath)
	if err != nil {
		t.Fatalf("loadCABundle() error: %v", err)
	}

	if err := verifyCertAgainstCA(&leaf, bundle); err != nil {
		t.Fatalf("verifyCertAgainstCA() should succeed with federation bundle: %v", err)
	}
}

func TestVerifyCertAgainstCA_FederationBundleWrongChain(t *testing.T) {
	// Federation bundle with two chains, but leaf is signed by an
	// intermediate NOT in the bundle.
	rootA, rootAKey := generateTestCA(t)
	interA1, _ := generateTestIntermediateCA(t, rootA, rootAKey, "Inter A1")

	rootB, rootBKey := generateTestCA(t)
	interB1, _ := generateTestIntermediateCA(t, rootB, rootBKey, "Inter B1")

	// Leaf signed by a third, unrelated intermediate.
	rogue, rogueKey := generateTestCA(t)
	rogueInter, rogueInterKey := generateTestIntermediateCA(t, rogue, rogueKey, "Rogue Inter")
	leaf := generateSignedCertECDSA(t, rogueInter, rogueInterKey)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "federation.pem")
	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*x509.Certificate{rootA, interA1, rootB, interB1} {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	bundle, err := loadCABundle(bundlePath)
	if err != nil {
		t.Fatalf("loadCABundle() error: %v", err)
	}

	err = verifyCertAgainstCA(&leaf, bundle)
	if err == nil {
		t.Fatal("expected error for leaf signed by CA not in federation bundle")
	}
}
