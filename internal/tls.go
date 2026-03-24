package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// certReloadDebounce is the delay after a filesystem event before reloading
// certificates. This coalesces rapid sequences of events (e.g. atomic file
// replacement via rename) into a single reload.
const certReloadDebounce = 500 * time.Millisecond

// certBundle holds a loaded TLS certificate along with precomputed SHA-256
// fingerprints of the leaf certificate and its SPKI public key.
type certBundle struct {
	cert              *tls.Certificate
	certFingerprint   string
	pubKeyFingerprint string
}

// tlsCertificates holds the current public and private certificate bundles
// and the private CA bundle under a RWMutex so the hot-reload goroutine
// can swap them while request handlers read them concurrently.
type tlsCertificates struct {
	mu        sync.RWMutex
	public    *certBundle
	private   *certBundle
	privateCA *caBundle
}

// validateTLSConfig checks that the private TLS certificate set is configured
// (required for end-to-end encryption bound to TEE attestation) and that each
// set has both cert and key paths in the same directory. The public certificate
// set remains optional.
func validateTLSConfig(cfg *Config) error {
	pubHasCert := cfg.PublicTLSCertPath != ""
	pubHasKey := cfg.PublicTLSKeyPath != ""
	privHasCert := cfg.PrivateTLSCertPath != ""
	privHasKey := cfg.PrivateTLSKeyPath != ""

	if !privHasCert || !privHasKey {
		if privHasCert || privHasKey {
			return fmt.Errorf("both private TLS cert and key paths must be specified")
		}
		return fmt.Errorf("private TLS certificate is required for attestation-bound end-to-end encryption")
	}
	if filepath.Dir(cfg.PrivateTLSCertPath) != filepath.Dir(cfg.PrivateTLSKeyPath) {
		return fmt.Errorf("private TLS cert and key paths must be in the same directory")
	}

	if cfg.PrivateTLSCAPath == "" {
		return fmt.Errorf("private TLS CA bundle is required (all private certificates in the dependency chain must be issued by the same CA)")
	}
	if filepath.Dir(cfg.PrivateTLSCAPath) != filepath.Dir(cfg.PrivateTLSCertPath) {
		return fmt.Errorf("private TLS CA path must be in the same directory as cert and key")
	}

	pubSet := pubHasCert || pubHasKey
	if pubSet {
		if !pubHasCert || !pubHasKey {
			return fmt.Errorf("both public TLS cert and key paths must be specified")
		}
		if filepath.Dir(cfg.PublicTLSCertPath) != filepath.Dir(cfg.PublicTLSKeyPath) {
			return fmt.Errorf("public TLS cert and key paths must be in the same directory")
		}
	}

	return nil
}

func certKeyType(cert *tls.Certificate) string {
	switch cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case *rsa.PrivateKey:
		return "RSA"
	default:
		return fmt.Sprintf("%T", cert.PrivateKey)
	}
}

// computeFingerprints returns SHA-256 hex-encoded fingerprints of the leaf
// certificate DER and its SPKI (SubjectPublicKeyInfo) DER.
func computeFingerprints(cert *tls.Certificate) (certFP, pubKeyFP string, err error) {
	if len(cert.Certificate) == 0 {
		return "", "", fmt.Errorf("certificate has no DER data")
	}
	certHash := sha256.Sum256(cert.Certificate[0])
	certFP = hex.EncodeToString(certHash[:])

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", "", fmt.Errorf("parsing leaf certificate: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshalling public key: %w", err)
	}
	pkHash := sha256.Sum256(spkiDER)
	pubKeyFP = hex.EncodeToString(pkHash[:])

	return certFP, pubKeyFP, nil
}

// certLeafAttrs returns slog attributes describing the leaf certificate
// (subject, SANs, validity period, fingerprints) for structured logging.
func certLeafAttrs(b *certBundle) []slog.Attr {
	if len(b.cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(b.cert.Certificate[0])
	if err != nil {
		return nil
	}
	return []slog.Attr{
		slog.String("subject", leaf.Subject.String()),
		slog.String("sans", joinSANs(leaf.DNSNames, leaf.IPAddresses, leaf.URIs)),
		slog.Time("not_before", leaf.NotBefore),
		slog.Time("not_after", leaf.NotAfter),
		slog.String("cert_fingerprint", b.certFingerprint),
		slog.String("pubkey_fingerprint", b.pubKeyFingerprint),
	}
}

func joinSANs(dnsNames []string, ips []net.IP, uris []*url.URL) string {
	sans := make([]string, 0, len(dnsNames)+len(ips)+len(uris))
	sans = append(sans, dnsNames...)
	for _, ip := range ips {
		sans = append(sans, ip.String())
	}
	for _, u := range uris {
		sans = append(sans, u.String())
	}
	return strings.Join(sans, ",")
}

// caBundle holds both root and intermediate certificates parsed from a
// PEM CA bundle. Roots are self-signed CA certificates (trust anchors);
// intermediates are all other CA certificates that may appear in the
// chain between the leaf and a root.
type caBundle struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

// loadCABundle reads a PEM-encoded CA bundle from disk and separates the
// certificates into roots (self-signed) and intermediates. This allows
// x509.Certificate.Verify to build chains through intermediate CAs that
// are only present in the bundle, not in the TLS cert file.
func loadCABundle(path string) (*caBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA file %s: %w", path, err)
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	var found bool
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing CA certificate: %w", err)
		}
		// Self-signed: issuer == subject. This is the standard structural
		// indicator and avoids depending on CheckSignatureFrom, which
		// rejects SHA-1 signatures in Go 1.18+.
		if cert.IsCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			roots.AddCert(cert)
		} else {
			intermediates.AddCert(cert)
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return &caBundle{roots: roots, intermediates: intermediates}, nil
}

// verifyCertAgainstCA verifies that the leaf certificate in the given
// tls.Certificate chains to a root in the CA bundle. Intermediates are
// sourced from both the TLS cert file (cert.Certificate[1:]) and the
// CA bundle, so chains like root → intermediate1 → intermediate2 → leaf
// work even when the TLS file only contains the leaf.
func verifyCertAgainstCA(cert *tls.Certificate, bundle *caBundle) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate has no DER data")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parsing leaf certificate: %w", err)
	}

	// Start with intermediates from the CA bundle, then add any
	// intermediates bundled in the TLS cert file itself.
	intermediates := bundle.intermediates.Clone()
	for _, derBytes := range cert.Certificate[1:] {
		ic, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return fmt.Errorf("parsing intermediate certificate: %w", err)
		}
		intermediates.AddCert(ic)
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         bundle.roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return fmt.Errorf("certificate does not chain to configured CA: %w", err)
	}
	return nil
}

// loadCertificates loads the initial public and/or private TLS certificates
// from disk, validates key types, computes fingerprints, optionally verifies
// the private cert against a CA bundle, and stores them in the server's
// tlsCertificates for use by request handlers.
func (s *Server) loadCertificates() error {
	if s.cfg.PublicTLSCertPath != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.PublicTLSCertPath, s.cfg.PublicTLSKeyPath)
		if err != nil {
			return fmt.Errorf("loading public TLS certificate: %w", err)
		}
		switch cert.PrivateKey.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey:
		default:
			return fmt.Errorf("public TLS key must be ECDSA or RSA, got %T", cert.PrivateKey)
		}
		certFP, pkFP, err := computeFingerprints(&cert)
		if err != nil {
			return fmt.Errorf("computing public certificate fingerprints: %w", err)
		}
		b := &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
		s.certs.mu.Lock()
		s.certs.public = b
		s.certs.mu.Unlock()
		attrs := append([]slog.Attr{
			slog.String("type", certKeyType(&cert)),
			slog.String("cert", s.cfg.PublicTLSCertPath),
			slog.String("key", s.cfg.PublicTLSKeyPath),
		}, certLeafAttrs(b)...)
		s.logger.LogAttrs(context.Background(), slog.LevelInfo, "loaded public TLS certificate", attrs...)
	}

	if s.cfg.PrivateTLSCertPath != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.PrivateTLSCertPath, s.cfg.PrivateTLSKeyPath)
		if err != nil {
			return fmt.Errorf("loading private TLS certificate: %w", err)
		}
		// Private certificates must use ECDSA. RSA is allowed for public
		// certs (Internet-facing ingress may need RSA for compatibility),
		// but service-to-service mTLS within the dependency chain uses ECDSA
		// for performance and because the SEV-SNP/Nitro attestation evidence
		// is already ECDSA-signed.
		if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("private TLS key must be ECDSA, got %T", cert.PrivateKey)
		}
		cab, err := loadCABundle(s.cfg.PrivateTLSCAPath)
		if err != nil {
			return fmt.Errorf("loading private TLS CA: %w", err)
		}
		if err := verifyCertAgainstCA(&cert, cab); err != nil {
			return fmt.Errorf("private TLS certificate CA verification: %w", err)
		}
		s.logger.Debug("verified private TLS certificate against CA bundle", "ca", s.cfg.PrivateTLSCAPath)
		certFP, pkFP, err := computeFingerprints(&cert)
		if err != nil {
			return fmt.Errorf("computing private certificate fingerprints: %w", err)
		}
		b := &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
		s.certs.mu.Lock()
		s.certs.private = b
		s.certs.privateCA = cab
		s.certs.mu.Unlock()
		attrs := []slog.Attr{
			slog.String("cert", s.cfg.PrivateTLSCertPath),
			slog.String("key", s.cfg.PrivateTLSKeyPath),
			slog.String("ca", s.cfg.PrivateTLSCAPath),
		}
		attrs = append(attrs, certLeafAttrs(b)...)
		s.logger.LogAttrs(context.Background(), slog.LevelInfo, "loaded private TLS certificate", attrs...)
	}

	return nil
}

// watchCertDir starts an fsnotify watcher on the given directory and calls
// reload when certificate files change. Used for hot-reloading TLS certs
// without restarting the server.
func (s *Server) watchCertDir(ctx context.Context, dir string, name string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher for %s certs: %w", name, err)
	}

	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watching directory %s: %w", dir, err)
	}
	s.logger.Debug("watching directory for certificate changes", "set", name, "dir", dir)

	go s.certWatchLoop(ctx, watcher, name, reload)

	return nil
}

// certWatchLoop is the event loop for a certificate directory watcher. It
// debounces filesystem events and invokes reload after a quiet period.
func (s *Server) certWatchLoop(ctx context.Context, watcher *fsnotify.Watcher, name string, reload func()) {
	defer watcher.Close()

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Rename|fsnotify.Create) == 0 {
				continue
			}
			s.logger.Debug("detected filesystem event in certificate directory", "set", name, "event", event.String())
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.NewTimer(certReloadDebounce)
			debounceCh = debounceTimer.C
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.logger.Error("certificate watcher error", "set", name, "error", err)
		case <-debounceCh:
			reload()
			debounceCh = nil
		}
	}
}

// reloadPublicCert hot-reloads the public TLS certificate from disk. Called
// by the fsnotify watcher when certificate files change. Errors are logged
// but do not crash the server — the old certificate remains in use.
func (s *Server) reloadPublicCert() {
	s.logger.Info("reloading public TLS certificate")
	cert, err := tls.LoadX509KeyPair(s.cfg.PublicTLSCertPath, s.cfg.PublicTLSKeyPath)
	if err != nil {
		s.logger.Error("failed to reload public TLS certificate", "error", err)
		return
	}
	switch cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
	default:
		s.logger.Error("reloaded public TLS key has unsupported type", "type", fmt.Sprintf("%T", cert.PrivateKey))
		return
	}
	certFP, pkFP, err := computeFingerprints(&cert)
	if err != nil {
		s.logger.Error("failed to compute public certificate fingerprints", "error", err)
		return
	}
	b := &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
	s.certs.mu.Lock()
	s.certs.public = b
	s.certs.mu.Unlock()
	attrs := append([]slog.Attr{slog.String("type", certKeyType(&cert))}, certLeafAttrs(b)...)
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "reloaded public TLS certificate", attrs...)
}

// reloadPrivateCert hot-reloads the private TLS certificate, key, and CA
// bundle from disk. All three are swapped atomically under tlsCertificates.mu
// so request handlers and the dependency HTTP client always see a consistent
// set. Errors are logged but do not crash the server.
func (s *Server) reloadPrivateCert() {
	s.logger.Info("reloading private TLS certificate")
	cert, err := tls.LoadX509KeyPair(s.cfg.PrivateTLSCertPath, s.cfg.PrivateTLSKeyPath)
	if err != nil {
		s.logger.Error("failed to reload private TLS certificate", "error", err)
		return
	}
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		s.logger.Error("reloaded private TLS key is not ECDSA", "type", fmt.Sprintf("%T", cert.PrivateKey))
		return
	}
	cab, err := loadCABundle(s.cfg.PrivateTLSCAPath)
	if err != nil {
		s.logger.Error("failed to load private TLS CA for reload", "error", err)
		return
	}
	if err := verifyCertAgainstCA(&cert, cab); err != nil {
		s.logger.Error("reloaded private TLS certificate does not chain to CA", "error", err)
		return
	}
	certFP, pkFP, err := computeFingerprints(&cert)
	if err != nil {
		s.logger.Error("failed to compute private certificate fingerprints", "error", err)
		return
	}
	b := &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
	s.certs.mu.Lock()
	s.certs.private = b
	s.certs.privateCA = cab
	s.certs.mu.Unlock()
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "reloaded private TLS certificate", certLeafAttrs(b)...)
}
