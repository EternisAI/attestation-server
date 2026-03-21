package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/url"
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
// under a RWMutex so the hot-reload goroutine can swap them while request
// handlers read them concurrently.
type tlsCertificates struct {
	mu      sync.RWMutex
	public  *certBundle
	private *certBundle
}

// validateTLSConfig checks that at least one TLS certificate set is configured
// and that each set has both cert and key paths in the same directory.
func validateTLSConfig(cfg *Config) error {
	pubHasCert := cfg.PublicTLSCertPath != ""
	pubHasKey := cfg.PublicTLSKeyPath != ""
	privHasCert := cfg.PrivateTLSCertPath != ""
	privHasKey := cfg.PrivateTLSKeyPath != ""

	pubSet := pubHasCert || pubHasKey
	privSet := privHasCert || privHasKey

	if !pubSet && !privSet {
		return fmt.Errorf("at least one TLS certificate set (public or private) must be configured")
	}

	if pubSet {
		if !pubHasCert || !pubHasKey {
			return fmt.Errorf("both public TLS cert and key paths must be specified")
		}
		if filepath.Dir(cfg.PublicTLSCertPath) != filepath.Dir(cfg.PublicTLSKeyPath) {
			return fmt.Errorf("public TLS cert and key paths must be in the same directory")
		}
	}

	if privSet {
		if !privHasCert || !privHasKey {
			return fmt.Errorf("both private TLS cert and key paths must be specified")
		}
		if filepath.Dir(cfg.PrivateTLSCertPath) != filepath.Dir(cfg.PrivateTLSKeyPath) {
			return fmt.Errorf("private TLS cert and key paths must be in the same directory")
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

// loadCertificates loads the initial public and/or private TLS certificates
// from disk, validates key types, computes fingerprints, and stores them in
// the server's tlsCertificates for use by request handlers.
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
		if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("private TLS key must be ECDSA, got %T", cert.PrivateKey)
		}
		certFP, pkFP, err := computeFingerprints(&cert)
		if err != nil {
			return fmt.Errorf("computing private certificate fingerprints: %w", err)
		}
		b := &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
		s.certs.mu.Lock()
		s.certs.private = b
		s.certs.mu.Unlock()
		attrs := append([]slog.Attr{
			slog.String("cert", s.cfg.PrivateTLSCertPath),
			slog.String("key", s.cfg.PrivateTLSKeyPath),
		}, certLeafAttrs(b)...)
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
	certFP, pkFP, err := computeFingerprints(&cert)
	if err != nil {
		s.logger.Error("failed to compute private certificate fingerprints", "error", err)
		return
	}
	b := &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
	s.certs.mu.Lock()
	s.certs.private = b
	s.certs.mu.Unlock()
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "reloaded private TLS certificate", certLeafAttrs(b)...)
}
