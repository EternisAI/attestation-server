package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"golang.org/x/sync/errgroup"
)

// cosignResult holds extracted Fulcio certificate extensions from a
// verified cosign bundle. Stored in the shared fetcherCache alongside
// *EndorsementDocument values. Caching avoids repeated Rekor online
// inclusion proof checks on subsequent requests within the TTL window.
type cosignResult struct {
	BuildSignerURI                  string
	BuildSignerDigest               string
	RunnerEnvironment               string
	SourceRepositoryURI             string
	SourceRepositoryDigest          string
	SourceRepositoryRef             string
	SourceRepositoryIdentifier      string
	SourceRepositoryOwnerURI        string
	SourceRepositoryOwnerIdentifier string
	BuildConfigURI                  string
	BuildConfigDigest               string
	BuildTrigger                    string
	RunInvocationURI                string
	SourceRepositoryVisibility      string
}

// initSigstoreVerifier creates an auto-updating Sigstore TUF client and
// a signed entity verifier configured for online Rekor inclusion proof
// verification. The TUF client refreshes the trusted root in the background.
func initSigstoreVerifier(logger *slog.Logger, tufCachePath string) (*verify.Verifier, error) {
	opts := tuf.DefaultOptions()
	if tufCachePath != "" {
		// Disk cache: survives restarts, faster startup after first fetch.
		// The directory must be writable.
		opts.WithCachePath(tufCachePath)
		logger.Info("sigstore tuf cache enabled", "path", tufCachePath)
	} else {
		// In-memory only: no disk writes. Background goroutine refreshes
		// every 24h; in-memory copy remains valid if network refresh fails.
		opts.WithDisableLocalCache()
	}

	trustedRoot, err := root.NewLiveTrustedRoot(opts)
	if err != nil {
		return nil, fmt.Errorf("fetching sigstore trusted root: %w", err)
	}

	v, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	logger.Info("initialized cosign verification with sigstore public-good infrastructure")
	return v, nil
}

// fetchCosignSignatures fetches signature bundles from all endorsement URLs
// (with the configured suffix appended) in parallel, verifies byte-for-byte
// identity, and returns the raw bundle bytes with the shortest TTL.
func (s *Server) fetchCosignSignatures(ctx context.Context, urls []*url.URL, client *http.Client) ([]byte, int, time.Duration, error) {
	if len(urls) == 0 {
		return nil, 0, 0, fmt.Errorf("no endorsement URLs for cosign signature fetch")
	}

	sigURLs := make([]*url.URL, len(urls))
	for i, u := range urls {
		sigU, err := url.Parse(u.String() + s.cfg.CosignURLSuffix)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("cosign signature URL %d: %w", i, err)
		}
		sigURLs[i] = sigU
	}

	if client == nil {
		client = s.fetchHTTPClient()
	}

	g, gctx := errgroup.WithContext(ctx)
	results := make([]fetchResult, len(sigURLs))

	for i, u := range sigURLs {
		g.Go(func() error {
			body, header, err := fetchWithRetry(gctx, client, u, s.logger)
			if err != nil {
				return fmt.Errorf("fetching %s: %w", u.String(), err)
			}
			results[i] = fetchResult{body: body, header: header}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, 0, 0, err
	}

	// Verify byte-for-byte identity across all responses
	refHash := sha256.Sum256(results[0].body)
	for i := 1; i < len(results); i++ {
		h := sha256.Sum256(results[i].body)
		if h != refHash {
			return nil, 0, 0, fmt.Errorf("cosign signature mismatch: %s (sha256:%s) differs from %s (sha256:%s)",
				sigURLs[i].String(), hex.EncodeToString(h[:8]),
				sigURLs[0].String(), hex.EncodeToString(refHash[:8]))
		}
	}

	// Use the most conservative (shortest) TTL across all responses
	ttl := fetchMaxTTL
	for _, r := range results {
		t := parseCacheTTL(r.header, s.cfg.HTTPCacheDefaultTTL)
		if t < ttl {
			ttl = t
		}
	}
	if ttl <= 0 {
		ttl = s.cfg.HTTPCacheDefaultTTL
	}

	return results[0].body, len(results[0].body), ttl, nil
}

// verifyCosignBundle parses and verifies a Cosign v3 protobuf bundle
// against the endorsement document bytes. It performs full online Rekor
// inclusion proof verification and extracts Fulcio OID extensions from
// the signing certificate.
func (s *Server) verifyCosignBundle(bundleJSON, endorsementDocBytes []byte) (*cosignResult, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing cosign bundle: %w", err)
	}

	digest := sha256.Sum256(endorsementDocBytes)

	// WithoutIdentitiesUnsafe skips the sigstore-go library's built-in
	// Fulcio certificate identity matching (issuer + SAN regex). This is
	// safe here because we perform our own strict OID-by-OID validation
	// in validateCosignOIDs afterward, comparing every Fulcio extension
	// against the server's BuildInfo. The library's matcher is too coarse
	// for our needs — we check individual fields rather than patterns.
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest[:]),
		verify.WithoutIdentitiesUnsafe(),
	)

	result, err := s.sigstoreVerifier.Verify(&b, policy)
	if err != nil {
		return nil, fmt.Errorf("verifying cosign bundle: %w", err)
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, fmt.Errorf("cosign bundle has no signing certificate")
	}

	ext := result.Signature.Certificate.Extensions
	return extensionsToCosignResult(ext), nil
}

// extensionsToCosignResult maps Fulcio certificate extensions to a
// cosignResult. Note the field name difference: Fulcio uses
// SourceRepositoryVisibilityAtSigning, BuildInfo uses SourceRepositoryVisibility.
func extensionsToCosignResult(ext certificate.Extensions) *cosignResult {
	return &cosignResult{
		BuildSignerURI:                  ext.BuildSignerURI,
		BuildSignerDigest:               ext.BuildSignerDigest,
		RunnerEnvironment:               ext.RunnerEnvironment,
		SourceRepositoryURI:             ext.SourceRepositoryURI,
		SourceRepositoryDigest:          ext.SourceRepositoryDigest,
		SourceRepositoryRef:             ext.SourceRepositoryRef,
		SourceRepositoryIdentifier:      ext.SourceRepositoryIdentifier,
		SourceRepositoryOwnerURI:        ext.SourceRepositoryOwnerURI,
		SourceRepositoryOwnerIdentifier: ext.SourceRepositoryOwnerIdentifier,
		BuildConfigURI:                  ext.BuildConfigURI,
		BuildConfigDigest:               ext.BuildConfigDigest,
		BuildTrigger:                    ext.BuildTrigger,
		RunInvocationURI:                ext.RunInvocationURI,
		SourceRepositoryVisibility:      ext.SourceRepositoryVisibilityAtSigning,
	}
}

// validateCosignOIDs compares extracted Fulcio certificate extensions
// against the provided BuildInfo.
//
// When endorsements.cosign.build_signer.uri or .uri_regex is configured,
// BuildSignerURI is validated against the override (.uri takes precedence
// if both set, with a warning logged) and BuildSignerDigest is skipped.
// When neither is configured, both are compared for exact match against
// BuildInfo — same as all other fields.
//
// DeploymentEnvironment has no standard Fulcio OID and is not checked.
func (s *Server) validateCosignOIDs(cr *cosignResult, bi *BuildInfo) error {
	hasBuildSignerOverride := s.cfg.CosignBuildSigner.URI != "" || s.cfg.CosignBuildSigner.URIRegex != nil

	// Validate BuildSignerURI
	if hasBuildSignerOverride {
		if err := s.validateBuildSignerURI(cr.BuildSignerURI); err != nil {
			return err
		}
	} else {
		if cr.BuildSignerURI != bi.BuildSignerURI {
			return fmt.Errorf("BuildSignerURI mismatch: cert %q, build_info %q", cr.BuildSignerURI, bi.BuildSignerURI)
		}
	}

	// Validate BuildSignerDigest: skip when build_signer config is set
	if !hasBuildSignerOverride {
		if cr.BuildSignerDigest != bi.BuildSignerDigest {
			return fmt.Errorf("BuildSignerDigest mismatch: cert %q, build_info %q", cr.BuildSignerDigest, bi.BuildSignerDigest)
		}
	}

	// All other fields: exact match
	checks := []struct {
		name     string
		certVal  string
		buildVal string
	}{
		{"RunnerEnvironment", cr.RunnerEnvironment, bi.RunnerEnvironment},
		{"SourceRepositoryURI", cr.SourceRepositoryURI, bi.SourceRepositoryURI},
		{"SourceRepositoryDigest", cr.SourceRepositoryDigest, bi.SourceRepositoryDigest},
		{"SourceRepositoryRef", cr.SourceRepositoryRef, bi.SourceRepositoryRef},
		{"SourceRepositoryIdentifier", cr.SourceRepositoryIdentifier, bi.SourceRepositoryIdentifier},
		{"SourceRepositoryOwnerURI", cr.SourceRepositoryOwnerURI, bi.SourceRepositoryOwnerURI},
		{"SourceRepositoryOwnerIdentifier", cr.SourceRepositoryOwnerIdentifier, bi.SourceRepositoryOwnerIdentifier},
		{"BuildConfigURI", cr.BuildConfigURI, bi.BuildConfigURI},
		{"BuildConfigDigest", cr.BuildConfigDigest, bi.BuildConfigDigest},
		{"BuildTrigger", cr.BuildTrigger, bi.BuildTrigger},
		{"RunInvocationURI", cr.RunInvocationURI, bi.RunInvocationURI},
		{"SourceRepositoryVisibility", cr.SourceRepositoryVisibility, bi.SourceRepositoryVisibility},
	}

	for _, c := range checks {
		if c.certVal != c.buildVal {
			return fmt.Errorf("%s mismatch: cert %q, build_info %q", c.name, c.certVal, c.buildVal)
		}
	}

	return nil
}

// validateBuildSignerURI validates the BuildSignerURI from the Fulcio
// certificate against the configured override. If both .uri and .uri_regex
// are set, .uri takes precedence (with a warning logged).
func (s *Server) validateBuildSignerURI(certURI string) error {
	cfg := s.cfg.CosignBuildSigner

	if cfg.URI != "" {
		if cfg.URIRegex != nil {
			s.logger.Warn("both endorsements.cosign.build_signer.uri and .uri_regex are set, using .uri only")
		}
		if certURI != cfg.URI {
			return fmt.Errorf("BuildSignerURI mismatch: cert %q, config %q", certURI, cfg.URI)
		}
		return nil
	}

	if cfg.URIRegex != nil {
		if !cfg.URIRegex.MatchString(certURI) {
			return fmt.Errorf("BuildSignerURI %q does not match regex %q", certURI, cfg.URIRegex.String())
		}
		return nil
	}

	return nil
}
