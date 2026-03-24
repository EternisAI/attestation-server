package app

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

// --- validateCosignOIDs ---

func TestValidateCosignOIDs(t *testing.T) {
	baseBuildInfo := &BuildInfo{
		BuildSignerURI:                  "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
		BuildSignerDigest:               "abc123",
		RunnerEnvironment:               "github-hosted",
		SourceRepositoryURI:             "https://github.com/org/repo",
		SourceRepositoryDigest:          "sha256:deadbeef",
		SourceRepositoryRef:             "refs/heads/main",
		SourceRepositoryIdentifier:      "12345",
		SourceRepositoryOwnerURI:        "https://github.com/org",
		SourceRepositoryOwnerIdentifier: "67890",
		BuildConfigURI:                  "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
		BuildConfigDigest:               "sha256:cafebabe",
		BuildTrigger:                    "push",
		RunInvocationURI:                "https://github.com/org/repo/actions/runs/123",
		SourceRepositoryVisibility:      "public",
		DeploymentEnvironment:           "production",
	}

	matchingResult := &cosignResult{
		BuildSignerURI:                  baseBuildInfo.BuildSignerURI,
		BuildSignerDigest:               baseBuildInfo.BuildSignerDigest,
		RunnerEnvironment:               baseBuildInfo.RunnerEnvironment,
		SourceRepositoryURI:             baseBuildInfo.SourceRepositoryURI,
		SourceRepositoryDigest:          baseBuildInfo.SourceRepositoryDigest,
		SourceRepositoryRef:             baseBuildInfo.SourceRepositoryRef,
		SourceRepositoryIdentifier:      baseBuildInfo.SourceRepositoryIdentifier,
		SourceRepositoryOwnerURI:        baseBuildInfo.SourceRepositoryOwnerURI,
		SourceRepositoryOwnerIdentifier: baseBuildInfo.SourceRepositoryOwnerIdentifier,
		BuildConfigURI:                  baseBuildInfo.BuildConfigURI,
		BuildConfigDigest:               baseBuildInfo.BuildConfigDigest,
		BuildTrigger:                    baseBuildInfo.BuildTrigger,
		RunInvocationURI:                baseBuildInfo.RunInvocationURI,
		SourceRepositoryVisibility:      baseBuildInfo.SourceRepositoryVisibility,
	}

	t.Run("all fields match", func(t *testing.T) {
		s := &Server{cfg: &Config{}}
		if err := s.validateCosignOIDs(matchingResult, baseBuildInfo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("DeploymentEnvironment different is ok", func(t *testing.T) {
		// cosignResult has no DeploymentEnvironment field (no Fulcio OID)
		// so BuildInfo.DeploymentEnvironment is ignored
		bi := *baseBuildInfo
		bi.DeploymentEnvironment = "staging"
		s := &Server{cfg: &Config{}}
		if err := s.validateCosignOIDs(matchingResult, &bi); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RunnerEnvironment mismatch", func(t *testing.T) {
		cr := *matchingResult
		cr.RunnerEnvironment = "self-hosted"
		s := &Server{cfg: &Config{}}
		err := s.validateCosignOIDs(&cr, baseBuildInfo)
		if err == nil {
			t.Fatal("expected error for RunnerEnvironment mismatch")
		}
		if !contains(err.Error(), "RunnerEnvironment") || !contains(err.Error(), "mismatch") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("SourceRepositoryVisibility maps correctly", func(t *testing.T) {
		// Fulcio uses SourceRepositoryVisibilityAtSigning, BuildInfo uses
		// SourceRepositoryVisibility. extensionsToCosignResult maps them.
		cr := *matchingResult
		cr.SourceRepositoryVisibility = "private"
		s := &Server{cfg: &Config{}}
		err := s.validateCosignOIDs(&cr, baseBuildInfo)
		if err == nil {
			t.Fatal("expected error for SourceRepositoryVisibility mismatch")
		}
		if !contains(err.Error(), "SourceRepositoryVisibility") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("BuildSignerURI mismatch without override", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerURI = "https://other.com/workflow.yml"
		s := &Server{cfg: &Config{}}
		err := s.validateCosignOIDs(&cr, baseBuildInfo)
		if err == nil {
			t.Fatal("expected error for BuildSignerURI mismatch")
		}
		if !contains(err.Error(), "BuildSignerURI") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("BuildSignerDigest mismatch without override", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerDigest = "different-digest"
		s := &Server{cfg: &Config{}}
		err := s.validateCosignOIDs(&cr, baseBuildInfo)
		if err == nil {
			t.Fatal("expected error for BuildSignerDigest mismatch")
		}
		if !contains(err.Error(), "BuildSignerDigest") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("BuildSignerDigest skipped when build_signer config set", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerDigest = "different-digest"
		s := &Server{cfg: &Config{
			CosignBuildSigner: CosignBuildSignerConfig{
				URI: baseBuildInfo.BuildSignerURI,
			},
		}}
		if err := s.validateCosignOIDs(&cr, baseBuildInfo); err != nil {
			t.Fatalf("expected BuildSignerDigest to be skipped when build_signer.uri is set, got: %v", err)
		}
	})

	t.Run("BuildSignerURI with config uri override", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerURI = "https://expected.com/workflow.yml"
		s := &Server{cfg: &Config{
			CosignBuildSigner: CosignBuildSignerConfig{
				URI: "https://expected.com/workflow.yml",
			},
		}}
		if err := s.validateCosignOIDs(&cr, baseBuildInfo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("BuildSignerURI config uri override mismatch", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerURI = "https://wrong.com/workflow.yml"
		s := &Server{cfg: &Config{
			CosignBuildSigner: CosignBuildSignerConfig{
				URI: "https://expected.com/workflow.yml",
			},
		}}
		err := s.validateCosignOIDs(&cr, baseBuildInfo)
		if err == nil {
			t.Fatal("expected error for BuildSignerURI config mismatch")
		}
		if !contains(err.Error(), "BuildSignerURI") || !contains(err.Error(), "config") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("BuildSignerURI with config uri_regex override", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerURI = "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main"
		s := &Server{cfg: &Config{
			CosignBuildSigner: CosignBuildSignerConfig{
				URIRegex: regexp.MustCompile(`^https://github\.com/org/repo/`),
			},
		}}
		if err := s.validateCosignOIDs(&cr, baseBuildInfo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("BuildSignerURI regex no match", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerURI = "https://gitlab.com/other/repo/build.yml"
		s := &Server{cfg: &Config{
			CosignBuildSigner: CosignBuildSignerConfig{
				URIRegex: regexp.MustCompile(`^https://github\.com/`),
			},
		}}
		err := s.validateCosignOIDs(&cr, baseBuildInfo)
		if err == nil {
			t.Fatal("expected error for regex non-match")
		}
		if !contains(err.Error(), "does not match regex") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("both uri and uri_regex set uses uri only", func(t *testing.T) {
		cr := *matchingResult
		cr.BuildSignerURI = "https://exact.com/workflow.yml"
		s := &Server{
			cfg: &Config{
				CosignBuildSigner: CosignBuildSignerConfig{
					URI:      "https://exact.com/workflow.yml",
					URIRegex: regexp.MustCompile(`never-matches`),
				},
			},
			logger: testLogger(),
		}
		// Should pass because .uri matches; .uri_regex is ignored
		if err := s.validateCosignOIDs(&cr, baseBuildInfo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- fetchCosignSignatures ---

func TestFetchCosignSignatures_Identical(t *testing.T) {
	bundleJSON := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`

	srv1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the URL suffix was appended
		if r.URL.Path != "/endorsement.json.sig" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Cache-Control", "max-age=600")
		w.Write([]byte(bundleJSON))
	}))
	defer srv1.Close()

	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=1200")
		w.Write([]byte(bundleJSON))
	}))
	defer srv2.Close()

	s := &Server{
		cfg: &Config{
			EndorsementClientTimeout: 5 * time.Second,
			CosignURLSuffix:          ".sig",
		},
	}

	u1, _ := url.Parse(srv1.URL + "/endorsement.json")
	u2, _ := url.Parse(srv2.URL + "/endorsement.json")

	body, _, ttl, err := s.fetchCosignSignatures(context.Background(), []*url.URL{u1, u2}, srv1.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != bundleJSON {
		t.Errorf("body = %q, want %q", string(body), bundleJSON)
	}
	// Should use most conservative TTL (600s = 10m)
	if ttl != 10*time.Minute {
		t.Errorf("TTL = %v, want %v", ttl, 10*time.Minute)
	}
}

func TestFetchCosignSignatures_Mismatch(t *testing.T) {
	srv1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"bundle":"a"}`))
	}))
	defer srv1.Close()

	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"bundle":"b"}`))
	}))
	defer srv2.Close()

	s := &Server{
		cfg: &Config{
			EndorsementClientTimeout: 5 * time.Second,
			CosignURLSuffix:          ".sig",
		},
	}

	u1, _ := url.Parse(srv1.URL + "/endorsement.json")
	u2, _ := url.Parse(srv2.URL + "/endorsement.json")

	_, _, _, err := s.fetchCosignSignatures(context.Background(), []*url.URL{u1, u2}, srv1.Client())
	if err == nil {
		t.Fatal("expected error for mismatched signatures")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention mismatch", err)
	}
}

func TestFetchCosignSignatures_URLSuffix(t *testing.T) {
	var receivedPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s := &Server{
		cfg: &Config{
			EndorsementClientTimeout: 5 * time.Second,
			CosignURLSuffix:          ".cosign-bundle",
		},
	}

	u, _ := url.Parse(srv.URL + "/measurements.json")
	_, _, _, err := s.fetchCosignSignatures(context.Background(), []*url.URL{u}, srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedPath != "/measurements.json.cosign-bundle" {
		t.Errorf("received path = %q, want %q", receivedPath, "/measurements.json.cosign-bundle")
	}
}

// --- fetcherCache ---

func TestFetcherCache_MixedTypes(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{SEVSNP: strPtr("aabbccdd")}
	cr := &cosignResult{BuildSignerURI: "https://example.com"}

	cache.setGroup([]string{"https://a.com/e.json"}, doc, 100, time.Minute)
	cache.setGroup([]string{"https://a.com/e.json.sig"}, cr, 50, time.Minute)

	// Retrieve endorsement doc
	val1, ok1 := cache.get("https://a.com/e.json")
	if !ok1 {
		t.Fatal("cache miss for endorsement URL")
	}
	gotDoc, ok := val1.(*EndorsementDocument)
	if !ok {
		t.Fatal("type assertion to *EndorsementDocument failed")
	}
	if gotDoc != doc {
		t.Error("expected same pointer for endorsement doc")
	}

	// Retrieve cosign result
	val2, ok2 := cache.get("https://a.com/e.json.sig")
	if !ok2 {
		t.Fatal("cache miss for cosign URL")
	}
	gotCR, ok := val2.(*cosignResult)
	if !ok {
		t.Fatal("type assertion to *cosignResult failed")
	}
	if gotCR != cr {
		t.Error("expected same pointer for cosign result")
	}

	// No collision between endorsement URL and signature URL
	_, ok3 := cache.get("https://a.com/e.json.sig.sig")
	if ok3 {
		t.Error("unexpected cache hit for non-existent URL")
	}
}

func TestFetcherCache_SetGroupDedup(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{SEVSNP: strPtr("aabbccdd")}
	cache.setGroup([]string{"https://a.com/e.json", "https://b.com/e.json"}, doc, 100, time.Minute)

	val1, ok1 := cache.get("https://a.com/e.json")
	val2, ok2 := cache.get("https://b.com/e.json")

	if !ok1 || !ok2 {
		t.Fatal("cache miss for stored URLs")
	}

	// Both should point to the same object (dedup)
	if val1 != val2 {
		t.Error("expected same pointer for deduplicated entries")
	}
}

func TestFetcherCache_Miss(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := cache.get("https://missing.com/e.json")
	if ok {
		t.Error("expected cache miss for unknown URL")
	}
}

// --- extensionsToCosignResult ---

func TestExtensionsToCosignResult_MapsVisibility(t *testing.T) {
	ext := certificate.Extensions{
		BuildSignerURI:                      "uri",
		SourceRepositoryVisibilityAtSigning: "public",
	}
	cr := extensionsToCosignResult(ext)
	if cr.SourceRepositoryVisibility != "public" {
		t.Errorf("SourceRepositoryVisibility = %q, want %q", cr.SourceRepositoryVisibility, "public")
	}
}

// --- dependency endorsement enforcement ---

func TestValidateDependencyEndorsements_CosignRequiresEndorsements(t *testing.T) {
	reportData := &AttestationReportData{
		Endorsements: []string{},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg: &Config{
			CosignVerify:             true,
			EndorsementClientTimeout: 5 * time.Second,
		},
	}
	parsed := &parsedDependencyEvidence{}

	err := s.validateDependencyEndorsements(context.Background(), report, parsed)
	if err == nil {
		t.Fatal("expected error when cosign is enabled but dependency has no endorsement URLs")
	}
	if !contains(err.Error(), "no endorsement URLs") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_NoCosignAllowsEmpty(t *testing.T) {
	reportData := &AttestationReportData{
		Endorsements: []string{},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg: &Config{
			CosignVerify:             false,
			EndorsementClientTimeout: 5 * time.Second,
		},
	}
	parsed := &parsedDependencyEvidence{}

	if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testLogger() *slog.Logger {
	return slog.Default()
}
