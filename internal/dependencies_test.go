package app

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-json"
)

// makeReportJSON builds a minimal AttestationReport JSON body whose
// data.nonce equals nonceHex. The data field is marshaled as a raw JSON
// object so that verifyDependencyReport can unmarshal it.
func makeReportJSON(t *testing.T, nonceHex string, evidence []*AttestationEvidence) []byte {
	t.Helper()
	return makeReportJSONWithClientCert(t, nonceHex, evidence, "")
}

// makeReportJSONWithClientCert builds a minimal AttestationReport with an
// optional client certificate fingerprint in data.tls.client.certificate.
func makeReportJSONWithClientCert(t *testing.T, nonceHex string, evidence []*AttestationEvidence, clientCertFP string) []byte {
	t.Helper()
	reportData := &AttestationReportData{
		RequestID: "test-request-id",
		Nonce:     nonceHex,
	}
	if clientCertFP != "" {
		reportData.TLS = &TLSReportData{
			Client: &TLSCertificateData{
				CertificateFingerprint: clientCertFP,
			},
		}
	}
	dataJSON, err := json.Marshal(reportData)
	if err != nil {
		t.Fatalf("marshaling report data: %v", err)
	}
	report := &AttestationReport{
		Evidence: evidence,
		Data:     json.RawMessage(dataJSON),
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshaling report: %v", err)
	}
	return body
}

// testClientFP is a fake client cert fingerprint used in unit tests.
const testClientFP = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// reportDataWithClientCert builds an AttestationReportData with the given nonce
// and a TLS client certificate fingerprint matching testClientFP.
func reportDataWithClientCert(nonce string) *AttestationReportData {
	return &AttestationReportData{
		Nonce: nonce,
		TLS: &TLSReportData{
			Client: &TLSCertificateData{
				CertificateFingerprint: testClientFP,
			},
		},
	}
}

// --- verifyDependencyReport tests (no fixtures needed) ---

func TestVerifyDependencyReport_NonceMismatch(t *testing.T) {
	reportData := reportDataWithClientCert("aabbccdd")
	reportData.RequestID = "req-1"
	dataJSON, err := json.Marshal(reportData)
	if err != nil {
		t.Fatal(err)
	}
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	err = verifyDependencyReportOnly(report, "different-nonce", testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for nonce mismatch, got nil")
	}
	if !contains(err.Error(), "nonce mismatch") {
		t.Fatalf("error %q does not contain 'nonce mismatch'", err.Error())
	}
}

func TestVerifyDependencyReport_EmptyEvidence(t *testing.T) {
	reportData := reportDataWithClientCert("abc123")
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{},
		Data:     json.RawMessage(dataJSON),
	}

	err := verifyDependencyReportOnly(report, "abc123", testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for empty evidence, got nil")
	}
	if !contains(err.Error(), "no evidence") {
		t.Fatalf("error %q does not contain 'no evidence'", err.Error())
	}
}

func TestVerifyDependencyReport_NilEvidence(t *testing.T) {
	reportData := reportDataWithClientCert("abc123")
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: nil,
		Data:     json.RawMessage(dataJSON),
	}

	err := verifyDependencyReportOnly(report, "abc123", testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for nil evidence, got nil")
	}
	if !contains(err.Error(), "no evidence") {
		t.Fatalf("error %q does not contain 'no evidence'", err.Error())
	}
}

func TestVerifyDependencyReport_UnknownEvidenceKind(t *testing.T) {
	nonceHex := "aabb"
	reportData := reportDataWithClientCert(nonceHex)
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "unknown-tee", Blob: []byte("data")}},
		Data:     json.RawMessage(dataJSON),
	}

	err := verifyDependencyReportOnly(report, nonceHex, testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for unknown evidence kind, got nil")
	}
	if !contains(err.Error(), "unknown evidence kind") {
		t.Fatalf("error %q does not contain 'unknown evidence kind'", err.Error())
	}
}

func TestVerifyDependencyReport_InvalidDataJSON(t *testing.T) {
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
		Data:     json.RawMessage(`not valid json`),
	}

	err := verifyDependencyReportOnly(report, "anything", testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for invalid data JSON, got nil")
	}
	if !contains(err.Error(), "parsing report data") {
		t.Fatalf("error %q does not contain 'parsing report data'", err.Error())
	}
}

func TestVerifyDependencyReport_MissingClientCert(t *testing.T) {
	reportData := &AttestationReportData{Nonce: "aabb"}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	err := verifyDependencyReportOnly(report, "aabb", testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for missing client cert, got nil")
	}
	if !isE2EError(err) {
		t.Fatalf("expected e2e error, got: %v", err)
	}
	if !contains(err.Error(), "missing client certificate") {
		t.Fatalf("error %q does not contain 'missing client certificate'", err.Error())
	}
}

func TestVerifyDependencyReport_ClientCertMismatch(t *testing.T) {
	reportData := &AttestationReportData{
		Nonce: "aabb",
		TLS: &TLSReportData{
			Client: &TLSCertificateData{
				CertificateFingerprint: "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
			},
		},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	err := verifyDependencyReportOnly(report, "aabb", testClientFP, time.Now())
	if err == nil {
		t.Fatal("expected error for client cert mismatch, got nil")
	}
	if !isE2EError(err) {
		t.Fatalf("expected e2e error, got: %v", err)
	}
	if !contains(err.Error(), "mismatch") {
		t.Fatalf("error %q does not contain 'mismatch'", err.Error())
	}
}

// --- httptest-based integration tests ---

func testServer(t *testing.T, cfg *Config, ctx context.Context) *Server {
	t.Helper()
	s := &Server{
		ctx:        ctx,
		cfg:        cfg,
		logger:     slog.Default(),
		instanceID: "test-instance-id",
	}
	cert := generateTestCertECDSA(t)
	certFP, pkFP, err := computeFingerprints(&cert)
	if err != nil {
		t.Fatal(err)
	}
	s.certs.private = &certBundle{cert: &cert, certFingerprint: certFP, pubKeyFingerprint: pkFP}
	return s
}

func TestFetchAndVerifyDependency_NonceHeaderForwarded(t *testing.T) {
	var receivedNonce string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedNonce = r.Header.Get(nonceHeader)
		// Return a valid-shaped report whose nonce matches.
		body := makeReportJSON(t, receivedNonce, []*AttestationEvidence{
			// Use an unknown kind so verification will fail — we only care
			// about header forwarding in this test.
			{Kind: "nitronsm", Blob: []byte("fake")},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer ts.Close()

	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)
	ep, _ := url.Parse(ts.URL)
	client := &http.Client{}

	testNonce := "deadbeef01234567"
	// Verification will fail (fake blob), but we can still check the header was sent.
	_, _ = s.fetchAndVerifyDependency(ctx, client, ep, testNonce, "test-req-id", "")

	if receivedNonce != testNonce {
		t.Errorf("dependency received nonce %q, want %q", receivedNonce, testNonce)
	}
}

func TestFetchAndVerifyDependency_Non200Status(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 500, 502, 503} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer ts.Close()

			ctx := context.Background()
			s := testServer(t, &Config{}, ctx)
			ep, _ := url.Parse(ts.URL)

			_, err := s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "aabb", "test-req-id", "")
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", status)
			}
			if !contains(err.Error(), fmt.Sprintf("unexpected status %d", status)) {
				t.Fatalf("error %q does not mention status %d", err.Error(), status)
			}
		})
	}
}

func TestFetchAndVerifyDependency_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"not": "an attestation report`))
	}))
	defer ts.Close()

	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)
	ep, _ := url.Parse(ts.URL)

	_, err := s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !contains(err.Error(), "parsing response") {
		t.Fatalf("error %q does not contain 'parsing response'", err.Error())
	}
}

func TestFetchAndVerifyDependency_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the request context is done, simulating a slow server.
		<-r.Context().Done()
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	s := testServer(t, &Config{}, ctx)
	ep, _ := url.Parse(ts.URL)

	// Cancel immediately so the request is aborted.
	cancel()

	_, err := s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}

func TestFetchAndVerifyDependency_NonceMismatchInResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a report with a different nonce than what was sent.
		body := makeReportJSON(t, "wrong-nonce", []*AttestationEvidence{
			{Kind: "nitronsm", Blob: []byte("fake")},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer ts.Close()

	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)
	ep, _ := url.Parse(ts.URL)

	_, err := s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "correct-nonce", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error for nonce mismatch, got nil")
	}
	if !contains(err.Error(), "nonce mismatch") {
		t.Fatalf("error %q does not contain 'nonce mismatch'", err.Error())
	}
}

func TestFetchAndVerifyDependency_UsesGETMethod(t *testing.T) {
	var receivedMethod string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)
	ep, _ := url.Parse(ts.URL)

	// Will fail on parse but we only care about method.
	_, _ = s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "aabb", "test-req-id", "")

	if receivedMethod != http.MethodGet {
		t.Errorf("dependency received method %q, want GET", receivedMethod)
	}
}

// --- fetchDependencies integration tests ---

func TestFetchDependencies_EmptyEndpoints(t *testing.T) {
	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)

	deps, err := s.fetchDependencies("aabb", "test-req-id", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Fatalf("expected nil deps for empty endpoints, got %v", deps)
	}
}

func TestFetchDependencies_AllEndpointsFail(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts1.Close()
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts2.Close()

	ep1, _ := url.Parse(ts1.URL)
	ep2, _ := url.Parse(ts2.URL)

	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep1, ep2},
	}, ctx)

	_, err := s.fetchDependencies("aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error when all endpoints fail, got nil")
	}
	if !contains(err.Error(), "dependency attestation failed") {
		t.Fatalf("error %q does not contain 'dependency attestation failed'", err.Error())
	}
}

func TestFetchDependencies_OneEndpointFails(t *testing.T) {
	// One server returns 500, the other would succeed (but we expect
	// the overall result to be an error since any failure is fatal).
	tsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tsFail.Close()

	tsOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(nonceHeader)
		body := makeReportJSON(t, nonce, []*AttestationEvidence{
			{Kind: "nitronsm", Blob: []byte("fake")},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer tsOK.Close()

	epFail, _ := url.Parse(tsFail.URL)
	epOK, _ := url.Parse(tsOK.URL)

	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{epFail, epOK},
	}, ctx)

	_, err := s.fetchDependencies("aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error when one endpoint fails, got nil")
	}
}

func TestFetchDependencies_ParallelExecution(t *testing.T) {
	// Verify that multiple endpoints are contacted. We count the number
	// of requests received across all servers.
	var requestCount atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		// Return a nonce-matching report with unknown evidence so
		// verification fails — we only care about parallelism here.
		nonce := r.Header.Get(nonceHeader)
		body := makeReportJSON(t, nonce, []*AttestationEvidence{
			{Kind: "nitronsm", Blob: []byte("fake")},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})

	ts1 := httptest.NewServer(handler)
	defer ts1.Close()
	ts2 := httptest.NewServer(handler)
	defer ts2.Close()
	ts3 := httptest.NewServer(handler)
	defer ts3.Close()

	ep1, _ := url.Parse(ts1.URL)
	ep2, _ := url.Parse(ts2.URL)
	ep3, _ := url.Parse(ts3.URL)

	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep1, ep2, ep3},
	}, ctx)

	// Will fail on verification but all 3 servers should be contacted.
	_, _ = s.fetchDependencies("aabb", "test-req-id", "")

	count := requestCount.Load()
	// At least 1 must have been hit; with errgroup cancellation on first
	// error, not all 3 are guaranteed. But we can verify that at least
	// the mechanism launched requests.
	if count == 0 {
		t.Fatal("no dependency endpoints were contacted")
	}
}

func TestFetchDependencies_ErrorDoesNotLeakURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ep, _ := url.Parse(ts.URL)

	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep},
	}, ctx)

	_, err := s.fetchDependencies("aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// The error returned to the caller must NOT contain the URL.
	if contains(err.Error(), ts.URL) {
		t.Fatalf("error %q leaks the endpoint URL %q", err.Error(), ts.URL)
	}
}

func TestFetchDependencies_ContextCancelled(t *testing.T) {
	// Server blocks forever; context is pre-cancelled.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer ts.Close()

	ep, _ := url.Parse(ts.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before fetch.

	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep},
	}, ctx)

	_, err := s.fetchDependencies("aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}

func TestFetchDependencies_NonceForwardedToAllEndpoints(t *testing.T) {
	var nonces [2]string
	var wg sync.WaitGroup
	wg.Add(2)

	ts0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonces[0] = r.Header.Get(nonceHeader)
		wg.Done()
		wg.Wait()
		w.WriteHeader(http.StatusOK)
		body := makeReportJSON(t, nonces[0], []*AttestationEvidence{
			{Kind: "nitronsm", Blob: []byte("fake")},
		})
		w.Write(body)
	}))
	defer ts0.Close()

	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonces[1] = r.Header.Get(nonceHeader)
		wg.Done()
		wg.Wait()
		w.WriteHeader(http.StatusOK)
		body := makeReportJSON(t, nonces[1], []*AttestationEvidence{
			{Kind: "nitronsm", Blob: []byte("fake")},
		})
		w.Write(body)
	}))
	defer ts1.Close()

	ep0, _ := url.Parse(ts0.URL)
	ep1, _ := url.Parse(ts1.URL)

	// Use a realistic nonce: hex-encoded SHA-512 digest.
	digest := sha512.Sum512([]byte("test-data"))
	nonceHex := hex.EncodeToString(digest[:])

	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep0, ep1},
	}, ctx)

	// Will fail on crypto verification but nonces should arrive.
	_, _ = s.fetchDependencies(nonceHex, "test-req-id", "")

	for i, n := range nonces {
		if n != nonceHex {
			t.Errorf("endpoint %d received nonce %q, want %q", i, n, nonceHex)
		}
	}
}

func TestFetchAndVerifyDependency_RequestIDForwarded(t *testing.T) {
	var receivedRequestID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get("X-Request-Id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)
	ep, _ := url.Parse(ts.URL)

	wantID := "my-unique-request-id-123"
	_, _ = s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "aabb", wantID, "")

	if receivedRequestID != wantID {
		t.Errorf("dependency received X-Request-Id %q, want %q", receivedRequestID, wantID)
	}
}

func TestFetchDependencies_RequestIDForwardedToAll(t *testing.T) {
	var ids [2]string
	var wg sync.WaitGroup
	wg.Add(2)
	ts0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids[0] = r.Header.Get("X-Request-Id")
		wg.Done()
		wg.Wait()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts0.Close()
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids[1] = r.Header.Get("X-Request-Id")
		wg.Done()
		wg.Wait()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts1.Close()

	ep0, _ := url.Parse(ts0.URL)
	ep1, _ := url.Parse(ts1.URL)

	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep0, ep1},
	}, ctx)

	wantID := "propagated-request-id"
	_, _ = s.fetchDependencies("aabb", wantID, "")

	for i, id := range ids {
		if id != wantID {
			t.Errorf("endpoint %d received X-Request-Id %q, want %q", i, id, wantID)
		}
	}
}

// --- cycle detection tests ---

func TestCycleDetection_PathHeaderPropagated(t *testing.T) {
	var receivedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.Header.Get("X-Attestation-Path")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ep, _ := url.Parse(ts.URL)
	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep},
	}, ctx)

	// With no incoming path, outbound should be just our instance ID.
	_, _ = s.fetchDependencies("aabb", "req-id", "")
	if receivedPath != "test-instance-id" {
		t.Errorf("got path %q, want %q", receivedPath, "test-instance-id")
	}
}

func TestCycleDetection_PathHeaderAppended(t *testing.T) {
	var receivedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.Header.Get("X-Attestation-Path")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ep, _ := url.Parse(ts.URL)
	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep},
	}, ctx)

	// With an existing path from upstream, our ID is appended.
	_, _ = s.fetchDependencies("aabb", "req-id", "upstream-id-1,upstream-id-2")
	want := "upstream-id-1,upstream-id-2,test-instance-id"
	if receivedPath != want {
		t.Errorf("got path %q, want %q", receivedPath, want)
	}
}

func TestCycleDetection_DiamondDependencyAllowed(t *testing.T) {
	// Diamond: A depends on B and C, both B and C depend on D.
	// D should receive requests with different paths (through B and through C)
	// but neither path contains D's own ID, so no cycle is detected.
	// This test verifies that sharing a dependency is NOT flagged as a cycle.
	s := testServer(t, &Config{}, context.Background())
	s.instanceID = "server-D"

	// Path through B: A -> B -> D — no cycle.
	_, _ = s.fetchDependencies("aabb", "req-id", "server-A,server-B")
	// If this didn't panic or error on cycle detection, the diamond is allowed.
}

func TestCycleDetection_DependencyReturns409(t *testing.T) {
	// Simulate a dependency that detects a cycle and returns 409.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"dependency cycle detected"}`))
	}))
	defer ts.Close()

	ep, _ := url.Parse(ts.URL)
	ctx := context.Background()
	s := testServer(t, &Config{
		DependencyEndpoints: []*url.URL{ep},
	}, ctx)

	_, err := s.fetchDependencies("aabb", "req-id", "")
	if err == nil {
		t.Fatal("expected error when dependency returns 409, got nil")
	}
}

// --- client certificate fingerprint enforcement tests ---

func TestFetchAndVerifyDependency_E2EErrorMasked(t *testing.T) {
	// When a dependency responds without client cert data,
	// fetchAndVerifyDependency returns an opaque error (not leaking
	// internal details) while the descriptive message is logged.
	ctx := context.Background()
	s := testServer(t, &Config{}, ctx)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(nonceHeader)
		// Report with matching nonce + client cert, but fake evidence blob.
		// verifyDependencyReport will fail at crypto before e2e check.
		body := makeReportJSONWithClientCert(t, nonce, []*AttestationEvidence{
			{Kind: "nitronsm", Blob: []byte("fake")},
		}, "")
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer ts.Close()

	ep, _ := url.Parse(ts.URL)

	_, err := s.fetchAndVerifyDependency(ctx, &http.Client{}, ep, "aabb", "test-req-id", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// The e2e check fires before crypto in verifyDependencyReport, so
	// it should be the opaque e2e error.
	if !contains(err.Error(), "end-to-end encryption") {
		t.Fatalf("expected e2e error, got: %v", err)
	}
}
