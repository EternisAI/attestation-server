package dnssec

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- Unit tests for unexported helpers ---

func TestParentZone(t *testing.T) {
	tests := []struct {
		zone string
		want string
	}{
		{".", "."},
		{"com.", "."},
		{"example.com.", "com."},
		{"sub.example.com.", "example.com."},
		{"deep.sub.example.com.", "sub.example.com."},
		{"test.", "."},
	}
	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			got := parentZone(tt.zone)
			if got != tt.want {
				t.Errorf("parentZone(%q) = %q, want %q", tt.zone, got, tt.want)
			}
		})
	}
}

func TestCleanHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"  example.com  ", "example.com"},
		{"[::1]:53", "::1"},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanHost(tt.input)
			if got != tt.want {
				t.Errorf("cleanHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestKeysMatch(t *testing.T) {
	a := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "dGVzdA==",
	}
	b := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "dGVzdA==",
	}
	if !keysMatch(a, b) {
		t.Error("identical keys should match")
	}

	c := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "dGVzdA==",
	}
	if keysMatch(a, c) {
		t.Error("different flags should not match")
	}

	d := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "b3RoZXI=",
	}
	if keysMatch(a, d) {
		t.Error("different public key should not match")
	}
}

func TestDSMatchesKey(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	privKey, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	_ = privKey

	for _, digestType := range []uint8{dns.SHA1, dns.SHA256, dns.SHA384} {
		t.Run(fmt.Sprintf("digest_%d", digestType), func(t *testing.T) {
			ds := key.ToDS(digestType)
			if ds == nil {
				t.Fatal("ToDS returned nil")
			}
			if !dsMatchesKey(ds, key) {
				t.Error("DS should match the key it was derived from")
			}
			// Tamper with digest.
			tampered := *ds
			tampered.Digest = strings.Repeat("00", len(ds.Digest)/2)
			if dsMatchesKey(&tampered, key) {
				t.Error("tampered DS should not match")
			}
		})
	}

	t.Run("unknown_digest", func(t *testing.T) {
		ds := &dns.DS{DigestType: 99}
		if dsMatchesKey(ds, key) {
			t.Error("unknown digest type should not match")
		}
	})
}

// --- Test infrastructure: in-process signed DNS server ---

type testZone struct {
	name    string
	ksk     *dns.DNSKEY
	kskPriv crypto.Signer
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer
	records []dns.RR // A, AAAA, CNAME, etc.
}

func generateKey(t *testing.T, name string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	privKey, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generating key for %s: %v", name, err)
	}
	return key, privKey.(crypto.Signer)
}

func signRRset(t *testing.T, rrset []dns.RR, zone string, key *dns.DNSKEY, privKey crypto.Signer) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(privKey, rrset); err != nil {
		t.Fatalf("signing RRset for %s: %v", zone, err)
	}
	return sig
}

func signExpiredRRset(t *testing.T, rrset []dns.RR, zone string, key *dns.DNSKEY, privKey crypto.Signer) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-48 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(privKey, rrset); err != nil {
		t.Fatalf("signing expired RRset for %s: %v", zone, err)
	}
	return sig
}

type testHierarchy struct {
	root   *testZone
	tld    *testZone
	domain *testZone

	// Signed records cached for serving.
	rootDNSKEYRRs  []dns.RR
	tldDNSKEYRRs   []dns.RR
	domDNSKEYRRs   []dns.RR
	tldDSRRs       []dns.RR
	domDSRRs       []dns.RR
	domARecords    []dns.RR
	domAAAARecords []dns.RR
}

func newTestHierarchy(t *testing.T) *testHierarchy {
	t.Helper()

	// Generate keys for all zones.
	rootKSK, rootKSKPriv := generateKey(t, ".", 257)
	rootZSK, rootZSKPriv := generateKey(t, ".", 256)
	tldKSK, tldKSKPriv := generateKey(t, "test.", 257)
	tldZSK, tldZSKPriv := generateKey(t, "test.", 256)
	domKSK, domKSKPriv := generateKey(t, "example.test.", 257)
	domZSK, domZSKPriv := generateKey(t, "example.test.", 256)

	h := &testHierarchy{
		root:   &testZone{name: ".", ksk: rootKSK, kskPriv: rootKSKPriv, zsk: rootZSK, zskPriv: rootZSKPriv},
		tld:    &testZone{name: "test.", ksk: tldKSK, kskPriv: tldKSKPriv, zsk: tldZSK, zskPriv: tldZSKPriv},
		domain: &testZone{name: "example.test.", ksk: domKSK, kskPriv: domKSKPriv, zsk: domZSK, zskPriv: domZSKPriv},
	}

	// Build DNSKEY RRsets.
	h.rootDNSKEYRRs = []dns.RR{rootKSK, rootZSK}
	h.tldDNSKEYRRs = []dns.RR{tldKSK, tldZSK}
	h.domDNSKEYRRs = []dns.RR{domKSK, domZSK}

	// Build DS records: child KSK → DS in parent.
	tldDS := tldKSK.ToDS(dns.SHA256)
	tldDS.Hdr = dns.RR_Header{Name: "test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}
	h.tldDSRRs = []dns.RR{tldDS}

	domDS := domKSK.ToDS(dns.SHA256)
	domDS.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}
	h.domDSRRs = []dns.RR{domDS}

	// Build A / AAAA records.
	h.domARecords = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}}
	h.domAAAARecords = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP("2001:db8::1"),
	}}

	return h
}

// startServer launches an in-process DNS server. The optional override
// function can tamper with the hierarchy for negative tests.
func (h *testHierarchy) startServer(t *testing.T, override func(qname string, qtype uint16, resp *dns.Msg)) (string, func()) {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true

		if len(req.Question) > 0 {
			q := req.Question[0]
			h.handleQuery(t, q.Name, q.Qtype, resp)
			if override != nil {
				override(q.Name, q.Qtype, resp)
			}
		}

		w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()

	server := &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}

	go server.ActivateAndServe()

	cleanup := func() {
		server.Shutdown()
	}

	return addr, cleanup
}

func (h *testHierarchy) handleQuery(t *testing.T, qname string, qtype uint16, resp *dns.Msg) {
	t.Helper()
	qname = dns.Fqdn(qname)

	switch {
	// Root zone
	case qname == "." && qtype == dns.TypeDNSKEY:
		resp.Answer = append(resp.Answer, h.rootDNSKEYRRs...)
		sig := signRRset(t, h.rootDNSKEYRRs, ".", h.root.ksk, h.root.kskPriv)
		resp.Answer = append(resp.Answer, sig)

	// TLD DS (served by root)
	case qname == "test." && qtype == dns.TypeDS:
		resp.Answer = append(resp.Answer, h.tldDSRRs...)
		sig := signRRset(t, h.tldDSRRs, ".", h.root.zsk, h.root.zskPriv)
		resp.Answer = append(resp.Answer, sig)

	// TLD DNSKEY
	case qname == "test." && qtype == dns.TypeDNSKEY:
		resp.Answer = append(resp.Answer, h.tldDNSKEYRRs...)
		sig := signRRset(t, h.tldDNSKEYRRs, "test.", h.tld.ksk, h.tld.kskPriv)
		resp.Answer = append(resp.Answer, sig)

	// Domain DS (served by TLD)
	case qname == "example.test." && qtype == dns.TypeDS:
		resp.Answer = append(resp.Answer, h.domDSRRs...)
		sig := signRRset(t, h.domDSRRs, "test.", h.tld.zsk, h.tld.zskPriv)
		resp.Answer = append(resp.Answer, sig)

	// Domain DNSKEY
	case qname == "example.test." && qtype == dns.TypeDNSKEY:
		resp.Answer = append(resp.Answer, h.domDNSKEYRRs...)
		sig := signRRset(t, h.domDNSKEYRRs, "example.test.", h.domain.ksk, h.domain.kskPriv)
		resp.Answer = append(resp.Answer, sig)

	// Domain A record
	case qname == "example.test." && qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, h.domARecords...)
		sig := signRRset(t, h.domARecords, "example.test.", h.domain.zsk, h.domain.zskPriv)
		resp.Answer = append(resp.Answer, sig)

	// Domain AAAA record
	case qname == "example.test." && qtype == dns.TypeAAAA:
		resp.Answer = append(resp.Answer, h.domAAAARecords...)
		sig := signRRset(t, h.domAAAARecords, "example.test.", h.domain.zsk, h.domain.zskPriv)
		resp.Answer = append(resp.Answer, sig)
	}
}

func newTestResolver(t *testing.T, addr string, trustAnchor *dns.DNSKEY) *Resolver {
	t.Helper()
	r, err := NewFromServers([]string{addr}, 5*time.Second, WithTrustAnchors([]*dns.DNSKEY{trustAnchor}))
	if err != nil {
		t.Fatalf("creating resolver: %v", err)
	}
	return r
}

// --- Validation tests ---

func TestValidate_FullChain(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, nil)
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	if err := r.Validate(context.Background(), "example.test."); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestValidate_IPLiteral(t *testing.T) {
	r := &Resolver{}
	for _, ip := range []string{"127.0.0.1", "::1", "192.168.1.1"} {
		if err := r.Validate(context.Background(), ip); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", ip, err)
		}
	}
}

func TestValidate_BareName(t *testing.T) {
	r := &Resolver{}
	if err := r.Validate(context.Background(), "localhost"); err != nil {
		t.Errorf("Validate(localhost) = %v, want nil", err)
	}
}

func TestValidate_BrokenSignature(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, func(qname string, qtype uint16, resp *dns.Msg) {
		// Tamper with A record RRSIG by replacing the answer with a different IP
		// but keeping the old signature.
		if qname == "example.test." && qtype == dns.TypeA {
			for i, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					a.A = net.ParseIP("10.0.0.99")
					resp.Answer[i] = a
				}
			}
		}
	})
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	err := r.Validate(context.Background(), "example.test.")
	if err == nil {
		t.Fatal("Validate() should fail with tampered A record")
	}
	var valErr *ErrValidation
	if !isErrValidation(err, &valErr) {
		t.Fatalf("expected *ErrValidation, got %T: %v", err, err)
	}
}

func TestValidate_MissingDS(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, func(qname string, qtype uint16, resp *dns.Msg) {
		// Remove DS records for example.test.
		if qname == "example.test." && qtype == dns.TypeDS {
			resp.Answer = nil
		}
	})
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	err := r.Validate(context.Background(), "example.test.")
	if err == nil {
		t.Fatal("Validate() should fail with missing DS")
	}
}

func TestValidate_ExpiredRRSIG(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, func(qname string, qtype uint16, resp *dns.Msg) {
		if qname == "example.test." && qtype == dns.TypeA {
			// Replace all RRSIGs with expired ones.
			var newAnswer []dns.RR
			var aRecords []dns.RR
			for _, rr := range resp.Answer {
				if _, ok := rr.(*dns.RRSIG); ok {
					continue
				}
				newAnswer = append(newAnswer, rr)
				if rr.Header().Rrtype == dns.TypeA {
					aRecords = append(aRecords, rr)
				}
			}
			if len(aRecords) > 0 {
				expSig := signExpiredRRset(t, aRecords, "example.test.", h.domain.zsk, h.domain.zskPriv)
				newAnswer = append(newAnswer, expSig)
			}
			resp.Answer = newAnswer
		}
	})
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	err := r.Validate(context.Background(), "example.test.")
	if err == nil {
		t.Fatal("Validate() should fail with expired RRSIG")
	}
}

// TestValidate_WrongSignerName is a regression test for GO-2022-0979:
// an RRSIG with a mismatched signer name must be rejected.
func TestValidate_WrongSignerName(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, func(qname string, qtype uint16, resp *dns.Msg) {
		if qname == "example.test." && qtype == dns.TypeA {
			// Replace RRSIG signer name with an attacker-controlled zone.
			for _, rr := range resp.Answer {
				if sig, ok := rr.(*dns.RRSIG); ok {
					sig.SignerName = "evil.test."
				}
			}
		}
	})
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	err := r.Validate(context.Background(), "example.test.")
	if err == nil {
		t.Fatal("Validate() should fail with wrong signer name")
	}
}

// TestValidate_FakeRootKey is a regression test for GO-2022-1026:
// a self-signed root key not matching any trust anchor must be rejected.
func TestValidate_FakeRootKey(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, nil)
	defer cleanup()

	// Use a different key as trust anchor — the real root key won't match.
	fakeAnchor := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	if _, err := fakeAnchor.Generate(256); err != nil {
		t.Fatalf("generating fake anchor: %v", err)
	}

	r := newTestResolver(t, addr, fakeAnchor)
	err := r.Validate(context.Background(), "example.test.")
	if err == nil {
		t.Fatal("Validate() should fail with fake root key")
	}
	var valErr *ErrValidation
	if !isErrValidation(err, &valErr) {
		t.Fatalf("expected *ErrValidation, got %T: %v", err, err)
	}
	if !strings.Contains(valErr.Reason, "trust anchor") {
		t.Errorf("error reason should mention trust anchor, got %q", valErr.Reason)
	}
}

func TestLookupHost_Success(t *testing.T) {
	h := newTestHierarchy(t)
	addr, cleanup := h.startServer(t, nil)
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	ips, err := r.LookupHost(context.Background(), "example.test.")
	if err != nil {
		t.Fatalf("LookupHost() = %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("LookupHost() returned no IPs")
	}
	found4, found6 := false, false
	for _, ip := range ips {
		if ip == "192.0.2.1" {
			found4 = true
		}
		if ip == "2001:db8::1" {
			found6 = true
		}
	}
	if !found4 {
		t.Error("expected 192.0.2.1 in results")
	}
	if !found6 {
		t.Error("expected 2001:db8::1 in results")
	}
}

func TestLookupHost_IPLiteral(t *testing.T) {
	r := &Resolver{}
	ips, err := r.LookupHost(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("LookupHost(IP) = %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Errorf("LookupHost(IP) = %v, want [192.0.2.1]", ips)
	}
}

func TestLookupHost_CNAME(t *testing.T) {
	h := newTestHierarchy(t)

	// Add a CNAME: alias.test. → example.test.
	cnameRR := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "example.test.",
	}

	// Generate keys for alias zone (we reuse TLD keys for simplicity, signing as test.)
	addr, cleanup := h.startServer(t, func(qname string, qtype uint16, resp *dns.Msg) {
		if qname == "alias.test." && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
			resp.Answer = []dns.RR{cnameRR}
			sig := signRRset(t, []dns.RR{cnameRR}, "test.", h.tld.zsk, h.tld.zskPriv)
			resp.Answer = append(resp.Answer, sig)
		}
		if qname == "alias.test." && qtype == dns.TypeDS {
			// No DS for alias — it's in the test. zone, signed by TLD.
			resp.Answer = nil
		}
	})
	defer cleanup()

	r := newTestResolver(t, addr, h.root.ksk)
	ips, err := r.LookupHost(context.Background(), "alias.test.")
	if err != nil {
		t.Fatalf("LookupHost(CNAME) = %v", err)
	}
	found := false
	for _, ip := range ips {
		if ip == "192.0.2.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 192.0.2.1 after CNAME following, got %v", ips)
	}
}

func TestValidate_MaxCNAMEExceeded(t *testing.T) {
	h := newTestHierarchy(t)

	// Create a CNAME loop: loop.test. → loop.test. (self-referencing).
	cnameRR := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "loop.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "loop.test.",
	}

	addr, cleanup := h.startServer(t, func(qname string, qtype uint16, resp *dns.Msg) {
		if qname == "loop.test." && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
			resp.Answer = []dns.RR{cnameRR}
			sig := signRRset(t, []dns.RR{cnameRR}, "test.", h.tld.zsk, h.tld.zskPriv)
			resp.Answer = append(resp.Answer, sig)
		}
	})
	defer cleanup()

	r, _ := NewFromServers([]string{addr}, 5*time.Second,
		WithTrustAnchors([]*dns.DNSKEY{h.root.ksk}),
		WithMaxCNAME(3),
	)
	err := r.Validate(context.Background(), "loop.test.")
	if err == nil {
		t.Fatal("Validate() should fail with CNAME loop")
	}
	if !strings.Contains(err.Error(), "too many CNAME hops") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNew_Constructors(t *testing.T) {
	t.Run("NewFromServers_empty", func(t *testing.T) {
		_, err := NewFromServers(nil, 5*time.Second)
		if err == nil {
			t.Error("expected error for empty servers")
		}
	})

	t.Run("NewFromServers_valid", func(t *testing.T) {
		r, err := NewFromServers([]string{"8.8.8.8:53"}, 5*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.Servers()) != 1 || r.Servers()[0] != "8.8.8.8:53" {
			t.Errorf("Servers() = %v, want [8.8.8.8:53]", r.Servers())
		}
	})

	t.Run("New_fallback", func(t *testing.T) {
		r, err := New(5 * time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(r.Servers()) == 0 {
			t.Error("expected at least one server")
		}
	})
}

func TestNetResolver(t *testing.T) {
	r, _ := NewFromServers([]string{"127.0.0.1:53"}, 5*time.Second)
	nr := r.NetResolver()
	if !nr.PreferGo {
		t.Error("NetResolver should prefer Go resolver")
	}
}

func TestWithMaxCNAME(t *testing.T) {
	r, _ := NewFromServers([]string{"127.0.0.1:53"}, 5*time.Second, WithMaxCNAME(42))
	if r.maxCNAME != 42 {
		t.Errorf("maxCNAME = %d, want 42", r.maxCNAME)
	}
}

// --- Live DNS tests ---

func TestLive_Validate(t *testing.T) {
	if os.Getenv("DNSSEC_LIVE_TEST") == "" {
		t.Skip("set DNSSEC_LIVE_TEST=1 to run live DNSSEC tests")
	}
	r, err := New(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"ietf.org", "internetsociety.org"} {
		t.Run(host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := r.Validate(ctx, host); err != nil {
				t.Errorf("Validate(%s) = %v", host, err)
			}
		})
	}
}

func TestLive_LookupHost(t *testing.T) {
	if os.Getenv("DNSSEC_LIVE_TEST") == "" {
		t.Skip("set DNSSEC_LIVE_TEST=1 to run live DNSSEC tests")
	}
	r, err := New(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, "ietf.org")
	if err != nil {
		t.Fatalf("LookupHost(ietf.org) = %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("no IPs returned")
	}
	t.Logf("ietf.org resolved to: %v", ips)
}

// isErrValidation is a helper that checks if err is *ErrValidation and
// assigns it to target.
func isErrValidation(err error, target **ErrValidation) bool {
	e, ok := err.(*ErrValidation)
	if ok {
		*target = e
	}
	return ok
}
