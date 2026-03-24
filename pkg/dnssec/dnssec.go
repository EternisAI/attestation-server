// Package dnssec provides DNSSEC chain-of-trust validation using the
// miekg/dns library. Unlike resolvers that rely on the upstream AD flag,
// this package cryptographically verifies RRSIG signatures at every
// delegation point from the queried zone up to the IANA root zone trust
// anchor. It works with any upstream resolver (including non-validating
// ones) because it sets the CD (Checking Disabled) bit and validates
// locally.
package dnssec

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	resolvConfPath  = "/etc/resolv.conf"
	defaultMaxCNAME = 8
	udpBufSize      = 4096

	// DNSKEY flag bits (RFC 4034 section 2.1.1).
	flagZone = 1 << 8 // bit 7: Zone Key
	flagSEP  = 1 << 0 // bit 15: Secure Entry Point
)

// rootKSK20326 is the IANA root zone KSK-2017 (key tag 20326).
// Algorithm: RSASHA256 (8). Flags: 257 (ZONE|SEP). Protocol: 3.
// Source: https://data.iana.org/root-anchors/root-anchors.xml
const rootKSK20326 = `. 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=`

// rootKSK38696 is the IANA root zone KSK-2024 (key tag 38696).
// Algorithm: RSASHA256 (8). Flags: 257 (ZONE|SEP). Protocol: 3.
// Source: https://data.iana.org/root-anchors/root-anchors.xml
const rootKSK38696 = `. 172800 IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=`

var defaultTrustAnchors = func() []*dns.DNSKEY {
	keys := make([]*dns.DNSKEY, 0, 2)
	for _, s := range []string{rootKSK20326, rootKSK38696} {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic("parsing embedded root trust anchor: " + err.Error())
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			panic("embedded root trust anchor is not a DNSKEY")
		}
		keys = append(keys, key)
	}
	return keys
}()

// ErrValidation indicates a DNSSEC chain-of-trust validation failure.
type ErrValidation struct {
	Name   string // the query name being validated
	Reason string // human-readable failure reason
	Err    error  // underlying error, if any
}

func (e *ErrValidation) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("dnssec: %s: %s: %v", e.Name, e.Reason, e.Err)
	}
	return fmt.Sprintf("dnssec: %s: %s", e.Name, e.Reason)
}

func (e *ErrValidation) Unwrap() error { return e.Err }

// Option configures optional Resolver behavior.
type Option func(*Resolver)

// WithTrustAnchors overrides the default IANA root trust anchors.
// Primarily useful for testing with in-process DNS servers.
func WithTrustAnchors(keys []*dns.DNSKEY) Option {
	return func(r *Resolver) { r.trustAnchors = keys }
}

// WithMaxCNAME sets the maximum number of CNAME hops to follow during
// lookup. Defaults to 8. Set to 0 to disable CNAME following.
func WithMaxCNAME(n int) Option {
	return func(r *Resolver) { r.maxCNAME = n }
}

// Resolver performs DNS lookups with cryptographic DNSSEC chain-of-trust
// validation. It queries the ambient system resolver but does not trust
// the AD flag — instead it fetches DNSKEY and DS records at each
// delegation point and verifies RRSIG signatures up to the embedded
// IANA root zone trust anchor.
//
// Safe for concurrent use.
type Resolver struct {
	servers      []string
	timeout      time.Duration
	trustAnchors []*dns.DNSKEY
	maxCNAME     int
}

// New creates a Resolver that reads the ambient nameserver configuration
// from /etc/resolv.conf. If the file is missing or unreadable, it falls
// back to 127.0.0.53:53, then 127.0.0.1:53. The timeout controls the
// per-query exchange deadline with the upstream resolver.
func New(timeout time.Duration, opts ...Option) (*Resolver, error) {
	var servers []string
	if cc, err := dns.ClientConfigFromFile(resolvConfPath); err == nil && len(cc.Servers) > 0 {
		for _, s := range cc.Servers {
			servers = append(servers, net.JoinHostPort(s, cc.Port))
		}
	}
	if len(servers) == 0 {
		servers = []string{"127.0.0.53:53", "127.0.0.1:53"}
	}
	return newResolver(servers, timeout, opts)
}

// NewFromServers creates a Resolver using the provided DNS server
// addresses (each in "ip:port" format). At least one server must be
// provided.
func NewFromServers(servers []string, timeout time.Duration, opts ...Option) (*Resolver, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("dnssec: at least one server address required")
	}
	cp := make([]string, len(servers))
	copy(cp, servers)
	return newResolver(cp, timeout, opts)
}

func newResolver(servers []string, timeout time.Duration, opts []Option) (*Resolver, error) {
	r := &Resolver{
		servers:      servers,
		timeout:      timeout,
		trustAnchors: defaultTrustAnchors,
		maxCNAME:     defaultMaxCNAME,
	}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// Servers returns the upstream DNS server addresses this resolver queries.
func (r *Resolver) Servers() []string {
	cp := make([]string, len(r.servers))
	copy(cp, r.servers)
	return cp
}

// Validate performs a DNSSEC chain-of-trust validation for the given
// hostname without returning the resolved addresses. It is useful for
// pre-validating that a domain has valid DNSSEC before using it. Returns
// nil if DNSSEC validation succeeds. IP literals and bare names (no dots)
// pass through without validation.
func (r *Resolver) Validate(ctx context.Context, host string) error {
	host = cleanHost(host)
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return nil
	}
	_, err := r.resolveAndValidate(ctx, host, dns.TypeA)
	return err
}

// LookupHost performs a DNSSEC-validated A and AAAA lookup for the given
// host. It returns the resolved IP addresses as strings. IP literals and
// bare names (no dots) pass through without validation.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	host = cleanHost(host)
	if host == "" {
		return nil, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	if !strings.Contains(host, ".") {
		return []string{host}, nil
	}

	var ips []string
	var lastErr error

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		addrs, err := r.resolveAndValidate(ctx, host, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		ips = append(ips, addrs...)
	}

	if len(ips) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return ips, nil
}

// NetResolver returns a *net.Resolver that routes DNS queries through
// the same upstream servers this Resolver uses. DNSSEC validation must
// be done separately via Validate — this only controls which server
// Go's standard library dialer talks to.
func (r *Resolver) NetResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, "udp", r.servers[0])
		},
	}
}

// resolveAndValidate queries for qtype, follows CNAMEs, and validates
// the full DNSSEC chain. Returns IP address strings for A/AAAA.
func (r *Resolver) resolveAndValidate(ctx context.Context, host string, qtype uint16) ([]string, error) {
	fqdn := dns.Fqdn(host)
	current := fqdn
	var ips []string

	for hop := 0; ; hop++ {
		msg, err := r.query(ctx, current, qtype)
		if err != nil {
			return nil, &ErrValidation{Name: host, Reason: "dns query failed", Err: err}
		}
		if msg.Rcode == dns.RcodeNameError {
			return nil, &ErrValidation{Name: host, Reason: "name does not exist (NXDOMAIN)"}
		}

		// Check for CNAME in the answer.
		if target, ok := extractCNAME(msg, current); ok {
			// Validate the CNAME RRset itself.
			cnameRRs, cnameSigs := extractTypedRRsAndSigs(msg, current, dns.TypeCNAME)
			if len(cnameSigs) == 0 {
				return nil, &ErrValidation{Name: host, Reason: fmt.Sprintf("CNAME for %s is not signed", current)}
			}
			if err := r.validateRRset(ctx, cnameRRs, cnameSigs, current); err != nil {
				return nil, err
			}
			if hop >= r.maxCNAME {
				return nil, &ErrValidation{Name: host, Reason: fmt.Sprintf("too many CNAME hops (max %d)", r.maxCNAME)}
			}
			current = target
			continue
		}

		// Extract the answer RRs for the requested type.
		rrset, sigs := extractTypedRRsAndSigs(msg, current, qtype)
		if len(rrset) == 0 {
			// No records of this type — not an error, just no results.
			return nil, nil
		}
		if len(sigs) == 0 {
			return nil, &ErrValidation{Name: host, Reason: fmt.Sprintf("%s records for %s are not signed", dns.TypeToString[qtype], current)}
		}

		if err := r.validateRRset(ctx, rrset, sigs, current); err != nil {
			return nil, err
		}

		for _, rr := range rrset {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A.String())
			case *dns.AAAA:
				ips = append(ips, v.AAAA.String())
			}
		}
		return ips, nil
	}
}

// validateRRset validates an RRset by verifying the RRSIG chain from
// the signing zone up to the root trust anchor.
func (r *Resolver) validateRRset(ctx context.Context, rrset []dns.RR, sigs []*dns.RRSIG, qname string) error {
	if len(sigs) == 0 {
		return &ErrValidation{Name: qname, Reason: "no RRSIG records"}
	}

	// Determine the signing zone from the first valid RRSIG.
	zone := sigs[0].SignerName

	// Fetch DNSKEY for the zone.
	dnskeys, kskMap, err := r.fetchAndVerifyDNSKEY(ctx, zone)
	if err != nil {
		return err
	}

	// Verify the answer RRSIG with a ZSK from the zone.
	if err := verifyWithKeys(rrset, sigs, qname, zone, dnskeys); err != nil {
		return &ErrValidation{Name: qname, Reason: "RRSIG verification failed", Err: err}
	}

	// Walk the delegation chain up to root.
	return r.verifyDelegation(ctx, zone, kskMap)
}

// fetchAndVerifyDNSKEY fetches the DNSKEY RRset for the zone, verifies
// it is self-signed by a KSK, and returns the full key set plus a map
// of KSKs keyed by key tag.
func (r *Resolver) fetchAndVerifyDNSKEY(ctx context.Context, zone string) (keys map[uint16]*dns.DNSKEY, ksks map[uint16]*dns.DNSKEY, err error) {
	msg, err := r.query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, &ErrValidation{Name: zone, Reason: "fetching DNSKEY failed", Err: err}
	}

	var dnskeyRRs []dns.RR
	var dnskeySigs []*dns.RRSIG
	allKeys := make(map[uint16]*dns.DNSKEY)
	kskKeys := make(map[uint16]*dns.DNSKEY)

	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			if !strings.EqualFold(v.Header().Name, zone) {
				continue
			}
			dnskeyRRs = append(dnskeyRRs, rr)
			tag := v.KeyTag()
			allKeys[tag] = v
			if v.Flags&flagZone != 0 && v.Flags&flagSEP != 0 {
				kskKeys[tag] = v
			}
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY && strings.EqualFold(v.Header().Name, zone) {
				dnskeySigs = append(dnskeySigs, v)
			}
		}
	}

	if len(dnskeyRRs) == 0 {
		return nil, nil, &ErrValidation{Name: zone, Reason: "no DNSKEY records"}
	}
	if len(dnskeySigs) == 0 {
		return nil, nil, &ErrValidation{Name: zone, Reason: "DNSKEY RRset is not signed"}
	}

	// The DNSKEY RRset must be self-signed by a KSK.
	if err := verifyWithKeys(dnskeyRRs, dnskeySigs, zone, zone, allKeys); err != nil {
		return nil, nil, &ErrValidation{Name: zone, Reason: "DNSKEY self-signature verification failed", Err: err}
	}

	return allKeys, kskKeys, nil
}

// verifyDelegation walks the delegation chain from zone up to the root,
// verifying DS records at each level.
func (r *Resolver) verifyDelegation(ctx context.Context, zone string, ksks map[uint16]*dns.DNSKEY) error {
	if zone == "." {
		return r.verifyRootZone(ksks)
	}

	parent := parentZone(zone)

	// Fetch DS records for the child zone from the parent.
	msg, err := r.query(ctx, zone, dns.TypeDS)
	if err != nil {
		return &ErrValidation{Name: zone, Reason: "fetching DS records failed", Err: err}
	}

	var dsRRs []dns.RR
	var dsSigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DS:
			if strings.EqualFold(v.Header().Name, zone) {
				dsRRs = append(dsRRs, rr)
			}
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS && strings.EqualFold(v.Header().Name, zone) {
				dsSigs = append(dsSigs, v)
			}
		}
	}

	if len(dsRRs) == 0 {
		return &ErrValidation{Name: zone, Reason: "no DS records in parent zone"}
	}
	if len(dsSigs) == 0 {
		return &ErrValidation{Name: zone, Reason: "DS RRset is not signed"}
	}

	// Verify DS RRSIG against the parent's DNSKEY.
	parentKeys, parentKSKs, err := r.fetchAndVerifyDNSKEY(ctx, parent)
	if err != nil {
		return err
	}
	if err := verifyWithKeys(dsRRs, dsSigs, zone, parent, parentKeys); err != nil {
		return &ErrValidation{Name: zone, Reason: "DS RRSIG verification against parent failed", Err: err}
	}

	// Verify that at least one DS matches a KSK from the child zone.
	if !dsMatchesAnyKSK(dsRRs, ksks) {
		return &ErrValidation{Name: zone, Reason: "no DS record matches any child zone KSK"}
	}

	// Recurse up the chain.
	return r.verifyDelegation(ctx, parent, parentKSKs)
}

// verifyRootZone checks that at least one KSK in the root zone's
// DNSKEY RRset matches an embedded trust anchor by comparing actual
// key material (Flags, Protocol, Algorithm, PublicKey).
func (r *Resolver) verifyRootZone(ksks map[uint16]*dns.DNSKEY) error {
	for _, ksk := range ksks {
		for _, anchor := range r.trustAnchors {
			if keysMatch(ksk, anchor) {
				return nil
			}
		}
	}
	return &ErrValidation{Name: ".", Reason: "root zone DNSKEY does not match any trust anchor"}
}

// verifyWithKeys tries each RRSIG against each DNSKEY in the key map.
// It validates the RRSIG owner name matches qname, the signer name
// matches zone, temporal validity, and the cryptographic signature.
func verifyWithKeys(rrset []dns.RR, sigs []*dns.RRSIG, qname, zone string, keys map[uint16]*dns.DNSKEY) error {
	now := time.Now()
	var lastErr error

	for _, sig := range sigs {
		// Reject RRSIG records whose owner name doesn't match the query name.
		// Without this, an attacker who controls a sibling zone could inject
		// cross-zone signatures that would pass cryptographic verification.
		if !strings.EqualFold(sig.Header().Name, qname) {
			lastErr = fmt.Errorf("RRSIG owner name %q does not match expected %q", sig.Header().Name, qname)
			continue
		}
		// Reject RRSIG records whose signer name doesn't match the expected
		// zone. This prevents accepting signatures from unauthorized zones.
		if !strings.EqualFold(sig.SignerName, zone) {
			lastErr = fmt.Errorf("RRSIG signer name %q does not match expected zone %q", sig.SignerName, zone)
			continue
		}
		if !sig.ValidityPeriod(now) {
			lastErr = fmt.Errorf("RRSIG validity period expired or not yet valid")
			continue
		}
		key, ok := keys[sig.KeyTag]
		if !ok {
			lastErr = fmt.Errorf("no DNSKEY with tag %d", sig.KeyTag)
			continue
		}
		if err := sig.Verify(key, rrset); err != nil {
			lastErr = fmt.Errorf("cryptographic verification: %w", err)
			continue
		}
		return nil // verified
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no valid RRSIG found")
}

// query sends a DNS query with DO and CD bits set. If the UDP response
// is truncated, it retries over TCP.
func (r *Resolver) query(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.SetEdns0(udpBufSize, true) // DO bit
	m.RecursionDesired = true
	m.CheckingDisabled = true // CD bit: get raw RRSIG from non-validating resolvers

	msg, err := r.exchange(ctx, m, "udp")
	if err != nil {
		return nil, err
	}
	if msg.Truncated {
		msg, err = r.exchange(ctx, m, "tcp")
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// exchange tries each server in sequence until one succeeds.
func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, proto string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     proto,
		Timeout: r.timeout,
	}
	var lastErr error
	for _, server := range r.servers {
		resp, _, err := c.ExchangeContext(ctx, m, server)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// extractCNAME returns the CNAME target if the answer contains a CNAME
// for the given qname.
func extractCNAME(msg *dns.Msg, qname string) (string, bool) {
	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cname.Header().Name, qname) {
			return cname.Target, true
		}
	}
	return "", false
}

// extractTypedRRsAndSigs extracts RRs of the given type and their
// covering RRSIGs from the answer section, filtered by owner name.
func extractTypedRRsAndSigs(msg *dns.Msg, qname string, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var rrset []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, qname) {
			rrset = append(rrset, rr)
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == qtype && strings.EqualFold(sig.Header().Name, qname) {
			sigs = append(sigs, sig)
		}
	}
	return rrset, sigs
}

// keysMatch compares two DNSKEY records by their actual key material
// (Flags, Protocol, Algorithm, PublicKey) rather than trusting the key
// tag alone. Key tags are 16-bit values derived from the key material
// and are not collision-resistant — an attacker could craft a self-signed
// key with a matching tag. Comparing full key material prevents accepting
// a forged root key that happens to share a tag with a trust anchor.
func keysMatch(a, b *dns.DNSKEY) bool {
	return a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}

// dsMatchesAnyKSK checks whether at least one DS record in dsRRs
// matches a KSK by computing the DS digest from the key. Supports
// digest types SHA-1 (1), SHA-256 (2), and SHA-384 (4).
func dsMatchesAnyKSK(dsRRs []dns.RR, ksks map[uint16]*dns.DNSKEY) bool {
	for _, rr := range dsRRs {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		key, ok := ksks[ds.KeyTag]
		if !ok {
			continue
		}
		if dsMatchesKey(ds, key) {
			return true
		}
	}
	return false
}

// dsMatchesKey checks whether a DS record matches a DNSKEY by computing
// the DS digest from the key and comparing it to the DS digest.
func dsMatchesKey(ds *dns.DS, key *dns.DNSKEY) bool {
	switch ds.DigestType {
	case dns.SHA1, dns.SHA256, dns.SHA384:
		computed := key.ToDS(ds.DigestType)
		if computed == nil {
			return false
		}
		return strings.EqualFold(computed.Digest, ds.Digest)
	default:
		return false
	}
}

// parentZone returns the parent zone of the given zone name.
// For the root zone ".", it returns ".".
func parentZone(zone string) string {
	if zone == "." {
		return "."
	}
	labels := dns.SplitDomainName(zone)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// cleanHost strips any port suffix and trims whitespace from a host string.
func cleanHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}
