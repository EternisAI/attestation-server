# pkg/dnssec

Cryptographic DNSSEC chain-of-trust validation using the [miekg/dns](https://github.com/miekg/dns) library.

## What it does

Unlike resolvers that rely on the upstream resolver's AD (Authenticated Data) flag, this package validates RRSIG signatures locally at every delegation point from the queried zone up to the IANA root zone. It works with any upstream resolver — including non-validating ones — because it sets the CD (Checking Disabled) bit and performs all cryptographic checks itself.

The validation chain:

1. Query for the target record (A, AAAA, or CNAME)
2. Verify the answer's RRSIG against the zone's DNSKEY
3. Verify the zone's DNSKEY is self-signed by a KSK
4. Fetch DS records from the parent zone and verify them
5. Walk up the delegation chain repeating steps 2–4
6. At the root zone, verify the KSK matches an embedded IANA trust anchor

## Usage

### Validate a hostname (no resolution)

```go
r, err := dnssec.New(5 * time.Second)
err = r.Validate(ctx, "example.com")
// nil if DNSSEC chain is valid
```

### Resolve with DNSSEC validation

```go
r, err := dnssec.New(5 * time.Second)
ips, err := r.LookupHost(ctx, "example.com")
// returns A + AAAA records after validating the full chain
```

### Use with Go's standard library dialer

```go
r, _ := dnssec.New(5 * time.Second)
// Validate DNSSEC first
r.Validate(ctx, host)
// Then use the same upstream servers for resolution
dialer := &net.Dialer{Resolver: r.NetResolver()}
```

### Custom DNS servers

```go
r, err := dnssec.NewFromServers([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5*time.Second)
```

## Embedded trust anchors

Two IANA root zone KSKs are embedded:

| Key | Tag | Algorithm | Source |
|-----|-----|-----------|--------|
| KSK-2017 | 20326 | RSASHA256 | [IANA root-anchors.xml](https://data.iana.org/root-anchors/root-anchors.xml) |
| KSK-2024 | 38696 | RSASHA256 | [IANA root-anchors.xml](https://data.iana.org/root-anchors/root-anchors.xml) |

Root zone keys are compared by full key material (Flags, Protocol, Algorithm, PublicKey), not by key tag alone, since key tags are 16-bit and not collision-resistant.

## Security hardening

- **RRSIG owner name validation** — rejects signatures whose owner name doesn't match the query, preventing cross-zone signature injection
- **RRSIG signer name validation** — rejects signatures from unauthorized zones
- **Full key material comparison** — root zone keys are matched against trust anchors by actual key data, not key tag
- **CNAME loop protection** — configurable maximum CNAME hops (default 8)
- **UDP → TCP fallback** — automatically retries over TCP when UDP responses are truncated

## Options

```go
dnssec.WithTrustAnchors(keys)  // override root trust anchors (for testing)
dnssec.WithMaxCNAME(n)         // set max CNAME hops (default 8, 0 to disable)
```
