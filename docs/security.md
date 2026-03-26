# Security model

This document describes the security properties of the attestation server, the threats it mitigates, and the trust assumptions it makes.

## Trust assumptions

The server assumes:

1. **TEE hardware is genuine** — the TEE vendor's root certificate (AWS Nitro Root CA, AMD ASK/ARK, Intel SGX Root CA) is embedded in the binary and trusted unconditionally
2. **TEE firmware is not compromised** — the hardware attestation mechanism faithfully reports the actual measurements of the running code
3. **The immutable image is correctly built** — the CI/CD pipeline that produces the TEE image correctly computes golden measurements from the final image and accurately records build provenance; the image cannot be modified after build
4. **The co-located Envoy proxy is correctly configured** — Envoy is baked into the same immutable image, terminates TLS, and populates XFCC headers faithfully; it is part of the trusted computing base
5. **The CA that issues private certificates is trusted** — all services in the dependency chain present certificates issued by this CA, and Envoy verifies them before forwarding requests
6. **Sigstore public-good infrastructure is trustworthy** — Fulcio, Rekor, and the OIDC provider used for keyless signing correctly attest the identity of the CI/CD pipeline

## Immutable trusted computing base

The server is designed for deployment in immutable, hermetic TEE images where security-critical components cannot be modified at runtime:

| Component | Baked into image | Purpose |
|-----------|-----------------|---------|
| attestation-server binary | Yes | Produces attestation reports |
| Envoy binary + config | Yes | TLS termination, mTLS, XFCC headers |
| `/etc/build-info.json` | Yes | Build provenance (Fulcio OID fields) |
| `/etc/endorsements.json` | Yes | URLs of golden measurement documents |
| Workload binary | Yes | The actual service being attested |

There is no runtime configuration surface for these components. An attacker who gains code execution inside the TEE cannot modify the endorsement URLs to point to forged documents, because the URL list is embedded in the immutable image whose measurements are verified by the TEE hardware.

## End-to-end encryption proof

Every attestation response must include evidence that the request arrived over an encrypted channel. This is enforced by requiring at least one of:

- **`data.tls.client`** — SHA-256 fingerprint of the client certificate (leaf DER), extracted from Envoy's XFCC header. This proves the request traversed an mTLS connection within the dependency chain.
- **`data.tls.public`** — SHA-256 fingerprint of the server's public TLS certificate (leaf DER). This covers external clients who connect without a client certificate (Internet ingress).

If neither is present, the handler returns 400. This prevents attestation responses from being generated on unencrypted channels.

### Private key confinement

Private TLS key material is loaded inside the TEE and never leaves it. The certificate fingerprints bound into the hardware-signed attestation evidence prove that the TLS channel terminates inside a specific TEE instance with verified measurements. A verifier can confirm that the encryption key is held by code that matches the endorsed golden measurements.

### Dependency e2e verification

After cryptographically verifying a dependency's attestation report, the server performs two certificate fingerprint checks:

1. **Client cert (XFCC)**: `data.tls.client` in the dependency's response must match the SHA-256 fingerprint of the private certificate that was presented as the TLS client cert when connecting. This confirms the dependency saw our specific client certificate (not a proxy's).
2. **Server cert** (HTTPS only): when the dependency was reached over HTTPS, the server's TLS leaf certificate fingerprint observed during the handshake must match the dependency's `data.tls.private`. This binds the attestation report to the actual TLS peer, catching relay proxies that hold a valid CA-signed cert but are not the TEE. This check is independent of Envoy's XFCC forwarding policy. Skipped for plain HTTP endpoints (transparent proxy configurations where Envoy terminates TLS on the loopback interface).

Together these confirm:

- The dependency saw our specific client certificate (not a proxy's)
- The connection was encrypted end-to-end between the two TEEs
- The attestation report was produced by the server that terminated our TLS connection, not relayed through an intermediary

If either fingerprint is missing or mismatched, a descriptive error is logged but an opaque error is returned to the caller (preventing information leakage about the internal certificate infrastructure).

### XFCC header validation

The server rejects requests with multiple comma-separated XFCC entries (HTTP 400). Multiple entries indicate proxy intermediaries in the TLS path, which breaks the direct end-to-end encryption guarantee. The design assumes a single forwarded client certificate entry per request — each hop in the dependency chain is a direct mTLS connection between TEEs, not a multi-hop proxy chain.

## Nonce binding

All server metadata is bound to the attestation evidence through a cryptographic hash chain:

```
report_data = { timestamp, request_id, nonce, build_info, tls, endorsements, user_data, secure_boot, tpm }
digest      = SHA-512(JSON(report_data))
evidence    = TEE_Attest(digest)
```

The `report_data` is marshaled with `json.DisableHTMLEscape()` and included as the `data` field in the response using `json.RawMessage` to guarantee byte-for-byte consistency. A verifier recomputes `SHA-512(compact(data))` and checks it against the nonce/report_data inside the evidence blob.

This binding ensures:

- **Freshness** — the caller's nonce is embedded in `data.nonce`, which feeds into the digest
- **Integrity** — any modification to the metadata changes the digest, which no longer matches the hardware-signed evidence
- **Non-replayability** — evidence from one request cannot be combined with metadata from another

## Endorsement validation

Endorsement documents contain golden measurement values (PCR digests, launch measurements) that are computed from the final immutable TEE image by the CI/CD pipeline. The server validates its own TEE evidence against these measurements.

### Multi-provider redundancy

Endorsement documents are uploaded to multiple public object storage buckets at different infrastructure providers. The server fetches from all configured URLs and requires byte-for-byte identity (SHA-256 comparison) across all copies. This mitigates:

- **Single-provider credential exposure** — if credentials for one storage provider are compromised, the attacker cannot serve forged endorsements because they won't match copies at other providers
- **Provider-side compromise** — a single compromised or coerced provider cannot unilaterally tamper with endorsement documents
- **CDN cache poisoning** — a poisoned cache at one provider is detected by comparison with other providers

When `endorsements.dnssec` is enabled, DNSSEC chain-of-trust validation adds another layer: even if an attacker compromises a provider's DNS infrastructure to redirect endorsement fetches, the forged DNS responses will fail RRSIG signature verification against the IANA root trust anchors. See [DNSSEC validation](#dnssec-validation) below.

### Startup validation

During `NewServer()`, after self-attestation captures parsed evidence results:

1. Endorsement documents are fetched from all configured URLs in parallel with retry
2. All documents are verified to be byte-for-byte identical (SHA-256 comparison)
3. Each configured evidence type is validated against the golden measurements
4. The server exits on any failure — it never starts with unverified evidence

### Per-request revalidation

Before collecting evidence for each request, the handler calls `validateOwnEndorsements`:

- **Cache hit** — pointer comparison against the cached document (sub-microsecond)
- **Cache miss** (TTL expired) — documents are re-fetched and revalidated
- **Failure** — handler returns 500, but the server stays up and self-heals when endorsements become available

### Skip validation mode

When `endorsements.skip_validation` is enabled (default `false`), endorsement *retrieval* failures are logged as warnings instead of causing errors. This is intended for disaster recovery when the endorsement serving infrastructure is completely unavailable but service operations must be restored. The server logs a startup warning that security is weakened.

**Only retrieval failures are skipped.** If endorsement documents are successfully fetched, measurement comparison is always performed — a mismatch between the endorsed golden values and the actual TEE evidence is a hard error regardless of this flag. This ensures that a TEE running modified code cannot pass attestation when endorsements are available.

The skip boundary is the `resolveEndorsements` call inside `validateOwnEndorsements` and `validateDependencyEndorsements`. Errors from endorsement document fetching, cosign signature fetching, or cosign bundle verification are treated as retrieval failures (skippable). Errors from cosign OID validation and measurement comparison are never skipped.

### Endorsement domain allowlist

When `endorsements.allowed_domains` is configured (non-empty), endorsement document URLs are checked against the allowlist before fetching. Matching is exact hostname (case-insensitive) — subdomain matching is not supported; each host must be listed explicitly. The check applies to both own endorsement URLs and dependency endorsement URLs.

An empty allowlist logs a startup warning because dependency attestation reports can contain attacker-controlled endorsement URLs — a compromised dependency could point to a malicious server, and the domain allowlist is the first defense against this (cosign verification is the second).

### Empty value rejection

The comparison functions reject empty endorsement values as a defense-in-depth measure. `hex.DecodeString("")` silently returns an empty byte slice, which could match an empty actual value via `bytes.Equal`. Each comparison function explicitly rejects empty hex strings before decoding.

For TDX, individual endorsement fields (MRTD, RTMR0–2) are optional, but at least one must be non-empty — an endorsement with all fields empty would accept any TDX quote.

## Cosign signature verification

When `endorsements.cosign.verify` is enabled (default), the server verifies that endorsement documents were signed by the same CI/CD pipeline that built the TEE image. This uses Sigstore's public-good infrastructure with OIDC-based keyless signing — there are no long-lived signing keys to manage, rotate, or protect.

The verification flow:

1. A cosign signature bundle (produced by `cosign sign-blob --bundle`) is fetched from `<endorsement_url><suffix>` (default suffix: `.sig`)
2. The bundle is verified against the Sigstore public-good infrastructure:
   - Fulcio certificate chain validation (short-lived cert issued via OIDC)
   - Rekor transparency log inclusion proof (online check)
   - Signed Certificate Timestamp validation
3. Fulcio OID extensions are extracted from the signing certificate and compared field-by-field against the server's `BuildInfo`:
   - Most fields: exact match (source repo, commit, builder identity, etc.)
   - `BuildSignerURI`: configurable override via exact string or regex (for CI workflow version pinning)
   - `BuildSignerDigest`: skipped when a `BuildSignerURI` override is configured (digest changes per-commit)
   - `DeploymentEnvironment`: not checked (no standard Fulcio OID)

The `WithoutIdentitiesUnsafe()` option is used during Sigstore verification because the server performs its own strict OID-by-OID validation afterward, which is more thorough than Sigstore's identity matching.

### Dependency cosign validation

When cosign verification is enabled, dependency attestation reports are required to include non-empty endorsement URL lists. The same cosign verification is applied to dependency endorsements, with OIDs validated against the dependency's `BuildInfo` from its attestation report. This ensures every service in the dependency chain has endorsements traceable to its own CI/CD pipeline.

## DNSSEC validation

DNSSEC chain-of-trust validation provides defense-in-depth for the endorsement fetch infrastructure. While multi-provider redundancy and cosign signatures already protect against content tampering, DNSSEC closes the DNS layer: it prevents an attacker who has compromised a provider's DNS infrastructure (or the network path to it) from redirecting endorsement fetches to an attacker-controlled server before the HTTPS connection is even established.

When `endorsements.dnssec` is enabled, endorsement URL hosts are validated via cryptographic DNSSEC chain-of-trust verification before fetching. The resolver:

1. Sets the CD (Checking Disabled) bit to get raw RRSIG records from any upstream resolver
2. Fetches DNSKEY and DS records at each delegation point
3. Verifies RRSIG signatures up the delegation chain to the root zone
4. Validates the root zone DNSKEY against embedded IANA trust anchors (KSK-2017 tag 20326, KSK-2024 tag 38696)

This prevents DNS spoofing attacks that could redirect endorsement fetches to attacker-controlled servers. The validation is performed locally and does not rely on the upstream resolver's AD (Authenticated Data) flag.

### RRSIG validation hardening

The DNSSEC resolver validates RRSIG owner names and signer names against expected values before accepting signatures. This prevents cross-zone signature injection (where an attacker who controls a sibling zone injects signatures that would pass cryptographic verification) and is enforced independently of the upstream resolver.

Root zone DNSKEY records are compared by full key material (Flags, Protocol, Algorithm, PublicKey) rather than key tag alone. Key tags are 16-bit values that are not collision-resistant, so an attacker could craft a self-signed key with a matching tag.

## Dependency cycle detection

The `X-Attestation-Path` header prevents infinite loops in the dependency chain. Each server computes a deterministic identity from `SHA-256(build_info || cert_subject || cert_SANs)` and appends it to the path before forwarding to dependencies. If a server finds its own identity already in the path, it returns 409 Conflict.

The identity is deterministic so that replicas of the same service produce the same ID — cycles are detected between services, not individual processes. SANs are included in the identity because SPIFFE SVIDs may have empty subjects and carry the service identity in a URI SAN instead.

## HTTP client hardening

Both the dependency client and endorsement/cosign fetch client are hardened against denial-of-service:

| Property | Dependency client | Endorsement client |
|----------|------------------|--------------------|
| Dial timeout | 5s | 3s |
| TLS handshake timeout | 10s | 5s |
| Response header timeout | 15s | 5s |
| Overall timeout | 30s | Configurable (default 10s) |
| Body limit | 4 MiB | 1 MiB |
| Keep-alives | Disabled | Disabled |

Keep-alives are disabled on both clients. For dependencies, this ensures every request gets a fresh TLS handshake so certificate rotation is respected. For endorsements, it avoids tying up sockets across the TTL-driven refetch interval.

Endorsement and cosign signature fetches use exponential backoff retry until the context deadline. Each failed attempt is logged at WARN level with the URL, attempt number, and specific error (DNS failure, TLS handshake error, HTTP status code, etc.) so that the root cause is visible even when the final error is "context deadline exceeded".

The dependency client enforces TLS 1.3 minimum for service-to-service mTLS. The endorsement client uses TLS 1.2 minimum since public CDNs may not yet support TLS 1.3.

## Rate limiting

The server supports optional per-IP rate limiting for edge requests (those without an XFCC header, indicating no client certificate). Service-to-service mTLS traffic is never rate-limited.

Over-limit requests are stalled (blocked) up to a configurable timeout before receiving HTTP 429 with a `Retry-After` header. This avoids immediately rejecting burst traffic while bounding resource consumption. Per-IP rate limiter entries are cleaned up automatically when idle.

## Certificate revocation checking

Background CRL fetching checks TEE endorsement key certificates against revocation lists:

- **SEV-SNP**: CRLs are fetched from AMD KDS (`kdsintf.amd.com`) for all supported product lines (Milan, Genoa, Turin), covering both VCEK and VLEK signing keys. The cache is refreshed on a configurable interval (default 12h). Design is fail-open: if no CRL data is available yet, certificates are accepted.
- **TDX**: Revocation checking is delegated to go-tdx-guest's built-in Intel PCS collateral fetching, which runs per-request when enabled.
- **Nitro**: No CRL mechanism exists (ephemeral certificate chains).

## Error information leakage

The server distinguishes between internal and external error messages:

- **E2E encryption failures** (missing/mismatched client certificate): a descriptive message is logged for debugging, but an opaque error is returned to the caller
- **Dependency URLs**: not included in error responses to callers
- **Upstream error classification**: timeout errors map to 504, transport errors (connection refused, reset, DNS) to 503, everything else (including TLS certificate verification failures) to 500 — without exposing internal details
- **5xx responses**: handler-controlled error messages (from `fiber.NewError`) are preserved — these are opaque by design (e.g. `"attestation failed"`, `"dependency attestation failed"`). Unhandled errors (plain `error` values) fall back to `"internal error"`. The real error is logged at ERROR level with request_id for debugging. 4xx errors preserve their message since they describe client-fixable problems

## Build info integrity

The `/etc/build-info.json` file integrity is assumed to be protected by the TEE's measured boot chain — the filesystem hash is included in launch measurements (SEV-SNP measurement, TDX MRTD, Nitro PCRs). An attacker who can modify this file has already achieved a TEE breakout, which is a higher-order compromise that invalidates all attestation guarantees.

## TLS private key memory

TLS private keys are held in Go process memory without `mlock`. In a TEE context, encrypted memory (SEV-SNP, TDX) protects against physical and hypervisor-level access. This is inherent to Go's `crypto/tls` implementation and applies to all Go TLS servers.
