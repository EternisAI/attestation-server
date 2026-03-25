# Architecture

## Immutable TEE images

The attestation server is designed to run inside immutable, hermetic images prepared for TEE workloads. A typical image contains:

- The workload binary
- The attestation server binary
- An Envoy proxy binary with baked-in configuration
- `/etc/build-info.json` — build provenance metadata (Fulcio OID fields)
- `/etc/endorsements.json` — a JSON array of HTTPS URLs pointing to endorsement documents

All of these are assembled by the CI/CD pipeline and are immutable at runtime. There is no mechanism to modify the build provenance, endorsement URLs, or Envoy configuration after the image is built — they are part of the trusted computing base.

## Envoy proxy as part of the TCB

The co-located Envoy proxy is baked into the same immutable image and is considered part of the trusted computing base. It provides:

**Inbound TLS termination:**
- Public listener — terminates TLS using the public certificate for Internet-facing ingress. No client certificate required.
- Private listener — terminates mTLS using the private certificate. Verifies the client certificate against the configured CA and populates the `x-forwarded-client-cert` (XFCC) header with the client certificate's SHA-256 hash.

**Outbound TLS origination:**
- For dependency connections, the attestation server connects to Envoy over plaintext HTTP on the loopback interface. Envoy wraps the connection in mTLS toward the upstream TEE, presenting the private certificate as the client cert. This allows the attestation server to use a simple HTTP client while Envoy handles the mTLS complexity.

```
┌──────────────────────────────────────────────────────────────┐
│                        TEE Instance                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Envoy (immutable config, baked into image)            │  │
│  │                                                        │  │
│  │  Inbound:                                              │  │
│  │    :443  (public TLS)   ──► :8187 (attestation-server) │  │
│  │    :8443 (private mTLS) ──► :8187 + XFCC header        │  │
│  │                                                        │  │
│  │  Outbound:                                             │  │
│  │    attestation-server ──► :15001 (Envoy egress)        │  │
│  │    Envoy ──► upstream TEE (mTLS)                       │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────────────────┐  ┌────────────────────────────┐     │
│  │ attestation-server  │  │ TEE Hardware               │     │
│  │ :8187 (HTTP)        │──│ /dev/nsm, /dev/tpm0        │     │
│  │                     │  │ /dev/sev-guest, configfs   │     │
│  └─────────────────────┘  └────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

## Deployment topology

### Edge + internal layering

A typical deployment has two tiers:

**Edge TEEs** face the public Internet. They serve attestation reports to external consumers via the public TLS listener. They configure `dependencies.endpoints` pointing to internal TEEs, so their responses include a full transitive attestation tree covering the entire service graph.

**Internal TEEs** communicate exclusively via private mTLS. They may have their own downstream dependencies (forming a DAG), and they provide attestation reports to edge TEEs to prove the integrity of the internal service mesh.

```
                          ┌────────────────┐
  External client ───────►│  Edge TEE (A)  │
  (public TLS,            │  public cert   │
   no client cert)        └───┬────────┬───┘
                              │        │
                    private mTLS    private mTLS
                              │        │
                    ┌─────────▼──┐  ┌──▼─────────┐
                    │ Internal   │  │ Internal   │
                    │ TEE (B)    │  │ TEE (C)    │
                    └─────┬──────┘  └──────┬─────┘
                          │                │
                    private mTLS    private mTLS
                          │                │
                          └───────┬────────┘
                            ┌─────▼──────┐
                            │ Internal   │
                            │ TEE (D)    │  ◄── diamond dependency (B→D, C→D)
                            └────────────┘
```

The attestation response from Edge TEE (A) embeds verified reports from B and C, which in turn embed verified reports from D. A verifier checking A's response gets cryptographic proof of the entire graph.

## TLS certificate design

### Public certificate

- **Key types**: ECDSA or RSA (RSA allowed for Internet compatibility)
- **Purpose**: Proves server identity to external clients who connect without client certificates
- **In attestation**: Included as `data.tls.public.certificate` (SHA-256 fingerprint of the leaf DER) and `data.tls.public.public_key` (SHA-256 of the SPKI DER)

### Private certificate

- **Key type**: ECDSA only (performance, consistency with TEE evidence signatures)
- **Purpose**: Service-to-service mTLS within the dependency chain
- **CA requirement**: All private certificates in the dependency chain must be issued by the same CA — Envoy only populates the XFCC header when the client cert passes CA verification
- **Key confinement**: Private key material is loaded inside the TEE and never leaves it. The certificate fingerprints bound into the attestation evidence prove that the TLS channel terminates inside a specific TEE instance.
- **In attestation**: Included as `data.tls.private.certificate` and `data.tls.private.public_key`
- **Client cert**: When a request arrives via the private listener, Envoy's XFCC header provides the caller's client certificate hash, included as `data.tls.client.certificate`

### SPIFFE readiness

The current design ingests private certificates as opaque PEM files and does not prescribe how they are issued. However, it is designed to support a SPIFFE-based implementation where SVIDs (SPIFFE Verifiable Identity Documents) are issued based on TEE attestation documents and endorsed golden measurements. The instance identity computation already incorporates certificate SANs — where SPIFFE SVIDs carry their identity as URI SANs with empty subjects — to support this path.

### Certificate hot-reload

Both certificate sets are monitored via fsnotify directory watchers. On filesystem events (create, rename — typical of atomic file replacement), the server debounces for 500ms then reloads the certificate, key, and CA bundle. The private cert, CA, and computed fingerprints are swapped atomically under a `sync.RWMutex` so request handlers always see a consistent set.

## Transitive dependency attestation

When `dependencies.endpoints` is configured, the server fetches attestation reports from all dependency endpoints before collecting its own evidence. This produces a tree of cryptographically linked attestation reports.

### Request flow

```
1. Client sends GET /api/v1/attestation?nonce=<hex>
2. Server builds AttestationReportData (metadata, TLS fingerprints, etc.)
3. Server computes nonce_digest = SHA-512(JSON(report_data))
4. Server fetches dependency reports in parallel:
   a. Each dependency receives nonce_digest as x-attestation-nonce header
   b. Each response is cryptographically verified (evidence + nonce binding)
   c. Client certificate fingerprint is checked for e2e encryption proof
   d. Endorsement measurements are validated against dependency evidence
5. Server collects own TEE evidence using nonce_digest
6. Server returns the full report with embedded dependency reports
```

### Evidence chaining

When NitroTPM and SEV-SNP are both enabled, the evidence is chained: the SEV-SNP report data is `SHA-512(nitroTPM_blob)` instead of the raw digest. This binds both evidence blobs to the same request — a verifier confirms the chain by hashing the NitroTPM blob and checking it against the SEV-SNP report data.

### Cycle detection

Each server computes a deterministic instance ID from `SHA-256(build_info || cert_subject || cert_SANs)`. The `X-Attestation-Path` header carries a comma-separated list of instance IDs visited along the dependency chain. If a server sees its own ID in the path, it returns `409 Conflict`. Replicas of the same service share the same ID (intentional — cycles are between services, not processes).

### HTTP client hardening

The dependency HTTP client is hardened against slowloris-like attacks:

| Phase | Timeout |
|-------|---------|
| TCP dial | 5s |
| TLS handshake | 10s |
| Response headers | 15s |
| Overall request | 30s |

Response bodies are limited to 4 MiB. Keep-alives are disabled so each request gets a fresh TLS handshake, ensuring certificate rotation is respected.

## Endorsement lifecycle

### Build pipeline

The endorsement lifecycle is driven entirely by the CI/CD pipeline:

1. **Build** — the pipeline builds the workload and attestation server binaries
2. **Compose** — the pipeline assembles the immutable TEE image with all components
3. **Measure** — the pipeline computes golden measurements from the final image (PCR values for Nitro/TPM, launch measurements for SEV-SNP, TD measurements for TDX)
4. **Endorse** — the measurements are packaged into an endorsement document
5. **Sign** — the document is signed with `cosign sign-blob --bundle` using Sigstore's public-good infrastructure with OIDC-based keyless signing (no long-lived signing keys to manage or protect)
6. **Upload** — the endorsement document and its cosign signature bundle are uploaded to one or more public object storage buckets
7. **Bake** — the endorsement URLs are written to `/etc/endorsements.json` and included in the immutable image

### Multi-provider redundancy

Multiple storage buckets at different infrastructure providers can be configured. The server requires byte-for-byte identity (SHA-256 comparison) across all configured URLs. This mitigates:

- **Credential exposure** at a single provider — an attacker who compromises one bucket cannot serve a forged endorsement because it won't match the copies at other providers
- **Provider-side malicious activity** — a compromised or coerced provider cannot tamper with endorsements unilaterally

### Runtime validation

At startup, the server fetches endorsement documents from all configured URLs, verifies identity, parses the golden measurements, and validates them against the self-attestation evidence. The server exits on any failure — it never starts with unverified evidence.

Per-request, endorsements are re-validated from cache (ristretto, TTL from Cache-Control headers, capped at 24h). On cache miss, documents are re-fetched and revalidated. If revalidation fails, the handler returns 500 but the server stays up and self-heals when endorsements become available.

### Endorsement document format

```jsonc
{
  // HashAlgorithm is mandatory; first token uppercased must be SHA1|SHA256|SHA384|SHA512.
  // Both "Sha384 { ... }" (Nitro-style) and plain "SHA384" are accepted.
  // PCR values must be valid hex of exactly the algorithm's digest size.
  "nitronsm": { "Measurements": { "HashAlgorithm": "...", "PCR0": "<hex>", ... } },
  "nitrotpm": { "Measurements": { "HashAlgorithm": "...", "PCR4": "<hex>", ... } },
  "sevsnp": "<hex>",                    // 96-char hex = 384-bit launch measurement
  "tdx": { "MRTD": "<hex>", "RTMR0": "<hex>", ... },
  "tpm": { "Measurements": { "HashAlgorithm": "...", "PCR0": "<hex>", ... } }
}
```

### Cosign signature verification

When enabled (default), the server fetches a cosign signature bundle from `<endorsement_url>.sig`, verifies it using the Sigstore public-good infrastructure (Fulcio certificate chain + Rekor transparency log inclusion proof), and validates every Fulcio OID extension against the server's build provenance. This closes the loop between the endorsement document and the CI/CD pipeline that produced the image — confirming they came from the same build.

### DNSSEC validation

As an additional defense-in-depth layer for the endorsement infrastructure, DNSSEC chain-of-trust validation can be enabled to protect the DNS resolution step. Even when endorsements are stored across multiple providers and cosign-signed, a DNS spoofing attack at one provider could redirect fetches to an attacker-controlled server before the HTTPS connection is established. DNSSEC prevents this by cryptographically validating the DNS responses.

When `endorsements.dnssec` is enabled, endorsement URL hosts are validated via cryptographic DNSSEC chain-of-trust verification before fetching. The resolver sets the CD (Checking Disabled) bit and validates RRSIG signatures locally at every delegation point up to embedded IANA root KSK trust anchors, so it works with any upstream resolver including non-validating ones.
