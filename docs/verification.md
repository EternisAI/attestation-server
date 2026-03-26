# Verifying attestation reports

This document describes how a client verifies an attestation response from the server. The verification process confirms that the server is running expected code inside a genuine TEE, that the code matches endorsed golden measurements from a trusted CI/CD pipeline, and that the response was delivered over an end-to-end encrypted channel.

## Overview

An attestation response contains three parts:

1. **`evidence`** — one or more hardware-signed blobs from the TEE platform
2. **`data`** — server metadata (timestamp, build info, TLS fingerprints, nonce, endorsement URLs) that was hashed into the evidence nonce
3. **`dependencies`** — (optional) recursively verified attestation reports from downstream services

The verification steps are:

1. Recompute the nonce digest and verify it matches the evidence
2. Verify the hardware evidence against the TEE vendor's root of trust
3. Verify the TLS channel binding
4. Verify endorsement measurements and cosign signatures
5. Verify dependency reports recursively

## Step 1: Nonce binding

The `data` field contains the exact JSON bytes that were hashed into the attestation nonce. Compact the JSON (remove whitespace) and compute:

```
expected_digest = SHA-512(compact(data))
```

Then check that this digest matches the nonce inside the evidence blob:

| TEE type | Nonce field |
|----------|-------------|
| Nitro NSM / NitroTPM | `nonce` field in the CBOR attestation document |
| SEV-SNP | `report_data` field in the attestation report (64 bytes) |
| TDX | `report_data` field in the TD quote body (64 bytes) |

If the caller supplied a nonce via the `nonce` query parameter or `x-attestation-nonce` header, verify that `data.nonce` matches it.

The `data.timestamp` field (RFC 3339, truncated to seconds) records when the report was generated. Verifiers should check that it is recent (within an acceptable window) to detect stale or replayed responses — the caller-supplied nonce provides replay protection, but the timestamp adds defense-in-depth and enables staleness detection when nonces are not used.

## Step 2: Evidence verification

Each TEE type has a different verification procedure. The `pkg/` packages in this repository implement all of them and can be used directly:

### Nitro (NSM and NitroTPM)

```go
import "github.com/eternisai/attestation-server/pkg/nitro"

doc, err := nitro.VerifyEvidence(blob, expectedDigest, time.Now())
```

This verifies the COSE_Sign1 ES384 signature, validates the certificate chain against the embedded AWS Nitro Enclaves Root CA (Root-G1), and checks the nonce.

### SEV-SNP

```go
import "github.com/eternisai/attestation-server/pkg/sevsnp"

// Basic offline verification (no revocation check):
report, err := sevsnp.VerifyEvidence(blob, expectedDigest, time.Now())

// With optional revocation checker (checks endorsement key against a CRL):
report, err := sevsnp.VerifyEvidence(blob, expectedDigest, time.Now(), revocationChecker)
```

This parses the raw report and certificate table, verifies the ECDSA-P384 signature against embedded AMD root certificates (Milan, Genoa, Turin product lines for both VCEK and VLEK signing keys), and checks the report data. The optional `RevocationChecker` callback (if non-nil) is invoked after certificate chain verification to check the endorsement key against a CRL.

### TDX

```go
import "github.com/eternisai/attestation-server/pkg/tdx"

// Basic offline verification (no revocation check):
quote, err := tdx.VerifyEvidence(blob, expectedDigest, time.Now())

// With online revocation checking via Intel PCS:
quote, err := tdx.VerifyEvidence(blob, expectedDigest, time.Now(),
    tdx.VerifyOpt{CheckRevocations: true})

// With a caching getter to avoid per-request network round-trips:
quote, err := tdx.VerifyEvidence(blob, expectedDigest, time.Now(),
    tdx.VerifyOpt{CheckRevocations: true, Getter: myGetter})
```

This parses the QuoteV4, verifies the ECDSA-P256 signature and PCK certificate chain against the embedded Intel SGX Root CA, and checks the report data. When `CheckRevocations` is true, collateral is fetched from the Intel PCS and the PCK certificate chain is checked against CRLs (adds network latency unless a caching `Getter` is provided).

### Chained evidence (NitroTPM + SEV-SNP)

When both NitroTPM and SEV-SNP evidence are present, they are chained:

1. Verify the NitroTPM evidence with `expected_digest` as the nonce
2. Compute `sevsnp_report_data = SHA-512(nitrotpm_blob)`
3. Verify the SEV-SNP evidence with `sevsnp_report_data`

This binding confirms both evidence blobs originated from the same request.

## Step 3: TLS channel binding

After verifying the evidence, confirm the TLS channel matches the attestation:

- **Public endpoint (edge mode)**: verify that `data.tls.public` matches the SHA-256 fingerprint of the server's leaf certificate DER you observed during the TLS handshake. This confirms the attestation was produced by the same TEE that terminated your TLS connection.
- **mTLS endpoint (internal mode)**: verify that `data.tls.client` matches the SHA-256 fingerprint of your own client certificate's leaf DER. This confirms the server saw your specific cert, proving end-to-end encryption between your TEE and the attesting TEE.

Also inspect `data.build_info` to verify the build provenance matches expected values (source repository, commit, builder identity).

## Step 4: Endorsement verification

The `data.endorsements` field contains one or more HTTPS URLs pointing to endorsement documents — JSON files with golden measurement values computed from the final immutable TEE image by the CI/CD pipeline.

### Fetching and cross-checking

Fetch endorsement documents from all URLs in `data.endorsements`. If multiple URLs are present (pointing to different storage providers), verify that all documents are byte-for-byte identical. A mismatch indicates tampering at one of the providers.

If DNSSEC-signed domains are used for the endorsement storage buckets, performing DNSSEC chain-of-trust validation before fetching provides additional assurance that DNS resolution has not been tampered with at the network or provider level (the server does this automatically when `endorsements.dnssec` is enabled).

### Measurement comparison

Compare the golden measurements against the parsed evidence:

| TEE type | Evidence field | Endorsement field |
|----------|---------------|-------------------|
| Nitro NSM | `doc.PCRs[N]` | `nitronsm.PCRN` or `nitronsm.N` |
| NitroTPM | `doc.NitroTPMPCRs[N]` | `nitrotpm.PCRN` or `nitrotpm.N` |
| SEV-SNP | `report.Measurement` | `sevsnp` (hex string) |
| TDX | `quote.TdQuoteBody.MrTd`, `.Rtmrs[N]` | `tdx.MRTD`, `.RTMRN` |

### Cosign signature verification

Fetch the cosign signature bundle from `<endorsement_url>.sig` and verify it against the Sigstore public-good infrastructure. This confirms the endorsement document was signed by the CI/CD pipeline using OIDC-based keyless signing. The Fulcio OID extensions in the signing certificate should match the `data.build_info` fields — this closes the loop between the endorsement, the build pipeline, and the running code.

## Step 5: Dependency verification

Each entry in `dependencies` is a complete attestation report with the same structure. Verify recursively using the same steps above. Key checks:

- **Nonce binding**: the dependency's nonce should match the nonce digest from the parent's `data`
- **Client certificate**: the dependency's `data.tls.client` should match the parent's private certificate fingerprint (`data.tls.private`), confirming mTLS between the two TEEs
- **Server certificate** (HTTPS only): if the dependency was fetched over HTTPS, the server's TLS leaf certificate fingerprint observed during the handshake should match the dependency's `data.tls.private`. This binds the attestation report to the actual TLS peer, catching relay proxies that hold a valid CA-signed cert but are not the TEE. Skipped for plain HTTP endpoints (transparent proxy configurations)
- **Endorsements**: the dependency's endorsement documents should be fetched and validated independently — each service in the chain has its own build provenance and golden measurements from its own CI/CD pipeline

## Example: minimal Go verifier

```go
// 1. Fetch attestation report
resp, _ := http.Get("https://service.example.com/api/v1/attestation?nonce=" + myNonce)
var report AttestationReport
json.NewDecoder(resp.Body).Decode(&report)

// 2. Recompute nonce digest
compact := new(bytes.Buffer)
json.Compact(compact, report.Data)
digest := sha512.Sum512(compact.Bytes())

// 3. Verify evidence
for _, ev := range report.Evidence {
    switch ev.Kind {
    case "sevsnp":
        _, err := sevsnp.VerifyEvidence(ev.Blob, digest, time.Now())
    case "nitronsm":
        _, err := nitro.VerifyEvidence(ev.Blob, digest[:], time.Now())
    // ...
    }
}

// 4. Check metadata and TLS binding
var data AttestationReportData
json.Unmarshal(report.Data, &data)
// verify data.Nonce == myNonce
// verify data.BuildInfo matches expectations
// verify hex.EncodeToString(data.TLS.Public) matches observed TLS cert fingerprint

// 5. Fetch and verify endorsements
for _, url := range data.Endorsements {
    // fetch endorsement document from url
    // compare golden measurements against parsed evidence
    // fetch and verify cosign bundle from url + ".sig"
}

// 6. Verify dependencies recursively
for _, dep := range report.Dependencies {
    // parse as AttestationReport, repeat steps 2-5
    // verify dep's data.TLS.Client == data.TLS.Private (same cert fingerprint)
}
```
