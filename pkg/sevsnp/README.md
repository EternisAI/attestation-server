# pkg/sevsnp

AMD SEV-SNP guest attestation: device access, extended report retrieval with certificate buffer caching, and offline ECDSA-P384 signature verification.

## What it does

1. Retrieves an extended attestation report (raw report + certificate table) from the SEV-SNP guest device
2. Parses the report into a protobuf and extracts the endorsement key (VCEK or VLEK) from the certificate table
3. Determines the AMD product line (Milan, Genoa, Turin) from the endorsement key's x509 extensions
4. Verifies the endorsement key's certificate chain against embedded AMD root certificates (ASK + ARK)
5. Verifies the ECDSA-P384 report signature directly against the original raw bytes
6. Checks that the report data matches the expected value

## Usage

### Verify evidence (standalone, no device needed)

```go
// Basic offline verification:
report, err := sevsnp.VerifyEvidence(blob, expectedReportData, time.Now())

// With optional revocation checker (checks endorsement key against a CRL):
report, err := sevsnp.VerifyEvidence(blob, expectedReportData, time.Now(), revChecker)
// report.Measurement — 384-bit launch measurement
// report.Policy, report.Vmpl, report.ReportData, etc.
```

The optional `RevocationChecker` callback is invoked after certificate chain verification to check the endorsement key (VCEK/VLEK) against a CRL. Pass nil or omit to skip revocation checking.

### Device access (requires /dev/sev-guest)

```go
dev, err := sevsnp.Open()
defer dev.Close()
blob, report, err := dev.Attest(reportData, vmpl)  // combined get + verify
blob, err := dev.GetEvidence(reportData, vmpl)      // get only
```

### Split a blob into components

```go
rawReport, certTable, err := sevsnp.SplitEvidence(blob)
```

## go-sev-guest workarounds

`VerifyEvidence` implements its own verification flow instead of using `verify.SnpAttestation` from go-sev-guest (v0.14.1) to work around three library issues:

1. **Unknown policy bits** — `abi.ReportToProto` rejects reports with policy bits the library doesn't recognize (e.g. bit 25 = PageSwapDisable on AWS). Workaround: mask unknown bits before parsing, restore original value afterward.

2. **Malformed ASK/ARK in certificate table** — some hypervisors (AWS Nitro) populate the extended report's certificate table with entries that `x509.ParseCertificate` rejects. Workaround: resolve the endorsement key directly and verify against pre-parsed AMD root certs embedded in the binary.

3. **Signature over reconstructed bytes** — the library reconstructs raw bytes from the sanitized protobuf for signature verification, but the sanitized policy differs from what the hardware signed. Workaround: verify the signature against the original raw report bytes.

These workarounds can be revisited when go-sev-guest ships a release including [PR #181](https://github.com/google/go-sev-guest/pull/181).

## Certificate buffer caching

`GetEvidence` caches the certificate table size after the first call. The go-sev-guest library performs two ioctls per call (probe for cert size + actual attestation) with a ~2s self-throttle between them. By caching the size, subsequent calls use a single ioctl, eliminating one PSP firmware round-trip and one throttle delay.

## Embedded trust anchors

AMD root certificates (ASK + ARK) for all supported product lines are parsed at init time from PEM bundles shipped with go-sev-guest:

| Product line | Signing keys |
|-------------|-------------|
| Milan | VCEK, VLEK |
| Genoa | VCEK, VLEK |
| Turin | VCEK, VLEK |
