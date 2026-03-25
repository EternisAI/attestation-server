# pkg/tdx

Intel TDX (Trust Domain Extensions) guest attestation: quote retrieval via ConfigFS and offline ECDSA-P256 signature verification.

## What it does

1. Retrieves a TDX attestation quote via the kernel's ConfigFS-based quote provider
2. Parses the quote into a QuoteV4 protobuf
3. Verifies the ECDSA-P256 signature and PCK certificate chain against the embedded Intel SGX Root CA
4. Checks that the report data matches the expected value

## Usage

### Verify evidence (standalone, no device needed)

```go
// Basic offline verification (no revocation check):
quote, err := tdx.VerifyEvidence(rawQuote, expectedReportData, time.Now())

// With online revocation checking via Intel PCS:
quote, err := tdx.VerifyEvidence(rawQuote, expectedReportData, time.Now(),
    tdx.VerifyOpt{CheckRevocations: true})

// With a caching getter to avoid per-request round-trips:
quote, err := tdx.VerifyEvidence(rawQuote, expectedReportData, time.Now(),
    tdx.VerifyOpt{CheckRevocations: true, Getter: myGetter})
// quote.TdQuoteBody.MrTd — TD measurement
// quote.TdQuoteBody.Rtmrs — runtime measurement registers
// quote.TdQuoteBody.ReportData — the 64-byte report data
```

When `CheckRevocations` is true, collateral is fetched from the Intel PCS and the PCK certificate chain is checked against CRLs. Provide a caching `Getter` implementation to avoid per-request network latency.

### Device access (requires ConfigFS TDX support)

```go
dev, err := tdx.Open()
defer dev.Close()
rawQuote, quote, err := dev.Attest(reportData)  // combined get + verify
rawQuote, err := dev.GetEvidence(reportData)     // get only
```

## ConfigFS quote provider

The package uses the ConfigFS-based `QuoteProvider` from go-tdx-guest, which is the non-deprecated path supported by modern kernels. The legacy `/dev/tdx_guest` ioctl returns `ENOTTY` for quote requests on these systems.

The `QuoteProvider` is stateless (empty struct) and creates an isolated temporary directory per request, so no mutex is needed — the kernel's ConfigFS subsystem handles concurrent access internally.

## Verification options

By default, verification is performed offline without fetching collateral or checking revocation lists. Pass a `VerifyOpt` to enable revocation checking:

```go
// Default (offline, no VerifyOpt):
verify.Options{CheckRevocations: false, GetCollateral: false, TrustedRoots: intelSGXRootPool, Now: now}

// With VerifyOpt{CheckRevocations: true} (online):
verify.Options{CheckRevocations: true, GetCollateral: true, TrustedRoots: intelSGXRootPool, Now: now}

// With VerifyOpt{CheckRevocations: true, Getter: myGetter} (online, cached):
// Same as above but uses the provided Getter for HTTP fetches instead of the default
```

`VerifyOpt.Getter` overrides the HTTP client used for Intel PCS collateral fetching. The attestation server provides a caching getter backed by a shared ristretto cache to avoid per-request network round-trips.

## Embedded trust anchor

The Intel SGX Root CA certificate is embedded in the binary:

- **Source**: https://certificates.trustedservices.intel.com/IntelSGXRootCA.der
- **SHA-256**: `44A0196B2B99F889B8E149E95B807A350E74249643998E85A7CBB8CCFAB674D3`
- **Validity**: 2018-05-21 to 2049-12-31
