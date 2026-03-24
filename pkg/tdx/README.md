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
quote, err := tdx.VerifyEvidence(rawQuote, expectedReportData, time.Now())
// quote.TdQuoteBody.MrTd — TD measurement
// quote.TdQuoteBody.Rtmrs — runtime measurement registers
// quote.TdQuoteBody.ReportData — the 64-byte report data
```

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

Verification is performed offline without fetching collateral or checking revocation lists:

```go
verify.Options{
    CheckRevocations: false,
    GetCollateral:    false,
    TrustedRoots:     intelSGXRootPool,
    Now:              now,
}
```

## Embedded trust anchor

The Intel SGX Root CA certificate is embedded in the binary:

- **Source**: https://certificates.trustedservices.intel.com/IntelSGXRootCA.der
- **SHA-256**: `44A0196B2B99F889B8E149E95B807A350E74249643998E85A7CBB8CCFAB674D3`
- **Validity**: 2018-05-21 to 2049-12-31
