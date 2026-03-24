# pkg/nitro

AWS Nitro attestation verification for NSM (Nitro Security Module) and NitroTPM evidence.

## What it does

Nitro attestation documents are COSE_Sign1-wrapped CBOR payloads signed with ES384. This package:

1. Parses the COSE_Sign1 envelope and extracts the protected header, payload, and signature
2. Verifies the protected header specifies ES384
3. Decodes the CBOR attestation document (PCRs, certificate chain, nonce, etc.)
4. Validates the certificate chain against the embedded AWS Nitro Enclaves Root CA (Root-G1)
5. Verifies the COSE ES384 signature using the leaf certificate's public key
6. Checks that the nonce matches the expected value

Both NSM and NitroTPM documents share the same COSE structure and verification logic. The only difference is the PCR field name: `pcrs` for NSM, `nitrotpm_pcrs` for NitroTPM.

## Usage

### Verify evidence (standalone, no device needed)

```go
doc, err := nitro.VerifyEvidence(blob, expectedNonce, time.Now())
// doc.PCRs or doc.NitroTPMPCRs contains the platform measurements
// doc.ModuleID, doc.Timestamp, doc.Digest are also available
```

### Device access (requires /dev/nsm or /dev/tpm0)

```go
// NSM
nsm, err := nitro.OpenNSM()
defer nsm.Close()
blob, doc, err := nsm.Attest(nonce)      // combined get + verify
blob, err := nsm.GetEvidence(nonce)       // get only, verify separately

// NitroTPM
tpm, err := nitro.OpenTPM()
defer tpm.Close()
blob, doc, err := tpm.Attest(nonce)
blob, err := tpm.GetEvidence(nonce)
```

## NitroTPM implementation

The NitroTPM uses a raw TPM2 protocol over `/dev/tpm0` (not the resource manager `/dev/tpmrm0`). Communication with the NSM happens via an NV index buffer: the caller writes a CBOR-encoded request, issues an AWS vendor command (`0x20000001`), and reads the response back. The NV space is allocated and freed per-request.

The device is opened via `syscall.Open` in blocking mode because Go's `os.OpenFile` puts fds into non-blocking mode and routes I/O through the runtime poller (epoll), which does not work reliably with `/dev/tpm0` — the driver's `poll()` may report ready before the response is available.

## Embedded trust anchor

The AWS Nitro Enclaves Root CA (Root-G1) is embedded in the binary:

- **Source**: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
- **SHA-256**: `641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B`
- **Validity**: 2019-10-28 to 2049-12-31
