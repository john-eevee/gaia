Package mtls - certs.go
=======================

Location: `pkg/mtls/certs.go`

Overview
--------
`certs.go` provides utilities for generating and loading certificate authorities (CAs), creating certificate signing requests (CSRs), and signing CSRs to produce PEM-encoded X.509 certificates. The implementation focuses on modern key types (Ed25519 as the default key generation) and uses PKCS#8 for private key encoding.

Key concepts
------------
- CertificateAuthority: simple container holding PEM-encoded `PrivateKey` and `Certificate` (both `[]byte`).
- Config: subject fields used when building certificate subjects (`pkix.Name`).
- CSRCertificate: container for a PEM-encoded CSR and the corresponding PEM-encoded private/public keys.
- CertificateError: a typed error with a `Message`, wrapped `Err`, and `Op` (CertificateOp) to identify which high-level operation failed.

Public functions
----------------
- `CreateRootCA(config Config) (CertificateAuthority, error)`
  - Generates an Ed25519 keypair and a self-signed root CA certificate valid for `RootCAValidityYears` (10 years).
  - Returns PEM-encoded private key (PKCS#8) and certificate.
  - Validates the provided `Config` and returns `CertificateError` on failure.

- `LoadRootCA(caPem, keyPem []byte) (CertificateAuthority, error)`
  - Loads and validates an existing PEM-encoded CA certificate and private key.
  - Ensures the certificate is a CA, the key matches the certificate public key, and the certificate is currently valid.

- `CreateCSRCertificate(config Config) (CSRCertificate, error)`
  - Generates an Ed25519 keypair and produces a CSR (PEM-encoded) using the subject data from `Config`.
  - Returns PEM-encoded CSR, private key (PKCS#8), and public key.

- `(*CertificateAuthority) SignCSR(csrPem []byte, validityDays int) ([]byte, error)`
  - Signs a PEM-encoded CSR with the CA's private key and returns a PEM-encoded certificate valid for `validityDays`.
  - Validates CSR signature and uses the CSR subject for the issued certificate.

Helper functions and types
--------------------------
- `toPKI()` (Config method): converts `Config` into a `pkix.Name` used inside X.509 subjects.
- `encodePEM`, `encodePrivateKeyPEM`, `encodePublicKeyPEM`: PEM encoding helpers. Private keys are marshalled with `x509.MarshalPKCS8PrivateKey`.
- `decodeCAPem`, `decodeCAPrivateKey`: PEM decoding and parsing helpers. Supported private key PEM types: `PRIVATE KEY` (PKCS#8) and `EC PRIVATE KEY` (EC). Encrypted private keys are rejected.
- `verifyKeyMatchesCert`: checks the provided private key corresponds to a certificate's public key. Supports RSA, ECDSA and Ed25519 private keys.

Error handling pattern
----------------------
Errors are returned as `CertificateError` which wraps inner errors and annotates the high-level operation via `Op` (CertificateOp). The `Error()` implementation concatenates the message with the wrapped error message if present.

Security & compatibility notes
------------------------------
- Key algorithm: Ed25519 is used by default for generating CA and CSR keys for simplicity and security.
- Private key format: PKCS#8 is produced for private keys. The code no longer attempts to parse legacy PKCS#1 RSA private keys (only PKCS#8 and EC are supported). Encrypted PEM blocks are rejected.
- mTLS usage: Certificates produced are configured to include appropriate key usages for client/server auth and to mark CA certificates with `IsCA=true`.

Examples
--------
Create a CA and sign a CSR (high-level):

```go
cfg := mtls.Config{Organization: "Acme", Country: "US", CommonName: "Acme Root CA"}
ca, err := mtls.CreateRootCA(cfg)
// write ca.PrivateKey and ca.Certificate to disk or load into TLS config

csrcfg := mtls.Config{Organization: "Acme", Country: "US", CommonName: "device1"}
csr, err := mtls.CreateCSRCertificate(csrcfg)
certPem, err := ca.SignCSR(csr.CSR, 365)
```

Where to look next
------------------
- `pkg/mtls` package tests (if present) to see usage patterns.
- Other code that consumes `CertificateAuthority` or CSRs (apps/hub, apps/farm) to understand integration and mTLS setup.

Maintenance
-----------
- If you need to accept PKCS#1 RSA private keys for backward compatibility, add parsing in `decodeCAPrivateKey` and update `pemTypeRSAPrivateKey` usage with clear migration notes.
- Consider adding unit tests for edge cases: invalid PEM, encrypted PEM, mismatched key/cert, expired CA.

File reference: `pkg/mtls/certs.go`
