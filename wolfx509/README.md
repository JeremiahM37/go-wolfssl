# wolfx509

X.509 cert and CSR handling backed by wolfCrypt — parse, build, sign,
chain-verify. Mirrors the shape of the Go stdlib's `crypto/x509`
package surface so consumers can mostly swap imports, but operates
entirely on wolfCrypt-owned key handles.

## Public API surface

- `ParseCertificate` / `ParseCertificates` — DER → `*Certificate`. The
  parsed `Certificate.PublicKey` (a `KeyHandle`) is populated from the
  SPKI when the algorithm is supported; today that is ECDSA-P256 only.
- `CreateCertificate(template, parent, pubKey, signer KeyHandle)` —
  v3 self-signed or CA-signed cert builder.
- `CreateCertificateRequest(template, key KeyHandle)` — PKCS#10 CSR
  builder.
- `GenerateP256Key()` — convenience factory returning a
  `*handles.EccKey`.
- `(c *Certificate) Verify(opts VerifyOptions)` — chain verification
  via wolfSSL's CertManager. Note: `VerifyOptions.CurrentTime` is
  currently ignored; wolfSSL uses the system clock.
- `(c *Certificate) PublicECCRawXY()` — raw `(X, Y)` point export
  for ECDSA-P256 leaves.

## Algorithm polymorphism

`KeyHandle` is the package's polymorphic-key interface
(`Algorithm() handles.Algorithm`, `CKeyPtr() unsafe.Pointer`,
`CRngPtr() unsafe.Pointer`). `*handles.EccKey` is the only
implementation today; future RSA support adds a `*handles.RsaKey`
satisfying the same interface, plus an `AlgRSA*` arm in
`buildAndSignCert`'s algorithm switch. No public signature change is
required to add new algorithms.

## Build

Cgo directives live in `certgen_wolfcrypt.go`. Run
`../generateOptions.sh <wolfssl-prefix>` once at the top of the tree
to point them at your wolfSSL install; see the top-level
[README.md](../README.md). The cert builder additionally needs
wolfSSL configured with `WOLFSSL_CERT_GEN`, `WOLFSSL_CERT_EXT`,
`WOLFSSL_CERT_REQ`, and (for the RFC 8737 ACME id-pe-acmeIdentifier
extension) `WOLFSSL_ACME_OID`. Builds against vanilla wolfSSL without
those flags compile and link, but cert minting falls through to a
runtime `NOT_COMPILED_IN` (-174).
