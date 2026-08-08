# Go SDK v1.3.3 defect report

## Purpose

This file records confirmed defects in the pinned Go SDK that were found during
Swift parity work. It is a separate report for the Go SDK maintainers. The
normal parity map describes supported behavior and links here when a defect
changes the shared compatibility domain.

Reference:

- Repository: [`bsv-blockchain/go-sdk`](https://github.com/bsv-blockchain/go-sdk)
- Release: `v1.3.3`
- Commit: `de26fdec57a945ddc06de5d5617f6c32374f3929`
- Audit date: 2026-08-08

The Swift SDK does not reproduce these defects. It keeps canonical valid wire
behavior compatible and rejects or corrects the defective case.

## Confirmed defects

### GO-001: Discovery results cannot contain more than one identity certificate

- Package: `wallet/serializer`
- Files: [`identity_certificate.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/wallet/serializer/identity_certificate.go),
  [`discover_certificates_result.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/wallet/serializer/discover_certificates_result.go)
- Severity: high

`DeserializeDiscoverCertificatesResult` passes one shared reader to
`DeserializeIdentityCertificate` for each item. The item decoder calls
`CheckComplete` before the outer decoder reads the next item. Therefore, the
first item reports trailing data when the result contains two or more identity
certificates.

Suggested correction: remove the item-level completion check when the decoder
uses a shared outer reader. Keep one completion check after the outer loop.

Swift handling: Swift reads each bounded item from the shared reader and checks
for completion after the full collection. The Go differential uses only zero or
one certificate until the Go decoder is corrected.

### GO-002: Prove-certificate result encoding is not deterministic

- Package: `wallet/serializer`
- File: [`prove_certificate.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/wallet/serializer/prove_certificate.go)
- Severity: high

`SerializeProveCertificateResult` writes `KeyringForVerifier` by ranging over a
Go map. Go map iteration order is not stable. The same semantic result can
produce different bytes.

Suggested correction: collect the keys, sort them by raw UTF-8 bytes, and write
the entries in that order.

Swift handling: Swift always writes keyring names in raw UTF-8 byte order.

### GO-003: SPV verification does not reject zero-fee or inflationary ancestors

- Package: `spv`
- File: [`verify.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/spv/verify.go)
- Severity: critical

The verifier adds each source-output value to `inputTotal`, but it never uses
the total. When no fee model is supplied, an unproved transaction can have
outputs that equal or exceed its inputs and still pass if its scripts pass.

Suggested correction: compare input and output totals for every unproved
transaction. Reject arithmetic overflow, output value above input value, and
zero fee. Apply an optional fee model as an additional root-transaction rule.

Swift handling: Swift requires input value to be greater than output value for
each unproved transaction and can apply a stronger injected fee policy.

### GO-004: BEEF parsing can index outside the BUMP collection

- Package: `transaction`
- File: [`beef.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/transaction/beef.go)
- Severity: critical

The BEEF reader assigns `BUMPs[int(bumpIndex)]` while it parses a raw
transaction with a BUMP index. This path does not first prove that the index is
inside the collection. A hostile packet can cause an out-of-range panic.

Suggested correction: validate the decoded index before any collection access
and return a typed parse error.

Swift handling: Swift validates every proof index before access and never
reproduces the panic.

### GO-005: Symmetric-key parsing can terminate the process

- Package: `primitives/ec`
- File: [`symmetric.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/primitives/ec/symmetric.go)
- Severity: critical

`NewSymmetricKeyFromString` calls `log.Fatalf` when Base64 input is malformed.
A library parser must not terminate its host process. The random constructor in
the same file also discards `crypto/rand` errors.

Suggested correction: return `(*SymmetricKey, error)` from both constructors.
Reject invalid key lengths before an AES operation.

Swift handling: Swift returns typed errors, propagates random-source failure,
and accepts only bounded canonical Base64.

### GO-006: Auth nonce generation discards random-source failure

- Package: `auth/utils`
- File: [`base64.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/utils/base64.go)
- Severity: critical

`RandomBase64` discards the result and error from `crypto/rand.Read`. A failed
read can return predictable or incomplete nonce material without an error.

Suggested correction: return `(wallet.StringBase64, error)`, require the exact
requested byte count, and propagate the error through every caller.

Swift handling: Swift uses an injected secure-random source and propagates each
failure.

### GO-007: Auth nonce verification accepts noncanonical HMAC lengths

- Package: `auth/utils`
- File: [`verify_nonce.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/utils/verify_nonce.go)
- Severity: high

`VerifyNonce` accepts every decoded value longer than 16 bytes. It copies the
remaining bytes into a fixed 32-byte HMAC. Short values are zero-padded and long
values are truncated by `copy`. This accepts multiple encodings for one HMAC
input.

Suggested correction: require exactly 48 decoded bytes: 16 data bytes and 32
HMAC bytes.

Swift handling: the compatibility handshake can read the exact 48-byte Go form.
It rejects all other HMAC-backed nonce sizes.

### GO-008: A responder authenticates an unsigned initial request

- Package: `auth`
- File: [`peer.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/peer.go)
- Severity: critical

`handleInitialRequest` creates a session with `IsAuthenticated: true`. It sets
the value to false only when certificates are required. The initial request has
no peer signature. A responder can therefore mark an unproved identity as
authenticated.

Suggested correction: keep the responder session unauthenticated until the
peer sends the first valid signed message that binds the session nonces and
identity key.

Swift handling: the responder waits for a valid signed `general` message before
it changes the session to authenticated.

### GO-009: The auth handshake does not enforce the expected peer identity

- Package: `auth`
- File: [`peer.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/peer.go)
- Severity: critical

The initial-response path verifies the signature against the identity key in
the received message, then stores that key in the pending session. It does not
compare the key with the identity that the caller requested for that session.
This permits identity substitution at the API boundary.

Suggested correction: store the expected identity in the pending session and
compare it before signature verification and session mutation.

Swift handling: a pending session binds an optional expected identity and
rejects a different response identity.

### GO-010: The block-headers client bypasses its configured HTTP client

- Package: `transaction/chaintracker/headers_client`
- File: [`headers_client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/transaction/chaintracker/headers_client/headers_client.go)
- Severity: high

`IsValidRootForHeight`, `BlockByHeight`, `GetBlockState`, and `GetChaintip`
create new `http.Client` values instead of using `getHTTPClient`. These paths
discard caller transport, timeout, proxy, and test configuration. Several paths
also read or decode an unbounded body and do not check the HTTP status before
they parse it.

Suggested correction: use the configured client for every request. Apply one
response-size limit, check status first, and return sanitized errors. Construct
URLs with `net/url` instead of string concatenation.

Swift handling: the Swift client uses the existing bounded, cancellable HTTP
transport for every request. It does not copy these unsafe request paths.

## Reporting format

When a new defect is confirmed, add one entry with:

- the pinned package and file;
- a small reproducible input or test;
- the effect on callers;
- a suggested correction;
- the Swift compatibility decision.

Do not add unverified differences to this file. Put ordinary API differences in
the surface matrix and deliberate Swift policy in the compatibility rulings.
