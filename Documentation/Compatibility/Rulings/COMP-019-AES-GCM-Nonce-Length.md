# COMP-019: AES-GCM nonce length

Status: Approved by the P2-B AES implementation packet.

## Conflict

The pinned Go production symmetric envelope uses a 32-byte AES-GCM nonce and
the underlying Go primitive also supports the official 8-byte nonce known-answer
edge. Apple Swift Crypto 4.5.1 accepts AES-GCM nonces only when they are at least
12 bytes long.

## Ruling

The Swift byte-oriented AES-GCM API accepts explicit nonces of 12 bytes or more.
This includes both the conventional 12-byte nonce and the Go envelope's 32-byte
nonce. It rejects every shorter nonce, including the 8-byte known-answer case,
with `AESPrimitiveError.invalidNonceByteCount(minimum: 12, actual: count)`.

No fallback cipher, nonce rewriting, truncation, padding, or silent test skip is
permitted. Callers must supply a unique nonce for every encryption under a key.

## Evidence and test obligation

- Swift Crypto 4.5.1 revision
  `47d3869a7291f085c1fb9fb1e6d3b97a793f45c6` enforces the 12-byte minimum in
  `Sources/Crypto/AEADs/Nonces.swift`.
- The dependency's Apache-2.0 Wycheproof corpus includes 12-byte, 32-byte, and
  8-byte nonce known answers. The committed strict-manifest subset must prove
  exact detached ciphertext/tag bytes for supported lengths and an explicit
  typed rejection for the 8-byte case.
- Pinned-Go differential execution is deferred until the dedicated oracle AES
  extension packet; no Go source, fixture, or generated oracle output is copied.
