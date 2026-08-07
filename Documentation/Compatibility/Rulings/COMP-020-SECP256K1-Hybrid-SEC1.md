# COMP-020: secp256k1 hybrid SEC1 input normalization

Status: Approved by the P2-C secp256k1 key implementation packet.

## Conflict

Standard modern SEC1 interchange uses compressed prefixes `02`/`03` or the
uncompressed prefix `04`. The pinned Go compatibility surface also accepts the
legacy hybrid prefixes `06`/`07`, while P256K/libsecp256k1 does not expose
hybrid serialization as an SDK format.

## Ruling

The Swift public-key parser accepts 65-byte hybrid input only when the prefix
parity bit matches the least-significant bit of the encoded Y coordinate. It
then replaces the prefix with `04` and delegates field and curve validation to
P256K/libsecp256k1. A parity mismatch produces
`Secp256k1KeyError.invalidHybridParity`; any subsequent point-validation
failure produces `Secp256k1KeyError.invalidPublicKey`.

Hybrid encoding is input-only. The SDK stores the canonical point and emits
only standard compressed or uncompressed SEC1 bytes. Consequently, equality
and hashing do not depend on whether a valid point entered as compressed,
uncompressed, or hybrid input.

## Evidence and test obligation

- Even- and odd-Y hybrid points must parse and normalize to exact standard SEC1
  bytes.
- Mismatched hybrid parity must fail before dependency point parsing.
- Field overflow and off-curve hybrid data with matching parity must still be
  rejected by P256K/libsecp256k1.
- Pinned-Go differential execution is deferred until the dedicated key-oracle
  extension; no Go source, fixture, or generated oracle output is copied.
