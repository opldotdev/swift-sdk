# P256K dependency audit

Status: Phase 0 ECDH target-graph gate cleared against swift-secp256k1 0.23.2.

## Decision

Use the public `P256K` product with its default traits. No custom ECDH C shim
target is required.

`P256K.KeyAgreement.PrivateKey.sharedSecretFromKeyAgreement(with:format:)`
returns the actual shared curve point using a custom libsecp256k1 ECDH callback:

- `.compressed`: 33-byte SEC1 point (`02/03 || X`).
- `.uncompressed`: 65-byte SEC1 point (`04 || X || Y`).

The returned `SharedSecret` conforms to `ContiguousBytes`. BRC-42 and Electrum
ECIES can consume the compressed point directly. Formats needing the fixed-width
X coordinate can remove the SEC1 prefix from the compressed result.

## Source evidence

Paths below are relative to the audited swift-secp256k1 0.23.2 source tree.

- Public agreement API and callback selection:
  `Sources/Shared/ECDH.swift`, lines 382–395.
- Compressed/uncompressed lengths:
  `Sources/Shared/Keys/P256K.swift`, lines 100–129.
- `SharedSecret` byte access:
  `Sources/Shared/DH.swift`, lines 57–88, and
  `Sources/Shared/Utility.swift`, lines 19–30.
- SEC1 callback encoding:
  `Sources/Shared/ECDH.swift`, lines 412–428.
- libsecp256k1 X/Y callback contract:
  `Sources/libsecp256k1/include/secp256k1_ecdh.h`, lines 10–48.

Go SDK consumers checked during the audit include BRC-42 derivation, BRC-77,
Electrum ECIES, Bitcore ECIES, and encrypted messages.

## Signature behavior

- DER and 64-byte compact parse/serialize APIs are public.
- Recoverable compact signatures expose `r || s` and recovery ID.
- Signatures produced by libsecp256k1 signing are low-S.
- Bitcoin Signed Message header packaging remains SDK-level behavior.

The pinned P256K 0.23.2 recovery initializer traps if libsecp256k1 reports
failure. The SDK therefore validates nonzero/in-range scalars and preflights
the complete libsecp256k1 recovery failure set before invoking it: recovery
point x overflow for IDs 2/3, invalid/off-curve recovery points, and
`sR - mG` at infinity. The preflight uses only throwing P256K-backed SEC1,
point-multiplication, and tweak-addition operations. This proof is specific to
P256K 0.23.2 and vendored libsecp256k1 0.7.1 and must be repeated for any
dependency revision.

One façade gap remains: P256K does not publicly expose low-S normalization for
an arbitrary externally supplied standard signature. The vendored
`secp256k1_ecdsa_signature_normalize` C function already exists, so Phase 2 will
add the narrowest possible wrapper and vector-test it. This does not require a
new SwiftPM target.
