# Fable key operations review

- Date: 2026-08-07
- Channel: read-only Claude Fable CLI consult
- Authentication: signed-in `claude.ai` Max subscription with
  `ANTHROPIC_API_KEY` removed from the process environment
- Scope: deterministic ECDSA/DER, secp256k1 tweaks, raw-point ECDH, WIF, and
  legacy P2PKH addresses

## Verdict

Fable returned **ship after one required API correction** and found no
cryptographic correctness defect. A second focused reconciliation review
returned **ship** with no blocker, required change, or meaningful advisory.

The review traced the wrappers into pinned P256K/libsecp256k1 source and
confirmed that the dependency owns RFC 6979 signing, low-S output, signature
verification, curve arithmetic, tweak operations, and raw-point ECDH. It also
confirmed that WIF and address handling compose the accepted bounded
Base58Check, hashing, and key primitives.

## Changes incorporated

1. Removed the no-op ECDH serialization parameter. `sharedSecret(with:)`
   returns one validated curve point, and callers serialize that `PublicKey`
   as compressed or uncompressed SEC1 when needed.
2. Replaced a P256K private-key construction used only for tweak range checking
   with a fixed-shape 32-byte comparison against the curve order.
3. Aligned tweak semantics with libsecp256k1 and future BIP-32 use: zero is the
   additive identity but remains invalid for multiplication; order and larger
   values remain invalid.
4. Removed misleading implicit `UInt8` raw values from `BitcoinNetwork`; WIF
   and P2PKH version bytes remain explicit at their format boundaries.

## Confirmed properties

- Compact signature input is length-checked before reaching P256K's C parser.
- Strict DER accepts one complete canonical sequence with scalar range checks.
- Digest signing and verification do not hash the supplied `Hash256` again.
- High-S signatures are preserved but fail verification as documented.
- ECDH returns the complete shared point rather than an x-only or hashed value.
- WIF and address parsing is bounded and preserves typed Base58Check failures.
- Exact independently sourced vectors and license hashes gate the new behavior.

The full review transcripts remain local build evidence and are not committed.
