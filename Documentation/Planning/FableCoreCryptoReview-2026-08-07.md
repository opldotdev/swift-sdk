# Fable core cryptography and key review

- Date: 2026-08-07
- Channel: read-only Claude Fable CLI consult
- Authentication: signed-in `claude.ai` Max subscription with
  `ANTHROPIC_API_KEY` removed from the process environment
- Scope: hashing, Base58Check, AES-CBC/GCM, HMAC-DRBG, and secp256k1 keys

## Verdict

Fable returned **approve with required changes** for both implementation waves.
It found no cryptographic correctness defect and confirmed that the SDK delegates
SHA-2, HMAC, AES, scalar validation, point parsing, derivation, and serialization
to the pinned Apple Swift Crypto and P256K/libsecp256k1 dependencies.

The local implementations were judged justified: Apple exposes neither
RIPEMD-160 nor HMAC-DRBG, and no Apple primitive covers Bitcoin Base58Check.

## Required changes incorporated

1. Base58Check size-limit failures now report the caller's payload limit rather
   than the internal payload-plus-checksum bound.
2. RIPEMD-160 compression fails loudly if its internal one-block invariant is
   violated.
3. The P256K product dependency moved from `BSVCrypto` to the target that imports
   it, `BSVKeys`; strict explicit-target import checking passes.
4. Private-key equality and hashing now use the already-derived public point
   instead of comparing or hashing raw secret bytes.

Recommended hardening was also applied: non-vacuous fixture counts, ambiguous
fixture-key rejection, debug digest-width assertions, stable AES encryption
error normalization, secret-copy/zeroization documentation, and an explicit
warning that copying HMAC-DRBG state repeats its future deterministic stream.

## Preserved strengths

- Exact dependency pins and thin wrapper APIs
- Required live Go-oracle differentials for hashing, encodings, and HMAC-DRBG
- Direct permissive/public-domain fixtures with strict content and license hashes
- Typed hostile-input errors and explicit resource bounds
- Compatibility rulings for AES-GCM nonce lengths and hybrid SEC1 input

## Residual validation gaps

- AES and secp256k1 Go-oracle operations remain a later conformance packet;
  current evidence uses direct upstream vectors and exact dependency behavior.
- This checkpoint was executed on macOS. Linux backend execution remains a CI
  obligation even though the selected dependencies and production sources are
  cross-platform.
