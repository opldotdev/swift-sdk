# Fable review: recoverable signatures, BIP-32, and BIP-39

Date: 2026-08-07

Reviewer: Claude Fable 5 through the signed-in first-party subscription

Verdict: **SHIP**

This review was run after independent adversarial reviews and remediation. The
reviewer inspected the live Swift implementation, tests, fixture manifests, the
pinned P256K 0.23.2 source, and its vendored libsecp256k1 0.7.1 recovery code.
No must-fix findings remained.

## Recovery safety conclusion

P256K's public recovery initializer traps if libsecp256k1 returns failure. The
SDK accepts only nonzero `r` and `s` values below the group order, then
preflights every remaining dependency failure before calling that initializer:

- recovery IDs 2 and 3 require `r < p - n` before computing `x = r + n`;
- compressed SEC1 parsing validates the selected recovery point and parity;
- P256K-backed point multiplication and tweak addition reject
  `sR - mG` at infinity with a typed error.

Because nonzero multiplication by `r^-1` preserves whether a point is at
infinity, a successful preflight proves the dependency recovery path succeeds
for the accepted `(r, s, recoveryID, digest)`. Tests cover the equality boundary
`r = p - n`, upstream off-curve cases, a constructed infinity case, high-S
interoperability, and successful recovery IDs 2 and 3.

This proof is specific to P256K 0.23.2 and libsecp256k1 0.7.1. Any dependency
revision must repeat the audit.

## BIP-32 and BIP-39 conclusions

- BIP-32 master generation, child derivation, fingerprints, versions, metadata,
  serialization, invalid-key handling, and official vectors are correct.
- BIP-39 entropy/checksum conversion, English wordlist, NFKD normalization, and
  the fixed PBKDF2-HMAC-SHA512 profile are correct against all 24 official
  English vectors.
- Hostile text is bounded before Base58 or Unicode normalization work.
- Mnemonic and extended-private-key descriptions are redacted; explicit
  `phrase` and `serialized` properties are required to export secrets.

## Dependency boundary

- SHA-2 and HMAC use Apple Swift Crypto.
- BIP-39 PBKDF2 uses CryptoExtras with its standards-mandated 2,048-round
  compatibility overload behind a fixed package-only wrapper.
- Curve parsing, signing, multiplication, tweaks, and recovery use P256K and
  libsecp256k1.
- The small fixed-width add/subtract helpers used by recovery operate on public
  signature and digest data because P256K exposes no public scalar-arithmetic
  API.

## Nonblocking follow-ups

- Consolidate the secp256k1 group-order constant shared by signature and tweak
  adapters.
- Keep recovery preflight and the dependency signer's internal invariant trap
  on the dependency-upgrade audit checklist.
- Consider whether leading-zero path components should be rejected rather than
  accepted and canonicalized.
- Evaluate an SDK-wide secret-buffer and redaction policy before 1.0.
