# Delivery roadmap

Status: P0 complete; foundational P1/P2 crypto and BIP-32/BIP-39 plus legacy
P3 key-format packets accepted after independent and Fable review. BigNum,
initial Script, and bounded legacy transaction wire foundations are accepted.

Each milestone ends with passing conformance tests, an updated compatibility
matrix, and an advisor review at architectural or security-sensitive boundaries.
Milestone completion is based on behavior, not file count.

## Phase 0: Repository foundation

- Approve the target graph and dependency policy.
- Record the completed P256K raw-point ECDH audit; no C shim is required.
- Resolve fixture licensing and provenance before copying upstream material.
- Create `Package.swift`, formatting/lint configuration, CI for Apple and Linux,
  documentation conventions, and ADR templates.
- Add upstream provenance manifests and fixture license directories.
- Establish Swift Testing/XCTest conventions, deterministic randomness, and a
  pinned-Go-SDK differential-test harness as a primary conformance mechanism.
- Record pinned Go SDK and BRC commits.

## Phase 1: Bytes, encodings, and hashes

Accepted checkpoint: bounded bytes/endian operations, CompactSize/VarBytes,
fixed-width values and transaction-ID byte order, Hex, strict Base64, raw
Bitcoin Base58, Base58Check, SHA-2, HMAC, RIPEMD-160, and HASH160. The bounded
BigInt adapter and 32 MiB resource gates are accepted on macOS and in the
768 MiB memory-capped Linux CI job.

- Bounded byte reader/writer and endian primitives.
- Hex, Bitcoin VarInt, Base58, and Base58Check.
- SHA-256, double SHA-256, SHA-512, HMAC, RIPEMD-160, and HASH160.
- Fixed-size digest and transaction identifier types.
- Big-integer ADR and experiments covering modular arithmetic, sign-magnitude
  conversion, resource limits, and 750 KB/32 MiB boundaries.

This phase establishes the fixture loader and the smallest dependencies required
by nearly every later feature.

## Phase 2: Cryptographic primitives

Accepted checkpoint: AES-CBC/PKCS#7, AES-GCM, HMAC-DRBG, secp256k1 private and
public key parsing/serialization, deterministic digest-level ECDSA with strict
DER and compact/recoverable forms, raw-point ECDH, and additive/multiplicative
key tweaks. BRC-42 derivation and key-sharing work remains open.

- AES block/CBC/GCM and PKCS#7 behavior.
- HMAC-DRBG.
- secp256k1 key parsing and serialization.
- Deterministic ECDSA, DER/BER handling, low-S normalization, compact recovery,
  ECDH, and key tweaks.
- Wrap and vector-test normalization of externally supplied high-S signatures;
  locally produced P256K signatures are already low-S.
- BRC-42 private/public derivation and BRC-94 proof behavior.
- Symmetric key envelopes, key shares, and backups.

## Phase 3: Key compatibility formats

Accepted checkpoint: bounded WIF and legacy P2PKH addresses for mainnet and
testnet, BIP-32 hierarchical deterministic keys, and English BIP-39 mnemonics
with the fixed standard PBKDF2 profile.

- WIF and legacy addresses. (Accepted)
- BIP-32 and BIP-39. (Accepted)
- Bitcoin Signed Message.
- Electrum- and Bitcore-compatible ECIES.

## Phase 4: Script and transaction models

In progress: bounded signed-magnitude Script numbers, raw opcode identity,
PUSHDATA parsing/building, standard structural classifiers, and the legacy
transaction wire model are implemented with permissive fixtures, pinned-Go
differentials, and Fable review.

- Transaction value/graph semantics and ADR. (Accepted)
- Script representation, parsing, ASM, opcodes, and templates that do not sign.
- Resource-bounded script numbers and era configuration.
- Transaction model, parsing, serialization, IDs, and outpoints. (Accepted)
- Fee models.
- Sighash variants and transaction-aware unlocking templates.

## Phase 5: Script execution

- Stack and control flow.
- Arithmetic, bitwise, splice, crypto, and signature opcodes.
- Pre-Genesis, Genesis, and Chronicle rules and limits.
- Full valid/invalid transaction and reference-script suites.
- Explicit compatibility rulings for Go script-number artifacts, including
  pre-Genesis clamping, overflow-until-reinterpretation, and in-place minimal
  encoding behavior.

## Phase 6: Merkle proofs and transaction envelopes

- Merkle paths and BUMP.
- BEEF and Atomic BEEF.
- SPV validation using transaction-owned chain-tracker protocols.
- Transaction graph operations and proof propagation.

Merkle/BUMP/BEEF parsing and serialization may run in parallel with Phase 5.
Only verification paths that execute scripts wait for the interpreter.

## Phase 7: Network services

- Broadcasters, chain trackers, HTTP utilities, retry/error mapping, and
  configurable endpoints.
- Cross-platform networking and mock transports.
- Linux WebSocket viability spike and fallback ADR if FoundationNetworking is
  insufficient.

## Phase 8: Wallets

- BRC-100 protocol types and capabilities.
- Proto wallet and key derivation/signing flows.
- Request/response serializers and substrates.
- Wallet encryption and certificate flows.

## Phase 9: Messages and authentication

- BRC-77 message encryption/signing.
- BRC-103 peer authentication.
- BRC-104 authenticated HTTP and WebSocket transports.
- Session, certificate, nonce, and replay protections.

## Phase 10: Overlay and application services

- Overlay topic and lookup services, SHIP/SLAP, and admin tokens.
- Identity and registry features.
- Key-value and storage/UHRP features.
- Remaining Go SDK utility and compatibility APIs.

## Phase 11: Parity hardening and release

- Close every compatibility-matrix gap.
- Differential tests against the pinned Go SDK.
- API documentation and migration examples for Go and SwiftBSV users.
- Performance, allocation, fuzz, concurrency, and security review.
- Final license and third-party notice audit; fixture licensing is resolved in
  Phase 0 rather than deferred here.
- Semantic versioning and release automation.

## Work-packet contract

Implementation agents receive bounded, non-overlapping ownership. Every packet
contains:

- Exact files and target ownership.
- Required public behavior and excluded behavior.
- Applicable BRC sections and pinned Go source references.
- Test vectors and expected failure cases.
- Dependency and API constraints.
- Completion commands and compatibility-matrix updates.

Implementation workers will use `gpt-5.6-sol` with high reasoning as requested.
They are told that other workers share the repository and must not revert or
overwrite unrelated changes.
