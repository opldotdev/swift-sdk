# Delivery roadmap

Status: P0 complete; foundational P1/P2 crypto and P3 key formats are accepted
after independent and Fable review. BigNum, Script, bounded raw and Extended
Format transactions, BRC-74 Merkle paths, and BEEF v1/v2 plus Atomic BEEF are
accepted. BIP-276, BRC-307 inscriptions, ARC, the offline BRC-52 certificate
engine, and the first wallet and portable-message checkpoints are also
accepted. Work proceeds by dependency and can land out of phase order. An
accepted checkpoint does not imply that every earlier phase is complete.

Each milestone ends with passing conformance tests, an updated compatibility
matrix, and an advisor review at architectural or security-sensitive boundaries.
Milestone completion is based on behavior, not file count.

## Phase 0: Repository foundation

- Approve the target graph and dependency policy.
- Record the completed P256K raw-point ECDH audit; no C shim is required.
- Resolve fixture licensing and provenance before copying upstream material.
- Create `Package.swift`, CI for Apple and Linux, documentation conventions,
  and ADR templates.
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
key tweaks. BRC-42 bilateral private/public derivation and BRC-94 verifiable
shared-secret proofs are accepted with bidirectional pinned-Go differentials.
The injectable operating-system secure-randomness seam and Go-compatible
AES-256-GCM symmetric-key envelope are accepted with bidirectional pinned-Go
differentials. BRC-140 key sharing and recovery are accepted with strict
canonical parsing and bounded offline interpolation.

- AES block/CBC/GCM and PKCS#7 behavior.
- HMAC-DRBG.
- secp256k1 key parsing and serialization.
- Deterministic ECDSA, DER/BER handling, low-S normalization, compact recovery,
  ECDH, and key tweaks.
- Wrap and vector-test normalization of externally supplied high-S signatures;
  locally produced P256K signatures are already low-S.
- BRC-42 private/public derivation and BRC-94 proof behavior. (Accepted)
- Injectable secure randomness. (Accepted)
- Symmetric key envelopes. (Accepted)
- BRC-140 key shares and backups. (Accepted)

## Phase 3: Key compatibility formats

Accepted checkpoint: `BSVKeys` contains bounded WIF and P2PKH addresses for
mainnet and testnet. The opt-in `BSVCompat` product contains BIP-32 hierarchical
deterministic keys, English BIP-39 mnemonics with the fixed standard PBKDF2
profile, Bitcoin Signed Message, and Electrum- and Bitcore-compatible ECIES.

- WIF and P2PKH addresses. (Accepted)
- BIP-32 and BIP-39. (Accepted)
- Bitcoin Signed Message. (Accepted)
- Electrum- and Bitcore-compatible ECIES. (Accepted)

## Phase 4: Script and transaction models

Accepted checkpoint: bounded signed-magnitude Script numbers, raw opcode
identity, PUSHDATA parsing/building, standard structural classifiers, raw
transactions, and explicit BRC-30/BIP-239 Extended Format transactions are
implemented with permissive fixtures, pinned-Go differentials, and Fable
review. Extended Format carries each input's source output; raw serialization,
transaction IDs, equality, and hashing remain unchanged. Parsing requires an
explicit wire format so marker-like raw transactions are never auto-detected.
BIP-276 text and BRC-307 inscription construction are also accepted with
explicit input and output limits. Strict bounded Script JSON is accepted with
bidirectional pinned-Go checks for canonical lowercase documents and an
explicit ruling for the pinned unmarshal artifacts. Strict bounded transaction
JSON is accepted with complete redundant-field checks and bidirectional
pinned-Go coverage.

- Transaction value/graph semantics and ADR. (Accepted)
- Script representation, parsing, ASM, strict bounded JSON, opcodes, and
  templates that do not sign. (Accepted)
- Resource-bounded script numbers and era configuration.
- Transaction model, parsing, serialization, IDs, and outpoints. (Accepted)
- Strict transaction, input, and output JSON compatibility. (Accepted)
- Extended Format parsing and serialization with source outputs. (Accepted)
- Bounded BIP-276 text encoding and decoding. (Accepted)
- BRC-307 basic, enriched, and specific-ordinal inscriptions. (Accepted)
- Fee models and checked equal change distribution. (Accepted)
- ForkID sighash variants and P2PKH transaction signing. (Accepted)

## Phase 5: Script execution

Accepted checkpoint: the bounded interpreter now covers stack/control flow,
splice, bitwise, arbitrary-precision arithmetic, hashing, P2SH, legacy and
ForkID `CHECKSIG`, `CHECKMULTISIG`, CLTV/CSV, and Chronicle version/slice/shift
rules. A selected pinned-Go corpus covers stack, failure, full-transaction
signature, and script-cleanup behavior on consensus-sensitive paths.

- Stack and control flow. (Accepted)
- Arithmetic, bitwise, splice, and crypto opcodes. (Accepted)
- Pre-Genesis, Genesis, and Chronicle rules and limits. (Accepted checkpoint)
- Legacy signature hashing and `CHECKMULTISIG`/`CHECKMULTISIGVERIFY`. (Accepted)
- Full valid/invalid transaction and reference-script suites.
- Explicit compatibility rulings for Go script-number artifacts, including
  pre-Genesis clamping, overflow-until-reinterpretation, and in-place minimal
  encoding behavior.

## Phase 6: Merkle proofs and transaction envelopes

- Merkle paths and BUMP. (Accepted)
- BEEF and Atomic BEEF. (Accepted)
- Transaction-owned chain-tracker protocol and BUMP/BEEF root verification.
  (Accepted)
- Full BRC-67 source resolution, value/fee, Script, lock-condition, and trusted
  Merkle-root validation in `BSVSPV`. (Accepted checkpoint)
- Canonical 80-byte block-header parsing, serialization, and hashing. (Accepted)
- Bounded BEEF merge, txid-only projection, known-ID trimming, and proof
  propagation. (Accepted)

Merkle/BUMP/BEEF parsing and serialization may run in parallel with Phase 5.
The accepted BRC-67 checkpoint composes the signature/multisignature interpreter
with BEEF ancestry and injected chain/fee policy. Network finality data remains
caller-owned rather than hard-wired to a service.

## Phase 7: Network services

Accepted checkpoint: `BSVNetwork` provides a bounded URLSession transport on
Apple platforms and Linux, typed network errors, and an unauthenticated
WhatsOnChain chain tracker for mainnet and testnet. Chain lookups use bounded
transient retries. The WhatsOnChain broadcaster submits each transaction once
and accepts the result only when the provider's canonical transaction ID
matches the locally computed ID. A cancellation or transport failure after the
POST begins can still leave delivery uncertain; callers must reconcile before
submitting again. The ARC client uses the same one-POST rule, validates ARC
status responses, and reports every non-rejection response failure after POST
as uncertain delivery.

- Bounded cross-platform HTTP transport and mockable package transport seam.
  (Accepted)
- Unauthenticated WhatsOnChain height and Merkle-root tracking. (Accepted)
- One-shot WhatsOnChain broadcasting with local transaction-ID verification.
  (Accepted)
- ARC broadcasting and status lookup with bounded responses. (Accepted)
- Additional broadcasters and authenticated service clients. (Future)
- Linux WebSocket viability spike and fallback ADR if FoundationNetworking is
  insufficient. (Future)

## Phase 8: Wallets

Accepted checkpoint: `BSVWallet` provides the offline BRC-100 cryptographic
kernel: validated identifiers and request/result values, stateless BRC-42 key
derivation, bounded JSON, and `ProtoWallet` public-key, encryption, HMAC, and
signature operations. The offline BRC-52 certificate checkpoint supplies
bounded certificate values, keyrings, signing, field encryption, acquisition,
projection, and cryptographic verification. These checkpoints have no
persistence, network substrate, revocation lookup, or interactive permission
policy.

- BRC-100 crypto protocol types and capability protocols. (Accepted)
- ProtoWallet key derivation, public-key, encryption, HMAC, and signing flows.
  (Accepted)
- Bounded Go-compatible request/result JSON for the seven cryptographic calls.
  (Accepted)
- Strict bounded wallet-wire framing and typed binary codecs for the seven
  cryptographic calls plus authentication, height/header, network, and version
  queries. (Accepted)
- Strict bounded wallet-wire action and output-query codecs for calls 1 through
  7, with explicit BEEF limits. (Accepted)
- Offline BRC-52 certificate values, keyrings, and binary codecs. (Accepted)
- Strict bounded wallet-wire certificate, discovery, and linkage codecs for
  calls 9, 10, and 17 through 22. (Accepted)
- Transport-neutral wallet-wire processor and transceiver for all 28 calls,
  with an injected originator authorizer. (Accepted)
- Persistent wallet state, HTTP or WebSocket remote execution, and interactive
  permission policy. (Future)
- Chain-aware certificate revocation checks. (Future)

## Phase 9: Messages and authentication

Accepted checkpoint: `BSVMessage` provides canonical BRC-77 portable signed
messages and BRC-78 portable encrypted messages, including recipient-specific
BRC-42 derivation and the BRC-77 anyone mode. `BSVAuth` supplies offline BRC-52
issue, acquire, project, and verify workflows.

- BRC-77 portable signed messages. (Accepted)
- BRC-78 portable encrypted messages. (Accepted)
- Offline BRC-52 certificate workflows. (Accepted)
- BRC-103 peer authentication and bounded session, nonce, and replay protection.
  (Accepted)
- Transport-neutral BRC-104 request and response payloads. (Accepted)
- Bounded transport-neutral BRC-104 authenticated HTTP framing. (Accepted)
- Signed bounded BRC-103 post-authentication certificate exchange and exact
  BRC-52 disclosure validation. (Accepted)
- Certificate-gated initial-handshake policy and chain-aware revocation checks.
  (Future)
- Concrete BRC-104 HTTP and WebSocket transports, AuthFetch policy, and
  automatic payment. (Future)

## Phase 10: Overlay and application services

Accepted checkpoint: `BSVOverlay` provides bounded SHIP and SLAP values,
strict signed administration-token verification, deterministic bounded lookup
resolution, and one-shot topic broadcast policy. `BSVNetwork` provides the
bounded HTTPS lookup and topic facilitators. The implementation has no default
tracker, retry, persistence, or wallet-backed token construction or spending.
The package does not expose an empty general services module. Each implemented
family uses a clear module name. `BSVIdentity` provides bounded parsing,
wallet-backed resolution, and public disclosure through an injected
broadcaster.

- Bounded overlay topic and lookup values and facilitator protocols. (Accepted)
- Strict signed overlay administration-token verification. (Accepted)
- Bounded overlay HTTPS facilitators and deterministic resolver and broadcaster
  policy. (Accepted)
- Wallet-backed administration-token construction or spending. (Future)
- Transport-neutral identity core. (Accepted)
- Transport-neutral registry core. (Accepted)
- Transport-neutral one-field key-value token core. (Accepted)
- Transport-neutral UHRP identifier and content core. (Accepted)
- Bounded UHRP overlay discovery and verified HTTPS download. (Accepted)
- Registry lookup transport, discovery, wallet publication, and revocation.
  (Future)
- Wallet-backed key-value orchestration and authenticated storage upload
  features. (Future)
- Remaining Go SDK utility and compatibility APIs.

## Phase 11: Parity hardening and release

- The pinned 51-family product inventory has 50 represented Swift families.
  Conservative weighted behavior coverage is approximately 93 percent.
  (Accepted)
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
