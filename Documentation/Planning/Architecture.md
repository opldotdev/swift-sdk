# Architecture proposal

Status: Implemented target graph, revised after architecture and primitive reviews.

## Design constraints

The package must provide one coherent SDK while keeping consensus-critical
components independently testable. The Go package graph cannot be mirrored
directly: transaction signing, script templates, and script execution create
conceptual cycles when collapsed into large Swift targets.

Public APIs should use Swift value types, explicit throwing initializers, and
bounded parsers. Cryptographic or consensus behavior must not depend on locale,
platform integer width, implicit string conversion, or Foundation serialization.

## Proposed target graph

```text
BSVBigNum      -> BSVCore
BSVCrypto      -> BSVCore, BSVBigNum
BSVKeys        -> BSVCore, BSVBigNum, BSVCrypto
BSVMessage     -> BSVCore, BSVCrypto, BSVKeys
BSVScript      -> BSVCore, BSVBigNum, BSVCrypto, BSVKeys
BSVTransaction -> BSVCore, BSVCrypto, BSVKeys, BSVScript
BSVInterpreter -> BSVCore, BSVBigNum, BSVCrypto, BSVKeys, BSVScript, BSVTransaction
BSVSPV         -> BSVCore, BSVCrypto, BSVTransaction, BSVInterpreter
BSVNetwork     -> BSVCore, BSVTransaction, BSVSPV
BSVOverlay     -> BSVCore, BSVTransaction
BSVWallet      -> BSVCore, BSVCrypto, BSVKeys, BSVScript, BSVTransaction
BSVAuth        -> BSVCore, BSVCrypto, BSVKeys, BSVTransaction, BSVWallet

BSV (thin umbrella using @_exported import for public feature modules)

BSVCompat (opt-in; depends on BSVCore, BSVCrypto, and BSVKeys)
```

Arrows point from each target to its direct imports. The target list is
approved. A Phase 0 source
audit confirmed that P256K 0.23.2 publicly returns compressed and uncompressed
raw ECDH points, so no C shim target is required. Modern feature modules are the stable
import surface. The `BSV` umbrella is a
convenience layer; its use of the underscored `@_exported` attribute is confined
to one file and recorded in an ADR so it can be replaced if Swift gains a
supported re-export mechanism. `BSVCompat` is outside this umbrella and the
modern dependency spine.

## Proposed responsibilities

### BSVCore

- Byte cursor and bounded binary writer.
- Hex and base encodings that do not require cryptography.
- Bitcoin variable integers and fixed-width little-endian encoding.
- Constant-size digest, transaction ID, outpoint, satoshi, and network value
  types where their dependency direction is safe.
- Error taxonomy shared by lower layers.

`BSVCore` must not depend on Foundation networking, secp256k1, or higher-level
protocols. `Data` interoperability may be provided at boundaries while internal
parsers operate on byte collections with explicit limits.

The package will use a small internal bounded cursor rather than adopting the
pre-1.0 `swift-binary-parsing` dependency. Declared lengths must be checked
against remaining bytes before allocation.

### BSVBigNum

- Shared arbitrary-precision magnitude and modular arithmetic below both
  `BSVCrypto` and `BSVScript`.
- Bitcoin sign-magnitude encoding remains a Script-layer concern, while field
  operations needed by Shamir/key shares are available to Crypto.
- The implementation boundary is internal or SPI so a vetted dependency can be
  replaced without public API surgery.
- A native-integer fast path may be used when it preserves identical behavior.

### BSVCrypto

- SHA-256, double SHA-256, SHA-512, HMAC-SHA256, HMAC-SHA512, RIPEMD-160,
  HASH160, and constant-time comparisons.
- AES-GCM, AES-CBC with PKCS#7, raw AES block behavior required by parity, and
  HMAC-DRBG.
- Symmetric key envelopes and HMAC-DRBG.
- Injected secure randomness for deterministic tests.

Proposed dependencies:

- `apple/swift-crypto` 4.x (`Crypto` and `CryptoExtras`).
- A small, separately audited RIPEMD-160 implementation because Swift Crypto
  does not expose RIPEMD-160.

### BSVKeys

- secp256k1 public/private keys, ECDSA, compact recovery, ECDH, tweaks, and
  serialized key validation.
- BRC-42 key derivation, BRC-94 proof behavior, Shamir shares, and backup
  formats.
- Base58Check, WIF, P2PKH addresses, and network versions.
- No transaction or script interpreter dependency.

Proposed dependency:

- `21-DOT-DEV/swift-secp256k1` 0.23.x (`P256K`).

### BSVCompat

- Bitcoin Signed Message compatibility APIs. New applications should use
  BRC-77 `SignedMessage` from `BSVMessage`.
- Electrum and Bitcore ECIES compatibility APIs. New applications should use
  BRC-78 `EncryptedMessage` from `BSVMessage`.
- BIP-32 extended keys. New protocol-key applications should use BRC-42.
- BIP-39 mnemonic backup and import workflows.
- An opt-in public product outside the `BSV` umbrella and modern dependency
  spine.

### BSVScript

- Script bytecode, opcodes, parsing, serialization, ASM, minimal-push rules,
  boolean casting, and script-number encoding.
- Locking script construction that does not require a transaction signature.
- A resource-bounded arbitrary-precision script number abstraction.

This layer must not import the transaction model. Unlocking templates that sign
a transaction belong above the transaction layer.

### BSVTransaction

- Transaction inputs, outputs, serialization, parsing, IDs, sighash,
  signature scopes, fee models, BUMP, BEEF, Atomic BEEF, merkle paths, and
  transaction templates that require signing context.
- Protocol-based signers and source-transaction resolution.
- `ChainTracker` and `Broadcaster` protocols required by transaction, merkle,
  and BEEF operations. Concrete network clients do not live here.

### BSVInterpreter

- Consensus-era configuration and execution engine.
- Stack, opcode implementations, transaction-aware signature checks, limits,
  and pre-Genesis, Genesis, and Chronicle behavior.

It imports both script representation and transactions, breaking the otherwise
cyclic relationship.

### BSVSPV and BSVNetwork

- `BSVSPV` owns block headers and full SPV validation that requires script execution.
- `BSVNetwork` owns concrete chain-tracker and broadcaster implementations,
  HTTP clients, request/response models, retry behavior, and transport
  abstractions. It imports `BSVSPV` for the block-header values exposed by the
  block-headers-service client; the dependency remains one-way.
- `FoundationNetworking` is isolated here for Linux support.

### BSVWallet

- BRC-100 wallet protocols, proto-wallet behavior, serializers, substrates,
  certificates used by wallets, and action/signing flows.

### BSVMessage

- Bounded BRC-77 portable signed messages.
- Bounded BRC-78 portable encrypted messages.
- No Wallet, Auth, Script, Transaction, or Network dependency.

### BSVAuth

- Offline certificate workflows.
- Future BRC-103/BRC-104 authentication, peer/client state, and HTTP or
  WebSocket transports.
- No portable-message declarations or aliases.

Future overlay, identity, registry, key-value, and storage work must use named
modules after each public boundary is implemented. The package does not expose
an empty general services module.

Wallet-backed PushDrop unlocker factories live in `BSVWallet`. The underlying
PushDrop encoding, locking script, and transaction-context signer live in
`BSVTransaction`, preserving the rule that Transaction cannot import Wallet.
Likewise, WIF, P2PKH addresses, and network versions live in `BSVKeys` even
where the Go SDK places them in EC, Script, or chaincfg packages. BIP-32 is in
the opt-in `BSVCompat` module.

## Big-integer boundary

Arbitrary precision is both cryptographic and consensus functionality, not a
convenience dependency. Shamir/key-share polynomial arithmetic needs modular
big integers in Phase 2, while the current Go SDK accepts script numbers up to
750 KB after Genesis and 32 MB after Chronicle. A candidate implementation must
be tested in Phase 1 for:

- Sign-magnitude little-endian Bitcoin encoding and minimality.
- Addition, subtraction, multiplication, division, remainder, and arithmetic
  shifts at protocol boundaries.
- Predictable allocation and operation limits for hostile scripts.
- Linux and Apple parity.
- No trapping conversions to native Swift integers.

`attaswift/BigInt` 5.7.0 is exact-pinned behind the internal `BSVBigNum` target.
The adapter, signed-magnitude codec, public-symbol isolation check, and macOS
and memory-capped Linux 750 KB/32 MiB resource gates pass. ADR 0004 records the
accepted dependency and evidence.

## Transaction graph semantics

ADR 0005 selects value-semantic transactions backed by an explicit ancestry
graph/store for BEEF and Atomic BEEF. Inputs may carry source-output signing
metadata, but hydration does not affect wire serialization, equality, or
hashing. Complete parent transactions are keyed by transaction ID outside the
wire value, avoiding recursive aliasing while preserving graph deduplication.

## Phase 0 dependency gates

- P256K raw/compressed ECDH is confirmed. Phase 2 must add a narrow wrapper for
  normalizing externally supplied high-S ECDSA signatures; the vendored C API
  already exposes the operation and no new target is required.
- Resolve how Open BSV-licensed test material may be used in an MIT repository
  before creating fixture directories or copying data.
- Record the umbrella-module `@_exported` tradeoff in an ADR.
- Use Swift 6.1 or newer and the default P256K traits.

## API and safety conventions

- Parsing entry points take explicit limits and reject trailing data unless the
  API says otherwise.
- Secret-bearing types avoid `CustomStringConvertible` output of secret bytes.
- Randomness is injected through a narrow protocol; production defaults use the
  operating system CSPRNG.
- Keys and signatures validate invariants at construction.
- Errors are typed by domain and preserve a stable category without promising
  exact Go error strings.
- Mutable reference semantics require an explicit justification. Value types
  are the default.
- Concurrency annotations are designed from the start under Swift 6 strict
  concurrency rather than retrofitted.
- Network-facing APIs are `async`/`await` native. A Phase 7 spike must prove
  Linux WebSocket support or select an isolated fallback transport dependency.

## Dependency acceptance rule

A runtime dependency requires an ADR documenting license, maintenance activity,
supported platforms, transitive dependencies, cryptographic provenance,
release pinning, and the cost of replacing it. Consensus-critical behavior must
remain covered by SDK-owned vectors even when delegated to a dependency.
