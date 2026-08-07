# Architecture proposal

Status: Revised after Fable review; the fixture-license Phase 0 blocker remains.

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
BSVCore
  |
  +--> BSVBigNum (internal or SPI)
  |       |
  |       +--> BSVCrypto
  |       |       |
  |       |       +--> BSVKeys
  |       |                |
  |       +--------------->+--> BSVScript
  |                                  |
  +--------------------------------->+--> BSVTransaction
  |                                           |
  +------------------------------------------>+--> BSVInterpreter
  |                                                    |
  +--------------------------------------------------->+--> BSVSPV
  |                                                            |
  +----------------------------------------------------------->+--> BSVNetwork
  |                                                                     |
  +-------------------------------------------------------------------->+--> BSVWallet
  |                                                                              |
  +----------------------------------------------------------------------------->+--> BSVAuth
                                                                                           |
                                                                                           +--> BSVServices

BSV (thin umbrella using @_exported import for public feature modules)
```

Arrows mean "is imported by." The target list is approved. A Phase 0 source
audit confirmed that P256K 0.23.2 publicly returns compressed and uncompressed
raw ECDH points, so no C shim target is required. Feature modules are the stable
import surface. The `BSV` umbrella is a
convenience layer; its use of the underscored `@_exported` attribute is confined
to one file and recorded in an ADR so it can be replaced if Swift gains a
supported re-export mechanism.

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
- secp256k1 public/private keys, ECDSA, compact recovery, ECDH, tweaks, and
  serialized key validation.
- BRC-42 key derivation, BRC-94 proof behavior, symmetric keys, Shamir shares,
  and backup formats.
- Injected secure randomness for deterministic tests.

Proposed dependencies:

- `apple/swift-crypto` 4.x (`Crypto` and `CryptoExtras`).
- `21-DOT-DEV/swift-secp256k1` 0.23.x (`P256K`).
- A small, separately audited RIPEMD-160 implementation because Swift Crypto
  does not expose RIPEMD-160.

### BSVKeys

- Base58Check, WIF, legacy addresses, BIP-32, BIP-39, Bitcoin Signed Message,
  and compatible ECIES formats.
- No transaction or script interpreter dependency.

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

- `BSVSPV` owns full SPV validation that requires script execution.
- `BSVNetwork` owns concrete chain-tracker and broadcaster implementations,
  HTTP clients, request/response models, retry behavior, and transport
  abstractions.
- `FoundationNetworking` is isolated here for Linux support.

### BSVWallet

- BRC-100 wallet protocols, proto-wallet behavior, serializers, substrates,
  certificates used by wallets, and action/signing flows.

### BSVAuth and BSVServices

- BRC-103/BRC-104 authentication, peer/client state, certificates, and HTTP or
  WebSocket transports.
- Overlay topic and lookup services, SHIP/SLAP, and admin tokens.
- Identity, registry, key-value storage, UHRP/storage, and other high-level
  services. Overlay and application services remain one target for the first
  release and may split after their APIs stabilize.
- `BSVServices` imports `BSVAuth` because identity and storage include
  authenticated certificate/fetch flows in the Go baseline. This is a
  one-directional high-level dependency, not a consensus-layer cycle.

Wallet-backed PushDrop unlocker factories live in `BSVWallet`. The underlying
PushDrop encoding, locking script, and transaction-context signer live in
`BSVTransaction`, preserving the rule that Transaction cannot import Wallet.
Likewise, WIF, legacy addresses, network versions, and BIP-32 conveniences live
in `BSVKeys` even where the Go SDK places them in EC, Script, or chaincfg
packages.

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

`attaswift/BigInt` is a candidate, not an approved dependency. A dedicated ADR
and performance/resource test suite are required before selection.

## Transaction graph semantics

The transaction model is not presumed to be a pure value type. Go inputs can
reference source transactions, and BEEF/Atomic BEEF operate on a deduplicated
ancestry graph. The first Phase 4 packet must prototype and decide between a
controlled reference graph and a value model backed by an explicit transaction
store keyed by transaction ID. The ADR must cover identity, mutation,
`Sendable`, locking or actor isolation, copy behavior, and serialization.

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
