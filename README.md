<div align="center">

# Swift BSV SDK

**A native Swift SDK for building applications on the BSV blockchain.**

[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1%2B-F05138?style=flat-square&logo=swift&logoColor=white)](https://www.swift.org/)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20iOS%20%7C%20tvOS%20%7C%20watchOS%20%7C%20visionOS-lightgrey?style=flat-square)](Package.swift)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

[Installation](#installation) · [Quick start](#quick-start) · [Capabilities](#capabilities) · [Documentation](#documentation) · [License](#license)

</div>

## Overview

Swift BSV SDK provides idiomatic, memory-safe Swift APIs for Bitcoin data,
wire encodings, hashing, symmetric cryptography, secp256k1 keys, signatures,
hierarchical deterministic keys, mnemonics, legacy key formats, and bounded
Bitcoin Script execution, transaction, Merkle-proof, and BEEF envelopes. It is
designed for behavioral and wire-format compatibility with the BSV SDK family
while embracing Swift value semantics, explicit resource bounds, and
structured errors.

The package can be imported through the `BSV` umbrella library or through its
focused `BSVCore`, `BSVCrypto`, `BSVKeys`, `BSVScript`, and `BSVTransaction`
libraries.

## Installation

Add the repository to the dependencies in your `Package.swift`:

```swift
dependencies: [
    .package(
        url: "https://github.com/opldotdev/swift-sdk",
        branch: "main"
    ),
]
```

Then add the umbrella library to the target that will use it:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "BSV", package: "swift-sdk"),
    ]
)
```

Import the package through its umbrella module:

```swift
import BSV
```

## Quick start

Encode and decode Bitcoin data with explicit resource limits:

```swift
import BSV

let payload = try Hex.decode(
    "deadbeef",
    maximumDecodedByteCount: 4
)

let framed = CompactSize.encodeVarBytes(payload)
let decoded = try CompactSize.decodeVarBytes(
    framed,
    maximumLength: 4
)

let base58 = Base58.encode(decoded.bytes)
print(base58)

let digest = BSVHashing.sha256d(decoded.bytes)
let checked = Base58Check.encode(digest.bytes)
print(checked)

let script = try Script(
    hex: "76a914000000000000000000000000000000000000000088ac",
    maximumByteCount: 25
)
print(script.isPayToPublicKeyHash)
```

Low-level decoders that can expand input require an explicit maximum output
size. Higher-level formats apply protocol-specific limits internally.

Derive standard BIP-39 and BIP-32 keys without exposing configurable legacy
KDF parameters:

```swift
import BSV

let mnemonic = try Mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
let seed = try mnemonic.seed(passphrase: "TREZOR")
let master = try ExtendedPrivateKey(seed: seed.bytes, network: .mainnet)
let account = try master.derived(path: "m/44'/236'/0'")

print(account.neutered.serialized)
```

## Capabilities

- Canonical Bitcoin CompactSize integers and length-prefixed byte strings
- Bounded Hex, Base64, Bitcoin Base58, and Base58Check encoding and decoding
- Transaction identifiers with explicit wire and display byte order
- Bounded legacy and ForkID signature preimages, including historical
  SIGHASH_SINGLE behavior, and transactional P2PKH input signing
- UTXO-backed transaction construction, checked satoshi fees, projected
  unsigned-input sizes, and atomic equal change distribution
- Fixed-width `Hash160`, `Hash256`, and `Hash512` value types
- SHA-256, double-SHA-256, SHA-512, HMAC, RIPEMD-160, and HASH160
- HMAC-SHA256 deterministic random bit generation
- AES-CBC with PKCS#7 padding and detached AES-GCM authenticated encryption
- Validated secp256k1 private keys and compressed, uncompressed, or hybrid
  public-key parsing backed by libsecp256k1
- Deterministic digest-level ECDSA with strict DER and compact signatures
- Deterministic recoverable ECDSA with typed, nontrapping recovery failures
- Raw-point ECDH plus additive and multiplicative secp256k1 key tweaks
- Wallet Import Format and legacy P2PKH addresses on mainnet and testnet
- English BIP-39 mnemonics with NFKD normalization and fixed
  PBKDF2-HMAC-SHA512 seed derivation
- BIP-32 extended private and public keys, child derivation, canonical paths,
  and xprv/xpub/tprv/tpub serialization
- Bounded Bitcoin Script bytes, BRC-106 ASM and compact SASM, raw opcode and
  PUSHDATA parsing, signed-magnitude numbers, and P2PK/P2PKH/P2SH/BRC-18 templates
- Era-aware Bitcoin Script execution with control flow, stack, splice, bitwise,
  arbitrary-precision numeric, hashing, P2SH, legacy/ForkID CHECKSIG,
  CHECKMULTISIG, CLTV/CSV, and Chronicle behavior under explicit resource limits
- Bounded legacy transaction parsing and canonical serialization, outpoints,
  transaction IDs, coinbase recognition, and checked satoshi totals
- Bounded BRC-74 BUMP binary and strict JSON codecs, Merkle-root computation,
  duplicate branches, compound paths, and conflict-checked proof merging
- Bounded BRC-62/BRC-96 BEEF v1/v2 and BRC-95 Atomic BEEF codecs with ordered
  dependency validation and explicit transaction-ID-only trust policy
- Async, transport-independent chain tracking with BUMP and BEEF root
  verification through the `BSVSPV` proof façade
- Immutable BEEF graph merge, proof propagation, BRC-96 txid-only projection,
  and known-ID trimming with stable parent-before-child ordering
- Redacted default descriptions for mnemonics and extended private keys, with
  explicitly named properties for intentional secret export
- Swift 6 value semantics, structured errors, and `Sendable` public values
- Unified `BSV` import plus focused core, cryptography, and key libraries

## Documentation

- [Architecture](Documentation/Planning/Architecture.md)
- [Compatibility](Documentation/Compatibility/README.md)
- [Roadmap](Documentation/Planning/Roadmap.md)
- [Testing and conformance](Documentation/Planning/Testing.md)
- [Architecture decisions](Documentation/ADRs/README.md)
- [Third-party notices](NOTICE.md)

## License

Swift BSV SDK is available under the [MIT License](LICENSE). Third-party
dependencies and test vectors retain their respective licenses as described in
[NOTICE.md](NOTICE.md).
