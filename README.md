<div align="center">

# ⛓️ BSV Blockchain | Swift SDK

**A unified, peer-to-peer, SPV-first SDK for scalable BSV applications in Swift.**

<br/>

<table align="center" border="0">
  <tr>
    <td align="right"><code>CI / CD</code>&nbsp;&nbsp;</td>
    <td align="left">
      <a href="https://github.com/opldotdev/swift-sdk/actions/workflows/ci.yml"><img src="https://github.com/opldotdev/swift-sdk/actions/workflows/ci.yml/badge.svg?branch=main" alt="Build"></a>
      <a href="https://github.com/opldotdev/swift-sdk/commits/main"><img src="https://img.shields.io/github/last-commit/opldotdev/swift-sdk?style=flat-square&amp;logo=git&amp;logoColor=white&amp;label=last%20update" alt="Last update"></a>
    </td>
    <td align="right">&nbsp;&nbsp;&nbsp;&nbsp;<code>Runtime</code>&nbsp;&nbsp;</td>
    <td align="left">
      <a href="https://www.swift.org/"><img src="https://img.shields.io/badge/Swift-6.1%2B-F05138?style=flat-square&amp;logo=swift&amp;logoColor=white" alt="Swift 6.1 or later"></a>
      <a href="Package.swift"><img src="https://img.shields.io/badge/platforms-Apple%20%7C%20Linux-lightgrey?style=flat-square" alt="Apple and Linux platforms"></a>
    </td>
  </tr>
  <tr>
    <td align="right"><code>License</code>&nbsp;&nbsp;</td>
    <td align="left">
      <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License"></a>
    </td>
    <td align="right">&nbsp;&nbsp;&nbsp;&nbsp;<code>Community</code>&nbsp;&nbsp;</td>
    <td align="left">
      <a href="https://github.com/opldotdev/swift-sdk/graphs/contributors"><img src="https://img.shields.io/github/contributors/opldotdev/swift-sdk?style=flat-square&amp;color=orange" alt="Contributors"></a>
    </td>
  </tr>
</table>

</div>

<br/>

<div align="center">

### <code>Project Navigation</code>

</div>

<table align="center">
  <tr>
    <td align="center" width="25%">📦&nbsp;<a href="#-installation"><code>Installation</code></a></td>
    <td align="center" width="25%">🚀&nbsp;<a href="#-basic-usage"><code>Basic&nbsp;Usage</code></a></td>
    <td align="center" width="25%">✨&nbsp;<a href="#-features"><code>Features</code></a></td>
    <td align="center" width="25%">🧪&nbsp;<a href="#-examples"><code>Examples</code></a></td>
  </tr>
  <tr>
    <td align="center">📚&nbsp;<a href="#-documentation"><code>Documentation</code></a></td>
    <td align="center">🧰&nbsp;<a href="#-tests"><code>Tests</code></a></td>
    <td align="center">🛠️&nbsp;<a href="#-code-standards"><code>Code&nbsp;Standards</code></a></td>
    <td align="center">👤&nbsp;<a href="#-maintainer"><code>Maintainer</code></a></td>
  </tr>
  <tr>
    <td align="center">🧱&nbsp;<a href="#-modules"><code>Modules</code></a></td>
    <td align="center">🤝&nbsp;<a href="#-contributing"><code>Contributing</code></a></td>
    <td align="center">📝&nbsp;<a href="#-license"><code>License</code></a></td>
    <td align="center">🔗&nbsp;<a href="Documentation/Compatibility/GoSDK-v1.3.3.md"><code>Go&nbsp;Parity</code></a></td>
  </tr>
</table>

<br/>

## 🧩 What is in the SDK

The Swift SDK supplies the main data types and functions for BSV applications.
It supports cryptography, keys, Script, transactions, Merkle proofs,
Background Evaluation Extended Format (BEEF), Simplified Payment Verification
(SPV), wallet cryptography, messages, ARC, and WhatsOnChain services.

The SDK uses Swift value types and typed errors. Public values that cross tasks
conform to `Sendable`. Decoders use explicit limits when input can cause large
memory use.

Use the `BSV` library to import all public modules. You can import a focused
library when you need a smaller dependency set.

## Requirements

| Item | Minimum version |
| --- | --- |
| Swift | 6.1 |
| macOS | 13 |
| iOS and tvOS | 16 |
| watchOS | 9 |
| visionOS | 1 |
| Linux | Swift 6.1 toolchain |

## 📦 Installation

Add the package to `Package.swift`:

```swift
dependencies: [
    .package(
        url: "https://github.com/opldotdev/swift-sdk",
        branch: "main"
    ),
]
```

Add the `BSV` product to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "BSV", package: "swift-sdk"),
    ]
)
```

Import the SDK:

```swift
import BSV
```

## 🚀 Basic usage

The following example creates a key and a mainnet address:

```swift
import BSV

// This fixed key is for an example only. Do not use it for funds.
let privateKey = try PrivateKey(
    [UInt8](repeating: 0, count: 31) + [1]
)
let address = LegacyAddress(
    publicKey: privateKey.publicKey,
    network: .mainnet
)

print(address)
```

The following example decodes bounded data and creates a Script value:

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

let script = try Script(
    hex: "76a914000000000000000000000000000000000000000088ac",
    maximumByteCount: 25
)

print(Base58.encode(decoded.bytes))
print(script.isPayToPublicKeyHash)
```

## ✨ Features

### Transactions and SPV

- Builds and signs P2PKH transactions.
- Calculates checked fees and change outputs.
- Parses raw transactions and BRC-30 Extended Format transactions.
- Creates BRC-307 inscriptions and specific-ordinal outputs.
- Calculates legacy and ForkID signature hashes.
- Parses BRC-74 BUMP proofs.
- Parses BRC-62, BRC-95, and BRC-96 BEEF envelopes.
- Verifies BRC-67 SPV proofs with an injected chain tracker.

### Script

- Parses raw opcodes and PUSHDATA operations.
- Reads and writes bounded BIP-276 text.
- Reads and writes BRC-106 ASM and compact SASM.
- Builds P2PK, P2PKH, P2SH, and BRC-18 scripts.
- Runs Script with explicit limits and network-era rules.
- Supports CHECKSIG, CHECKMULTISIG, CLTV, CSV, and Chronicle rules.

### Cryptography and keys

- Supplies SHA-256, SHA-512, HMAC, RIPEMD-160, and HASH160.
- Supplies AES-CBC, AES-GCM, and HMAC-DRBG.
- Uses libsecp256k1 for keys, ECDSA, recovery, ECDH, and key tweaks.
- Supports BRC-42 child keys and BRC-94 shared-secret proofs.
- Supports BIP-32 keys and English BIP-39 mnemonics.
- Supports WIF, legacy P2PKH addresses, BSM, and legacy ECIES.
- Supports BRC-140 key shares for offline backups.

### Wallets, messages, and network services

- Supplies seven offline BRC-100 cryptographic wallet calls.
- Reads and writes bounded Go-compatible JSON for these calls.
- Issues, acquires, projects, and verifies offline BRC-52 certificates.
- Signs BRC-77 portable messages.
- Encrypts BRC-78 portable messages.
- Tracks chain data with the unauthenticated WhatsOnChain service.
- Broadcasts with ARC and WhatsOnChain.
- Verifies each broadcast transaction ID against the local transaction ID.

### Safety

- Uses explicit limits for bounded parsing and cryptographic input.
- Uses typed errors instead of process termination.
- Redacts secret values from default descriptions and reflection.
- Reports an ARC response failure after POST as uncertain delivery.
- Compares specified wire formats with the pinned Go SDK v1.3.3.

## 🧱 Modules

| Module | Purpose |
| --- | --- |
| `BSV` | Imports all public SDK modules. |
| `BSVCore` | Supplies bytes, fixed hashes, encodings, and CompactSize. |
| `BSVCrypto` | Supplies hashes, symmetric cryptography, and secp256k1. |
| `BSVKeys` | Supplies key formats, addresses, BIP-32, BIP-39, BSM, and ECIES. |
| `BSVScript` | Supplies Script data, BIP-276, opcodes, ASM, numbers, and templates. |
| `BSVTransaction` | Supplies transactions, inscriptions, fees, signing, BUMP, and BEEF. |
| `BSVInterpreter` | Runs Bitcoin Script with explicit limits. |
| `BSVSPV` | Verifies BRC-67 SPV proofs. |
| `BSVNetwork` | Supplies ARC, chain tracking, and transaction broadcast services. |
| `BSVWallet` | Supplies offline BRC-100 cryptography and BRC-52 certificate values. |
| `BSVAuth` | Supplies portable messages and offline certificate workflows. |

## 🧪 Examples

### Hierarchical keys

Create a BIP-39 seed and derive a BIP-32 account key:

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

### BIP-276

Encode a Script payload as bounded BIP-276 text:

```swift
import BSV

let limits = try BIP276Limits(
    maximumTextByteCount: 4_096,
    maximumPrefixByteCount: 64,
    maximumDataByteCount: 2_048
)
let value = BIP276(
    prefix: BIP276.scriptPrefix,
    version: BIP276.currentVersion,
    network: BIP276.mainnet,
    data: [0x51]
)

print(try value.encoded(limits: limits))
```

## 📚 Documentation

- [Architecture](Documentation/Planning/Architecture.md)
- [Compatibility decisions](Documentation/Compatibility/README.md)
- [Roadmap](Documentation/Planning/Roadmap.md)
- [Tests and conformance](Documentation/Planning/Testing.md)
- [Architecture decisions](Documentation/ADRs/README.md)
- [Third-party notices](NOTICE.md)

## 🧰 Tests

Run the complete Swift test suite:

```bash
swift test --disable-sandbox
```

GitHub Actions runs the test suite on macOS and Linux. It also checks the
public API and compares supported wire behavior with the pinned Go SDK v1.3.3.

## 🛠️ Code standards

- Use Swift 6 language mode and strict concurrency checks.
- Use typed errors for invalid input and failed operations.
- Set explicit limits for data that comes from outside the process.
- Add unit tests and conformance tests for each wire format.
- Keep secret values out of descriptions, reflection, and error text.

## 👤 Maintainer

Luke maintains this repository.

| [<img src="https://github.com/rohenaz.png" height="50" alt="Luke" />](https://github.com/rohenaz) |
|:---:|
| [Luke](https://github.com/rohenaz) |

## 🤝 Contributing

Contributions are welcome.

1. Fork and clone the repository.
2. Create a branch for one change.
3. Add tests for the change.
4. Run `swift test --disable-sandbox`.
5. Open a pull request.

## 📝 License

The Swift SDK uses the [MIT License](LICENSE).

Third-party dependencies and test vectors keep their original licenses. See
[NOTICE.md](NOTICE.md) for details.
