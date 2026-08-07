<div align="center">

# Swift BSV SDK

**An idiomatic, peer-to-peer and SPV-first Swift SDK for the BSV blockchain.**

[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1%2B-F05138?style=flat-square&logo=swift&logoColor=white)](https://www.swift.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

[What's inside](#whats-inside) · [Installation](#installation) · [Module map](#module-map) · [Status](#current-status) · [Conformance](#conformance-and-testing) · [Documentation](#documentation) · [Development](#development) · [Contributing](#contributing) · [License](#license)

</div>

## What's inside

This package is being built toward complete behavioral and wire-format parity
with [`bsv-blockchain/go-sdk`](https://github.com/bsv-blockchain/go-sdk), with
peer-to-peer operation and simplified payment verification (SPV) as first-class
design concerns.

The public API will follow Swift conventions instead of reproducing the Go
package layout. The package targets supported Apple platforms and Linux, uses
Swift 6 strict concurrency as an architectural constraint, and develops each
primitive against known-answer, differential, property, and negative tests.

The repository is still in its foundation phase. The target graph and
conformance infrastructure are present, but the SDK does not yet implement the
transaction, wallet, or service APIs described by the compatibility plans.

## Installation

> [!WARNING]
> This package is pre-release and not ready for production use. Its public API
> and module boundaries may change while primitive implementation is underway.

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

The import currently exposes the package skeleton. There is no transaction or
wallet usage example yet because those APIs have not been implemented.

## Module map

The feature modules are intended to become stable import boundaries. The
responsibilities below are planned; they are not claims of completed behavior.

| Module | Planned responsibility |
| --- | --- |
| `BSV` | Thin convenience module that re-exports the public feature modules. |
| `BSVCore` | Bounded byte parsing and writing, encodings, Bitcoin variable integers, identifiers, value types, and shared errors. |
| `BSVBigNum` | Internal arbitrary-precision arithmetic shared by cryptographic and Script implementations; it is not a public library product. |
| `BSVCrypto` | Hashing, symmetric encryption, secp256k1 operations, signatures, key derivation, and deterministic-testable randomness. |
| `BSVKeys` | Base58Check, WIF, addresses, BIP-32, BIP-39, Bitcoin Signed Message, and compatible ECIES formats. |
| `BSVScript` | Script bytecode, opcodes, parsing, serialization, minimal-push rules, boolean casting, and Script numbers. |
| `BSVTransaction` | Transactions, serialization, IDs, sighash, signing contexts, fees, merkle paths, BUMP, BEEF, and transaction templates. |
| `BSVInterpreter` | Resource-bounded Script execution, transaction-aware signature checks, and consensus-era behavior. |
| `BSVSPV` | SPV validation that combines transaction proofs with Script execution. |
| `BSVNetwork` | Chain trackers, broadcasters, HTTP clients, retries, and transport abstractions with Linux networking isolated here. |
| `BSVWallet` | BRC-100 wallet protocols, action and signing flows, serializers, substrates, and wallet certificates. |
| `BSVAuth` | BRC-103/BRC-104 peer authentication, session state, certificates, and HTTP or WebSocket transports. |
| `BSVServices` | Overlay discovery and lookup, identity, registries, storage, key-value services, and other high-level clients. |

See the [architecture plan](Documentation/Planning/Architecture.md) for the
dependency graph and the reasoning behind these boundaries.

## Compatibility baselines

Compatibility work is pinned so conformance results can be reproduced:

| Baseline | Exact reference |
| --- | --- |
| Go SDK | `bsv-blockchain/go-sdk` v1.3.3 at `de26fdec57a945ddc06de5d5617f6c32374f3929` |
| BRC specifications | Commit `a0b5e42c01f13a1506b063a83070e81d4090debb` |
| Swift | 6.1 or newer |
| Apple platforms | macOS 13+, iOS/tvOS 16+, watchOS 9+, and visionOS 1+ |
| Other platform goal | Linux |

The Go SDK is a behavioral reference. Public Swift names and types may differ
where a native Swift design can preserve the required behavior and wire format.
When sources disagree, the project records an explicit
[compatibility ruling](Documentation/Compatibility/Rulings.md).

## Current status

The reviewed foundation checkpoint is green. It includes the SwiftPM module
graph, strict fixture provenance and license verification, a pinned external Go
SDK differential oracle, bounded byte readers and writers, CompactSize and
VarBytes, fixed-width hash values, transaction-ID byte-order handling, and
strict Hex, Base64, and raw Bitcoin Base58 codecs.

Hash functions, Base58Check, keys, scripts, transactions, wallets, and network
services are not implemented yet. In particular, there is still no public
transaction or wallet workflow.

The detailed sequence and readiness gates live in the
[roadmap](Documentation/Planning/Roadmap.md). Compatibility documents describe
the intended surface and evidence; they do not indicate that an API is already
implemented.

## Conformance and testing

Development is vector-first. An implementation packet includes the relevant
permissively licensed or public-domain static vectors, provenance metadata, and
tests alongside the code. The fixture loader verifies manifest structure,
declared files, hashes, licenses, and deterministic merge order.

Behavior without suitable static vectors is checked against a separate,
exactly pinned checkout of the Go SDK. The Go oracle is development tooling,
not a runtime package dependency. Its outputs remain ephemeral unless their
provenance has been reviewed.

No Open BSV-licensed Go source or fixtures are copied into this MIT repository.
Committed fixture groups must follow the
[fixture policy](Documentation/Planning/FixtureLicensePolicy.md). The test
strategy aims for byte-identical cryptographic and wire-format results on Apple
platforms and Linux; platform-specific networking is exercised behind transport
abstractions.

## Documentation

- [Planning index](Documentation/Planning/README.md) — project gates and the implementation plan.
- [Compatibility evidence](Documentation/Compatibility/README.md) — Go surface inventory, BRC matrix, and recorded decisions.
- [Roadmap](Documentation/Planning/Roadmap.md) — phased work without duplicating the detailed matrices here.
- [Architecture](Documentation/Planning/Architecture.md) — module ownership, dependencies, and API constraints.
- [Architecture decision records](Documentation/ADRs/README.md) — accepted repository-level decisions.
- [Compatibility rulings](Documentation/Compatibility/Rulings.md) — explicit resolutions where references disagree.
- [Fixture policy](Documentation/Planning/FixtureLicensePolicy.md) — allowed sources, provenance, and isolation rules.
- [Third-party notices](NOTICE.md) — dependency notices and the boundary around the external Go reference.

## Development

Install Swift 6.1 or newer, clone the repository, then run the standard SwiftPM
workflow from its root:

```sh
swift package resolve
swift build
swift test
```

To focus on the fixture manifest infrastructure:

```sh
swift test --filter FixtureManifest
```

SwiftPM normally uses `.build/` for repository-local build products. In a
restricted environment where the global cache and process sandbox are
unavailable, keep module and package caches inside the repository:

```sh
env CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-module-cache" \
    SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/swiftpm-module-cache" \
    swift package --disable-sandbox --cache-path .build/swiftpm-cache resolve

env CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-module-cache" \
    SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/swiftpm-module-cache" \
    swift build --disable-sandbox --cache-path .build/swiftpm-cache

env CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-module-cache" \
    SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/swiftpm-module-cache" \
    swift test --disable-sandbox --cache-path .build/swiftpm-cache
```

The optional differential oracle needs an external clean checkout at the exact
Go baseline. See the
[conformance tool guide](Tools/Conformance/README.md) before setting
`BSV_GO_SDK_PATH`; the checkout must remain outside this repository.

## Contributing

There is no separate contribution guide yet. Before starting a large change,
open an issue that names the affected module and compatibility rows. Keep public
APIs idiomatic to Swift, include the applicable vectors and negative cases with
the implementation, and document any intended difference from the Go baseline
in the compatibility rulings.

Run `swift test` before opening a pull request. New fixtures must include their
source revision, hashes, transformation notes, governing license, and notice as
required by the fixture policy. Do not copy Go SDK source or fixtures into this
repository.

## License

Original Swift source in this repository is available under the
[MIT License](LICENSE). Runtime dependencies retain their own licenses and
notices as described in [NOTICE.md](NOTICE.md).

The external Go SDK reference remains governed by Open BSV License Version 5.
It is not vendored or relicensed by this project. Each committed test-vector
source keeps its own attribution and licensing boundary.
