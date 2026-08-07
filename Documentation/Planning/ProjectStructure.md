# Proposed project structure

Status: Target graph approved by Fable; fixture directories use the conservative
no-copy policy.

```text
swift-sdk/
├── Package.swift
├── LICENSE
├── NOTICE.md
├── README.md
├── Documentation/
│   ├── ADRs/
│   ├── Compatibility/
│   └── Planning/
├── Sources/
│   ├── BSV/                  # convenience umbrella only
│   ├── BSVCore/
│   ├── BSVBigNum/            # internal/SPI; no library product
│   ├── BSVCrypto/
│   ├── BSVKeys/
│   ├── BSVScript/
│   ├── BSVTransaction/
│   ├── BSVInterpreter/
│   ├── BSVSPV/
│   ├── BSVNetwork/
│   ├── BSVWallet/
│   ├── BSVAuth/
│   └── BSVServices/
├── Tests/
│   ├── BSVCoreTests/
│   ├── BSVBigNumTests/
│   ├── BSVCryptoTests/
│   ├── BSVKeysTests/
│   ├── BSVScriptTests/
│   ├── BSVTransactionTests/
│   ├── BSVInterpreterTests/
│   ├── BSVSPVTests/
│   ├── BSVNetworkTests/
│   ├── BSVWalletTests/
│   ├── BSVAuthTests/
│   ├── BSVServicesTests/
│   └── BSVConformanceTests/
│       ├── Fixtures/         # permissive/public-domain sources only
│       │   ├── Manifests/    # one provenance fragment per fixture group
│       │   └── Licenses/
│       └── Support/
└── Tools/
    └── Conformance/          # pinned Go oracle/differential harness
```

## SwiftPM products

- `BSV`: convenience umbrella.
- One library product for every public feature module.
- No public `BSVBigNum` product; lower-level implementation details remain
  replaceable.

The feature modules are the stable import path. `Sources/BSV/Exports.swift` is
the only file permitted to use `@_exported import`.

## Source organization inside targets

Targets begin flat while primitives are few. Subdirectories are introduced only
for real domains, not one-file categories. Expected examples include:

```text
BSVCrypto/
├── Hashing/
├── Symmetric/
└── Random/

BSVKeys/
├── Secp256k1/
├── Encoding/
├── Derivation/
└── Sharing/

BSVTransaction/
├── Model/
├── Serialization/
├── Signatures/
├── Merkle/
├── BEEF/
├── Fees/
└── Templates/

BSVAuth/
├── Certificates/
├── Sessions/
└── Transports/
```

Folders do not create pseudo-namespaces. Public type names should remain clear
without mirroring directory names or Go package prefixes.

## Tests

- Module test targets own focused unit, invariant, and negative tests.
- `BSVConformanceTests` owns cross-module vectors and behavior parity.
- Large fixtures are resources, never embedded as giant Swift literals.
- The Go oracle stays tooling-only and is not a runtime/package dependency.
- Tests that await a prerequisite record the exact blocked compatibility row;
  broad disabled suites are not allowed.

## Files intentionally absent from the first skeleton

- Copied Open BSV-licensed or unlicensed BRC fixtures.
- A BigInt package dependency, pending the Phase 1 ADR and scale experiments.
- A secp256k1 C shim target; the P256K audit proved it unnecessary.
- Network implementation dependencies beyond Foundation, pending the Linux
  WebSocket spike.
