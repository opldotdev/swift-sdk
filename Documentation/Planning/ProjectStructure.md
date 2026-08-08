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
│   ├── BSVMessage/
│   ├── BSVCompat/            # opt-in compatibility feature module
│   ├── BSVScript/
│   ├── BSVTransaction/
│   ├── BSVInterpreter/
│   ├── BSVSPV/
│   ├── BSVNetwork/
│   ├── BSVWallet/
│   └── BSVAuth/
├── Tests/
│   ├── BSVCoreTests/
│   ├── BSVBigNumTests/
│   ├── BSVCryptoTests/
│   ├── BSVKeysTests/
│   ├── BSVMessageTests/
│   ├── BSVCompatTests/
│   ├── BSVScriptTests/
│   ├── BSVTransactionTests/
│   ├── BSVInterpreterTests/
│   ├── BSVSPVTests/
│   ├── BSVNetworkTests/
│   ├── BSVWalletTests/
│   ├── BSVAuthTests/
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
- `BSVCompat`: opt-in BSM, ECIES, BIP-32, and BIP-39 compatibility APIs.
- One library product for every public feature module.
- No public `BSVBigNum` product; lower-level implementation details remain
  replaceable.

The feature modules are the stable import path. Re-export declarations are
confined to `Sources/BSV/Exports.swift`. `BSVCompat` consumers import dependency
modules explicitly. The modern umbrella does not re-export `BSVCompat`.

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

BSVCompat/
├── BSM/
├── ECIES/
├── HD/
└── Mnemonic/

BSVMessage/
├── SignedMessage.swift
├── EncryptedMessage.swift
├── PortableMessageError.swift
└── PortableMessageLimits.swift

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

## Dependency boundaries retained from the first skeleton

- Copied Open BSV-licensed or unlicensed BRC fixtures.
- BigInt is now exact-pinned only in `BSVBigNum`; no public symbol may expose
  its concrete types, and ADR 0004 owns its resource and Linux release gates.
- A secp256k1 C shim target; the P256K audit proved it unnecessary.
- Network implementation dependencies beyond Foundation, pending the Linux
  WebSocket spike.
