# Compatibility inventory

Status: Initial inventory; detailed symbol-level mapping will be generated from
the pinned Go SDK during Phase 0.

| Area | Required capability groups | Primary conformance source |
| --- | --- | --- |
| Core | Bytes, endian encoding, VarInt, hashes, Base58 | Go tests and standard vectors |
| Big numbers | Modular arithmetic for shares and bounded Script arithmetic | BRCs, Go differential cases, boundary/resource tests |
| Crypto | AES, DRBG, secp256k1, ECDSA, recovery, ECDH, BRC-42, BRC-94, shares | Go vectors, BRCs, NIST/secp256k1 vectors |
| Compatibility | WIF, addresses, BIP-32, BIP-39, BSM, ECIES | Go tests and published BIPs |
| Script | Opcodes, parsing, ASM, templates, script numbers | Go reference tests and consensus behavior |
| Interpreter | Era rules, stack, limits, signature checks, Chronicle operations | Go valid/invalid suites and node-derived vectors |
| Transaction | Model, serialization, sighash, fees, BUMP, BEEF, Atomic BEEF | Go transaction fixtures |
| SPV | Merkle paths, validation, chain trackers | Go tests and protocol specifications |
| Network | Broadcasters, trackers, HTTP/transports | Go mocks and contract tests |
| Wallet | BRC-100 interfaces, proto wallet, serializers, substrates | BRCs and Go wallet fixtures |
| Messages/Auth | BRC-77, BRC-103, BRC-104, certificates, HTTP/WebSocket | BRCs and Go integration tests |
| Overlay | Topic/lookup services, SHIP/SLAP, admin token | BRCs and Go tests |
| Services | Identity, registry, KV store, storage/UHRP | BRCs and Go tests |

## Matrix states

Each generated row uses one of:

- `unplanned`: discovered but not assigned to a milestone.
- `planned`: dependency and work packet identified.
- `blocked`: test/implementation waits on a named lower-level capability.
- `implemented`: API exists but conformance is incomplete.
- `conformant`: required vectors and negative tests pass.
- `deviation`: intentional difference with an approved specification rationale.

No area is considered complete from exported-symbol counts alone. Unexported Go
behavior that is observable through public APIs remains in scope.
