# Linear work items

This is the handoff for creating and maintaining Swift SDK work in Linear from
a harness with a working Linear credential bridge.

## Destination

- Workspace: Open Protocol Labs (canonical key `openprotocollabs`; UI may show
  the short name `OPL`)
- Team: OPL (`d7a8e5a8-67a8-4325-915a-5ec21357c5ca`)
- Project: Swift-SDK
- Required label: `repo:swift-sdk`
- GitHub repository: `opldotdev/swift-sdk`
- Branch format: `OPL-<number>-<slug>`
- Commit format: `OPL-<number>: <description>`

The duplicate-search transport in the current harness did not return a body.
Before creating anything, search the Swift-SDK project for each exact or similar
title below. Reuse a genuine duplicate; otherwise create the issue, apply the
project and repo label, and preserve the dependencies listed here.

## Shipping checkpoint required now

### Swift SDK: publish the accepted P0/P1 foundation checkpoint

Status when created: In Progress.

Publish the repository's initial reviewed checkpoint to GitHub. This checkpoint
contains the project/module structure and documentation; the strict fixture
provenance loader; the pinned external Go v1.3.3 oracle; bounded binary,
CompactSize, VarBytes, fixed-value, and transaction-ID primitives; strict Hex,
Base64, and raw Base58 codecs; permissively licensed fixtures; and the completed
P0/P1 Fable review record.

Acceptance:

- external Go oracle tests pass with Go 1.25.0 and the exact pinned archive;
- the required-oracle Swift suite passes all 84 tests;
- fixture and license hashes verify;
- `git diff --check` and the publication safety scan pass;
- the initial commit uses this issue ID and is pushed to `opldotdev/swift-sdk`;
- no ignored `SPEC-*.md`, build products, credentials, Go SDK source, or oracle
  output is committed.

The GitHub repository is currently empty, so this issue authorizes establishing
`main`. Normal Linear-linked feature branches and pull requests begin with the
next implementation packet.

## Immediate implementation wave

### Swift SDK: fixture provenance and conformance loader

Status when work begins: In Progress.

Build the Phase P0-A fixture foundation described in
`Documentation/Planning/PrimitiveWorkPackets.md`: deterministic per-group
manifest fragments, SHA-256 verification, license/provenance enforcement,
path-safety checks, and focused Swift tests. No Go SDK or unlicensed BRC fixture
may be copied.

Acceptance:

- `swift test --filter FixtureManifest`
- `swift test`
- `git diff --check`

Dependencies: none. May run in parallel with the Go oracle issue.

### Swift SDK: pinned Go v1.3.3 differential oracle

Status when work begins: In Progress.

Build Phase P0-B from `PrimitiveWorkPackets.md`: an original bounded NDJSON Go
adapter against the external pinned `bsv-blockchain/go-sdk` v1.3.3 checkout,
strict source/toolchain/hash metadata validation, normalized errors, the full
Phase 1 operation registry, a timeout-safe Swift client, and offline/required-CI
behavior. No Go SDK implementation or fixture is copied into this repository.

Acceptance:

- Go oracle unit tests through its external-checkout test script
- `swift test --filter GoOracleProtocol`
- required integration test against an exact clean pinned checkout
- `swift test`
- `git diff --check`

Dependencies: none. May run in parallel with the fixture-loader issue.

### Swift SDK: replace the root README with the SDK project guide

Status when work begins: In Progress.

Rewrite `README.md` using the information architecture and navigation
conventions of the Go SDK README, adapted honestly for SwiftPM, the Swift module
graph, Apple/Linux support, the v1.3.3 parity baseline, vector-first
conformance, development commands, current implementation status, licensing,
and the planning/compatibility documentation. Do not advertise unimplemented
transaction APIs, examples, releases, coverage, or CI.

Acceptance: all links resolve to existing repository paths, shell snippets are
valid, project status is explicit, `swift test` still passes, and
`git diff --check` is clean.

Dependencies: none; documentation-only and parallel-safe.

## Next primitive wave

Create these only after both P0 issues pass coordinator review and the
post-implementation Fable gate.

1. **Swift SDK: bounded binary primitives and CompactSize (P1-A)**
   - Byte cursor/writer, endian IO, VarInt/VarBytes bounds, fixed hashes and
     transaction-ID display/wire order.
   - Depends on both P0 issues.
2. **Swift SDK: hex, Base64, and bounded Bitcoin Base58 (P1-B)**
   - Cross-platform encodings with explicit policies and size limits.
   - Depends on the fixture loader and oracle.
3. **Swift SDK: hashes, HMAC, and RIPEMD-160 (P1-C)**
   - Swift Crypto adapters, SDK-owned RIPEMD-160, composed SHA256d/HASH160,
     constant-time dependency verification, negative vectors.
   - Depends on P1-A and P1-B acceptance.
4. **Swift SDK: BigInt candidate and resource model (P1-D)**
   - Run the measurable macOS/Linux scale gates in ADR 0004 before accepting
     attaswift/BigInt; keep concrete types internal.
   - Depends on P1-C clearing its `Package.swift` ownership barrier.
5. **Swift SDK: Base58Check, WIF, and P2PKH addresses**
   - First Phase 3 key-format packet; deliberately includes Base58Check rather
     than creating a one-file Phase 1 issue.
   - Depends on P1-B, P1-C, and Phase 2 key parsing for complete WIF validation.

## Roadmap backlog

Use the phase headings in `Documentation/Planning/Roadmap.md` as Linear project
milestones, then create implementation issues from the detailed package rows in
`Documentation/Compatibility/GoSDK-v1.3.3.md` and BRC gates in
`Documentation/Compatibility/BRC-Matrix.md`:

- Phase 2: AES/CBC/GCM/DRBG; secp256k1 keys/ECDH; ECDSA/DER/recovery; BRC-42
  derivation; symmetric envelopes and key shares.
- Phase 3: WIF/address/Base58Check; BIP-32/BIP-39; Bitcoin Signed Message;
  Electrum/Bitcore ECIES.
- Phase 4: transaction graph ADR; Script model/templates; transaction model,
  serialization, sighash, fees, and unlockers.
- Phase 5: era-aware Script interpreter and resource limits.
- Phase 6: merkle paths, BUMP, BEEF/Atomic BEEF, SPV verification.
- Phase 7: broadcasters, chain trackers, HTTP/retry/error mapping, Linux
  WebSocket decision.
- Phase 8: BRC-100 wallet types, ProtoWallet, serializers, substrates,
  certificates, and wallet encryption.
- Phase 9: BRC-77 messaging and BRC-103/104 authentication/transports.
- Phase 10: overlay, identity, registry, KV, storage/UHRP, and remaining
  compatibility APIs.
- Phase 11: parity closure, fuzz/performance/concurrency/security reviews,
  documentation, license audit, and release automation.

Every implementation issue must own disjoint paths, name its permissive vector
sources and oracle operations, list malformed-input gates, include exact test
commands, and finish with a Fable review before the feature batch is accepted.
