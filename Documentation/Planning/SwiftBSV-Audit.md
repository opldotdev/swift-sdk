# SwiftBSV reference audit

Reference: <https://github.com/wtsnz/SwiftBSV>

Status: useful precedent and provenance lead; not a dependency or compatibility
baseline.

## What is useful

The repository is MIT-licensed and demonstrates prior Swift APIs for:

- Base58/Base58Check, addresses, WIF-like private-key handling, BIP-32, BIP-39,
  and Bitcoin Signed Message.
- Transaction, input, output, outpoint, VarInt, sighash, and builder concepts.
- Script parsing, chunks, opcodes, a script machine, and era-related limits.
- Test-vector directories attributed to BIP-39, bitcoind, Bitcoin ABC, and
  Bitcoin SV.

Those tests are valuable as a map to original vector sources and as examples of
Swift-facing ergonomics. Any vector used here must be re-sourced from its
authoritative permissive upstream and entered in the fixture provenance
manifest; it is not copied merely because it appears in SwiftBSV.

## What must not be inherited

- The package is a single SwiftPM 5.1 target and predates Swift 6 concurrency.
- It depends on older `secp256k1.swift` and `CryptoSwift` packages rather than
  the selected Swift Crypto and P256K dependencies.
- BIP-39 calls Apple `CommonCrypto` directly, which is not a Linux-compatible
  package boundary.
- The source contains many `fatalError`, `try!`, forced unwrap, and
  precondition-driven parsing paths. This SDK requires typed errors and bounded
  parsing for untrusted bytes.
- It owns a large custom `BInt` and low-level elliptic-curve code. Neither is a
  suitable source for new cryptographic or arbitrary-precision
  implementations.
- Foundation `Data` permeates consensus internals, whereas this SDK reserves
  Foundation interoperability for boundaries and uses explicit byte cursors
  internally.
- Its feature set is far smaller than Go SDK v1.3.3 and does not define parity.

## Decision

Use SwiftBSV only for:

1. API naming and usability comparisons.
2. Locating original public test-vector families.
3. Migration examples for existing SwiftBSV users late in the roadmap.

Go SDK v1.3.3 plus the pinned BRC specifications remain the functional
inventory. Consensus/BRC requirements remain higher precedence than either
repository's incidental implementation behavior.
