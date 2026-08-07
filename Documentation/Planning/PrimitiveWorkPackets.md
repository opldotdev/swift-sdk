# Primitive implementation work packets

Status: Approved with the required Fable readiness-review changes incorporated.
Dispatch still requires the coordinator to create the corresponding tracked
work item and issue a packet-specific implementation brief.

These packets cover repository Phase 0 and the lowest Phase 1 primitives. They
are deliberately smaller than the complete Go SDK surface inventory, but every
seam is chosen so later packages can build without target cycles or public API
rewrites.

## Dispatch contract

Every implementation packet is dispatched to a native sub-agent pinned to
`gpt-5.6-sol` with high reasoning. The coordinator retains architecture,
review, verification, git, and acceptance ownership.

Each worker must be told:

- It is not alone in the repository and must not revert or rewrite unrelated
  work.
- It may edit only the paths listed in its packet.
- It must not commit, push, change dependency versions, replace build tooling,
  or add unapproved cryptographic implementations/dependencies.
- If it encounters an environment blocker, it stops and reports it instead of
  changing the design or bypassing the dependency.
- Its final report lists files changed, commands and outcomes, every acceptance
  criterion, and anything it could not complete.

Test vectors and their provenance ship in the same packet as the behavior they
gate. Go SDK source and fixtures are never copied; the pinned external oracle is
used for Go-specific behavior.

## Stable low-level seams

These names and responsibilities are proposed, not yet frozen:

```swift
package struct ByteCursor
package struct ByteWriter

public enum BinaryDecodingError: Error, Equatable, Sendable
public enum CompactSizeCanonicality: Sendable
public struct DecodedCompactSize: Equatable, Sendable
public struct DecodedVarBytes: Equatable, Sendable
public enum CompactSize

public struct Hash160: Hashable, Sendable
public struct Hash256: Hashable, Sendable
public struct Hash512: Hashable, Sendable
public struct TransactionID: Hashable, Sendable

public enum Hex
public enum Base64Encoding
public enum Base58

public enum BSVHashing
public protocol SecureRandomSource: Sendable
```

Rules shared by every seam:

- Byte constructors validate exact widths and never silently pad or truncate.
- Parsers are bounded before allocation and reject trailing bytes unless their
  API explicitly returns a consumed-byte count.
- Unsigned 64-bit and arbitrary-size values cross JSON as decimal strings.
- `TransactionID` owns display-versus-wire byte order; generic hashes never
  reverse themselves implicitly.
- `DecodedCompactSize` carries the raw `UInt64`, consumed-byte count, and an
  `isCanonical` flag. Decoding `UInt64.max` remains an ordinary numeric result;
  only a consuming wire format may interpret that value as its named absent
  sentinel under COMP-001.
- Foundation `Data` conveniences are adapters. Consensus codecs operate on
  bytes and do not use Foundation encoders/decoders for their wire format.
- No `@frozen` promise is made in the first release.

## P0-A — Fixture provenance and loader

Objective: make every committed fixture auditable before primitive code lands.

Owned paths:

- `Tests/BSVConformanceTests/Support/FixtureManifest.swift`
- `Tests/BSVConformanceTests/FixtureManifestTests.swift`
- `Tests/BSVConformanceTests/Fixtures/Manifests/**`
- `Tests/BSVConformanceTests/Fixtures/Licenses/**`
- `Documentation/Compatibility/FixtureSources.md`

Required behavior:

- Versioned per-group manifest-fragment schema with group ID, source URL,
  original path, local path, SHA-256, license identifier/path, transformation,
  and notes.
- The loader discovers `Fixtures/Manifests/*.json`, merges them deterministically
  by group ID, and cross-validates the complete fixture tree. Each later packet
  owns a uniquely named fragment, so parallel packets never edit one manifest.
- Loader rejects duplicate IDs/paths, missing license files, invalid hashes,
  files not declared in the manifest, declared files that are absent, and path
  traversal.
- The first manifest may contain only its own schema/empty groups plus small
  permissive fixtures needed by the first primitive packet.
- No Go SDK or unlicensed BRC content enters the directory.

Vectors: the manifest tests use independently authored tiny files. Vector
groups added by later packets cite the exact permissive sources cataloged in
`VectorInventory.md`.

Acceptance:

```text
swift test --filter FixtureManifest
swift test
git diff --check
```

## P0-B — Pinned Go differential oracle

Objective: query deterministic Go v1.3.3 behavior without copying Go source,
fixtures, or generated goldens into the Swift repository.

Owned paths:

- `Tools/Conformance/GoOracle/**`
- `Tools/Conformance/go-sdk.lock.json`
- `Tools/Conformance/README.md`
- `Tests/BSVConformanceTests/Support/GoOracleClient.swift`
- `Tests/BSVConformanceTests/GoOracleProtocolTests.swift`

Protocol:

- `metadata` and `serve` commands.
- `serve` uses bounded NDJSON: one request line produces one response line in
  order; stdout contains protocol JSON only and diagnostics go to stderr.
- Schema is `bsv-conformance/1`. Requests contain `id`, `op`, and a fixed
  per-operation `args` object. Responses contain `ok` and exactly one of
  `result` or normalized `error`.
- Bytes are lowercase even-length hex. Large integers are decimal strings.
- Unknown fields, duplicate IDs, overlong lines, unsupported operations, and
  non-deterministic/ambient inputs are rejected.
- Operation failures return exit zero with a normalized response. Startup,
  pin, and protocol-stream corruption fail the process.

Initial operations:

- `metadata`
- `bytes.reverse`
- `u16|u32|u64.encode|decode`
- `hex.encode|decode`
- `varint.encode|decode`
- `varbytes.encode|decode`
- `hash.sha256|sha256d|sha512|ripemd160|hash160`
- `hmac.sha256|sha512`
- `base64.encode|decode`
- `digest32.parse|display`
- `base58.encode|decode`
- `base58check.encode|decode`
- `big.umod`
- `scriptnum.encode|decode`

Pin validation:

- Git checkout mode requires exact HEAD/tag commit, clean status, correct
  module path, and a checkout outside this Swift repository.
- Archive mode requires a trusted archive or deterministic tree-manifest hash.
- Lock records tag/commit/module plus SHA-256 for license, `go.mod`, `go.sum`,
  and archive/tree.
- Metadata returns schema, tag/commit, source mode/hash, dirty flag, Go version,
  dependency-graph hash, license hash, and operation list. Swift verifies it
  before sending cases.
- CI pins the exact Go toolchain version recorded in the lock and rejects any
  metadata drift. Optional local runs with another toolchain report the oracle
  as unavailable; required runs fail closed rather than silently accepting
  major, minor, or patch drift.
- Use a temporary Go workspace/replace directive; never mutate the external
  checkout.

Error categories begin with those listed in `VectorInventory.md`. String
matching is isolated and tested; diagnostic messages are never asserted.
Verification mismatch is `ok: true` with `valid: false`, not an error.

CI behavior:

- Static permissive fixtures always run without Go/network.
- Requests and responses are capped at 1 MiB per NDJSON line. Big-number oracle
  differentials therefore use small and medium operands; 750 KiB and 32 MiB
  scale/resource tests are Swift-only and never cross the oracle boundary.
- The Swift client applies a 10-second per-request deadline. On expiry it
  terminates the oracle, waits no more than two seconds, then force-kills it;
  every outstanding request fails with a stable timeout/transport error.
- Differential tests are a separate offline job with a pre-provisioned pinned
  source/toolchain/module cache.
- Local absence produces one explicit unavailable/skip result.
- `BSV_ORACLE_REQUIRED=1` turns absence or any pin mismatch into failure.
- Oracle stdout is never committed or cached as fixture data.

Acceptance:

```text
(cd Tools/Conformance/GoOracle && go test ./...)
swift test --filter GoOracleProtocol
BSV_GO_SDK_PATH=<clean-pinned-path> BSV_ORACLE_REQUIRED=1 swift test --filter GoOracle
git diff --check
```

## P1-A — Bounded binary primitives and CompactSize

Objective: establish the byte parser/writer used by every later wire format.

Owned paths:

- `Package.swift` only to add `BSVCoreTests`
- `Sources/BSVCore/Binary/**`
- `Sources/BSVCore/Values/FixedBytes.swift`
- `Sources/BSVCore/Values/TransactionID.swift`
- `Tests/BSVCoreTests/Binary/**`
- A uniquely named P0-A fixture manifest fragment and its fixtures only
- Applicable compatibility/error-map rows

Required behavior:

- Package-scoped cursor with position/remaining, exact reads, fixed-width
  LE/BE unsigned integers, reversed reads, bounded slices, and explicit
  completion/trailing-data checks. Failure has defined cursor semantics and
  never traps.
- Package-scoped writer with fixed integers, exact bytes, reversed bytes, and
  canonical CompactSize/length-prefixed bytes.
- Public CompactSize encode, encoded-length, and bounded decode returning value
  plus consumed count and canonicality. Public `encodeVarBytes` and
  `decodeVarBytes` provide symmetric length-prefixed byte operations.
  Canonical-required and permissive policies implement COMP-001; decode never
  uses unchecked indexing. The decoder returns raw `UInt64.max`; sentinel
  naming and interpretation belong only to the consuming codec.
- Declared lengths are checked against remaining bytes, configured maximum,
  and representable Swift collection sizes before allocation.
- Exact-width 20/32/64-byte values use private storage and safe byte access.
  `TransactionID` stores wire/internal order and exposes reversed display bytes.

Vectors:

- ISC btcd `wire/common_test.go` canonical, noncanonical, truncation, and
  VarBytes cases, with notice/provenance.
- Independently generated truncation at every boundary.
- External Go oracle for permissive non-minimal behavior and the max-u64
  sentinel formats only; Go panic behavior is recorded but never reproduced.

Negative gates: every truncated prefix/body, non-minimal encodings in both
policies, trailing bytes, max-u64, UInt64-to-Int overflow, declared maximum,
zero length, and exact maximum.

Acceptance:

```text
swift test --filter BSVCoreTests
swift test --filter BSVConformanceTests
swift test
git diff --check
```

## P1-B — Text/base encodings

Objective: implement the non-cryptographic encodings used by every key and
protocol layer.

Owned paths:

- `Sources/BSVCore/Encoding/Hex.swift`
- `Sources/BSVCore/Encoding/Base64Encoding.swift`
- `Sources/BSVCore/Encoding/Base58.swift`
- `Tests/BSVCoreTests/Encoding/**`
- A uniquely named P0-A fixture manifest fragment and its fixtures only
- Applicable compatibility/error-map rows

Required behavior:

- Hex emits lowercase; decode accepts upper/lowercase, rejects odd digits and
  reports invalid-character category without trapping.
- Base64 exposes named standard/URL-safe and padded/unpadded policies. Any
  Foundation adapter must produce identical Linux/Apple results and enforce a
  decoded-byte maximum.
- Base58 preserves leading zero bytes, uses the Bitcoin alphabet, rejects every
  forbidden character, and is implemented with bounded byte arithmetic rather
  than coupling Core to BigInt.
- Base58 decoding requires an explicit maximum decoded byte count and provides
  no unbounded overload. Tests cover limit minus one, exact, and plus one;
  later key/address wrappers impose their tighter format-specific limits.
- Empty-input/output behavior is explicit and tested.

Vectors:

- BSD Go stdlib hex/Base64 or direct RFC 4648 cases with provenance.
- ISC `bitcoinsv/bsvutil` raw Base58 cases plus independent leading-zero and
  invalid-alphabet properties.
- Go oracle comparisons for behavior, never copied goldens.

Acceptance uses the same commands as P1-A. This packet must not touch binary,
hashing, crypto, key, or manifest loader source files.

## P1-C — Hashes, HMAC, and constant-time authentication checks

Objective: wrap Swift Crypto for supported algorithms and add the one missing
Bitcoin hash implementation from a permissive/specification source.

Owned paths:

- `Package.swift` only to add `BSVCryptoTests`
- `Sources/BSVCrypto/Hashing/**`
- `Tests/BSVCryptoTests/Hashing/**`
- A uniquely named P0-A fixture manifest fragment and its fixtures only
- Applicable compatibility/error-map rows

Required behavior:

- `BSVHashing` one-shot SHA-256, double-SHA-256, SHA-512, RIPEMD-160,
  HASH160, HMAC-SHA256, and HMAC-SHA512 over bytes.
- Swift Crypto backs SHA and HMAC. HMAC verification uses its public
  authentication-code validation rather than a hand-rolled public
  “constant-time” promise.
- RIPEMD-160 is an SDK-owned, small pure-Swift implementation authored from the
  specification or a clearly permissive source. It supports incremental
  internal processing if useful, but the first public surface is one-shot.
- Results use `Hash160`, `Hash256`, or `Hash512` exact-width values from Core.
- No secret-bearing debug descriptions are introduced.

Vectors:

- Swift Crypto Apache-2.0 SHA vectors.
- RFC 4231 HMAC cases, preferably recorded with the RFC as provenance.
- BSD x/crypto RIPEMD-160 canonical corpus including million-`a`.
- ISC chain-hash display/wire cases for composed txid behavior.
- Go oracle differential cases for SDK composition.

Negative/property gates: empty key/message, block-size boundaries, multi-block,
incremental/one-shot equivalence where applicable, exact digest width, and
transaction-ID byte-order round trips. HMAC verification separately covers a
valid tag, a tampered tag at every boundary of interest, and every truncated
tag length; a verification mismatch returns `false` rather than throwing.

Acceptance:

```text
swift test --filter BSVCoreTests
swift test --filter BSVHashing
swift test --filter BSVConformanceTests
swift test
git diff --check
```

## P1-D — Big integer candidate and resource model

Objective: decide, with executable evidence, whether `attaswift/BigInt` 5.7.0
can back the internal `BSVBigNum` target.

Owned paths:

- `Package.swift` only for the exact candidate pin and `BSVBigNumTests`
- `Package.resolved` only as produced by that exact pin
- `Sources/BSVBigNum/**`
- `Tests/BSVBigNumTests/**`
- `Documentation/ADRs/0004-big-integer-candidate.md`
- Applicable compatibility/error-map rows

Required behavior:

- First run the candidate experiments from ADR 0004. If any hard gate fails,
  stop and report; do not hide the failure with a bespoke BigInt or a different
  dependency.
- On acceptance, expose only package/SPI-owned `BigMagnitude` and `BigSigned`
  adaptation. No public SDK signature mentions `BigInt` or `BigUInt`.
- Provide unsigned big-endian import/export, compare, add/subtract/multiply,
  quotient/remainder, shifts, positive modular normalization, and modular
  inverse needed by key shares.
- Bitcoin sign-magnitude remains outside this packet in `BSVScript`.
- Conversion is linear in input size. Operation budgets reject unsafe large
  multiplication/division/shift requests before expensive allocation.
- Division by zero and native-integer overflow are typed errors, never traps.
- Random helpers from the dependency are not used.

Vectors/experiments:

- Independently authored modular arithmetic and negative-residue cases, with
  ephemeral Go `big.umod` comparisons.
- ISC btcd small Script-number cases may validate later adaptation concepts,
  but do not make Script number public here.
- Generated values at 750,000 bytes and 32 MiB, each at limit minus one, exact,
  and plus one. Large blobs are generated during tests and not committed.
- Release-mode timing and peak-allocation evidence is recorded without copying
  Go's quadratic conversion strategy.
- macOS and Linux builds/tests are mandatory before the ADR becomes Accepted.
  The worker records macOS evidence; the coordinator-owned required Linux CI
  job produces the Linux evidence, and the ADR cannot advance without it.

Acceptance:

```text
swift test --filter BSVBigNumTests
swift test -c release --filter BigNumScale
swift test
git diff --check
```

The normal PR suite may gate the full 32 MiB resource test behind a documented
slow-test flag only if CI has a required dedicated job that runs it.

## Phase 3 Base58Check/WIF/address packet (registered dependency)

Base58Check is intentionally not a standalone Phase 1 packet. It combines with
the first Phase 3 WIF/address work packet in `BSVKeys`, after P1-B Base58 and
P1-C SHA256d are accepted. That packet will own arbitrary version/payload
Base58Check, checksum and size validation, WIF scalar/network/compression rules,
and legacy address formats. ISC `bitcoinsv/bsvutil` fixtures and the P0-B
`base58check.encode|decode` operations are registered now so the dependency is
visible without adding a one-file scheduling barrier.

## Wave and ownership plan

1. Run P0-A and P0-B in parallel; their paths do not overlap.
2. After the fixture/oracle barrier, run P1-A and P1-B in parallel. P1-A alone
   owns the `BSVCoreTests` package target; each packet owns a different fixture
   manifest fragment, and P1-B does not edit `Package.swift`.
3. Review and test the full Core diff.
4. Run P1-C. It alone owns the Crypto test-target manifest entry.
5. Run P1-D after P1-C's manifest edit has cleared the barrier. It owns the
   BigNum test-target entry and the only dependency change in this primitive
   wave.
6. The first Phase 3 packet combines Base58Check, WIF, and addresses after
   accepted P1-B/P1-C work.

At each barrier the coordinator reviews the complete diff, checks for shims or
unapproved dependency/build changes, reruns acceptance outside the worker
sandbox, updates compatibility rows, and asks Fable to review the completed
feature batch before it is accepted.

## Blocked tests registered early

- HASH160 waits for SHA-256 plus RIPEMD-160.
- Base58Check waits for Base58 plus SHA256d.
- Address-from-public-key waits for HASH160, Base58Check, and secp key parsing.
- VarBytes waits for CompactSize plus safe length conversion/allocation limits.
- ECDH vectors wait for private/public key parsing and must name
  compressed/uncompressed/x-only output explicitly.
- ECDSA verification/recovery waits for key parsing and 32-byte digest plumbing.
- PBKDF2-HMAC-SHA512/BIP-39 needs a directly licensable authoritative vector;
  until sourced, exact Go behavior is differential/ephemeral only.
- Post-Genesis/Chronicle Script numbers wait for accepted BigNum resource
  policy and era-aware Script code; the BigNum packet alone cannot claim them.
