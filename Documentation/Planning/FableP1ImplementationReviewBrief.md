# Fable review brief: Phase 1 binary and encoding primitives

You are the independent, read-only architecture and implementation reviewer for
`/Users/satchmo/code/swift-sdk`. Inspect the repository directly with Read,
Grep, and Glob. Do not edit files and do not run shell commands.

## Goal

Review the completed first primitive wave of a Swift 6.1 SDK intended to reach
behavioral and wire compatibility with `bsv-blockchain/go-sdk` v1.3.3. Decide
whether P1-A bounded binary/CompactSize and P1-B Hex/Base64/Base58 are designed,
implemented, and evidenced well enough to accept and use as foundations for
hashing and cryptography.

## Governing constraints

- Apple-platform and Linux support; public APIs are `[UInt8]`-oriented and
  avoid Foundation serialization in consensus primitives.
- Clean minimal code, typed nontrapping failures, explicit resource bounds,
  Swift concurrency safety, and non-`@frozen` public declarations.
- Open BSV Go source/tests/fixtures may be queried only through the external
  pinned oracle. They must not be copied into this MIT repository.
- Committed fixtures must come from permissive upstream sources with exact
  provenance, license notice bytes, and SHA-256 verification.
- Go compatibility is subordinate to safe Swift behavior where Go exposes a
  panic, unbounded allocation, or ambiguous error behavior; deliberate
  differences must be explicit.
- Module names retain the `BSV` prefix to avoid Swift's global import-name
  collisions, while public value/type names remain unprefixed.

## Pinned baselines and accepted P0

- Go SDK: tag `v1.3.3`, commit
  `de26fdec57a945ddc06de5d5617f6c32374f3929`, exact Go `1.25.0`.
- Trusted external research archive tree:
  `09f05c13ee9286d5f5d6ed8724625a28edcd923b5b3d961a277cfd16347e4337`.
- BRC repository baseline:
  `a0b5e42c01f13a1506b063a83070e81d4090debb`.
- P0 fixture loader and persistent Go oracle were previously reviewed by
  Fable. All required F1-F5 remediation is recorded in
  `Documentation/Planning/FableP0ImplementationReview-2026-08-07.md`.

## Review surface

Read at minimum:

- `Package.swift`
- `Sources/BSVCore/Binary/*.swift`
- `Sources/BSVCore/Values/*.swift`
- `Sources/BSVCore/Encoding/*.swift`
- `Tests/BSVCoreTests/Binary/*.swift`
- `Tests/BSVCoreTests/Encoding/*.swift`
- `Tests/BSVConformanceTests/CompactSizeConformanceTests.swift`
- `Tests/BSVConformanceTests/EncodingConformanceTests.swift`
- `Tests/BSVConformanceTests/Support/FixtureManifest.swift`
- all JSON fragments under
  `Tests/BSVConformanceTests/Fixtures/Manifests/`
- all P1 fixture JSON and license notices under
  `Tests/BSVConformanceTests/Fixtures/{Permissive,Licenses}/`
- `Documentation/Compatibility/{Rulings,FixtureSources,VectorInventory}.md`
- `Documentation/Planning/{PrimitiveWorkPackets,Testing}.md`

The implementation intentionally does not yet add TransactionID hexadecimal
conveniences; that small cross-packet integration follows this review. It also
does not implement hashes, Base58Check, WIF, addresses, or any higher layer.

## Current evidence

The coordinator independently ran, after worker completion:

- `swift test --disable-sandbox --filter BSVCoreTests`: 38/38 passed.
- required external-Go `CompactSizeConformance`: 3/3 passed.
- required external-Go `EncodingConformance`: 2/2 passed.
- full `BSV_ORACLE_REQUIRED=1 swift test --disable-sandbox`: 83/83 passed
  across 10 suites.
- exact Go 1.25 offline oracle tests and metadata pin validation passed during
  the immediately preceding P0 barrier.
- fixture and license SHA-256 values match every manifest; the three committed
  license files are byte-identical to their pinned local upstream originals.
- static audit found no force unwraps, trapping assertions, unsafe operations,
  Foundation/Data, BigInt, or BSVBigNum use in the new BSVCore primitives.

Passing tests are evidence, not a substitute for reviewing the algorithms and
API contracts.

## Specific questions

1. Are `ByteCursor`, `ByteWriter`, `BinaryDecodingError`, and the public
   CompactSize/VarBytes APIs transactional, overflow-safe, bounded, and suitable
   as consensus-wire foundations? Look for integer-conversion, allocation,
   cursor-advancement, canonicality, trailing-data, and error-precedence bugs.
2. Are `Hash160`, `Hash256`, `Hash512`, and `TransactionID` minimal and clear,
   with correct value semantics and wire/display byte-order ownership? Flag any
   API decision that will create ambiguity for later transaction/hash work.
3. Do Hex and Base64 define a stable cross-platform language for casing,
   alphabets, padding, discarded bits, whitespace, Unicode indexing, output
   bounds, and typed errors? Inspect the decoder logic rather than trusting the
   RFC examples.
4. Is the byte-array Base58 conversion mathematically correct and safely
   bounded? Audit the 138/100, 137/100, and 733/1000 capacity bounds, saturated
   `Int.max` arithmetic, leading-zero handling, loop indices, allocation order,
   and worst-case work. Identify a counterexample if one exists.
5. Do the static fixtures and manifest records stay on the permitted side of
   the no-copy boundary, with accurate one-source/one-license provenance? Are
   the selected cases sufficient alongside the real persistent Go oracle?
6. What important negative, boundary, property, or differential test is still
   missing before later primitives depend on these APIs?
7. Does any required finding block acceptance of P1-A/P1-B or dispatch of the
   next hashing/cryptography packet? Separate required fixes from improvements
   and later-layer recommendations.

## Required response

Start with exactly one verdict: `APPROVE`, `APPROVE WITH REQUIRED CHANGES`, or
`REJECT`.

Then provide:

- required findings, numbered and tied to exact files/symbols;
- improvements that are not blockers;
- an explicit P1 acceptance/next-packet dispatch ruling;
- the single risk that most determines the verdict.

Give a verdict, not a survey: do X, not Y, because Z. If the implementation is
sound, say so plainly and do not manufacture objections. If missing information
would change the answer, name it precisely and say what each answer implies.
Keep the response concise, but use enough detail to make every required change
directly actionable.
