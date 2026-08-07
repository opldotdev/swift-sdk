# Swift BSV SDK planning

Status: Architecture reviewed by Fable and revised. Phase 0 gates are resolved
for skeleton creation through a conservative no-copy fixture policy.

This directory defines how the Swift SDK will reach functional parity with
`bsv-blockchain/go-sdk` without mechanically translating its Go package layout.

## Baseline

- Compatibility baseline: `bsv-blockchain/go-sdk` v1.3.3.
- Normative specifications: the local BRC repository, pinned by commit in the
  compatibility manifest before implementation begins.
- API direction: idiomatic Swift with behavioral and wire-format parity.
- Compatibility precedence:
  1. Published BRC and network consensus behavior.
  2. Accepted cross-SDK and Go SDK test vectors.
  3. Go SDK behavior not covered above.
- Platforms: Apple platforms and Linux.
- Minimum toolchain proposal: Swift 6.1.
- Original Swift source license proposal: MIT. Copied or adapted upstream
  fixtures and source retain their upstream licenses and notices. This must be
  reviewed before the first release.

## Review gate

Fable completed a subscription-authenticated, read-only review on 2026-08-07.
Its required changes are incorporated into the drafts. The initial skeleton may
be created without copying Open BSV or unlicensed BRC material.

Documents:

- [Architecture](Architecture.md)
- [Research baselines](Baselines.md)
- [Roadmap](Roadmap.md)
- [Primitive implementation work packets](PrimitiveWorkPackets.md)
- [Fable primitive-readiness brief](FablePrimitiveReadinessBrief.md)
- [Fable primitive-readiness review](FablePrimitiveReadinessReview-2026-08-07.md)
- [Fable Phase 0 implementation-review brief](FableP0ImplementationReviewBrief.md)
- [Fable Phase 0 implementation review](FableP0ImplementationReview-2026-08-07.md)
- [Fable Phase 1 implementation-review brief](FableP1ImplementationReviewBrief.md)
- [Fable Phase 1 implementation review](FableP1ImplementationReview-2026-08-07.md)
- [Testing and conformance](Testing.md)
- [Compatibility inventory](Compatibility.md)
- [Detailed compatibility evidence](../Compatibility/README.md)
- [Fable review](FableReview-2026-08-07.md)
- [P256K dependency audit](P256K-Audit.md)
- [SwiftBSV reference audit](SwiftBSV-Audit.md)
- [Proposed project structure](ProjectStructure.md)
- [Fixture license policy](FixtureLicensePolicy.md)

## Non-goals of the planning phase

- Translating Go files one-for-one.
- Freezing public API names before primitive prototypes exist.
- Selecting a big-integer implementation without consensus-scale tests.
- Copying upstream implementation code into MIT-licensed source files.
