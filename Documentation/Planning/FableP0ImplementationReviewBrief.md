# Fable consult: Phase 0 implementation review

## Goal

Act as an independent, read-only architecture, security, and conformance
reviewer for the completed Phase 0 foundation of a Swift BSV SDK targeting full
behavioral and wire parity with `bsv-blockchain/go-sdk` v1.3.3. Decide whether
the fixture-provenance loader, external Go oracle, Swift oracle client, and
project README are safe and credible enough to begin P1-A bounded binary/
CompactSize and P1-B encoding implementation.

Do not edit files or implement fixes. Inspect the repository with Read/Grep/Glob
only. Treat passing tests as evidence, not proof.

## Constraints and boundary

- Original Swift source is provisionally MIT.
- No Open BSV Go source, test fixture, mechanically transformed fixture, or
  generated oracle golden may enter the repository.
- The Go SDK is external and pinned to v1.3.3 commit
  `de26fdec57a945ddc06de5d5617f6c32374f3929` under Open BSV License v5.
- Static fixtures must be independently permissive/public-domain, include
  exact provenance/license/hash fragments, and work offline.
- The oracle is test tooling only, not a Swift runtime dependency.
- Swift 6.1 minimum; Apple platforms and Linux.
- Unknown/oversized/hostile inputs fail closed without traps or uncontrolled
  allocation. Toolchain/source drift fails required CI.

## Read first

1. `Documentation/Planning/PrimitiveWorkPackets.md`
2. `Documentation/Planning/FablePrimitiveReadinessReview-2026-08-07.md`
3. `Documentation/Planning/FixtureLicensePolicy.md`
4. `Documentation/Compatibility/VectorInventory.md`
5. `Documentation/Compatibility/FixtureSources.md`
6. `Tools/Conformance/go-sdk.lock.json`
7. `Tools/Conformance/README.md`
8. All files under `Tools/Conformance/GoOracle/`
9. `Tests/BSVConformanceTests/Support/FixtureManifest.swift`
10. `Tests/BSVConformanceTests/FixtureManifestTests.swift`
11. `Tests/BSVConformanceTests/Support/GoOracleClient.swift`
12. `Tests/BSVConformanceTests/GoOracleProtocolTests.swift`
13. `Package.swift`
14. `README.md`

The ignored worker specs remain available as
`SPEC-P0-A-fixture-provenance.md`, `SPEC-P0-B-go-oracle.md`, and
`SPEC-README-project-guide.md` if exact acceptance intent is needed.

## Implementation evidence

- Fixture loader: 20 focused tests pass; fragment merge, strict JSON, hashes,
  license/file presence, traversal, symlink, undeclared data, and bootstrap are
  exercised.
- Go oracle: exact Go 1.25.0 external suite and archive pin validation pass.
- Swift oracle: protocol tests and exact required integration against the
  pinned archive pass.
- Combined required-oracle Swift suite: 35 tests pass in the final tree,
  including the real exact archive integration.
- README-only validation resolves every local path/anchor and does not advertise
  unimplemented APIs.

The coordinator rejected the worker's first green oracle client because it
spawned `go run` for every request. The corrected version reuses one long-lived
`serve` subprocess per client, serializes requests, applies one absolute
deadline to a killable pipe write plus response wait, terminally invalidates a
failed child, and cleans it up. The same correction adds strict Swift response/
metadata decoding, a stable external Go build cache, symlink rejection in
complete-tree hashing, stdout draining before process-exit classification, and
Darwin/Linux broken-pipe handling.

Coordinator reruns after the correction:

- Exact external Go 1.25.0 suite: pass.
- Full Swift suite with `BSV_ORACLE_REQUIRED=1` and the pinned archive: 35/35
  pass; real integration response approximately 1.36 seconds.
- Shell syntax, trap/shim scan, and `git diff --check`: pass.

## Review questions

Give a specific ruling on each:

1. Does the fixture schema/loader actually enforce the stated licensing and
   provenance boundary, including deterministic fragments, unknown fields,
   paths, symlinks, reserved metadata, duplicates, hashes, and undeclared data?
   Identify any cross-platform false positive/negative or time-of-check issue
   that matters for committed resources.
2. Does the source/toolchain handshake authenticate both a clean exact git
   checkout and the trusted extracted archive without a substitution path?
   Review full-tree/dependency hashes, path containment, tag/commit validation,
   symlink handling, temporary workspace, cache, and environment overrides.
3. Is the persistent Swift `serve` client safe under Swift 6 concurrency and
   Foundation `Process` behavior on macOS/Linux? Look for pipe deadlocks,
   framing races, timeout/kill gaps, deinit hazards, response misassociation,
   output limits, reuse-after-failure, stderr pressure, and unchecked Sendable.
4. Do the initial operation adapters faithfully and safely expose the intended
   Go behavior for endian values, encodings, CompactSize/VarBytes, hashes/HMAC,
   digest byte order, Base58Check, unsigned mod, and Script numbers? Flag any
   adapter policy masquerading as Go behavior or malformed case with the wrong
   stable category.
5. Are tests capable of catching contamination, pin drift, unknown fields,
   multi-request process reuse, timeout/termination, line overflow, panic
   normalization, and at least one real oracle result? Name false-green gaps.
6. Does `README.md` follow the Go SDK's useful project-guide conventions while
   remaining truthful about Swift status, platforms, modules, installation,
   testing, and licensing?
7. What exact findings, if any, block P1-A/P1-B dispatch? Separate blockers
   from improvements that belong to later scale/CI/security phases.

## Required response

Start with exactly one verdict: `APPROVE`, `APPROVE WITH REQUIRED CHANGES`, or
`BLOCK`.

Then provide:

- Findings ordered by severity with exact paths/lines and a concrete fix.
- Separate verdicts for fixture boundary, Go pin/oracle, Swift process client,
  adapter semantics/tests, and README.
- A dispatch ruling for P1-A and P1-B.
- The single risk that decides the overall verdict.

Give a verdict, not a survey: do X, not Y, because Z. If the work is sound, say
so without manufacturing objections. If missing information changes the
answer, state precisely what evidence is missing and what each outcome implies.
