# Fable consult: primitive implementation readiness

Status: Historical review brief. Its package map is superseded by ADR-0001 and
`Documentation/Planning/Architecture.md`.

## Goal

Act as an independent, read-only architecture and cryptography reviewer for a
new Swift SDK whose target is complete behavioral and wire-format parity with
`bsv-blockchain/go-sdk` v1.3.3. Decide whether the repository structure and the
Phase 0/1 work packets are precise and safe enough to hand to independent
implementation agents.

Do not edit files and do not implement anything. Inspect the repository using
Read/Grep/Glob only.

## Constraints

- Swift 6.1 minimum; Apple platforms and Linux.
- Idiomatic Swift API, not one-for-one Go names, while preserving observable
  behavior and wire formats.
- Precedence: consensus/applicable BRC requirements, accepted vectors, then
  incidental Go behavior. Every contradiction needs an explicit ruling.
- Original Swift source is provisionally MIT.
- No Go SDK fixture/source is copied. The Go SDK remains a pinned external
  oracle under Open BSV License v5.
- Prefer Apple Swift Crypto and P256K; do not reimplement available vetted
  crypto. RIPEMD-160 and an internal BigNum adaptation are the known gaps.
- Test vectors land with each primitive. Skips are temporary dependency
  markers, not acceptance evidence.
- Implementation agents will be native `gpt-5.6-sol` agents at high reasoning,
  with disjoint file ownership. The main coordinator reviews and reruns every
  acceptance command.

## State and evidence to inspect

Read these first:

1. `Package.swift`
2. `Documentation/Planning/Architecture.md`
3. `Documentation/Planning/Roadmap.md`
4. `Documentation/Planning/PrimitiveWorkPackets.md`
5. `Documentation/Compatibility/README.md`
6. `Documentation/Compatibility/Rulings.md`
7. `Documentation/Compatibility/GoSDK-v1.3.3.md`
8. `Documentation/Compatibility/BRC-Matrix.md`
9. `Documentation/Compatibility/VectorInventory.md`
10. `Documentation/Planning/FixtureLicensePolicy.md`
11. `Documentation/Planning/P256K-Audit.md`
12. `Documentation/ADRs/0004-big-integer-candidate.md`

Important findings already incorporated:

- P256K 0.23.2 can return compressed/uncompressed raw ECDH points. A custom C
  shim target is not needed. Arbitrary parsed high-S normalization needs a
  narrow Swift wrapper over an already-vendored C symbol.
- `BSVBigNum` sits below both Crypto and Script.
- `ChainTracker` and `Broadcaster` protocols live in Transaction; concrete
  implementations live in Network.
- `BSVServices` now imports `BSVAuth` because storage and identity use
  authenticated fetch/certificate flows.
- Wallet-backed PushDrop factories live in Wallet; transaction-neutral
  PushDrop codecs/signers live in Transaction.
- WIF/address/BIP-32 ownership is Keys even where Go namespaces differ.
- The developer's `~/code/go-sdk` checkout is dirty and excluded. The baseline
  is locked to v1.3.3 commit
  `de26fdec57a945ddc06de5d5617f6c32374f3929`.
- `attaswift/BigInt` 5.7.0 is only a candidate. It is MIT, dependency-free,
  `Sendable`, strict-concurrency checked, and passed its 211 tests under Swift
  6.3.3 on macOS. Linux and 750 KB/32 MiB resource experiments remain gates.
- The Swift skeleton builds and its umbrella smoke test passes after the
  Services→Auth dependency correction.

## Review questions

Give a specific ruling on each:

1. Is the target graph now acyclic and correctly layered for every package in
   the Go surface inventory? Identify any remaining missing dependency or
   misplaced type that would force later graph surgery.
2. Are the proposed lowest-level seams in `PrimitiveWorkPackets.md` sound for
   Swift 6—especially package/public visibility, fixed-byte value types,
   TransactionID byte order, CompactSize canonicality, randomness, and HMAC
   verification? Name exact API changes required before implementation.
3. Are P0-A through P1-E coherent worker-sized units with safe non-overlapping
   ownership and correct dependency ordering? Flag packets that should split,
   merge, or move.
4. Can the NDJSON Go oracle, pin handshake, offline CI policy, and no-copy
   fixture strategy provide credible parity evidence without contaminating the
   Swift runtime/package? Name missing metadata, operations, or failure modes.
5. Review every proposed COMP ruling. Block on any ruling that is unsafe,
   contradicts a stronger specification, or would freeze the wrong public API.
6. Is the BigInt experiment sufficient to decide the candidate, including
   Chronicle-scale denial-of-service risk and modular operations for key
   shares? Name measurable gates that are missing.
7. Are the static vector sources and malformed-input matrices sufficient for
   the first primitive waves? Identify false-parity gaps, especially cases
   where dependency tests would only test the dependency rather than our
   adapter.
8. What is the smallest set of required changes that truly blocks dispatching
   P0-A/P0-B and then P1-A/P1-B? Separate blockers from later recommendations.

## Required response

Start with exactly one verdict: `APPROVE`, `APPROVE WITH REQUIRED CHANGES`, or
`BLOCK`.

Then provide:

- Required changes, ordered by leverage/severity and citing paths/lines.
- Packet readiness table for P0-A, P0-B, P1-A, P1-B, P1-C, P1-D, P1-E.
- Explicit judgment on target graph, oracle/licensing boundary, BRC rulings,
  and BigInt gates.
- The smallest dispatch-ready sequence after corrections.

Give a verdict, not a survey: “do X, not Y, because Z,” plus the single risk
that decides each required change. If the plan is sound, say so; do not invent
objections merely to justify the consult. If missing information would change
the answer, name it precisely and state what each answer would imply. This is a
large architecture review, so exceed 200 words only where the evidence truly
requires it.
