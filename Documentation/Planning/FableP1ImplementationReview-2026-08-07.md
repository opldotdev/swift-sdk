# Fable Phase 1 implementation review

- Date: 2026-08-07
- Channel: read-only Claude Fable CLI consult
- Authentication: signed-in Claude subscription with `ANTHROPIC_API_KEY`
  removed from the process environment
- Initial verdict: **APPROVE WITH REQUIRED CHANGES**
- Final disposition: **ACCEPTED AFTER REMEDIATION**

Fable inspected the P1 binary, fixed-value, encoding, unit-test, conformance,
fixture, manifest, license, ruling, and planning surfaces. It found no binary,
Base64, Base58, overflow, allocation, transactional-state, byte-order, fixture,
or provenance correctness counterexample. P1-A was approved unconditionally.

## Required finding

The strict text-decoding compatibility policy was implemented and tested in
Swift but not registered as a deliberate compatibility ruling. The pinned Go
SDK uses Go's ordinary `base64.StdEncoding.DecodeString` at auth/wallet call
sites, while Swift rejects embedded CR/LF and noncanonical discarded bits. The
review requires a ruling plus negative differentials that demonstrate both the
Swift error and the Go-side behavior. Invalid Base58 also needs an explicit
negative differential.

## Coordinator reconciliation

Primary evidence refined two details in the advisory response before work was
dispatched:

- the existing oracle's `base64.decode` used `StdEncoding.Strict()`, so it
  rejected `Zh==` and could not yet evidence the pinned SDK's non-strict call
  sites; remediation must add an explicit Go-SDK policy to the adapter instead
  of claiming the current strict adapter represents that behavior;
- the permissive BSVUtil ancestor returns empty bytes on an invalid Base58
  character, but pinned Go SDK v1.3.3's `compat/base58.Decode` returns a `bad
  character in encoding` error. The differential must assert that actual Go SDK
  error category, not the ancestor's behavior.

## Accepted improvements

Before shipping the P1 baseline, also:

1. rename `CompactSize.encode(bytes:)` / `decodeBytes` to the symmetric,
   intention-revealing `encodeVarBytes(_:)` / `decodeVarBytes(_:)`;
2. document public error/index/bounds semantics and the cursor's transactional
   failure contract;
3. exercise Base58's final carry guard with `zz` under a one-byte limit;
4. add Base64 pure-padding, cross-quantum padding, and zero-output-limit
   negatives.

The later hashing packet should decide whether to add a nonthrowing
`TransactionID` initializer from `Hash256`. Inline fixed-hash storage remains a
profiling decision, not a correctness concern.

## Dispatch ruling

P1-A is accepted. P1-B becomes accepted when the ruling and negative
differentials pass against the real pinned oracle. The repository should ship
that accepted P0/P1 baseline before beginning P1-C so external reviewers have a
stable checkpoint.

The determining risk is undocumented divergence on malformed-but-Go-tolerated
Base64 input surfacing much later in auth or wallet processing.

## Remediation and acceptance

The required changes and accepted improvements were completed before the P1
checkpoint shipped:

- `CompactSize` now exposes the symmetric `encodeVarBytes(_:)` and
  `decodeVarBytes(_:maximumLength:canonicality:)` API; the earlier names were
  removed rather than retained as aliases.
- Public binary and encoding APIs document transactional reads, explicit
  completion, bounds, byte order, UTF-8 error offsets, and stable error cases.
- `COMP-018` records Swift's strict Hex, Base64, and Base58 policy and the
  pinned Go SDK's ordinary Base64 decoding behavior.
- The Go oracle's unchanged `base64.decode` operation accepts an explicit
  `strict` or `goSDK` policy. Real differentials prove Swift rejects embedded
  newlines and noncanonical discarded bits that the Go SDK-like policy accepts,
  while both sides reject invalid Base58 input.
- The requested Base58 carry-limit and Base64 padding/limit negatives are part
  of the unit suite.

Coordinator acceptance on 2026-08-07 passed the external Go 1.25.0 oracle
suite and the complete required-oracle Swift suite: 84 tests across 10 suites.
The accepted P0/P1 checkpoint contains P1-A and P1-B; hashing and BigInt work
remain future packets.
