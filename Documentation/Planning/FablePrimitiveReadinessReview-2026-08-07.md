# Fable primitive-readiness review

- Date: 2026-08-07
- Channel: read-only Claude Fable CLI consult
- Authentication: signed-in Claude subscription with `ANTHROPIC_API_KEY`
  removed from the process environment
- Verdict: **APPROVE WITH REQUIRED CHANGES**

Fable inspected the package graph, planning documents, compatibility matrices,
vector inventory, dependency audits, and oracle lock. It judged the architecture
acyclic, the no-copy licensing/oracle boundary credible, and COMP-001 through
COMP-014 safe. It required the following changes before dispatch:

1. Make the P0-B oracle registry match the vector inventory so later primitive
   packets do not need to violate its file ownership.
2. Replace the single fixture manifest with deterministic per-group fragments,
   removing the P1-A/P1-B parallel write collision.
3. Declare `BSVScript` and `BSVTransaction` as direct `BSVAuth` dependencies.
4. Make the BigInt time/allocation gates measurable and explicitly document the
   variable-time posture for secret-bearing key-share arithmetic.

The review also required packet-local refinements: raw `UInt64.max` handling in
CompactSize, `isCanonical` on decoded values, oracle line/time/process limits,
exact Go toolchain validation, HMAC verification negatives, a bounded Base58
decoder, a hybrid public-key compatibility ruling, coordinator-owned Linux
evidence, and merging standalone Base58Check into the first WIF/address packet.

All required changes are incorporated in the linked planning and compatibility
documents. The resulting dispatch order is P0-A and P0-B in parallel, a review
barrier, P1-A and P1-B in parallel, another barrier, then P1-C and P1-D
sequentially. Base58Check begins the Phase 3 WIF/address packet.

## Deciding risk

The fixture manifest was the only shared mutable file in the parallel packet
design. Per-group fragments resolve that collision at the schema boundary,
before any fixture-bearing implementation work inherits it.
