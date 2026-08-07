# Fable Phase 0 implementation review

- Date: 2026-08-07
- Channel: read-only Claude Fable CLI consult
- Authentication: signed-in Claude subscription with `ANTHROPIC_API_KEY`
  removed from the process environment
- Verdict: **APPROVE WITH REQUIRED CHANGES**
- Dispatch ruling: P1-A and P1-B may run in parallel after the coordinator
  closes the required Phase 0 changes below.

Fable approved the fixture boundary, archive pin handshake, persistent Swift
process client, adapter routing, tests, and README design. It found two required
gaps:

1. Oracle adapters had smoke/category coverage but almost no independently
   known value assertions. A mislabeled HMAC argument or endian branch could
   therefore redefine “Go behavior” while every test remained green. Add
   standards-derived/independently computed constants in Go tests and exercise
   every operation family through the real persistent Swift integration.
2. Git mode verified HEAD/tag/clean status but did not compare the computed
   complete-tree hash to a trusted value. Pin a distinct `gitTreeSHA256` and
   reject mismatches, including ignored-file substitution.

The coordinator also accepted these boundary refinements before P1:

- COMP-016 records that fixed digest parsing is an explicit exact-width adapter
  policy, not raw Go `chainhash` behavior.
- COMP-017 limits the composed Base58Check oracle claim to one-byte-version
  Bitcoin Base58Check; higher-level formats require their own evidence.
- Fixture license bytes receive their own SHA-256 field before any real fixture
  fragments adopt the schema.
- Process invalidation kills a blocked child before closing its stdin, metadata
  startup has a separate deadline, Linux's test-target SIGPIPE policy is
  documented, and the default Go cache becomes repository-private.

The exact GitHub archive extracted at
`/private/tmp/go-sdk-verify.itq5wh/go-sdk-de26fdec57a945ddc06de5d5617f6c32374f3929`
has complete-tree SHA-256
`2d2b2012877f208b46a295dbc1cada9fabcb8416a85bcf35ad3c55afeb3ce367`.
The separately trusted research archive remains
`09f05c13ee9286d5f5d6ed8724625a28edcd923b5b3d961a277cfd16347e4337`;
their only observed content differences are eight `.github` metadata files,
not Go source.

## Deciding risk

The oracle is authoritative only if both sides of the comparison are anchored.
Pinning the source tree is insufficient when an adapter can be wrong in a way
that its own smoke tests accept; independent known values close that loop.

## Remediation acceptance

All required changes and accepted boundary refinements were completed before
P1 dispatch. The coordinator independently reran the exact Go 1.25 offline
suite, verified the archive metadata/32-operation registry, passed 23 fixture
manifest tests and 16 oracle protocol/lifecycle tests, and passed the complete
40-test Swift suite with `BSV_ORACLE_REQUIRED=1` against the trusted external
archive. The source audit found no dependency substitution, copied Open BSV
fixture, unsafe build workaround, or edit outside the authorized P0 paths.

P1-A and P1-B are therefore cleared for parallel implementation under their
disjoint file-ownership specifications.
