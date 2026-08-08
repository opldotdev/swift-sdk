# Fable review: BigNum and Script foundation

- Date: 2026-08-07
- Reviewer: Claude Fable 5 through the read-only advisor lane
- Authentication: signed-in Claude Max subscription; `ANTHROPIC_API_KEY` unset
- Scope: exact BigInt dependency boundary, bounded arbitrary-precision adapter,
  Script numbers, opcodes, PUSHDATA parsing/building, tests, and fixture provenance
- Verdict: accept as the foundation; no must-fix correctness, safety, API, or
  portability defect found

## Findings

The reviewer verified that hostile PUSHDATA4 lengths are checked for native
integer representability before conversion, push lengths are bounded before
slicing/allocation, and all push-prefix ranges are complete. Signed-magnitude
negative zero, sign boundaries, Int64 minimum, clamping, and minimal encoding
were judged nontrapping and consistent with the permissive reference. The
`BSVBigNum` dependency is package-scoped and is not a public product.

The deciding residual risk was missing Linux scale evidence. The review also
identified two evidence gaps: scale cases did not include limit minus one, and
the ADR described peak memory while the test sampled resident memory after
each operation. It requested an automated guard against `BigInt`/`BigUInt`
appearing in public signatures.

## Resolution

- Added 750,000-minus-one and 32-MiB-minus-one release scale cases.
- Corrected the ADR to describe completed-operation resident growth rather
  than unsampled transient peak memory.
- Added a symbol-graph check across every public SDK module.
- Added macOS/Linux Swift 6.1 CI and a 768-MiB memory-capped Linux release
  scale job. The Linux scale gate passed on the shipped revision in GitHub
  Actions run [31229942005](https://github.com/opldotdev/swift-sdk/actions/runs/31229942005),
  closing the review's final acceptance condition.
