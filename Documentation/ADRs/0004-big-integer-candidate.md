# ADR 0004: Arbitrary-precision integer dependency

- Status: Proposed; dependency not yet approved
- Date: 2026-08-07

## Context

The SDK needs arbitrary-precision integers below both `BSVCrypto` and
`BSVScript`:

- Shamir/key-share polynomial arithmetic requires modular operations over the
  secp256k1 order.
- Bitcoin Script uses signed-magnitude little-endian integers whose permitted
  sizes depend on the active consensus era.
- Chronicle configurations can admit values up to 32 MiB, so correct arithmetic
  alone is insufficient; parsing, allocation, and operation limits must be
  predictable for hostile inputs.

Swift exposes `StaticBigInt` for integer literals, but it is not a general
mutable runtime arbitrary-precision integer implementation. The package
therefore needs either a third-party dependency or an SDK-owned implementation.

## Leading candidate

Evaluate `attaswift/BigInt` 5.7.0 behind the internal `BSVBigNum` target.
No public SDK type will expose the dependency's concrete types.

Evidence gathered before the decision:

- MIT license.
- Pure Swift and no runtime package dependencies.
- SwiftPM tools version 5.9 with strict-concurrency checking enabled.
- `BigInt` and `BigUInt` conform to `Sendable`.
- Addition, subtraction, multiplication, division, remainder, shifts,
  modular exponentiation, and modular inverse are available.
- Its 211 upstream tests pass on macOS with Apple Swift 6.3.3.

This evidence makes it the leading candidate, not an accepted dependency.

## Acceptance experiments

The dependency may be added only after a Phase 1 packet demonstrates:

1. A clean Swift 6 build and upstream test run on both macOS and Linux.
2. Correct SDK-owned Bitcoin signed-magnitude encode/decode behavior, including
   negative zero, sign-bit boundaries, minimality, and native-integer overflow.
3. Modular arithmetic parity for the exact operations used by Shamir/key-share
   code, including negative operands and canonical positive residues.
4. Linear-time decode/encode behavior and bounded peak allocation at 750,000
   bytes and 32 MiB, tested at limit minus one, the limit, and limit plus one.
   On the documented reference macOS arm64 and Linux x86_64 CI machines, each
   32 MiB import and export must complete in no more than eight seconds in a
   release build. Incremental peak resident memory above the idle-process
   baseline must remain at or below four times the input byte count.
5. Explicit operation budgets for multiplication, division, shifts, and other
   hostile large-value operations; merely accepting a 32 MiB value must not
   imply that every arithmetic operation is unbounded. Limit-plus-one parsing
   must reject before invoking the dependency constructor, verified with an
   injected construction spy, and may increase resident memory by no more than
   1 MiB above test noise after calibration.
6. No use of the dependency's ambient random-number helpers. Production
   randomness must enter through the SDK's injectable secure-randomness
   protocol.
7. A replacement test showing that no public SDK signature mentions `BigInt`
   or `BigUInt`.
8. The required Linux scale job runs in a memory-capped environment and fails
   on timeout, out-of-memory termination, or either resource ceiling. A worker's
   local report cannot substitute for this coordinator-owned CI evidence.

## Timing side-channel position

`attaswift/BigInt` is variable-time. The SDK does not claim constant-time
behavior for its arbitrary-precision adapter. Public Script arithmetic is not
secret-bearing. Where P256K/libsecp256k1 exposes the needed secret-scalar
operation, cryptographic code must use that implementation instead of BigInt.

Go v1.3.3 uses variable-time `math/big` for Shamir/key-share polynomial work.
Initial Swift parity accepts the same timing-leak posture for offline key-share
creation and reconstruction, documents that limitation, and requires a focused
security review before those APIs are described as safe in a shared-process or
attacker-observable timing environment. This is a deliberate compatibility
decision, not an assertion that the dependency is side-channel hardened.

## Alternatives considered

- SDK-owned big integer: maximum control but too much security- and
  performance-sensitive code before the need is proven.
- GMP or another C library: mature arithmetic, but a larger portability,
  distribution, and audit burden across Apple platforms and Linux.
- `mkrd/Swift-BigInt`: active and MIT, but its documented surface and package
  maturity are less aligned with the required modular operations.
- Other Swift packages: remain eligible if the scale experiment exposes a
  blocker in the leading candidate.

## Consequences if accepted

- `BSVBigNum` depends on the exact approved version and owns all adaptation,
  error conversion, signed-magnitude encoding, and resource enforcement.
- `BSVCrypto` and `BSVScript` depend only on `BSVBigNum`, not directly on the
  third-party module.
- A future replacement does not change public SDK APIs or the target graph.

## References

- <https://github.com/attaswift/BigInt/tree/v5.7.0>
- <https://developer.apple.com/documentation/swift/staticbigint>
