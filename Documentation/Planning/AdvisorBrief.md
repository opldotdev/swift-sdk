# Fable architecture review brief

## Advice contract

Review the proposed architecture and delivery plan for a new Swift SDK whose
goal is complete functional parity with `bsv-blockchain/go-sdk` v1.3.3. This is
a read-only advisory pass. Do not edit files or propose implementation code.

Return:

1. A clear recommendation: approve, approve with required changes, or redesign.
2. Required changes ordered by severity and architectural leverage.
3. A revised SwiftPM target graph if the proposal is too coarse or too fine.
4. Specific dependency decisions or experiments required before approval.
5. Testing gaps that could allow false parity with the Go SDK.
6. Risks involving Swift 6 concurrency, value/reference semantics, binary
   parsing, consensus-scale big integers, cryptographic wrappers, Linux support,
   or the umbrella import design.
7. Any milestone ordering changes needed to keep work packets independently
   testable.
8. The smallest set of open questions that truly block creation of the package
   skeleton.

## Files to review

- `Documentation/Planning/README.md`
- `Documentation/Planning/Architecture.md`
- `Documentation/Planning/Roadmap.md`
- `Documentation/Planning/Testing.md`
- `Documentation/Planning/Compatibility.md`

## Evidence available

- Upstream Go SDK research checkout: `~/code/go-sdk`
- SwiftBSV research checkout: `/tmp/swiftbsv-research`
- Apple Swift Crypto research checkout: `/tmp/swift-crypto-research`
- swift-secp256k1 research checkout: `/tmp/swift-secp256k1-research`
- Swift Bitcoin research checkout: `/tmp/swift-bitcoin-research`
- Normative BRC repository: `/Users/satchmo/code/BRCs`

Inspect only the portions needed to validate the architecture. Do not treat the
Go package layout as an architecture requirement; its observable behavior and
wire compatibility are the target.

## Accepted product decisions

- Apple platforms plus Linux.
- Swift 6.1 minimum unless evidence requires a higher floor.
- Idiomatic Swift API with behavioral parity.
- BRC/network consensus behavior takes precedence over incidental Go quirks.
- Upstream test vectors should enter work packets as early as their prerequisites
  allow.
- Original source is provisionally MIT; copied or adapted upstream material
  must retain its governing license pending formal license review.
- Primitive implementation workers will be bounded subagents using
  `gpt-5.6-sol` with high reasoning, followed by Fable review.

## Questions requiring special scrutiny

- Should consumers get one stable `import BSV`, several feature modules, or
  both? Avoid relying on underscored Swift re-export behavior without explicitly
  accepting that risk.
- Is `BSVCore -> BSVCrypto -> BSVKeys -> BSVScript -> BSVTransaction ->
  BSVInterpreter` the right cycle-breaking boundary?
- Should script-number arithmetic use a general BigInt library, a specialized
  sign-magnitude implementation, or a hybrid? The protocol permits inputs up to
  32 MB after Chronicle.
- Is a small internal byte cursor safer than adopting Apple's pre-1.0
  `swift-binary-parsing` package?
- Are `BSVAuth`, `BSVOverlay`, and higher services separate targets, or should
  the first release keep fewer targets and split after APIs stabilize?
