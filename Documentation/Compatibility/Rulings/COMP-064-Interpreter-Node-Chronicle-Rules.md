# COMP-064: Interpreter follows SV Node v1.2.3 Chronicle and signature rules

## Context

The interpreter was built against pinned Go SDK v1.3.3. A review against
TypeScript `@bsv/sdk` 4.1.1 found ten places (review items T1 to T10) where
Swift, and in several cases Go, disagree with the TypeScript interpreter.
Script validity is consensus, so the deciding source is the SV Node
implementation, not either SDK. Every item was checked against SV Node v1.2.3
(`bitcoin-sv` tag `v1.2.3`, commit `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`).
Where TypeScript and the node disagree, Swift follows the node.

## Ruling

Swift follows SV Node v1.2.3 for the rules below. References are to
`src/script/interpreter.cpp` unless noted.

1. **Chronicle flag.** `ScriptVerificationFlags.chronicle` (`1 << 15`) mirrors
   `SCRIPT_CHRONICLE`. The `.afterChronicle` era always implies it, and
   `.enableForkID` implies `.strictEncoding`, as in the node's standard flags.
2. **Malleability relaxation (T10).** `EnforceNonMalleability` (line 40) is
   false only when `.chronicle` is set and the spending transaction's version,
   read as a signed 32-bit integer, is greater than 1. Without a transaction
   the version is 0. When it is false, MINIMALDATA, MINIMALIF, LOW_S,
   NULLFAIL, NULLDUMMY, SIGPUSHONLY and CLEANSTACK are not enforced
   (lines 285, 433, 801, 1493, 1643, 1666, 2441). P2SH push-only is not
   relaxed.
3. **Splice operands (T1).** `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` decode
   their numeric operands as the node's `CScriptNum` int64 path does
   (line 609): era length check, minimal check, at most 9 bytes
   (`scriptNumberOverflow` otherwise), then saturation to `Int32`.
4. **Numeric shifts (T2, T7).** `OP_LSHIFTNUM` and `OP_RSHIFTNUM`
   (lines 692 and 728) reject a negative shift and, for a right shift, a
   shift above `INT32_MAX`. A right shift of a negative value rounds toward
   zero (`BN_rshift` on the magnitude in `big_int.cpp`), so `-3 >> 1 == -1`.
   A left shift fails when `current_size + shift / 8` exceeds the number
   limit, even for the value 0, and the result size is checked again.
5. **Number limit (T3).** The post-Chronicle script-number limit is
   `MAX_SCRIPT_NUM_LENGTH_AFTER_CHRONICLE = 32 * ONE_MEGABYTE`
   (`src/consensus/consensus.h:66`), which is 32,000,000 bytes, not 32 MiB.
   `ScriptResourceLimits.standard` keeps its separate 32 MiB allocation cap.
6. **Chronicle digest (T4).** Under `.chronicle` a signature may carry
   `SIGHASH_CHRONICLE` (`0x20`, `src/script/sighashtype.h:19`). The digest is
   BIP143 only when ForkID is enabled, the hash type has ForkID, and it does
   not have the Chronicle bit (line 2118). Otherwise the original (OTDA)
   digest is used. Without `.chronicle` the Chronicle bit fails with
   `illegalChronicle` (line 303).
7. **Hash-type order.** Under STRICTENC the checks run in node order:
   defined base type, then illegal ForkID, then illegal Chronicle, then
   `MUST_USE_FORKID` when ForkID is enabled and the bit is missing
   (line 306).
8. **ForkID digest only with ForkID enabled (T8).** A hash type with the ForkID
   bit, verified without `.enableForkID`, uses the original digest.
9. **Original-digest script code (T9).** `SerializeScriptCode` (line 1864)
   writes the length minus code separators and the bytes up to where a
   failed final push stopped the parser. `FindAndDelete` removes only exact
   push encodings of the signature, and applies whenever ForkID is not
   enabled or the hash type lacks ForkID (`CleanupScriptCode`, line 255).
10. **Chronicle unlocking script code.** A `CHECKSIG` that runs in the
    unlocking script under `.chronicle` signs the unlocking script code
    followed by the locking script.
11. **Alt stack (T5).** The alt stack is cleared before each script runs,
    so items do not leak from the unlocking script into the locking script
    after an early `OP_RETURN`.
12. **Public-key check (T6).** `CheckPubKeyEncoding` runs even for an empty
    signature, in `CHECKSIG` and on every `CHECKMULTISIG` comparison.
13. **NULLFAIL.** When enforced, NULLFAIL applies to every non-empty
    signature that fails, including one rejected before the ECDSA check
    (lines 1489 to 1497).
14. **Multisig counts.** `CHECKMULTISIG` key and signature counts are decoded
    as 4-byte script numbers in every era.

New public consensus failures: `ScriptConsensusFailure.illegalChronicle(UInt8)`
and `ScriptConsensusFailure.scriptNumberOverflow`.

## Not changed

- Node also bounds arithmetic results (`OP_ADD`, `OP_MUL` and others) by the
  script-number length. Swift bounds them by the push limit. This is outside
  T1 to T10 and remains open.
- Signing stays ForkID-only (COMP-023). The interpreter now validates
  Chronicle/OTDA signatures, but `ForkIDSignatureHashType` does not create
  them.

## Go difference

Pinned Go v1.3.3 uses a 32 MiB Chronicle number limit, floors a negative
right shift (`-3 >> 1 == -2`), and does not implement the Chronicle hash type
or the malleability relaxation. Swift no longer matches Go in these cases. The
Go differential case for a negative right shift was removed; the node result
is pinned in `NodeConformanceRegressionTests`.

## Tests

`Tests/BSVInterpreterTests/NodeConformance/NodeConformanceRegressionTests.swift`
runs all 21 TypeScript node-conformance vectors and a test for each item
above. Each test fails on the code before this ruling.
