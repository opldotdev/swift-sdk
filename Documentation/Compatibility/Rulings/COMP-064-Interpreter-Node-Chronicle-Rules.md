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
   `SCRIPT_CHRONICLE`. The `.afterChronicle` era always implies it, because a
   post-Chronicle output can only be spent in a Chronicle block.
   `.enableForkID` implying `.strictEncoding` predates this ruling and
   matches `VerifyScript` (lines 2314-2318).
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
8. **Structural DER only.** The DER rule is the node's structural
   `IsValidSignatureEncoding` (lines 177-245). A structurally valid
   signature whose `r` or `s` is zero or not below the curve order passes
   it and fails verification without an error. LOW_S follows the node's lax
   parser (`CPubKey::CheckLowS`, `src/pubkey.cpp:32-175, 353-363`): a value
   longer than 32 bytes or not below the curve order makes it read the zero
   signature, which is low S; otherwise the real `s` is checked, so `r = 0`
   with `s` above half the order fails LOW_S. NULLFAIL still applies.
9. **Arithmetic results.** After Genesis, a numeric result longer than the
   script-number limit fails with `numberTooLarge`, as the node's big-number
   `+=`, `-=` and `*=` do (`script_num.cpp:166, 196, 216`). This covers
   `OP_ADD`, `OP_SUB`, `OP_MUL`, `OP_1ADD`, `OP_1SUB` and `OP_2MUL`. Before
   Genesis the node computes in int64 with no result check, so a result can
   be up to eight bytes (`OP_MUL`).
10. **ForkID digest only with ForkID enabled (T8).** A hash type with the
    ForkID bit, verified without `.enableForkID`, uses the original digest.
11. **Original-digest script code (T9).** `SerializeScriptCode` (line 1864)
    writes the length minus code separators and the bytes up to where a
    failed final push stopped the parser. `FindAndDelete` removes only exact
    push encodings of the signature, and applies whenever ForkID is not
    enabled or the hash type lacks ForkID (`CleanupScriptCode`, line 255).
    An empty signature removes `OP_0` instructions.
12. **Chronicle unlocking script code.** A `CHECKSIG` or `CHECKMULTISIG`
    that runs in the unlocking script under `.chronicle` signs the unlocking
    script code followed by the locking script (lines 1472-1481 and
    1568-1576).
13. **Alt stack (T5).** The alt stack is cleared before each script runs,
    so items do not leak from the unlocking script into the locking script
    after an early `OP_RETURN`.
14. **Public-key check (T6).** `CheckPubKeyEncoding` runs even for an empty
    signature, in `CHECKSIG` and on every `CHECKMULTISIG` comparison.
15. **NULLFAIL.** When enforced, NULLFAIL applies to every non-empty
    signature that fails, including one rejected before the ECDSA check
    (lines 1489 to 1497).
16. **Multisig counts.** `CHECKMULTISIG` key and signature counts are decoded
    as 4-byte script numbers in every era.

New public consensus failures: `ScriptConsensusFailure.illegalChronicle(UInt8)`
and `ScriptConsensusFailure.scriptNumberOverflow`.

## Caller-visible changes

- **Legacy signatures with `.enableForkID`.** A signature without the
  ForkID bit now fails with `illegalForkID` when `.enableForkID` is set. It
  used to pass the hash-type check and verify against the legacy digest.
  This matches node `SCRIPT_ERR_MUST_USE_FORKID` and closes a replay-style
  acceptance. Callers validating pre-UAHF history must not set
  `.enableForkID`.
- **`.chronicle` for older outputs.** `.chronicle` is a block-level flag.
  Only `.afterChronicle` implies it. For a spend mined at or after Chronicle
  activation (mainnet height 943,816) of an `.afterGenesis` or
  `.beforeGenesis` output, the caller must pass `.chronicle` to match the
  node. Without it Swift is stricter than the node: it rejects `0x20` hash
  types and keeps the malleability rules for transaction versions above 1.
- **`.bip143SignatureHash`.** Under strict encoding it only requires the
  ForkID bit; a signature without it fails with `invalidSignatureHashType`.
  It no longer selects the ForkID digest. That digest is used only with
  `.enableForkID`, and without `.enableForkID` a ForkID signature fails with
  `illegalForkID`. Use it with `.enableForkID`, where it changes only which
  failure is reported.
- **Signature script-code size.** The script code of a signature check, which
  under `.chronicle` can be the unlocking script plus the locking script, is
  bounded only by the context's `TransactionLimits.maximumScriptByteCount`
  and fails with `ScriptExecutionError.transaction(.scriptTooLarge)`. The
  node has no such bound; this is a local resource stop.

## Not changed

- The node checks SIGPUSHONLY only when `SCRIPT_GENESIS` or
  `SCRIPT_CHRONICLE` is set (lines 2321-2333). Swift checks it whenever
  `.signaturePushOnly` is passed, so a caller that sets it for a spend in
  a block before Genesis activation is stricter than the node.
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
runs all 21 TypeScript node-conformance vectors and pins the behaviour
introduced by this ruling, with a test for each item above.
