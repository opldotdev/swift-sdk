@testable import BSVInterpreter
import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

/// SV Node v1.2.3 script rules that the pinned Go SDK v1.3.3 does not follow.
///
/// Transaction vectors come from TypeScript `@bsv/sdk` 4.1.1
/// `packages/sdk/src/script/__tests/Spend.node-conformance-regressions.test.ts`
/// (cited as `TS:<line>`), whose verdicts are SV Node's. Rules without a TS
/// vector cite `bitcoin-sv` v1.2.3 `src/script/interpreter.cpp` (`node:<line>`).
@Suite("SV Node script conformance regressions")
struct NodeConformanceRegressionTests {
    // MARK: TS node-conformance vectors

    @Test("every TypeScript node-conformance vector gets the node verdict", arguments: Self.vectors)
    func nodeVector(_ vector: NodeVector) throws {
        if vector.valid {
            #expect(try vector.run().stack.last.map(scriptTruth) == true, "TS:\(vector.sourceLine)")
        } else {
            #expect(throws: ScriptExecutionError.self, "TS:\(vector.sourceLine)") {
                try vector.run()
            }
        }
    }

    // MARK: T1 splice operands

    @Test("OP_SUBSTR, OP_LEFT and OP_RIGHT reject operands longer than nine bytes")
    func spliceOperandsLongerThanNineBytes() throws {
        for lock in [
            "03000102000a01000000000000000000b3", // SUBSTR, ten-byte length 1
            "030001020a0100000000000000000051b3", // SUBSTR, ten-byte offset 1
            "0200010a01000000000000000000b4", // LEFT, ten-byte count 1
            "0200010a01000000000000000000b5", // RIGHT, ten-byte count 1
        ] {
            #expect(throws: ScriptExecutionError.consensus(.scriptNumberOverflow), "\(lock)") {
                try run(lock: lock, era: .afterChronicle)
            }
        }
    }

    @Test("nine-byte splice operands decode the full signed 64-bit value")
    func nineByteSpliceOperands() throws {
        let nineByteOne = "09010000000000000000"
        let nineByteMinusOne = "09010000000000000080"
        for lock in [
            "0300010200" + nineByteOne + "b3" + "0100" + "87", // SUBSTR length 1 gives 00
            "020001" + nineByteOne + "b4" + "0100" + "87", // LEFT 1 gives 00
            "020001" + nineByteOne + "b5" + "0101" + "87", // RIGHT 1 gives 01
        ] {
            #expect(try run(lock: lock, era: .afterChronicle).stack == [[1]], "\(lock)")
        }
        // A nine-byte -1 is out of range, not a truncated 1 or a huge count.
        let negativeOne: [(String, ScriptConsensusFailure)] = [
            ("03000102" + nineByteMinusOne + "51b3", .invalidSplitPosition(position: -1, byteCount: 3)),
            ("0300010200" + nineByteMinusOne + "b3", .invalidSplitPosition(position: 0, byteCount: 3)),
            ("020001" + nineByteMinusOne + "b4", .invalidSplitPosition(position: -1, byteCount: 2)),
            ("020001" + nineByteMinusOne + "b5", .invalidSplitPosition(position: -1, byteCount: 2)),
        ]
        for (lock, failure) in negativeOne {
            #expect(throws: ScriptExecutionError.consensus(failure), "\(lock)") {
                try run(lock: lock, era: .afterChronicle)
            }
        }
        // TS:164 gen-00795: offset 04 00 00 00 00 00 00 00 80 is -4, not 4.
        #expect(throws: ScriptExecutionError.consensus(
            .invalidSplitPosition(position: -4, byteCount: 16)
        )) {
            try run(
                lock: "10000102030405060708090a0b0c0d0e0f0904000000000000008054b3040405060787",
                era: .afterChronicle
            )
        }
        for operand in [
            "09ffffffffffffffff00", // 2^64 - 1
            "09000000000000008000", // 2^63
            "09010000000000000001", // value bits in the sign byte
        ] {
            #expect(throws: ScriptExecutionError.consensus(.scriptNumberOverflow), "\(operand)") {
                try run(lock: "020001" + operand + "b4", era: .afterChronicle)
            }
        }
        // -2^63 decodes and saturates to INT32_MIN, which is out of range.
        #expect(throws: ScriptExecutionError.consensus(
            .invalidSplitPosition(position: Int64(Int32.min), byteCount: 2)
        )) {
            try run(lock: "020001" + "09000000000000008080" + "b4", era: .afterChronicle)
        }
        // A large in-range value saturates to INT32_MAX, which is out of range.
        #expect(throws: ScriptExecutionError.consensus(
            .invalidSplitPosition(position: Int64(Int32.max), byteCount: 2)
        )) {
            try run(lock: "020001" + "09ffffffffffffff7f00" + "b4", era: .afterChronicle)
        }
        // MINIMALDATA applies before the nine-byte rule.
        #expect(throws: ScriptExecutionError.consensus(.nonMinimalNumber)) {
            try run(
                lock: "020001" + "0a01000000000000000000" + "b4",
                era: .afterChronicle,
                flags: [.minimalData]
            )
        }
    }

    // MARK: T2 / T7 numeric shifts

    @Test("numeric shift counts above INT32_MAX are rejected")
    func shiftCountAboveInt32() throws {
        // TS:173 gen-00835 and TS:303: 1 >> 2^31 and 1 << 2^31.
        for lock in ["51050000008000b77551", "51050000008000b67551", "00050000008000b67551"] {
            #expect(throws: ScriptExecutionError.self, "\(lock)") {
                try run(lock: lock, era: .afterChronicle)
            }
        }
        #expect(throws: ScriptExecutionError.consensus(.invalidShiftAmount(1 << 31))) {
            try run(lock: "51050000008000b77551", era: .afterChronicle)
        }
        // 0 >> 2^31 is rejected too: bint::operator>>= checks the count first.
        #expect(throws: ScriptExecutionError.consensus(.invalidShiftAmount(1 << 31))) {
            try run(lock: "00050000008000b77551", era: .afterChronicle)
        }
        // INT32_MAX itself is a valid right-shift count.
        #expect(try run(lock: "5104ffffff7fb70087", era: .afterChronicle).stack == [[1]])
    }

    @Test("OP_LSHIFTNUM bounds the operand size plus shifted bytes by the number limit")
    func leftShiftSizeBound() throws {
        // TS:191 gen-00813: 1 << INT32_MAX.
        #expect(throws: ScriptExecutionError.consensus(
            .numberTooLarge(actual: 1 + Int(Int32.max) / 8, maximum: 32_000_000)
        )) {
            try run(lock: "5104ffffff7fb67551", era: .afterChronicle)
        }
        // node script_num.cpp operator<<=: zero is bounded too. 256,000,000
        // bits add exactly 32,000,000 bytes; eight more bits exceed the limit.
        #expect(try run(lock: "00040040420fb60087", era: .afterChronicle).stack == [[1]])
        #expect(throws: ScriptExecutionError.consensus(
            .numberTooLarge(actual: 32_000_001, maximum: 32_000_000)
        )) {
            try run(lock: "00040840420fb67551", era: .afterChronicle)
        }
    }

    @Test("OP_RSHIFTNUM rounds negative values toward zero")
    func rightShiftRoundsTowardZero() throws {
        // -3 >> 1 == -1 (0x81) and -1 >> 1 == 0: BN_rshift shifts the magnitude.
        #expect(try run(lock: "538f51b7018187", era: .afterChronicle).stack == [[1]])
        #expect(try run(lock: "4f51b70087", era: .afterChronicle).stack == [[1]])
        #expect(try run(lock: "548f51b7018287", era: .afterChronicle).stack == [[1]])
        #expect(try run(lock: "538f51b7", era: .afterChronicle).stack == [[0x81]])
    }

    // MARK: T3 number size

    @Test("after Chronicle the script number limit is 32,000,000 bytes")
    func chronicleNumberLimit() throws {
        let vector = try #require(Self.vectors.first { $0.name == "gen-00009" })
        #expect(throws: ScriptExecutionError.consensus(
            .numberTooLarge(actual: 32_000_001, maximum: 32_000_000)
        )) {
            try vector.run()
        }
    }

    // MARK: T4 SIGHASH_CHRONICLE

    @Test("a SIGHASH_CHRONICLE|FORKID signature verifies against the original digest")
    func chronicleSignatureUsesOriginalDigest() throws {
        // TS:78 gen-00974: a pre-Chronicle output spent in a Chronicle block
        // with hash type 0x61 (ALL|FORKID|CHRONICLE).
        let vector = try #require(Self.vectors.first { $0.name == "gen-00974" })
        #expect(try vector.run().stack == [[1]])
        // node:296-303: outside Chronicle rules strict encoding rejects bit 0x20.
        #expect(throws: ScriptExecutionError.consensus(.illegalChronicle(0x61))) {
            try vector.run(flags: [.enableForkID])
        }
        // node:2118: the CHRONICLE bit selects the original digest whatever
        // the flags, so without strict encoding the signature still verifies.
        #expect(try vector.run(flags: []).stack == [[1]])
        #expect(try vector.run(flags: [.derSignatures, .lowS, .nullFail]).stack == [[1]])
        // TS:97 and TS:106: the original digest walk includes the malformed
        // bytes after OP_RETURN.
        for name in ["gen-01001", "gen-00999"] {
            let walkVector = try #require(Self.vectors.first { $0.name == name })
            #expect(try walkVector.run().stack == [[1]], "\(name)")
        }
    }

    @Test("strict encoding checks hash types in the node's order")
    func hashTypeMatrix() throws {
        let vector = try #require(Self.vectors.first { $0.name == "gen-00974" })
        let element = Array(try vector.transaction().inputs[0].unlockingScript.bytes.dropFirst())
        let der = Array(element.dropLast())
        let checkSignature = hex(vector.lockHex)
        let profiles: [(ScriptVerificationFlags, (UInt8) -> ScriptConsensusFailure?)] = [
            ([.enableForkID, .chronicle], { hashType in
                guard (1...3).contains(hashType & 0x1f) else { return .invalidSignatureHashType(hashType) }
                return hashType & 0x40 == 0 ? .illegalForkID(hashType) : nil
            }),
            ([.enableForkID], { hashType in
                guard (1...3).contains(hashType & 0x1f) else { return .invalidSignatureHashType(hashType) }
                if hashType & 0x20 != 0 { return .illegalChronicle(hashType) }
                return hashType & 0x40 == 0 ? .illegalForkID(hashType) : nil
            }),
            ([.strictEncoding, .chronicle], { hashType in
                guard (1...3).contains(hashType & 0x1f) else { return .invalidSignatureHashType(hashType) }
                return hashType & 0x40 != 0 ? .illegalForkID(hashType) : nil
            }),
        ]
        for (flags, expected) in profiles {
            for hashType in UInt8.min...UInt8.max {
                let signature = der + [hashType]
                let lock = [UInt8(signature.count)] + signature + checkSignature + [0x91]
                let lockHex = Hex.encode(lock)
                if let failure = expected(hashType) {
                    #expect(throws: ScriptExecutionError.consensus(failure), "\(flags) \(hashType)") {
                        try run(lock: lockHex, era: .afterGenesis, flags: flags, context: true)
                    }
                } else {
                    // The encoding passes; the signature does not verify here.
                    #expect(
                        try run(lock: lockHex, era: .afterGenesis, flags: flags, context: true).stack == [[1]],
                        "\(flags) \(hashType)"
                    )
                }
            }
        }
    }



    @Test("the alternate stack does not survive an unlocking-script OP_RETURN")
    func altStackDoesNotLeak() throws {
        for era in [ScriptExecutionEra.afterGenesis, .afterChronicle] {
            #expect(throws: ScriptExecutionError.consensus(.altStackUnderflow)) {
                try run(unlock: "516b6a", lock: "6c", era: era)
            }
        }
    }

    // MARK: T6 empty signature and public-key encoding

    @Test("an empty signature still requires a strictly encoded public key")
    func emptySignaturePublicKeyEncoding() throws {
        // CHECKSIG: OP_0, pubkey 00, CHECKSIG, NOT.
        #expect(throws: ScriptExecutionError.consensus(.invalidPublicKeyEncoding)) {
            try run(lock: "000100ac91", era: .afterGenesis, flags: [.strictEncoding], context: true)
        }
        #expect(try run(lock: "000100ac91", era: .afterGenesis, context: true).stack == [[1]])
        // CHECKMULTISIG: dummy, empty signature, 1, pubkey 00, 1, CHECKMULTISIG, NOT.
        #expect(throws: ScriptExecutionError.consensus(.invalidPublicKeyEncoding)) {
            try run(lock: "000051010051ae91", era: .afterGenesis, flags: [.strictEncoding], context: true)
        }
        #expect(try run(lock: "000051010051ae91", era: .afterGenesis, context: true).stack == [[1]])
    }

    // MARK: T8 ForkID digest gating

    @Test("a FORKID-bit signature uses the original digest when ForkID is not enabled")
    func preForkIDSignatures() throws {
        // TS:340: three P2PK inputs signed with 0x01, 0x41 and 0x01 at height 478000.
        for (index, lock) in Self.preUAHFLocks.enumerated() {
            #expect(try runPreUAHF(index: index, lock: lock).stack == [[1]], "input \(index)")
        }
        // With ForkID enabled the legacy signatures must use FORKID (node:296-306).
        #expect(throws: ScriptExecutionError.consensus(.illegalForkID(0x01))) {
            try runPreUAHF(index: 0, lock: Self.preUAHFLocks[0], flags: [.enableForkID])
        }
    }

    // MARK: T9 original digest script-code walk

    @Test("the original digest walk writes what the node walk consumes")
    func originalDigestWalk() throws {
        // TS:311-331: CompactSize plus bytes of the preimage script field.
        for (scriptHex, expectedHex) in [
            ("4d0100aa", "044d0100aa"),
            ("4e01000000aa", "064e01000000aa"),
            ("6a4e050000", "056a4e"),
            ("6a4e05000000aabb", "086a4e05000000"),
            ("51ab52ab", "025152"),
            ("ab", "00"),
            ("51ab4c", "0251" + "4c"),
        ] {
            let walk = ScriptMachine.originalDigestScriptCode(hex(scriptHex))
            #expect([UInt8(walk.encodedLength)] + walk.bytes == hex(expectedHex), "\(scriptHex)")
        }
    }

    @Test("FindAndDelete removes only exact signature pushes at instruction boundaries")
    func findAndDelete() throws {
        let signature: [UInt8] = [0xaa, 0xbb]
        let pattern = ScriptMachine.pushEncoding(signature)
        #expect(pattern == [0x02, 0xaa, 0xbb])
        // Exact pushes are removed, repeated ones too.
        #expect(ScriptMachine.findAndDelete(hex("02aabb5102aabb02aabbac"), pattern: pattern) == hex("51ac"))
        // A push that merely contains the signature stays (pinned Go removes it).
        #expect(ScriptMachine.findAndDelete(hex("03aabbcc51"), pattern: pattern) == hex("03aabbcc51"))
        // A match inside push data is not at an instruction boundary.
        #expect(ScriptMachine.findAndDelete(hex("0302aabb51"), pattern: pattern) == hex("0302aabb51"))
        // A non-minimal push of the same bytes is a different instruction.
        #expect(ScriptMachine.findAndDelete(hex("4c02aabb51"), pattern: pattern) == hex("4c02aabb51"))
        // A truncated tail ends the walk and is kept.
        #expect(ScriptMachine.findAndDelete(hex("02aabb4d05"), pattern: pattern) == hex("4d05"))
        // An empty signature is pushed as OP_0.
        #expect(ScriptMachine.pushEncoding([]) == [0x00])
        #expect(ScriptMachine.pushEncoding(Array(repeating: 1, count: 76)).prefix(2) == [0x4c, 76])
        #expect(ScriptMachine.pushEncoding(Array(repeating: 1, count: 256)).prefix(3) == [0x4d, 0, 1])
    }

    // MARK: T10 Chronicle malleability relaxation

    @Test("Chronicle relaxes the malleability rules only for transaction versions above one")
    func chronicleMalleabilityRelaxation() throws {
        // TS:274: SIGPUSHONLY is kept for version one.
        let flow = try #require(Self.vectors.first { $0.name == "flow-00961" })
        #expect(throws: ScriptExecutionError.consensus(.signatureScriptNotPushOnly)) {
            try flow.run(version: 1)
        }
        // NULLFAIL (TS:15 crypto-00012).
        let crypto = try #require(Self.vectors.first { $0.name == "crypto-00012" })
        #expect(throws: ScriptExecutionError.consensus(.nullFail)) {
            try crypto.run(version: 1)
        }
        // MINIMALDATA (TS:33 arith-00351).
        let arith = try #require(Self.vectors.first { $0.name == "arith-00351" })
        #expect(throws: ScriptExecutionError.consensus(.nonMinimalNumber)) {
            try arith.run(version: 1)
        }
        // A version above INT32_MAX is negative to the node, so not malleable.
        #expect(throws: ScriptExecutionError.consensus(.signatureScriptNotPushOnly)) {
            try flow.run(version: 0x8000_0002)
        }
        // Without Chronicle rules nothing is relaxed, whatever the version.
        #expect(throws: ScriptExecutionError.consensus(.signatureScriptNotPushOnly)) {
            try flow.run(era: .afterGenesis, chronicle: false)
        }
    }

    @Test("Chronicle relaxes MINIMALIF, NULLDUMMY, CLEANSTACK and LOW_S for version two")
    func chronicleRelaxationOfRemainingRules() throws {
        let minimalIf = ("52", "6351670068") // 2 IF 1 ELSE 0 ENDIF
        let nullDummy = ("51", "0000ae") // dummy 1, 0-of-0 CHECKMULTISIG
        let cleanStack = ("5151", "51")
        let cases: [(String, (String, String), ScriptVerificationFlags, ScriptConsensusFailure)] = [
            ("MINIMALIF", minimalIf, [.minimalIf], .minimalIf),
            ("NULLDUMMY", nullDummy, [.strictMultiSignatureDummy], .nullDummy),
            ("CLEANSTACK", cleanStack, [.cleanStack, .payToScriptHash], .cleanStackViolation(actualItemCount: 3)),
        ]
        for (name, scripts, flags, failure) in cases {
            #expect(throws: ScriptExecutionError.consensus(failure), "\(name) v1") {
                try run(unlock: scripts.0, lock: scripts.1, era: .afterChronicle, flags: flags, context: true, version: 1)
            }
            #expect(try run(
                unlock: scripts.0, lock: scripts.1, era: .afterChronicle, flags: flags, context: true, version: 2
            ).stack.last == [1], "\(name) v2")
        }

        // LOW_S: a high-S P2PK signature.
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [7])
        let lock = try Script.payToPublicKey(key.publicKey, maximumByteCount: 100)
        for version: UInt32 in [1, 2] {
            var transaction = try simpleTransaction(version: version, unlocking: [], lock: lock)
            let digest = try transaction.legacySignatureHash(
                inputIndex: 0,
                hashType: .all,
                scriptCode: lock,
                limits: Self.limits
            )
            let low = try key.sign(digest: digest)
            let high = try ECDSASignature(
                compactBytes: Array(low.compactBytes[..<32])
                    + subtract(Array(low.compactBytes[32...]), from: curveOrder)
            )
            let element = high.derBytes + [0x01]
            transaction.inputs[0].unlockingScript = try Script(
                bytes: [UInt8(element.count)] + element,
                maximumByteCount: 100
            )
            let execute = {
                try ScriptInterpreter.execute(
                    unlockingScript: transaction.inputs[0].unlockingScript,
                    lockingScript: lock,
                    configuration: ScriptExecutionConfiguration(
                        era: .afterChronicle,
                        flags: [.lowS],
                        resourceLimits: .standard
                    ),
                    context: ScriptExecutionContext(
                        transaction: transaction,
                        inputIndex: 0,
                        spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
                        transactionLimits: Self.limits
                    )
                )
            }
            if version == 1 {
                #expect(throws: ScriptExecutionError.consensus(.invalidSignatureEncoding)) {
                    try execute()
                }
            } else {
                #expect(try execute().stack == [[1]])
            }
        }
    }

    // MARK: Other node signature-check rules

    @Test("a CHECKSIG in the unlocking script also commits to the locking script under Chronicle")
    func chronicleUnlockingScriptCode() throws {
        // node:1472-1481: scriptCode += scriptPubKey when CHRONICLE is set.
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [9])
        let lock = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        let scriptCode = try Script(
            bytes: [Opcode.checkSigVerify.rawValue, Opcode.one.rawValue],
            maximumByteCount: 2
        )
        var transaction = try simpleTransaction(version: 2, unlocking: [], lock: lock)
        let digest = try transaction.forkIDSignatureHash(
            inputIndex: 0,
            scriptCode: scriptCode,
            limits: Self.limits
        )
        let element = try key.sign(digest: digest).derBytes + [0x41]
        let publicKey = key.publicKey.compressedBytes
        transaction.inputs[0].unlockingScript = try Script(
            bytes: [UInt8(element.count)] + element + [UInt8(publicKey.count)] + publicKey
                + [Opcode.codeSeparator.rawValue, Opcode.checkSigVerify.rawValue],
            maximumByteCount: 200
        )
        let context = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
            transactionLimits: Self.limits
        )
        func execute(_ era: ScriptExecutionEra, _ flags: ScriptVerificationFlags) throws -> ScriptExecutionResult {
            try ScriptInterpreter.execute(
                unlockingScript: transaction.inputs[0].unlockingScript,
                lockingScript: lock,
                configuration: ScriptExecutionConfiguration(
                    era: era,
                    flags: flags,
                    resourceLimits: .standard
                ),
                context: context
            )
        }
        #expect(try execute(.afterChronicle, [.enableForkID]).stack == [[1]])
        #expect(try execute(.afterGenesis, [.enableForkID, .chronicle]).stack == [[1]])
        #expect(throws: ScriptExecutionError.consensus(.checkSignatureVerifyFailed)) {
            try execute(.afterGenesis, [.enableForkID])
        }
    }

    @Test("NULLFAIL applies to every failed non-empty signature")
    func nullFailOnEveryFailure() throws {
        // A one-byte signature (hash type only) and an invalid public key: the
        // node's CheckSig fails and NULLFAIL rejects the non-empty element.
        #expect(throws: ScriptExecutionError.consensus(.nullFail)) {
            try run(lock: "0101" + "0100" + "ac91", era: .afterGenesis, flags: [.nullFail], context: true)
        }
        #expect(try run(lock: "0101" + "0100" + "ac91", era: .afterGenesis, context: true).stack == [[1]])
    }

    @Test("CHECKMULTISIG counts are four-byte Script numbers in every era")
    func multiSignatureCountSize() throws {
        // node:1530-1535: CScriptNum(..., CScriptNum::MAXIMUM_ELEMENT_SIZE).
        #expect(throws: ScriptExecutionError.consensus(.numberTooLarge(actual: 5, maximum: 4))) {
            try run(lock: "0000050000000000ae", era: .afterGenesis, context: true)
        }
        #expect(throws: ScriptExecutionError.consensus(.numberTooLarge(actual: 5, maximum: 4))) {
            try run(lock: "00050000000000" + "00ae", era: .afterGenesis, context: true)
        }
        #expect(try run(lock: "00000400000000ae", era: .afterGenesis, context: true).stack == [[1]])
    }
}

// MARK: - Fixtures

struct NodeVector: Sendable, CustomTestStringConvertible {
    let name: String
    let sourceLine: Int
    let lockHex: String
    let coinHeight: UInt32
    let txHex: String
    let valid: Bool

    var testDescription: String { name }

    func transaction(version: UInt32? = nil) throws -> Transaction {
        var transaction = try Transaction(hex: txHex, limits: NodeConformanceRegressionTests.limits)
        if let version { transaction.version = version }
        return transaction
    }

    /// TS `createSpend`: current block flags plus the UTXO era by coin height.
    var flags: ScriptVerificationFlags {
        switch name {
        case "eras-00052":
            return [.payToScriptHash, .derSignatures, .checkLockTimeVerify]
        case "eras-00054":
            return [.payToScriptHash, .derSignatures, .checkLockTimeVerify, .checkSequenceVerify]
        default:
            var flags: ScriptVerificationFlags = [
                .payToScriptHash, .strictEncoding, .derSignatures, .lowS,
                .signaturePushOnly, .checkLockTimeVerify, .checkSequenceVerify,
                .nullFail, .enableForkID, .chronicle,
            ]
            if name == "arith-00351" {
                flags.formUnion([
                    .strictMultiSignatureDummy, .minimalData,
                    .discourageUpgradeableNops, .cleanStack,
                ])
            }
            return flags
        }
    }

    var era: ScriptExecutionEra {
        if name == "eras-00052" || name == "eras-00054" { return .beforeGenesis }
        if coinHeight >= 943_816 { return .afterChronicle }
        if coinHeight >= 620_538 { return .afterGenesis }
        return .beforeGenesis
    }

    @discardableResult
    func run(
        flags overrideFlags: ScriptVerificationFlags? = nil,
        version: UInt32? = nil,
        era overrideEra: ScriptExecutionEra? = nil,
        chronicle: Bool = true
    ) throws -> ScriptExecutionResult {
        let transaction = try transaction(version: version)
        let lock = try Script(hex: lockHex, maximumByteCount: 1_000)
        var flags = overrideFlags ?? self.flags
        if !chronicle { flags.remove(.chronicle) }
        return try ScriptInterpreter.execute(
            unlockingScript: transaction.inputs[0].unlockingScript,
            lockingScript: lock,
            configuration: ScriptExecutionConfiguration(
                era: overrideEra ?? era,
                flags: flags,
                resourceLimits: .standard
            ),
            context: ScriptExecutionContext(
                transaction: transaction,
                inputIndex: 0,
                spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
                transactionLimits: NodeConformanceRegressionTests.limits
            )
        )
    }
}

extension NodeConformanceRegressionTests {
    static let limits: TransactionLimits = {
        do {
            return try TransactionLimits(
                maximumTransactionByteCount: 100_000,
                maximumInputCount: 10,
                maximumOutputCount: 10,
                maximumScriptByteCount: 100_000
            )
        } catch {
            preconditionFailure("valid limits")
        }
    }()

    static let vectors: [NodeVector] = [
        NodeVector(
            name: "crypto-00012",
            sourceLine: 15,
            lockHex: "21035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ac91",
            coinHeight: 967896,
            txHex: "0200000001d9fa799b3044ad9589c87a3e67980b12da738e9b13542dd868726cf0a0b39e250000000049483045022100d7d09ade8b4adb6372ef31dab5fe96ef44e0661156c1ecf6f81a8353d14060650220057e129a333dda81260ba7ee86b8a15cf88e51ef06a5d30cdebbbfc4f10d361341ffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "flow-00961",
            sourceLine: 24,
            lockHex: "51",
            coinHeight: 967896,
            txHex: "02000000010a7b1c40c67f02436acff2a4b6e22ca7b3deb60852f4c10f18e05f07e5d0f5260000000002516affffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "arith-00351",
            sourceLine: 33,
            lockHex: "020100985287",
            coinHeight: 967896,
            txHex: "020000000120aaf54d327d617af4e5bb4a3db9d7d135afe0ff8f03bd59cc79eb969fb988e600000000014fffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "eras-00001",
            sourceLine: 42,
            lockHex: "516a",
            coinHeight: 620537,
            txHex: "02000000018e7c542db81ed89b3270ff26342988db87785631329107fb7a0e11ded53b6e6d0000000000ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "eras-00019",
            sourceLine: 51,
            lockHex: "5163516700675168",
            coinHeight: 620537,
            txHex: "0200000001f01a60cf6e52c646d620388d2619756c63fafc35e451377d37bb2e638ed8f4c10000000000ffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "gen-00006",
            sourceLine: 60,
            lockHex: "5103b1710b808b7551",
            coinHeight: 620538,
            txHex: "0200000001d778b0553b5c7c553a74ae08b43a94b3fc9fc3097fde32fb54d29970050fb8ed0000000000ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "gen-00009",
            sourceLine: 69,
            lockHex: "51040148e801808b7551",
            coinHeight: 943816,
            txHex: "02000000010282f68044beaa91d8f3424e5499046c9a2fc62222344f786bdf10882a0dcb050000000000ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "gen-00974",
            sourceLine: 78,
            lockHex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac",
            coinHeight: 620538,
            txHex: "0200000001421e09a1497b8976eafb681be43ab7ff15ca2075266f785f9610e4f935a8f8360000000049483045022100874e74f0c4921c200fbb90fd537ebefb84844f1b74d02355896bee35d213ee1b022048a1a59726aa089318f650f58b413615f32789d9eba562f6a1254d657f75992d61ffffffff02010000000000000001510200000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "crypto-00084 (version 1)",
            sourceLine: 87,
            lockHex: "473044022072b7e219170a2ae089c149ae684a1a7ad50a3251ad466b94a145b86bb76d150002205190440eb08efa92ced4e80a9c2f8e2721cf21a9c14d81015d16c05686eda235417521035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ac",
            coinHeight: 967896,
            txHex: "01000000010339699bf39cbdfa8e8965583d70faa0301fe96efc6f17053cbbb31ff1d0b7670000000048473044022072b7e219170a2ae089c149ae684a1a7ad50a3251ad466b94a145b86bb76d150002205190440eb08efa92ced4e80a9c2f8e2721cf21a9c14d81015d16c05686eda23541ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "gen-01001",
            sourceLine: 97,
            lockHex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4d05",
            coinHeight: 943816,
            txHex: "0200000001df9aea25028895f34dd187cd56c319ed0eb8d6896c2cd0866bc0544fe52394d9000000004847304402204519a364c695b04b7e5017be05deb0a3fdf25d09d31f0940b3e9efedbe7f496f02202c7b917f465dd4a505816f2a28d839d2044dbbdaeb1df9f3c39e9975c6f7e3de61ffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "gen-00999",
            sourceLine: 106,
            lockHex: "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac6a4c05aabb",
            coinHeight: 943816,
            txHex: "0200000001f81e0cf3c931477cbe57a9388d22c15466688974e66c7a7fae77a5623925265d0000000049483045022100e7bd08a7cf0a1bda318923e1e931e83070adb546eed21d79fbc92ef12966f958022071a9fada8e08eafc1758a8dc47501e4999ea89774872a3d96d0611d5aab7548761ffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "eras-00015",
            sourceLine: 115,
            lockHex: "51b17551",
            coinHeight: 620537,
            txHex: "0200000001b4b3e19df37673ec4804630b153244aa2a83317c5ba79e4b78c085849df944050000000000feffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "eras-00052",
            sourceLine: 124,
            lockHex: "51b17551",
            coinHeight: 100,
            txHex: "0200000001bed48f683afbb0e47b069b3120ccc36eff75c5e5183bc47362c878543816d2160000000000feffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "eras-00017",
            sourceLine: 133,
            lockHex: "51b27551",
            coinHeight: 620537,
            txHex: "020000000149186975113ea88ff53e1c51d65bc3338afe5d704801d927a4fe8db8224e6b6a000000000000000000010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "eras-00054",
            sourceLine: 142,
            lockHex: "51b27551",
            coinHeight: 100,
            txHex: "0200000001c1bf107a0b3b61e2511f9914dfdb0eb4399042a51493aa7d7c0fe9ee82709471000000000000000000010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "bytes-00435 (version 1)",
            sourceLine: 151,
            lockHex: "b2",
            coinHeight: 967896,
            txHex: "01000000017e41122de6de8c7c28680fc3a234f7838c43e6592331fe4a0ad68ae13462f6250000000006515253545556ffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "gen-00795",
            sourceLine: 164,
            lockHex: "10000102030405060708090a0b0c0d0e0f0904000000000000008054b3040405060787",
            coinHeight: 943816,
            txHex: "0200000001bd713e289714213b3d76b5168a550fe3bc8bee30363eb9a72795e051c88686500000000000ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "gen-00835",
            sourceLine: 173,
            lockHex: "51050000008000b77551",
            coinHeight: 943816,
            txHex: "0200000001829896aed1733429283adb214280217591f00929568490f2c8530c8a9f7260310000000000ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "arith-00163",
            sourceLine: 182,
            lockHex: "04ffffff7f98010087",
            coinHeight: 967896,
            txHex: "0200000001bbc9d9c85aca832a951c9630dbb352b3c012b48c1ecbcfb12ff5bcc67f9fc833000000000153ffffffff010100000000000000015100000000",
            valid: true
        ),
        NodeVector(
            name: "gen-00813",
            sourceLine: 191,
            lockHex: "5104ffffff7fb67551",
            coinHeight: 943816,
            txHex: "0200000001503dd6f80c4ebe381c7c8fb609d1555c2ea5fa2aa59f002acd05151f46c7ad5d0000000000ffffffff010100000000000000015100000000",
            valid: false
        ),
        NodeVector(
            name: "stack-00217",
            sourceLine: 200,
            lockHex: "0500000080008051",
            coinHeight: 967896,
            txHex: "020000000187a34732a06ac0f3edeca5c9a239399da4c91d80f507fbd34c06ce985d415f27000000000151ffffffff010100000000000000015100000000",
            valid: false
        ),
    ]

    static let preUAHFTransactionHex = "02000000031c03d65739de2b55f51b600abb4b3eba4c3bbc3c62244bf10eaa53b6c63d39ad000000004948304502210080089464b438a3c3b800805194aaf845845ff0fb73dd55da5bc32a2ba016a0da022003e74a9cf63659240c2814006ada6fb982fdf01c292bff03da79692cafb6c5cd01ffffffff140155ec0e942dc40a8f418e720b4e996e50788fb0b5a4e23a5659df6f939063000000004847304402207acc9a382964cf2c03c83df3f877ddaa942ecfd5fb48c9e4636b1ee46fea0a29022022373d2f768a83c2b5f0a843c0e48bd19716922c4831ba083a4a0e25f14005a641ffffffff8e47aab4115643d43d0428135ef7eb3d37472c0cfec5e3eda8339921f8efeb4a000000004847304402206e1f94c990cb392dab5e7e46faa775bdfeea9ab8787cba307de9c3f7bcec046b022015bedb0d8f5e295de76de219de674c41649057f8e77494855c868b709e14667901ffffffff02010000000000000001510200000000000000015100000000"

    static let preUAHFLocks = [
        "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac",
        "2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac",
        "2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac",
    ]

    func runPreUAHF(
        index: Int,
        lock lockHex: String,
        flags: ScriptVerificationFlags = [
            .payToScriptHash, .derSignatures, .checkLockTimeVerify, .checkSequenceVerify,
        ]
    ) throws -> ScriptExecutionResult {
        let transaction = try Transaction(hex: Self.preUAHFTransactionHex, limits: Self.limits)
        let lock = try Script(hex: lockHex, maximumByteCount: 1_000)
        return try ScriptInterpreter.execute(
            unlockingScript: transaction.inputs[index].unlockingScript,
            lockingScript: lock,
            configuration: ScriptExecutionConfiguration(
                era: .beforeGenesis,
                flags: flags,
                resourceLimits: .standard
            ),
            context: ScriptExecutionContext(
                transaction: transaction,
                inputIndex: index,
                spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
                transactionLimits: Self.limits
            )
        )
    }

    func simpleTransaction(version: UInt32, unlocking: [UInt8], lock: Script) throws -> Transaction {
        Transaction(
            version: version,
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(wireBytes: Array(repeating: 0x42, count: 32)),
                    outputIndex: 0
                ),
                unlockingScript: try Script(bytes: unlocking, maximumByteCount: 1_000),
                sourceOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock)
            )],
            outputs: [TransactionOutput(
                satoshis: 900,
                lockingScript: try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
            )]
        )
    }

    @discardableResult
    func run(
        unlock: String = "",
        lock: String,
        era: ScriptExecutionEra,
        flags: ScriptVerificationFlags = [],
        context withContext: Bool = false,
        version: UInt32 = 2
    ) throws -> ScriptExecutionResult {
        let unlocking = try Script(hex: unlock, maximumByteCount: 1_000)
        let locking = try Script(hex: lock, maximumByteCount: 1_000)
        var context: ScriptExecutionContext?
        if withContext {
            var transaction = try simpleTransaction(version: version, unlocking: [], lock: locking)
            transaction.inputs[0].unlockingScript = unlocking
            context = ScriptExecutionContext(
                transaction: transaction,
                inputIndex: 0,
                spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: locking),
                transactionLimits: Self.limits
            )
        }
        return try ScriptInterpreter.execute(
            unlockingScript: unlocking,
            lockingScript: locking,
            configuration: ScriptExecutionConfiguration(
                era: era,
                flags: flags,
                resourceLimits: .standard
            ),
            context: context
        )
    }
}

private func hex(_ text: String) -> [UInt8] {
    (try? Hex.decode(text, maximumDecodedByteCount: 10_000)) ?? []
}

private func scriptTruth(_ bytes: [UInt8]) -> Bool {
    for index in bytes.indices where bytes[index] != 0 {
        return !(index == bytes.count - 1 && bytes[index] == 0x80)
    }
    return false
}

private let curveOrder: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]

private func subtract(_ value: [UInt8], from minuend: [UInt8]) -> [UInt8] {
    var result = Array(repeating: UInt8(0), count: value.count)
    var borrow = 0
    for index in value.indices.reversed() {
        var difference = Int(minuend[index]) - Int(value[index]) - borrow
        if difference < 0 {
            difference += 256
            borrow = 1
        } else {
            borrow = 0
        }
        result[index] = UInt8(difference)
    }
    return result
}

// MARK: - Review follow-ups

extension NodeConformanceRegressionTests {
    private static let generatorPublicKeyHex =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    @Test("a structurally valid DER signature with unusable scalars fails CHECKSIG without an error")
    func outOfRangeScalarsFailWithoutError() throws {
        // node:177-235 IsValidSignatureEncoding is structural only; the lax
        // parser reads r or s outside 1..<n as the zero signature, which is
        // low S and does not verify.
        let zeroS = "09" + "300602010102010001"
        let maximalR = "29" + "3026022100" + String(repeating: "ff", count: 32) + "02010101"
        let checkSigNot = "21" + Self.generatorPublicKeyHex + "ac91"
        for signature in [zeroS, maximalR] {
            for flags: ScriptVerificationFlags in [[.derSignatures], [.strictEncoding], [.lowS]] {
                #expect(try run(
                    lock: signature + checkSigNot, era: .afterGenesis, flags: flags, context: true
                ).stack == [[1]], "\(signature.prefix(8)) \(flags)")
            }
            // The failed non-empty signature still triggers NULLFAIL.
            #expect(throws: ScriptExecutionError.consensus(.nullFail)) {
                try run(
                    lock: signature + checkSigNot, era: .afterGenesis,
                    flags: [.derSignatures, .nullFail], context: true
                )
            }
        }
        // A structural violation (negative r) is still an encoding error.
        #expect(throws: ScriptExecutionError.consensus(.invalidSignatureEncoding)) {
            try run(
                lock: "09" + "300602018102010101" + checkSigNot, era: .afterGenesis,
                flags: [.derSignatures], context: true
            )
        }
        #expect(ScriptMachine.isValidSignatureEncoding(hex("300602010102010001")))
        #expect(!ScriptMachine.isValidSignatureEncoding(hex("3006020101020101")))
        #expect(!ScriptMachine.isValidSignatureEncoding(hex("300602010002010101") + [0]))
    }

    @Test("LOW_S reads r = 0 with a high s the way the node's lax parser does")
    func lowSOnZeroR() throws {
        // node interpreter.cpp:282-289 and pubkey.cpp:32-175, 353-363: r = 0 is
        // not an overflow, so the lax parse keeps s = n - 1, which is high.
        let nMinusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        let signature = "29" + "3026020100022100" + nMinusOne + "01"
        let key = "21" + Self.generatorPublicKeyHex
        let checkSig = signature + key + "ac91"
        let checkMultiSig = "00" + signature + "51" + key + "51" + "ae91"
        for lock in [checkSig, checkMultiSig] {
            #expect(throws: ScriptExecutionError.consensus(.invalidSignatureEncoding)) {
                try run(lock: lock, era: .afterGenesis, flags: [.lowS], context: true, version: 1)
            }
            // Chronicle relaxes LOW_S for version two; the check then fails.
            #expect(try run(
                lock: lock, era: .afterChronicle, flags: [.lowS], context: true, version: 2
            ).stack == [[1]])
            #expect(try run(lock: lock, era: .afterGenesis, flags: [.derSignatures], context: true).stack == [[1]])
        }
        // A low s with r = 0 passes LOW_S and simply fails.
        let lowS = "09" + "300602010002010101"
        #expect(try run(lock: lowS + key + "ac91", era: .afterGenesis, flags: [.lowS], context: true).stack == [[1]])
        // Overflowing values read as the zero signature, which is low S.
        let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        #expect(ScriptMachine.laxParseIsLowS(hex("3026022100" + order + "020101")))
        #expect(!ScriptMachine.laxParseIsLowS(hex("3026020100022100" + nMinusOne)))
        #expect(ScriptMachine.laxParseIsLowS(hex("3026020101022100" + String(repeating: "ff", count: 32))))
    }

    @Test("2MUL results are bounded by the number limit")
    func twoMulResultBound() throws {
        // 2MUL is bn += bn (interpreter.cpp:1247-1249), checked like ADD.
        // A local 1,000-byte number budget exercises the same check cheaply.
        let size = 1_000
        let largest = Array(repeating: UInt8(0xff), count: size - 1) + [0x7f]
        let lock = [Opcode.pushData2.rawValue, UInt8(size & 0xff), UInt8(size >> 8)] + largest
            + [0x8d, Opcode.drop.rawValue, Opcode.one.rawValue]
        let standard = ScriptResourceLimits.standard
        let limits = ScriptResourceLimits(
            maximumScriptByteCount: standard.maximumScriptByteCount,
            maximumPushDataByteCount: standard.maximumPushDataByteCount,
            maximumStackItemCount: standard.maximumStackItemCount,
            maximumStackMemoryByteCount: standard.maximumStackMemoryByteCount,
            maximumOperationCountPerScript: standard.maximumOperationCountPerScript,
            maximumConditionalDepth: standard.maximumConditionalDepth,
            maximumScriptNumberByteCount: size
        )
        func execute(_ bytes: [UInt8]) throws -> ScriptExecutionResult {
            try ScriptInterpreter.execute(
                unlockingScript: try Script(bytes: [], maximumByteCount: 1),
                lockingScript: try Script(bytes: bytes, maximumByteCount: bytes.count),
                configuration: ScriptExecutionConfiguration(era: .afterChronicle, resourceLimits: limits),
                context: nil
            )
        }
        #expect(throws: ScriptExecutionError.resourceBudgetExceeded(
            .scriptNumberByteCount(actual: size + 1, maximum: size)
        )) {
            try execute(lock)
        }
        // 2MUL of a value one byte shorter fits.
        let shorter = Array(repeating: UInt8(0xff), count: size - 2) + [0x3f]
        #expect(try execute(
            [Opcode.pushData2.rawValue, UInt8((size - 1) & 0xff), UInt8((size - 1) >> 8)] + shorter
                + [0x8d, Opcode.drop.rawValue, Opcode.one.rawValue]
        ).stack == [[1]])
    }

    @Test("ADD, SUB, MUL and 1ADD results are bounded by the number limit after Genesis")
    func arithmeticResultBound() throws {
        // node script_num.cpp:166, 196, 216: bint results longer than the
        // number limit throw scriptnum_overflow_error.
        let limit = 750_000
        // 2^(8 * limit - 1) - 1: the largest positive number of `limit` bytes.
        let largest = Array(repeating: UInt8(0xff), count: limit - 1) + [0x7f]
        let push = [Opcode.pushData4.rawValue] + le32(limit) + largest
        let drop1 = [Opcode.drop.rawValue, Opcode.one.rawValue]
        let cases: [(String, [UInt8])] = [
            ("1ADD", push + [Opcode.oneAdd.rawValue]),
            ("ADD", push + [Opcode.dup.rawValue, Opcode.add.rawValue]),
            ("SUB", push + [Opcode.dup.rawValue, Opcode.negate.rawValue, Opcode.sub.rawValue]),
            ("MUL", push + [0x02, 0x00, 0x01, Opcode.mul.rawValue]),
        ]
        for (name, script) in cases {
            #expect(throws: ScriptExecutionError.consensus(
                .numberTooLarge(actual: limit + 1, maximum: limit)
            ), "\(name)") {
                try runBytes(lock: script + drop1, era: .afterGenesis)
            }
        }
        // A result that stays within the limit is accepted.
        #expect(try runBytes(
            lock: push + [Opcode.oneSub.rawValue] + drop1, era: .afterGenesis
        ).stack == [[1]])
        // Before Genesis the node computes in int64: 0x7fffffff + 1 is five bytes.
        #expect(try run(lock: "04ffffff7f8b05000000800087", era: .beforeGenesis).stack == [[1]])
    }

    @Test("an over-long Chronicle signature script code fails with a typed error")
    func chronicleScriptCodeSizeIsTyped() throws {
        // node:1472-1481 appends the locking script to the unlocking script
        // code. Each script fits the limits; their sum does not.
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [11])
        let lock = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        var transaction = try simpleTransaction(version: 2, unlocking: [], lock: lock)
        let digest = try transaction.forkIDSignatureHash(
            inputIndex: 0,
            scriptCode: lock,
            limits: Self.limits
        )
        let element = try key.sign(digest: digest).derBytes + [0x41]
        let publicKey = key.publicKey.compressedBytes
        let unlockingBytes = [UInt8(element.count)] + element + [UInt8(publicKey.count)] + publicKey
            + [Opcode.checkSig.rawValue]
        transaction.inputs[0].unlockingScript = try Script(bytes: unlockingBytes, maximumByteCount: 200)
        let size = unlockingBytes.count
        func execute(scriptLimit: Int, transactionScriptLimit: UInt64) throws -> ScriptExecutionResult {
            let standard = ScriptResourceLimits.standard
            return try ScriptInterpreter.execute(
                unlockingScript: transaction.inputs[0].unlockingScript,
                lockingScript: lock,
                configuration: ScriptExecutionConfiguration(
                    era: .afterChronicle,
                    flags: [.enableForkID],
                    resourceLimits: ScriptResourceLimits(
                        maximumScriptByteCount: scriptLimit,
                        maximumPushDataByteCount: standard.maximumPushDataByteCount,
                        maximumStackItemCount: standard.maximumStackItemCount,
                        maximumStackMemoryByteCount: standard.maximumStackMemoryByteCount,
                        maximumOperationCountPerScript: standard.maximumOperationCountPerScript,
                        maximumConditionalDepth: standard.maximumConditionalDepth,
                        maximumScriptNumberByteCount: standard.maximumScriptNumberByteCount
                    )
                ),
                context: ScriptExecutionContext(
                    transaction: transaction,
                    inputIndex: 0,
                    spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
                    transactionLimits: try TransactionLimits(
                        maximumTransactionByteCount: 100_000,
                        maximumInputCount: 10,
                        maximumOutputCount: 10,
                        maximumScriptByteCount: transactionScriptLimit
                    )
                )
            )
        }
        // The script resource limit bounds each script, not the combined
        // script code, so this no longer escapes as a raw ScriptError.
        #expect(try execute(scriptLimit: size, transactionScriptLimit: 100_000).stack == [[], [1]])
        // The transaction limit bounds the digest's script code.
        #expect(throws: ScriptExecutionError.transaction(
            .scriptTooLarge(actual: UInt64(size + 1), maximum: UInt64(size))
        )) {
            try execute(scriptLimit: 100_000, transactionScriptLimit: UInt64(size))
        }
    }

    @Test("bip143SignatureHash only requires the ForkID bit and does not select the digest")
    func bip143SignatureHashFlag() throws {
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [13])
        let lock = try Script.payToPublicKey(key.publicKey, maximumByteCount: 100)
        let base = try simpleTransaction(version: 2, unlocking: [], lock: lock)
        func spend(hashType: UInt8, flags: ScriptVerificationFlags) throws -> ScriptExecutionResult {
            var transaction = base
            let digest = hashType & 0x40 != 0
                ? try transaction.forkIDSignatureHash(inputIndex: 0, scriptCode: lock, limits: Self.limits)
                : try transaction.legacySignatureHash(inputIndex: 0, scriptCode: lock, limits: Self.limits)
            let element = try key.sign(digest: digest).derBytes + [hashType]
            transaction.inputs[0].unlockingScript = try Script(
                bytes: [UInt8(element.count)] + element,
                maximumByteCount: 100
            )
            return try ScriptInterpreter.execute(
                unlockingScript: transaction.inputs[0].unlockingScript,
                lockingScript: lock,
                configuration: ScriptExecutionConfiguration(
                    era: .afterGenesis,
                    flags: flags,
                    resourceLimits: .standard
                ),
                context: ScriptExecutionContext(
                    transaction: transaction,
                    inputIndex: 0,
                    spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
                    transactionLimits: Self.limits
                )
            )
        }
        #expect(try spend(hashType: 0x41, flags: [.enableForkID, .bip143SignatureHash]).stack == [[1]])
        // Without enableForkID a ForkID signature is illegal (node:296-300),
        // whatever this flag says.
        #expect(throws: ScriptExecutionError.consensus(.illegalForkID(0x41))) {
            try spend(hashType: 0x41, flags: [.strictEncoding, .bip143SignatureHash])
        }
        // With enableForkID a legacy signature fails either way; the flag only
        // changes which failure is reported.
        #expect(throws: ScriptExecutionError.consensus(.invalidSignatureHashType(0x01))) {
            try spend(hashType: 0x01, flags: [.enableForkID, .bip143SignatureHash])
        }
        #expect(throws: ScriptExecutionError.consensus(.illegalForkID(0x01))) {
            try spend(hashType: 0x01, flags: [.enableForkID])
        }
        #expect(try spend(hashType: 0x01, flags: []).stack == [[1]])
    }

    @Test("Chronicle relaxes CHECKMULTISIG NULLFAIL for version two")
    func multiSignatureNullFailRelaxation() throws {
        // node:1640-1649: dummy, a failing one-byte signature, 1-of-1, NOT.
        let lock = "00" + "0101" + "51" + "21" + Self.generatorPublicKeyHex + "51" + "ae91"
        #expect(throws: ScriptExecutionError.consensus(.nullFail)) {
            try run(lock: lock, era: .afterChronicle, flags: [.nullFail], context: true, version: 1)
        }
        #expect(try run(
            lock: lock, era: .afterChronicle, flags: [.nullFail], context: true, version: 2
        ).stack == [[1]])
    }

    @Test("a CHECKMULTISIG in the unlocking script also commits to the locking script under Chronicle")
    func chronicleUnlockingMultiSignatureScriptCode() throws {
        // node:1568-1576: scriptCode += scriptPubKey when CHRONICLE is set.
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [15])
        let lock = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        let scriptCode = try Script(
            bytes: [Opcode.checkMultiSigVerify.rawValue, Opcode.one.rawValue],
            maximumByteCount: 2
        )
        var transaction = try simpleTransaction(version: 2, unlocking: [], lock: lock)
        let digest = try transaction.forkIDSignatureHash(
            inputIndex: 0,
            scriptCode: scriptCode,
            limits: Self.limits
        )
        let element = try key.sign(digest: digest).derBytes + [0x41]
        let publicKey = key.publicKey.compressedBytes
        transaction.inputs[0].unlockingScript = try Script(
            bytes: [Opcode.zero.rawValue, UInt8(element.count)] + element + [Opcode.one.rawValue]
                + [UInt8(publicKey.count)] + publicKey
                + [Opcode.one.rawValue, Opcode.codeSeparator.rawValue, Opcode.checkMultiSigVerify.rawValue],
            maximumByteCount: 200
        )
        let context = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: TransactionOutput(satoshis: 1_000, lockingScript: lock),
            transactionLimits: Self.limits
        )
        func execute(_ era: ScriptExecutionEra, _ flags: ScriptVerificationFlags) throws -> ScriptExecutionResult {
            try ScriptInterpreter.execute(
                unlockingScript: transaction.inputs[0].unlockingScript,
                lockingScript: lock,
                configuration: ScriptExecutionConfiguration(era: era, flags: flags, resourceLimits: .standard),
                context: context
            )
        }
        #expect(try execute(.afterChronicle, [.enableForkID]).stack == [[1]])
        #expect(try execute(.afterGenesis, [.enableForkID, .chronicle]).stack == [[1]])
        #expect(throws: ScriptExecutionError.consensus(.checkMultiSignatureVerifyFailed)) {
            try execute(.afterGenesis, [.enableForkID])
        }
    }

    @Test("an empty signature removes OP_0 instructions from the legacy script code")
    func emptySignatureRemovesOpZero() {
        // node:247-256: CScript(vchSig) of an empty signature is OP_0. The
        // removal cannot change a verdict, because an empty signature never
        // verifies, so it is pinned at the FindAndDelete level.
        let pattern = ScriptMachine.pushEncoding([])
        #expect(ScriptMachine.findAndDelete(hex("0051000100ac"), pattern: pattern) == hex("510100ac"))
        #expect(ScriptMachine.findAndDelete(hex("51ac"), pattern: pattern) == hex("51ac"))
    }

    @Test("OP_LSHIFTNUM of zero accepts exactly the number limit in added bytes")
    func zeroLeftShiftBoundary() throws {
        // 256,000,007 / 8 == 32,000,000 bytes: allowed; 256,000,008 is not.
        #expect(try run(lock: "00040740420fb60087", era: .afterChronicle).stack == [[1]])
        #expect(throws: ScriptExecutionError.consensus(
            .numberTooLarge(actual: 32_000_001, maximum: 32_000_000)
        )) {
            try run(lock: "00040840420fb67551", era: .afterChronicle)
        }
    }

    private func runBytes(lock: [UInt8], era: ScriptExecutionEra) throws -> ScriptExecutionResult {
        try ScriptInterpreter.execute(
            unlockingScript: try Script(bytes: [], maximumByteCount: 1),
            lockingScript: try Script(bytes: lock, maximumByteCount: lock.count),
            configuration: ScriptExecutionConfiguration(era: era, resourceLimits: .standard),
            context: nil
        )
    }
}

private func le32(_ value: Int) -> [UInt8] {
    (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
}
