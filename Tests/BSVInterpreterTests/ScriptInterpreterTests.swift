import BSVCore
import BSVCrypto
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@Suite("Script interpreter foundation")
struct ScriptInterpreterTests {
    private let maximumScriptByteCount = 40 * 1_024 * 1_024

    @Test("final truth and negative zero follow Script boolean rules")
    func finalTruth() throws {
        let success = try execute(unlocking: [], locking: [Opcode.one.rawValue])
        #expect(success.stack == [[1]])

        #expect(throws: ScriptExecutionError.consensus(.evaluatedFalse)) {
            try execute(unlocking: [], locking: [Opcode.zero.rawValue])
        }
        #expect(throws: ScriptExecutionError.consensus(.evaluatedFalse)) {
            try execute(unlocking: [1, 0x80], locking: [])
        }
        #expect(throws: ScriptExecutionError.consensus(.emptyFinalStack)) {
            try execute(unlocking: [], locking: [])
        }
    }

    @Test("pushes, equality, verification, and stack operations compose")
    func stackOperations() throws {
        let result = try execute(
            unlocking: [1, 0x2a],
            locking: [
                Opcode.dup.rawValue,
                Opcode.twoDup.rawValue,
                Opcode.twoDrop.rawValue,
                1, 0x2a,
                Opcode.equalVerify.rawValue,
                Opcode.one.rawValue,
            ]
        )
        #expect(result.stack == [[0x2a], [1]])
    }

    @Test("alternative stack boundary behavior matches ordinary and early-return transitions")
    func altStackBoundaries() throws {
        #expect(throws: ScriptExecutionError.consensus(.altStackUnderflow)) {
            try execute(
                unlocking: [Opcode.one.rawValue, Opcode.toAltStack.rawValue],
                locking: [Opcode.fromAltStack.rawValue]
            )
        }

        let earlyReturn = try execute(
            unlocking: [
                Opcode.one.rawValue,
                Opcode.toAltStack.rawValue,
                Opcode.return.rawValue,
            ],
            locking: [Opcode.fromAltStack.rawValue],
            era: .genesis
        )
        #expect(earlyReturn.stack == [[1]])
    }

    @Test("conditionals execute only the selected branch")
    func conditionals() throws {
        let result = try execute(
            unlocking: [],
            locking: [
                Opcode.zero.rawValue,
                Opcode.if.rawValue,
                Opcode.zero.rawValue,
                Opcode.else.rawValue,
                Opcode.one.rawValue,
                Opcode.endIf.rawValue,
            ]
        )
        #expect(result.stack == [[1]])

        #expect(throws: ScriptExecutionError.consensus(.unbalancedConditional)) {
            try execute(
                unlocking: [],
                locking: [Opcode.one.rawValue, Opcode.if.rawValue, Opcode.one.rawValue]
            )
        }

        #expect(throws: ScriptExecutionError.consensus(.unbalancedConditional)) {
            try execute(
                unlocking: [],
                locking: [
                    Opcode.one.rawValue,
                    Opcode.if.rawValue,
                    Opcode.return.rawValue,
                ],
                era: .genesis
            )
        }

        let balancedReturn = try execute(
            unlocking: [Opcode.one.rawValue],
            locking: [
                Opcode.one.rawValue,
                Opcode.if.rawValue,
                Opcode.return.rawValue,
                Opcode.endIf.rawValue,
                Opcode.zero.rawValue,
                Opcode.one.rawValue,
            ],
            era: .genesis
        )
        #expect(balancedReturn.stack == [[1]])

        let hiddenGenesisVersionConditional = try execute(
            unlocking: [],
            locking: [
                Opcode.zero.rawValue,
                Opcode.if.rawValue,
                Opcode.verIf.rawValue,
                Opcode.endIf.rawValue,
                Opcode.one.rawValue,
            ],
            era: .genesis
        )
        #expect(hiddenGenesisVersionConditional.stack == [[1]])

        let returnedGenesisVersionConditional = try execute(
            unlocking: [Opcode.one.rawValue],
            locking: [
                Opcode.one.rawValue,
                Opcode.if.rawValue,
                Opcode.return.rawValue,
                Opcode.verIf.rawValue,
                Opcode.endIf.rawValue,
            ],
            era: .genesis
        )
        #expect(returnedGenesisVersionConditional.stack == [[1]])

        #expect(throws: ScriptExecutionError.consensus(.reservedOpcode(.verIf))) {
            try execute(
                unlocking: [],
                locking: [Opcode.one.rawValue, Opcode.if.rawValue, Opcode.verIf.rawValue],
                era: .genesis
            )
        }
    }

    @Test("Chronicle version opcodes use the transaction version")
    func chronicleVersionOpcodes() throws {
        let unlocking = try script([])
        let locking = try script([
            Opcode.ver.rawValue,
            4, 2, 0, 0, 0,
            Opcode.equalVerify.rawValue,
            4, 2, 0, 0, 0,
            Opcode.verIf.rawValue,
            Opcode.one.rawValue,
            Opcode.else.rawValue,
            Opcode.zero.rawValue,
            Opcode.endIf.rawValue,
        ])
        let context = try executionContext(
            unlocking: unlocking,
            locking: locking,
            version: 2
        )
        let result = try ScriptInterpreter.execute(
            unlockingScript: unlocking,
            lockingScript: locking,
            configuration: configuration(era: .chronicle),
            context: context
        )
        #expect(result.stack == [[1]])

        #expect(throws: ScriptExecutionError.missingExecutionContext(opcode: .ver)) {
            try execute(
                unlocking: [],
                locking: [Opcode.ver.rawValue, Opcode.one.rawValue],
                era: .chronicle
            )
        }
        #expect(throws: ScriptExecutionError.consensus(.unbalancedConditional)) {
            try execute(
                unlocking: [],
                locking: [Opcode.verIf.rawValue],
                era: .chronicle
            )
        }
    }

    @Test("unknown opcode bytes are reserved, not upgradeable NOPs")
    func unknownOpcodes() throws {
        for rawValue in [UInt8(0xba), 0xbc, 0xbd, 0xfe, 0xff] {
            #expect(throws: ScriptExecutionError.consensus(
                .reservedOpcode(Opcode(rawValue: rawValue))
            )) {
                try execute(unlocking: [], locking: [rawValue], era: .chronicle)
            }
        }

        let hidden = try execute(
            unlocking: [],
            locking: [
                Opcode.zero.rawValue,
                Opcode.if.rawValue,
                0xba,
                Opcode.endIf.rawValue,
                Opcode.one.rawValue,
            ],
            era: .genesis
        )
        #expect(hidden.stack == [[1]])
    }

    @Test("Genesis permits only one ELSE while legacy preserves historical behavior")
    func multipleElse() throws {
        let script: [UInt8] = [
            Opcode.one.rawValue,
            Opcode.if.rawValue,
            Opcode.one.rawValue,
            Opcode.else.rawValue,
            Opcode.zero.rawValue,
            Opcode.else.rawValue,
            Opcode.one.rawValue,
            Opcode.endIf.rawValue,
        ]
        _ = try execute(unlocking: [], locking: script, era: .legacy)
        #expect(throws: ScriptExecutionError.consensus(.multipleElse)) {
            try execute(unlocking: [], locking: script, era: .genesis)
        }
    }

    @Test("post-Genesis OP_RETURN ignores trailing malformed push data")
    func returnStopsIncrementalDecoding() throws {
        let result = try execute(
            unlocking: [
                Opcode.one.rawValue,
                Opcode.return.rawValue,
                Opcode.pushData1.rawValue,
            ],
            locking: [Opcode.one.rawValue],
            era: .genesis
        )
        #expect(result.didEarlyReturn)
        #expect(result.stack == [[1], [1]])

        #expect(throws: ScriptExecutionError.consensus(.earlyReturn)) {
            try execute(
                unlocking: [],
                locking: [Opcode.return.rawValue],
                era: .legacy
            )
        }
    }

    @Test("ordinary malformed pushes remain typed decoding failures")
    func malformedPush() throws {
        #expect(throws: ScriptExecutionError.malformedScript(
            phase: .locking,
            offset: 0,
            cause: .truncatedPushLength(expected: 1, remaining: 0)
        )) {
            try execute(
                unlocking: [],
                locking: [Opcode.pushData1.rawValue],
                era: .genesis
            )
        }
    }

    @Test("minimal push and minimal IF flags are independently enforced")
    func minimalEncoding() throws {
        let minimalData = try configuration(
            era: .genesis,
            flags: [.minimalData]
        )
        #expect(throws: ScriptExecutionError.consensus(.nonMinimalPush)) {
            try ScriptInterpreter.execute(
                unlockingScript: try script([1, 1]),
                lockingScript: try script([]),
                configuration: minimalData
            )
        }

        let minimalIf = try configuration(
            era: .genesis,
            flags: [.minimalIf]
        )
        #expect(throws: ScriptExecutionError.consensus(.minimalIf)) {
            try ScriptInterpreter.execute(
                unlockingScript: try script([]),
                lockingScript: try script([
                    1, 2,
                    Opcode.if.rawValue,
                    Opcode.one.rawValue,
                    Opcode.endIf.rawValue,
                ]),
                configuration: minimalIf
            )
        }
    }

    @Test("push-only validation preserves malformed and resource failure types")
    func pushOnlyFailureTypes() throws {
        let malformedConfiguration = try configuration(
            era: .legacy,
            flags: [.signaturePushOnly]
        )
        #expect(throws: ScriptExecutionError.malformedScript(
            phase: .unlocking,
            offset: 0,
            cause: .truncatedPushLength(expected: 1, remaining: 0)
        )) {
            try ScriptInterpreter.execute(
                unlockingScript: script([Opcode.pushData1.rawValue]),
                lockingScript: script([Opcode.one.rawValue]),
                configuration: malformedConfiguration
            )
        }

        let limits = ScriptResourceLimits(
            maximumScriptByteCount: 100,
            maximumPushDataByteCount: 1,
            maximumStackItemCount: 100,
            maximumStackMemoryByteCount: 100,
            maximumOperationCountPerScript: 100,
            maximumConditionalDepth: 10,
            maximumScriptNumberByteCount: 10
        )
        let resourceConfiguration = try ScriptExecutionConfiguration(
            era: .genesis,
            flags: [.signaturePushOnly],
            resourceLimits: limits
        )
        #expect(throws: ScriptExecutionError.resourceBudgetExceeded(
            .pushDataByteCount(actual: 2, maximum: 1)
        )) {
            try ScriptInterpreter.execute(
                unlockingScript: script([2, 1, 2]),
                lockingScript: script([Opcode.one.rawValue]),
                configuration: resourceConfiguration
            )
        }
    }

    @Test("operation ceilings reset between unlocking and locking scripts")
    func operationCountResets() throws {
        let limits = ScriptResourceLimits(
            maximumScriptByteCount: 100,
            maximumPushDataByteCount: 100,
            maximumStackItemCount: 100,
            maximumStackMemoryByteCount: 1_000,
            maximumOperationCountPerScript: 1,
            maximumConditionalDepth: 10,
            maximumScriptNumberByteCount: 100
        )
        let configuration = try ScriptExecutionConfiguration(
            era: .genesis,
            resourceLimits: limits
        )
        let result = try ScriptInterpreter.execute(
            unlockingScript: try script([Opcode.nop.rawValue]),
            lockingScript: try script([Opcode.nop.rawValue, Opcode.one.rawValue]),
            configuration: configuration
        )
        #expect(result.operationCount == 2)
    }

    @Test("resource ceilings remain distinct from consensus failures")
    func resourceAndConsensusErrors() throws {
        let restrictive = ScriptResourceLimits(
            maximumScriptByteCount: 5,
            maximumPushDataByteCount: 5,
            maximumStackItemCount: 5,
            maximumStackMemoryByteCount: 5,
            maximumOperationCountPerScript: 5,
            maximumConditionalDepth: 5,
            maximumScriptNumberByteCount: 5
        )
        let genesis = try ScriptExecutionConfiguration(
            era: .genesis,
            resourceLimits: restrictive
        )
        #expect(throws: ScriptExecutionError.resourceBudgetExceeded(
            .scriptByteCount(actual: 6, maximum: 5)
        )) {
            try ScriptInterpreter.execute(
                unlockingScript: try script([]),
                lockingScript: try script(Array(repeating: Opcode.one.rawValue, count: 6)),
                configuration: genesis
            )
        }

        let legacy = try configuration(era: .legacy)
        #expect(throws: ScriptExecutionError.consensus(
            .scriptTooLarge(actual: 10_001, maximum: 10_000)
        )) {
            try ScriptInterpreter.execute(
                unlockingScript: try script([]),
                lockingScript: try script(Array(repeating: Opcode.one.rawValue, count: 10_001)),
                configuration: legacy
            )
        }
    }

    @Test("execution context is validated as one coherent value")
    func executionContext() throws {
        let unlocking = try script([Opcode.one.rawValue])
        let locking = try script([Opcode.one.rawValue])
        let transaction = Transaction(inputs: [TransactionInput(
            previousOutput: try Outpoint(
                transactionID: TransactionID(wireBytes: Array(repeating: 0, count: 32)),
                outputIndex: 0
            ),
            unlockingScript: unlocking
        )])
        let spentOutput = TransactionOutput(satoshis: 1, lockingScript: locking)
        let context = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: spentOutput,
            transactionLimits: try TransactionLimits(
                maximumTransactionByteCount: 1_000,
                maximumInputCount: 10,
                maximumOutputCount: 10,
                maximumScriptByteCount: 1_000
            )
        )
        _ = try ScriptInterpreter.execute(
            unlockingScript: unlocking,
            lockingScript: locking,
            configuration: try configuration(era: .genesis),
            context: context
        )

        let wrongLock = try script([Opcode.zero.rawValue])
        #expect(throws: ScriptExecutionError.invalidContext(.lockingScriptMismatch)) {
            try ScriptInterpreter.execute(
                unlockingScript: unlocking,
                lockingScript: wrongLock,
                configuration: try configuration(era: .genesis),
                context: context
            )
        }
    }

    @Test("clean-stack configuration requires P2SH and is enforced")
    func cleanStack() throws {
        #expect(throws: ScriptConfigurationError.cleanStackRequiresPayToScriptHash) {
            try ScriptExecutionConfiguration(
                era: .legacy,
                flags: [.cleanStack],
                resourceLimits: .standard
            )
        }

        let configuration = try self.configuration(
            era: .legacy,
            flags: [.cleanStack, .payToScriptHash]
        )
        #expect(throws: ScriptExecutionError.consensus(
            .cleanStackViolation(actualItemCount: 2)
        )) {
            try ScriptInterpreter.execute(
                unlockingScript: try script([Opcode.one.rawValue]),
                lockingScript: try script([Opcode.one.rawValue]),
                configuration: configuration
            )
        }
    }

    @Test("splice and numeric byte-conversion opcodes round-trip")
    func spliceOperations() throws {
        let splitAndCat = try execute(
            unlocking: [],
            locking: try Hex.decode(
                "0461626364527f7e046162636487",
                maximumDecodedByteCount: 100
            ),
            era: .genesis
        )
        #expect(splitAndCat.stack == [[1]])

        let num2bin = try execute(
            unlocking: [],
            locking: try Hex.decode(
                "017f5280027f0087",
                maximumDecodedByteCount: 100
            ),
            era: .genesis
        )
        #expect(num2bin.stack == [[1]])

        let bin2num = try execute(
            unlocking: [],
            locking: try Hex.decode(
                "020100815187",
                maximumDecodedByteCount: 100
            ),
            era: .genesis
        )
        #expect(bin2num.stack == [[1]])
    }

    @Test("bitwise operations require equal operand lengths")
    func bitwiseOperations() throws {
        let result = try execute(
            unlocking: [],
            locking: try Hex.decode(
                "020ff00233cc840203c087",
                maximumDecodedByteCount: 100
            ),
            era: .genesis
        )
        #expect(result.stack == [[1]])

        #expect(throws: ScriptExecutionError.consensus(
            .invalidInputLength(left: 1, right: 2)
        )) {
            try execute(
                unlocking: [],
                locking: try Hex.decode(
                    "010102010284",
                    maximumDecodedByteCount: 100
                ),
                era: .genesis
            )
        }
    }

    @Test(arguments: [
        (Opcode.ripemd160, "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (Opcode.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (Opcode.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (Opcode.hash160, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"),
        (Opcode.hash256, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"),
    ])
    func hashingOpcode(opcode: Opcode, digestHex: String) throws {
        let result = try execute(
            unlocking: [],
            locking: [Opcode.zero.rawValue, opcode.rawValue],
            era: .genesis
        )
        #expect(result.stack == [try Hex.decode(
            digestHex,
            maximumDecodedByteCount: 32
        )])
    }

    @Test(arguments: [
        "528b539c",
        "5253944f9c",
        "5354955c9c",
        "575296539c",
        "578f53974f9c",
        "52539f",
        "5352a0",
        "535255a5",
    ])
    func numericOpcode(scriptHex: String) throws {
        let result = try execute(
            unlocking: [],
            locking: try Hex.decode(scriptHex, maximumDecodedByteCount: 100),
            era: .genesis
        )
        #expect(result.stack.last == [1])
    }

    @Test("arbitrary precision arithmetic exceeds native integer width")
    func arbitraryPrecisionArithmetic() throws {
        let value = "000000000000000001"
        let doubled = "000000000000000002"
        let scriptHex = "09\(value)09\(value)9309\(doubled)9c"
        let result = try execute(
            unlocking: [],
            locking: try Hex.decode(scriptHex, maximumDecodedByteCount: 100),
            era: .genesis
        )
        #expect(result.stack == [[1]])
    }

    @Test("byte shifts preserve width and Chronicle numeric shifts are arithmetic")
    func shifts() throws {
        for scriptHex in [
            "021234549802234087",
            "021234549902012387",
        ] {
            #expect(try execute(
                unlocking: [],
                locking: Hex.decode(scriptHex, maximumDecodedByteCount: 100),
                era: .genesis
            ).stack == [[1]])
        }

        #expect(try execute(
            unlocking: [],
            locking: Hex.decode("538f51b701829c", maximumDecodedByteCount: 100),
            era: .chronicle
        ).stack == [[1]])
    }

    @Test("division and modulo by zero are typed consensus failures")
    func divisionByZero() throws {
        for opcode in [Opcode.div, Opcode.mod] {
            #expect(throws: ScriptExecutionError.consensus(.divisionByZero)) {
                try execute(
                    unlocking: [],
                    locking: [Opcode.one.rawValue, Opcode.zero.rawValue, opcode.rawValue],
                    era: .genesis
                )
            }
        }
    }

    @Test("ForkID P2PKH signatures execute through the transaction context")
    func forkIDCheckSignature() throws {
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 10_000
        )
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        let locking = try Script.payToPublicKeyHash(
            BSVHashing.hash160(key.publicKey.compressedBytes),
            maximumByteCount: 25
        )
        let spentOutput = TransactionOutput(satoshis: 12_345, lockingScript: locking)
        var transaction = Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(wireBytes: Array(repeating: 0x11, count: 32)),
                    outputIndex: 0
                ),
                unlockingScript: try script([]),
                sourceOutput: spentOutput
            )],
            outputs: [TransactionOutput(satoshis: 12_000, lockingScript: locking)]
        )
        try transaction.signPayToPublicKeyHashInput(
            at: 0,
            with: key,
            limits: limits
        )
        let context = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: spentOutput,
            transactionLimits: limits
        )
        let configuration = try self.configuration(
            era: .genesis,
            flags: [.enableForkID, .derSignatures, .lowS, .nullFail]
        )
        let result = try ScriptInterpreter.execute(
            unlockingScript: transaction.inputs[0].unlockingScript,
            lockingScript: locking,
            configuration: configuration,
            context: context
        )
        #expect(result.stack == [[1]])

        let wrongValueContext = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: TransactionOutput(satoshis: 12_346, lockingScript: locking),
            transactionLimits: limits
        )
        #expect(throws: ScriptExecutionError.consensus(.nullFail)) {
            try ScriptInterpreter.execute(
                unlockingScript: transaction.inputs[0].unlockingScript,
                lockingScript: locking,
                configuration: configuration,
                context: wrongValueContext
            )
        }
    }

    @Test("signature opcodes never execute with partial or absent context")
    func missingSignatureContext() throws {
        #expect(throws: ScriptExecutionError.missingExecutionContext(opcode: .checkSig)) {
            try execute(
                unlocking: [Opcode.zero.rawValue, Opcode.zero.rawValue],
                locking: [Opcode.checkSig.rawValue],
                era: .genesis
            )
        }
    }

    @Test("legacy P2SH restores the unlocking stack and executes the redeem script")
    func payToScriptHash() throws {
        let redeem = try script([Opcode.one.rawValue])
        let locking = try Script.payToScriptHash(
            BSVHashing.hash160(redeem.bytes),
            maximumByteCount: 23
        )
        var unlocking = try script([])
        try unlocking.appendPushData(
            redeem.bytes,
            maximumScriptByteCount: maximumScriptByteCount
        )
        let result = try ScriptInterpreter.execute(
            unlockingScript: unlocking,
            lockingScript: locking,
            configuration: try configuration(
                era: .legacy,
                flags: [.payToScriptHash]
            )
        )
        #expect(result.stack == [[1]])
    }

    @Test("legacy CLTV and CSV use coherent transaction context")
    func lockTimeAndSequence() throws {
        let empty = try script([])
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 1_000,
            maximumInputCount: 2,
            maximumOutputCount: 2,
            maximumScriptByteCount: 1_000
        )
        let input = TransactionInput(
            previousOutput: try Outpoint(
                transactionID: TransactionID(wireBytes: Array(repeating: 0, count: 32)),
                outputIndex: 0
            ),
            unlockingScript: empty,
            sequence: 10
        )
        let transaction = Transaction(
            version: 2,
            inputs: [input],
            lockTime: 100
        )

        for (scriptBytes, flags) in [
            ([1, 100, Opcode.checkLockTimeVerify.rawValue, Opcode.drop.rawValue, Opcode.one.rawValue], ScriptVerificationFlags.checkLockTimeVerify),
            ([Opcode.five.rawValue, Opcode.checkSequenceVerify.rawValue, Opcode.drop.rawValue, Opcode.one.rawValue], ScriptVerificationFlags.checkSequenceVerify),
        ] {
            let currentLocking = try script(scriptBytes)
            let context = ScriptExecutionContext(
                transaction: transaction,
                inputIndex: 0,
                spentOutput: TransactionOutput(satoshis: 1, lockingScript: currentLocking),
                transactionLimits: limits
            )
            #expect(try ScriptInterpreter.execute(
                unlockingScript: empty,
                lockingScript: currentLocking,
                configuration: configuration(era: .legacy, flags: flags),
                context: context
            ).stack == [[1]])
        }

        let failingLock = try script([
            1, 101,
            Opcode.checkLockTimeVerify.rawValue,
            Opcode.drop.rawValue,
            Opcode.one.rawValue,
        ])
        let failingContext = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: TransactionOutput(satoshis: 1, lockingScript: failingLock),
            transactionLimits: limits
        )
        #expect(throws: ScriptExecutionError.consensus(.unsatisfiedLockTime)) {
            try ScriptInterpreter.execute(
                unlockingScript: empty,
                lockingScript: failingLock,
                configuration: configuration(
                    era: .legacy,
                    flags: [.checkLockTimeVerify]
                ),
                context: failingContext
            )
        }


        let disabledSequence = try script([
            5, 0, 0, 0, 0x80, 1,
            Opcode.checkSequenceVerify.rawValue,
            Opcode.drop.rawValue,
            Opcode.one.rawValue,
        ])
        let disabledContext = ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: TransactionOutput(satoshis: 1, lockingScript: disabledSequence),
            transactionLimits: limits
        )
        #expect(try ScriptInterpreter.execute(
            unlockingScript: empty,
            lockingScript: disabledSequence,
            configuration: configuration(
                era: .legacy,
                flags: [.checkSequenceVerify]
            ),
            context: disabledContext
        ).stack == [[1]])
    }

    private func execute(
        unlocking: [UInt8],
        locking: [UInt8],
        era: ScriptExecutionEra = .legacy
    ) throws -> ScriptExecutionResult {
        try ScriptInterpreter.execute(
            unlockingScript: script(unlocking),
            lockingScript: script(locking),
            configuration: configuration(era: era)
        )
    }

    private func executionContext(
        unlocking: Script,
        locking: Script,
        version: UInt32
    ) throws -> ScriptExecutionContext {
        let transaction = Transaction(
            version: version,
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(
                        wireBytes: Array(repeating: 0, count: 32)
                    ),
                    outputIndex: 0
                ),
                unlockingScript: unlocking
            )]
        )
        return ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: TransactionOutput(satoshis: 0, lockingScript: locking),
            transactionLimits: try TransactionLimits(
                maximumTransactionByteCount: 1_000,
                maximumInputCount: 1,
                maximumOutputCount: 1,
                maximumScriptByteCount: UInt64(maximumScriptByteCount)
            )
        )
    }

    private func configuration(
        era: ScriptExecutionEra,
        flags: ScriptVerificationFlags = []
    ) throws -> ScriptExecutionConfiguration {
        try ScriptExecutionConfiguration(
            era: era,
            flags: flags,
            resourceLimits: .standard
        )
    }

    private func script(_ bytes: [UInt8]) throws -> Script {
        try Script(bytes: bytes, maximumByteCount: maximumScriptByteCount)
    }
}
