import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@Suite("Transaction fees and construction")
struct TransactionFeeTests {
    @Test("integer fee rounding matches decimal kilobytes")
    func feeRounding() throws {
        for (bytes, rate, expected) in [
            (240, 100, 24),
            (240, 1, 1),
            (240, 10, 3),
            (250, 500, 125),
            (1_000, 100, 100),
            (1_500, 100, 150),
            (1_500, 500, 750),
        ] as [(UInt64, UInt64, UInt64)] {
            #expect(try SatoshisPerKilobyteFeeModel.roundedUpFee(
                byteCount: bytes,
                satoshisPerKilobyte: rate
            ) == expected)
        }
        #expect(try SatoshisPerKilobyteFeeModel.roundedUpFee(
            byteCount: 999,
            satoshisPerKilobyte: .max
        ) == 18_428_297_329_635_842_064)
        #expect(throws: TransactionError.feeCalculationOverflow) {
            try SatoshisPerKilobyteFeeModel.roundedUpFee(
                byteCount: 1_001,
                satoshisPerKilobyte: .max
            )
        }
    }

    @Test("actual scripts override estimates and unsigned inputs require bounds")
    func projectedSize() throws {
        let limits = try feeLimits()
        let nonempty = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let source = TransactionOutput(satoshis: 10_000, lockingScript: empty)
        let outpoint = try testOutpoint(fill: 1)
        let model = SatoshisPerKilobyteFeeModel(satoshisPerKilobyte: 1_000)

        let actual = Transaction(inputs: [TransactionInput(
            previousOutput: outpoint,
            unlockingScript: nonempty,
            sourceOutput: source,
            estimatedUnlockingScriptByteCount: 900
        )])
        #expect(try model.fee(for: actual, limits: limits) == 52)

        let projected = Transaction(inputs: [TransactionInput(
            previousOutput: outpoint,
            unlockingScript: empty,
            sourceOutput: source,
            estimatedUnlockingScriptByteCount: 106
        )])
        #expect(try model.fee(for: projected, limits: limits) == 157)

        let missing = Transaction(inputs: [TransactionInput(
            previousOutput: outpoint,
            unlockingScript: empty,
            sourceOutput: source
        )])
        #expect(throws: TransactionError.missingUnlockingScriptEstimate(inputIndex: 0)) {
            try model.fee(for: missing, limits: limits)
        }

        var negative = missing
        negative.inputs[0].estimatedUnlockingScriptByteCount = -1
        #expect(throws: TransactionError.invalidUnlockingScriptEstimate(
            inputIndex: 0,
            byteCount: -1
        )) {
            try model.fee(for: negative, limits: limits)
        }

        var oversized = missing
        oversized.inputs[0].estimatedUnlockingScriptByteCount = 1_001
        #expect(throws: TransactionError.unlockingScriptEstimateExceedsLimit(
            inputIndex: 0,
            actual: 1_001,
            maximum: 1_000
        )) {
            try model.fee(for: oversized, limits: limits)
        }
    }

    @Test("equal change distribution is atomic and leaves only rounding dust")
    func applyFee() throws {
        let limits = try feeLimits()
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let source = TransactionOutput(satoshis: 10_000, lockingScript: empty)
        var transaction = Transaction(
            inputs: [TransactionInput(
                previousOutput: try testOutpoint(fill: 2),
                unlockingScript: empty,
                sourceOutput: source,
                estimatedUnlockingScriptByteCount: 106
            )],
            outputs: [
                TransactionOutput(satoshis: 1_000, lockingScript: empty),
                TransactionOutput(satoshis: 0, lockingScript: empty, isChange: true),
                TransactionOutput(satoshis: 0, lockingScript: empty, isChange: true),
            ]
        )
        let model = SatoshisPerKilobyteFeeModel(satoshisPerKilobyte: 500)
        let requiredFee = try model.fee(for: transaction, limits: limits)
        try transaction.applyFee(using: model, limits: limits)

        #expect(transaction.outputs[1].satoshis == transaction.outputs[2].satoshis)
        #expect(try transaction.fee() >= requiredFee)
        #expect(try transaction.fee() - requiredFee < 2)

        let beforeFailure = transaction
        transaction.outputs[0].satoshis = 10_000
        let underfunded = transaction
        #expect(throws: TransactionError.self) {
            try transaction.applyFee(using: model, limits: limits)
        }
        #expect(transaction == underfunded)
        transaction = beforeFailure
    }

    @Test("dust change is removed and no-change transactions preserve excess fee")
    func dustAndNoChange() throws {
        let limits = try feeLimits()
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let model = SatoshisPerKilobyteFeeModel(satoshisPerKilobyte: 0)

        var dust = Transaction(
            inputs: [TransactionInput(
                previousOutput: try testOutpoint(fill: 3),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: 101, lockingScript: empty),
                estimatedUnlockingScriptByteCount: 0
            )],
            outputs: [
                TransactionOutput(satoshis: 100, lockingScript: empty),
                TransactionOutput(satoshis: 0, lockingScript: empty, isChange: true),
                TransactionOutput(satoshis: 0, lockingScript: empty, isChange: true),
            ]
        )
        try dust.applyFee(using: model, limits: limits)
        #expect(dust.outputs.count == 1)
        #expect(try dust.fee() == 1)

        var noChange = Transaction(
            inputs: dust.inputs,
            outputs: [TransactionOutput(satoshis: 90, lockingScript: empty)]
        )
        try noChange.applyFee(using: model, limits: limits)
        #expect(noChange.outputs.count == 1)
        #expect(noChange.outputs[0].satoshis == 90)
        #expect(try noChange.fee() == 11)

        var overspent = noChange
        overspent.outputs[0].satoshis = 102
        #expect(throws: TransactionError.outputSatoshisExceedInputs(inputs: 101, outputs: 102)) {
            try overspent.fee()
        }
    }

    @Test("UTXO construction metadata stays outside wire identity")
    func constructionMetadata() throws {
        let limits = try feeLimits()
        let key = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let publicKeyHash = BSVHashing.hash160(key.publicKey.compressedBytes)
        let lockingScript = try Script.payToPublicKeyHash(
            publicKeyHash,
            maximumByteCount: 25
        )
        let unspent = UnspentTransactionOutput(
            transactionID: try TransactionID(wireBytes: [UInt8](repeating: 4, count: 32)),
            outputIndex: 7,
            satoshis: 20_000,
            lockingScript: lockingScript
        )
        var transaction = Transaction()
        let inputIndex = try transaction.addPayToPublicKeyHashInput(spending: unspent)
        _ = try transaction.addPayToPublicKeyHashOutput(
            satoshis: 19_000,
            publicKeyHash: publicKeyHash
        )

        #expect(inputIndex == 0)
        #expect(transaction.inputs[0].sourceOutput == unspent.output)
        #expect(transaction.inputs[0].estimatedUnlockingScriptByteCount == 107)
        let unsignedBytes = try transaction.serialized(limits: limits)
        var metadataChanged = transaction
        metadataChanged.inputs[0].estimatedUnlockingScriptByteCount = 900
        metadataChanged.outputs[0].isChange = true
        #expect(metadataChanged == transaction)
        #expect(try metadataChanged.serialized(limits: limits) == unsignedBytes)

        let projectedFee = try SatoshisPerKilobyteFeeModel(
            satoshisPerKilobyte: 1_000
        ).fee(for: transaction, limits: limits)
        try transaction.signPayToPublicKeyHashInput(at: 0, with: key, limits: limits)
        #expect(transaction.inputs[0].unlockingScript.byteCount <= 107)
        let signedFee = try SatoshisPerKilobyteFeeModel(
            satoshisPerKilobyte: 1_000
        ).fee(for: transaction, limits: limits)
        #expect(signedFee <= projectedFee)
    }

    @Test("P2PKH projection covers DER R sign padding")
    func p2pkhMaximumProjection() throws {
        let limits = try feeLimits()
        let key = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let lockingScript = try Script.payToPublicKeyHash(
            BSVHashing.hash160(key.publicKey.compressedBytes),
            maximumByteCount: 25
        )
        let empty = try Script(bytes: [], maximumByteCount: 0)
        var base = Transaction(
            inputs: [TransactionInput(
                previousOutput: try testOutpoint(fill: 5),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(
                    satoshis: 20_000,
                    lockingScript: lockingScript
                )
            )],
            outputs: [TransactionOutput(satoshis: 19_000, lockingScript: lockingScript)]
        )

        var observedByteCounts: Set<Int> = []
        for lockTime in UInt32(0)..<64 {
            base.lockTime = lockTime
            var candidate = base
            try candidate.signPayToPublicKeyHashInput(at: 0, with: key, limits: limits)
            observedByteCounts.insert(candidate.inputs[0].unlockingScript.byteCount)
        }
        #expect(observedByteCounts.contains(106))
        #expect(observedByteCounts.contains(107))
        #expect(observedByteCounts.allSatisfy {
            $0 <= TransactionInput.payToPublicKeyHashUnlockingScriptByteCount
        })
    }
}

private func feeLimits() throws -> TransactionLimits {
    try TransactionLimits(
        maximumTransactionByteCount: 10_000,
        maximumInputCount: 100,
        maximumOutputCount: 100,
        maximumScriptByteCount: 1_000
    )
}

private func testOutpoint(fill: UInt8) throws -> Outpoint {
    Outpoint(
        transactionID: try TransactionID(wireBytes: [UInt8](repeating: fill, count: 32)),
        outputIndex: 0
    )
}
