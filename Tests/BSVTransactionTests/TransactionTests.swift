import BSVCore
import BSVCrypto
import BSVScript
import BSVTransaction
import Testing

@Suite("Transaction identifiers and outpoints")
struct OutpointTests {
    @Test("display and wire byte order are explicit")
    func byteOrder() throws {
        let display = String(repeating: "00", count: 31) + "01"
        let transactionID = try TransactionID(displayHex: display)
        #expect(transactionID.displayHex == display)
        #expect(transactionID.wireBytes.first == 0x01)
        #expect(transactionID.wireBytes.dropFirst().allSatisfy { $0 == 0 })

        let outpoint = Outpoint(transactionID: transactionID, outputIndex: 0x7856_3412)
        #expect(outpoint.wireBytes.count == 36)
        #expect(Array(outpoint.wireBytes.suffix(4)) == [0x12, 0x34, 0x56, 0x78])
        #expect(try Outpoint(wireBytes: outpoint.wireBytes) == outpoint)
    }

    @Test("dot and ordinal text forms are canonical")
    func textForms() throws {
        let txid = String(repeating: "ab", count: 32)
        let dot = try Outpoint("\(txid).4294967295")
        let ordinal = try Outpoint(ordinal: "\(txid)_4294967295")
        #expect(dot == ordinal)
        #expect(dot.description == "\(txid).4294967295")
        #expect(dot.ordinalDescription == "\(txid)_4294967295")

        #expect(throws: OutpointError.invalidFormat) { try Outpoint("\(txid):1") }
        #expect(throws: OutpointError.invalidOutputIndex) { try Outpoint("\(txid).-1") }
        #expect(throws: OutpointError.invalidOutputIndex) { try Outpoint("\(txid).4294967296") }
        #expect(throws: OutpointError.invalidOutputIndex) {
            try Outpoint("\(txid)." + String(repeating: "1", count: 1_000_000))
        }
        #expect(throws: TextEncodingError.invalidLength) {
            try TransactionID(displayHex: String(repeating: "a", count: 1_000_000))
        }
        #expect(throws: FixedByteCountError.invalidByteCount(expected: 36, actual: 35)) {
            try Outpoint(wireBytes: Array(repeating: 0, count: 35))
        }
    }
}

@Suite("Legacy transaction wire format")
struct TransactionTests {
    @Test("empty transaction has the canonical ten-byte image")
    func emptyTransaction() throws {
        let limits = try testLimits()
        let transaction = Transaction()
        let expected: [UInt8] = [
            0x01, 0x00, 0x00, 0x00,
            0x00,
            0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
        #expect(try transaction.serialized(limits: limits) == expected)
        #expect(try Transaction(bytes: expected, limits: limits) == transaction)
        #expect(try transaction.serializedByteCount(limits: limits) == expected.count)
    }

    @Test("permissive count parsing reports parity while serialization canonicalizes")
    func noncanonicalCount() throws {
        let limits = try testLimits()
        let noncanonical: [UInt8] = [
            0x01, 0x00, 0x00, 0x00,
            0xfd, 0x00, 0x00,
            0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
        #expect(throws: TransactionError.self) {
            try Transaction(bytes: noncanonical, limits: limits)
        }
        let decoded = try Transaction(
            bytes: noncanonical,
            limits: limits,
            compactSizeCanonicality: .permissive
        )
        #expect(try decoded.serialized(limits: limits).count == 10)
    }

    @Test("hex parsing rejects oversized text after bounded inspection")
    func oversizedHexText() throws {
        let tinyLimits = try TransactionLimits(
            maximumTransactionByteCount: 10,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 10
        )
        #expect(throws: TransactionError.invalidHex(
            .decodedSizeLimitExceeded(maximum: 10)
        )) {
            try Transaction(
                hex: String(repeating: "00", count: 1_000_000),
                limits: tinyLimits
            )
        }
    }

    @Test("every truncated boundary and trailing byte is rejected")
    func truncation() throws {
        let limits = try testLimits()
        let full = try hexBytes(block113875TransactionHex)
        for count in 0..<full.count {
            #expect(throws: TransactionError.self) {
                try Transaction(bytes: Array(full.prefix(count)), limits: limits)
            }
        }
        #expect(throws: TransactionError.self) {
            try Transaction(bytes: full + [0], limits: limits)
        }
    }

    @Test("parsing and serialization enforce independent count, script, and byte limits")
    func resourceLimits() throws {
        let full = try hexBytes(block113875TransactionHex)
        let byteLimited = try TransactionLimits(
            maximumTransactionByteCount: full.count - 1,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 100
        )
        #expect(throws: TransactionError.transactionTooLarge(
            actual: full.count,
            maximum: full.count - 1
        )) {
            try Transaction(bytes: full, limits: byteLimited)
        }

        let noInputs = try TransactionLimits(
            maximumTransactionByteCount: full.count,
            maximumInputCount: 0,
            maximumOutputCount: 1,
            maximumScriptByteCount: 100
        )
        #expect(throws: TransactionError.inputCountExceedsLimit(actual: 1, maximum: 0)) {
            try Transaction(bytes: full, limits: noInputs)
        }

        let noOutputs = try TransactionLimits(
            maximumTransactionByteCount: full.count,
            maximumInputCount: 1,
            maximumOutputCount: 0,
            maximumScriptByteCount: 100
        )
        #expect(throws: TransactionError.outputCountExceedsLimit(actual: 1, maximum: 0)) {
            try Transaction(bytes: full, limits: noOutputs)
        }

        let shortScript = try TransactionLimits(
            maximumTransactionByteCount: full.count,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 6
        )
        #expect(throws: TransactionError.self) {
            try Transaction(bytes: full, limits: shortScript)
        }
    }

    @Test("the independent block 113875 known answer has the exact txid")
    func knownTransactionID() throws {
        let limits = try testLimits()
        let transaction = try Transaction(hex: block113875TransactionHex, limits: limits)
        #expect(transaction.version == 1)
        #expect(transaction.inputs.count == 1)
        #expect(transaction.outputs.count == 1)
        #expect(transaction.isCoinbase)
        #expect(transaction.outputs[0].satoshis == 5_000_000_000)
        #expect(
            try transaction.transactionID(limits: limits).displayHex
                == "f051e59b5e2503ac626d03aaeac8ab7be2d72ba4b7e97119c5852d70d52dcb86"
        )
        #expect(try transaction.hex(limits: limits) == block113875TransactionHex)
    }

    @Test("coinbase recognition ignores sequence and requires the null outpoint")
    func coinbase() throws {
        let emptyScript = try Script(bytes: [], maximumByteCount: 0)
        let zeroID = try TransactionID(wireBytes: Array(repeating: 0, count: 32))
        var transaction = Transaction(inputs: [TransactionInput(
            previousOutput: Outpoint(transactionID: zeroID, outputIndex: .max),
            unlockingScript: emptyScript,
            sequence: 0
        )])
        #expect(transaction.isCoinbase)
        transaction.inputs[0].previousOutput = Outpoint(
            transactionID: zeroID,
            outputIndex: 0
        )
        #expect(!transaction.isCoinbase)
    }

    @Test("source metadata is outside wire bytes and satoshi totals are checked")
    func sourceMetadataAndTotals() throws {
        let limits = try testLimits()
        let script = try Script(bytes: [], maximumByteCount: 0)
        let transactionID = try TransactionID(wireBytes: Array(repeating: 1, count: 32))
        let outpoint = Outpoint(transactionID: transactionID, outputIndex: 2)
        let output = TransactionOutput(satoshis: 7, lockingScript: script)
        let withoutSource = Transaction(
            inputs: [TransactionInput(previousOutput: outpoint, unlockingScript: script)],
            outputs: [output]
        )
        var withSource = withoutSource
        withSource.inputs[0].sourceOutput = TransactionOutput(
            satoshis: 11,
            lockingScript: script
        )
        #expect(
            try withoutSource.serialized(limits: limits)
                == withSource.serialized(limits: limits)
        )
        #expect(withoutSource == withSource)
        #expect(withoutSource.hashValue == withSource.hashValue)
        #expect(try withSource.totalInputSatoshis() == 11)
        #expect(try withSource.totalOutputSatoshis() == 7)
        #expect(throws: TransactionError.missingSourceOutput(inputIndex: 0)) {
            try withoutSource.totalInputSatoshis()
        }

        let overflowing = Transaction(outputs: [
            TransactionOutput(satoshis: .max, lockingScript: script),
            TransactionOutput(satoshis: 1, lockingScript: script),
        ])
        #expect(throws: TransactionError.satoshiTotalOverflow) {
            try overflowing.totalOutputSatoshis()
        }
    }

    @Test("declared counts cannot amplify reservation beyond remaining bytes")
    func countReservationIsWireBounded() throws {
        let hugeCount = CompactSize.encode(1_000_000)
        let hostile = [UInt8](arrayLiteral: 1, 0, 0, 0) + hugeCount
        let permissiveLimits = try TransactionLimits(
            maximumTransactionByteCount: hostile.count,
            maximumInputCount: 1_000_000,
            maximumOutputCount: 1_000_000,
            maximumScriptByteCount: 1_000_000
        )
        #expect(throws: TransactionError.self) {
            try Transaction(bytes: hostile, limits: permissiveLimits)
        }
    }
}

private let block113875TransactionHex =
    "01000000010000000000000000000000000000000000000000000000000000000000000000" +
    "ffffffff070431dc001b0162ffffffff0100f2052a01000000434104d64bdfd09eb1c5fe295a" +
    "bdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f0478" +
    "34bc06d6d6edf620d184241a6aed8b63a6ac00000000"

private func testLimits() throws -> TransactionLimits {
    try TransactionLimits(
        maximumTransactionByteCount: 1_000_000,
        maximumInputCount: 10_000,
        maximumOutputCount: 10_000,
        maximumScriptByteCount: 100_000
    )
}

private func hexBytes(_ text: String) throws -> [UInt8] {
    try Hex.decode(text, maximumDecodedByteCount: text.utf8.count / 2)
}
