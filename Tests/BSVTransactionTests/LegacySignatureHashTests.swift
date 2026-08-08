import BSVCore
import BSVScript
import BSVTransaction
import Testing

@Suite("Legacy transaction signature hashes")
struct LegacySignatureHashTests {
    @Test("canonical hash-type bytes are explicit")
    func hashTypes() throws {
        for (rawValue, outputs, anyoneCanPay) in [
            (UInt8(0x01), SignatureHashOutputs.all, false),
            (0x02, .none, false),
            (0x03, .single, false),
            (0x81, .all, true),
            (0x82, .none, true),
            (0x83, .single, true),
        ] {
            let value = try LegacySignatureHashType(rawValue: rawValue)
            #expect(value.outputs == outputs)
            #expect(value.anyoneCanPay == anyoneCanPay)
            #expect(value.rawValue == rawValue)
        }

        for rawValue in [UInt8(0), 4, 0x40, 0x41, 0xff] {
            #expect(throws: LegacySignatureHashTypeError.invalidValue(rawValue)) {
                try LegacySignatureHashType(rawValue: rawValue)
            }
        }
    }

    @Test("all modes are deterministic and leave the transaction unchanged")
    func deterministicModes() throws {
        let transaction = try fixtureTransaction(outputCount: 2)
        let original = transaction
        let scriptCode = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        let limits = try limits()
        var digests = Set<Hash256>()

        for hashType in [
            LegacySignatureHashType.all,
            .none,
            .single,
            LegacySignatureHashType(outputs: .all, anyoneCanPay: true),
            LegacySignatureHashType(outputs: .none, anyoneCanPay: true),
            LegacySignatureHashType(outputs: .single, anyoneCanPay: true),
        ] {
            let first = try transaction.legacySignatureHash(
                inputIndex: 1,
                hashType: hashType,
                scriptCode: scriptCode,
                limits: limits
            )
            let second = try transaction.legacySignatureHash(
                inputIndex: 1,
                hashType: hashType,
                scriptCode: scriptCode,
                limits: limits
            )
            #expect(first == second)
            digests.insert(first)
        }

        #expect(digests.count == 6)
        #expect(transaction == original)
    }

    @Test("SIGHASH_SINGLE out of range is the un-hashed uint256 one")
    func singleBug() throws {
        let transaction = try fixtureTransaction(outputCount: 0)
        let scriptCode = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        let limits = try limits()
        let expected = [UInt8(1)] + Array(repeating: 0, count: 31)

        #expect(try transaction.legacySignaturePreimage(
            inputIndex: 1,
            hashType: .single,
            scriptCode: scriptCode,
            limits: limits
        ) == expected)
        #expect(try transaction.legacySignatureHash(
            inputIndex: 1,
            hashType: .single,
            scriptCode: scriptCode,
            limits: limits
        ).bytes == expected)

        // Raw 0x43 is noncanonical but masks to SINGLE in consensus code.
        #expect(try transaction.legacySignatureHash(
            inputIndex: 1,
            rawHashType: 0x43,
            scriptCode: scriptCode,
            limits: limits
        ).bytes == expected)
    }

    @Test("preimage size is bounded by script policy, not original wire size")
    func preimageMayExceedTransactionWireLimit() throws {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let source = TransactionOutput(satoshis: 1, lockingScript: empty)
        let transaction = Transaction(inputs: [TransactionInput(
            previousOutput: Outpoint(
                transactionID: try TransactionID(
                    wireBytes: Array(repeating: 3, count: 32)
                ),
                outputIndex: 0
            ),
            unlockingScript: empty,
            sourceOutput: source
        )])
        let explicitScript = try Script(
            bytes: Array(repeating: Opcode.nop.rawValue, count: 100),
            maximumByteCount: 100
        )
        let tightWireLimits = try TransactionLimits(
            maximumTransactionByteCount: 60,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 100
        )

        let preimage = try transaction.legacySignaturePreimage(
            inputIndex: 0,
            scriptCode: explicitScript,
            limits: tightWireLimits
        )
        #expect(preimage.count > tightWireLimits.maximumTransactionByteCount)
    }

    private func limits() throws -> TransactionLimits {
        try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
    }

    private func fixtureTransaction(outputCount: Int) throws -> Transaction {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let source = TransactionOutput(
            satoshis: 42,
            lockingScript: try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        )
        let firstID = try TransactionID(wireBytes: Array(repeating: 1, count: 32))
        let secondID = try TransactionID(wireBytes: Array(repeating: 2, count: 32))
        let inputs = [
            TransactionInput(
                previousOutput: Outpoint(
                    transactionID: firstID,
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sequence: 0x11111111
            ),
            TransactionInput(
                previousOutput: Outpoint(
                    transactionID: secondID,
                    outputIndex: 1
                ),
                unlockingScript: empty,
                sequence: 0x22222222,
                sourceOutput: source
            ),
        ]
        let outputs = try (0..<outputCount).map { index in
            TransactionOutput(
                satoshis: UInt64(index + 1),
                lockingScript: try Script(
                    bytes: [UInt8(Opcode.one.rawValue + UInt8(index))],
                    maximumByteCount: 1
                )
            )
        }
        return Transaction(
            version: 2,
            inputs: inputs,
            outputs: outputs,
            lockTime: 9
        )
    }
}
