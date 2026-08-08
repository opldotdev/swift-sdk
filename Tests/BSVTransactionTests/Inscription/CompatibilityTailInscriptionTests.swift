import BSVCore
import BSVScript
import BSVTransaction
import Testing

@Suite("BRC-307 inscription compatibility tail")
struct CompatibilityTailInscriptionTests {
    private func inscriptionLimits(
        script: Int = 4_096,
        contentType: Int = 128,
        content: Int = 2_048,
        enrichedCount: Int = 8,
        enrichedItem: Int = 256
    ) throws -> InscriptionLimits {
        try InscriptionLimits(
            maximumScriptByteCount: script,
            maximumContentTypeByteCount: contentType,
            maximumContentByteCount: content,
            maximumEnrichedItemCount: enrichedCount,
            maximumEnrichedItemByteCount: enrichedItem
        )
    }

    private func transactionLimits(outputs: UInt64 = 8, script: UInt64 = 4_096) throws -> TransactionLimits {
        try TransactionLimits(
            maximumTransactionByteCount: 32_768,
            maximumInputCount: 8,
            maximumOutputCount: outputs,
            maximumScriptByteCount: script
        )
    }

    private func emptyScript() throws -> Script {
        try Script(bytes: [], maximumByteCount: 0)
    }

    private func arguments(
        lockingScript: Script? = nil,
        data: [UInt8] = Array("hi".utf8),
        contentType: String = "text/plain",
        enriched: EnrichedInscriptionArguments? = nil
    ) throws -> InscriptionArguments {
        InscriptionArguments(
            lockingScript: try lockingScript ?? Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1),
            data: data,
            contentType: contentType,
            enrichedArguments: enriched
        )
    }

    private func wireBytes(_ transaction: Transaction) throws -> [UInt8] {
        try transaction.serialized(limits: transactionLimits(outputs: 16, script: 100_000))
    }

    private func input(
        idByte: UInt8,
        outputIndex: UInt32,
        satoshis: UInt64?
    ) throws -> TransactionInput {
        let empty = try emptyScript()
        return TransactionInput(
            previousOutput: Outpoint(
                transactionID: try TransactionID(wireBytes: Array(repeating: idByte, count: 32)),
                outputIndex: outputIndex
            ),
            unlockingScript: empty,
            sourceOutput: satoshis.map { TransactionOutput(satoshis: $0, lockingScript: empty) }
        )
    }

    @Test("the independently derived basic envelope matches BRC-307 and Go layout")
    func envelope() throws {
        let script = try arguments().brc307LockingScript(limits: inscriptionLimits())
        #expect(script.hex == "0063036f7264510a746578742f706c61696e000268696851")
        let operations = try script.operations(maximumPushDataByteCount: 128)
        #expect(operations[0] == .opcode(.false))
        #expect(operations[1] == .opcode(.if))
        #expect(operations[2].pushedData == Array("ord".utf8))
        #expect(operations[4].pushedData == Array("text/plain".utf8))
        #expect(operations[6].pushedData == Array("hi".utf8))
        #expect(operations[7] == .opcode(.endIf))
    }

    @Test("Unicode content and bounded UTF-8 content types survive exactly")
    func unicodeBody() throws {
        let body = Array("🌎 café".utf8)
        let script = try arguments(data: body, contentType: "text/plain;charset=utf-8")
            .brc307LockingScript(limits: inscriptionLimits())
        #expect(try script.operations(maximumPushDataByteCount: 128)[6].pushedData == body)
        let unicodeType = "application/x-雪"
        let unicodeTypeScript = try arguments(contentType: unicodeType)
            .brc307LockingScript(limits: inscriptionLimits())
        #expect(
            try unicodeTypeScript.operations(maximumPushDataByteCount: 128)[4].pushedData
                == Array(unicodeType.utf8)
        )
        let quoted = "text/plain; charset=\"utf-8\""
        let quotedScript = try arguments(contentType: quoted)
            .brc307LockingScript(limits: inscriptionLimits())
        #expect(
            try quotedScript.operations(maximumPushDataByteCount: 128)[4].pushedData
                == Array(quoted.utf8)
        )
        #expect(throws: InscriptionError.invalidContentType) {
            try arguments(contentType: "")
                .brc307LockingScript(limits: inscriptionLimits())
        }
    }

    @Test("BRC-307 enriched pushes are emitted despite the pinned Go omission artifact")
    func enriched() throws {
        let enriched = EnrichedInscriptionArguments(opReturnData: [Array("MAP".utf8), [], [0xff]])
        let script = try arguments(enriched: enriched).brc307LockingScript(limits: inscriptionLimits())
        let operations = try script.operations(maximumPushDataByteCount: 128)
        #expect(operations[8] == .opcode(.one))
        #expect(operations[9] == .opcode(.return))
        #expect(operations[10].pushedData == Array("MAP".utf8))
        #expect(operations[11] == .opcode(.zero))
        #expect(operations[12].pushedData == [0xff])
    }

    @Test("push thresholds and every independent limit are enforced")
    func boundaries() throws {
        let atLimit = try arguments(data: Array(repeating: 7, count: 76))
            .brc307LockingScript(limits: inscriptionLimits(content: 76))
        #expect(atLimit.bytes.contains(Opcode.pushData1.rawValue))
        #expect(throws: InscriptionError.contentTooLarge(actual: 77, maximum: 76)) {
            try arguments(data: Array(repeating: 7, count: 77))
                .brc307LockingScript(limits: inscriptionLimits(content: 76))
        }
        #expect(throws: InscriptionError.contentTypeTooLarge(actual: 10, maximum: 9)) {
            try arguments().brc307LockingScript(limits: inscriptionLimits(contentType: 9))
        }
        let malformed = try Script(bytes: [Opcode.pushData1.rawValue], maximumByteCount: 1)
        #expect(throws: InscriptionError.malformedLockingScript) {
            try arguments(lockingScript: malformed).brc307LockingScript(limits: inscriptionLimits())
        }
    }

    @Test("negative limits are rejected independently")
    func negativeLimits() {
        let cases = [
            (-1, 0, 0, 0, 0),
            (0, -1, 0, 0, 0),
            (0, 0, -1, 0, 0),
            (0, 0, 0, -1, 0),
            (0, 0, 0, 0, -1),
        ]
        for values in cases {
            #expect(throws: InscriptionError.invalidLimits) {
                try InscriptionLimits(
                    maximumScriptByteCount: values.0,
                    maximumContentTypeByteCount: values.1,
                    maximumContentByteCount: values.2,
                    maximumEnrichedItemCount: values.3,
                    maximumEnrichedItemByteCount: values.4
                )
            }
        }
    }

    @Test("BRC-307 exact limits succeed and max plus one fails")
    func exactLimits() throws {
        let enriched = EnrichedInscriptionArguments(opReturnData: [[1, 2], [3, 4]])
        let value = try arguments(data: [5, 6, 7], enriched: enriched)
        let generous = try value.brc307LockingScript(limits: inscriptionLimits())
        let exact = try inscriptionLimits(
            script: generous.byteCount,
            contentType: "text/plain".utf8.count,
            content: 3,
            enrichedCount: 2,
            enrichedItem: 2
        )
        #expect(try value.brc307LockingScript(limits: exact) == generous)

        #expect(throws: InscriptionError.contentTypeTooLarge(actual: 10, maximum: 9)) {
            try value.brc307LockingScript(limits: inscriptionLimits(contentType: 9))
        }
        #expect(throws: InscriptionError.contentTooLarge(actual: 3, maximum: 2)) {
            try value.brc307LockingScript(limits: inscriptionLimits(content: 2))
        }
        #expect(throws: InscriptionError.tooManyEnrichedItems(actual: 2, maximum: 1)) {
            try value.brc307LockingScript(limits: inscriptionLimits(enrichedCount: 1))
        }
        #expect(throws: InscriptionError.enrichedItemTooLarge(index: 0, actual: 2, maximum: 1)) {
            try value.brc307LockingScript(limits: inscriptionLimits(enrichedItem: 1))
        }
        #expect(throws: InscriptionError.scriptTooLarge(
            actual: generous.byteCount,
            maximum: generous.byteCount - 1
        )) {
            try value.brc307LockingScript(limits: inscriptionLimits(
                script: generous.byteCount - 1,
                contentType: 10,
                content: 3,
                enrichedCount: 2,
                enrichedItem: 2
            ))
        }
    }

    @Test("BRC-307 emits canonical Go-compatible pushes at every boundary")
    func canonicalPushBoundaries() throws {
        let cases: [(Int, [UInt8])] = [
            (0, [0x00]),
            (1, [0x01]),
            (16, [0x10]),
            (17, [0x11]),
            (75, [0x4b]),
            (76, [0x4c, 0x4c]),
            (255, [0x4c, 0xff]),
            (256, [0x4d, 0x00, 0x01]),
            (65_535, [0x4d, 0xff, 0xff]),
            (65_536, [0x4e, 0x00, 0x00, 0x01, 0x00]),
        ]
        for (byteCount, prefix) in cases {
            let item = Array(repeating: UInt8(0xa5), count: byteCount)
            let script = try arguments(enriched: EnrichedInscriptionArguments(opReturnData: [item]))
                .brc307LockingScript(limits: inscriptionLimits(
                    script: 70_000,
                    enrichedCount: 1,
                    enrichedItem: 65_536
                ))
            #expect(Array(script.bytes.suffix(prefix.count + item.count)) == prefix + item)
        }
    }

    @Test("nil and empty enriched arguments are byte-identical")
    func nilEqualsEmptyEnriched() throws {
        let absent = try arguments(enriched: nil).brc307LockingScript(limits: inscriptionLimits())
        let empty = try arguments(enriched: EnrichedInscriptionArguments(opReturnData: []))
            .brc307LockingScript(limits: inscriptionLimits())
        #expect(absent.bytes == empty.bytes)
    }

    @Test("total enriched OP_RETURN size reports the public inscription error")
    func totalEnrichedSizeOverflow() throws {
        let value = try arguments(enriched: EnrichedInscriptionArguments(
            opReturnData: [Array(repeating: 1, count: 10), Array(repeating: 2, count: 10)]
        ))
        let complete = try value.brc307LockingScript(limits: inscriptionLimits())
        let maximum = complete.byteCount - 1
        #expect(throws: InscriptionError.scriptTooLarge(actual: complete.byteCount, maximum: maximum)) {
            try value.brc307LockingScript(limits: inscriptionLimits(
                script: maximum,
                enrichedCount: 2,
                enrichedItem: 10
            ))
        }
    }

    @Test("simple inscription appends one satoshi without changing input metadata")
    func inscribe() throws {
        let source = TransactionOutput(satoshis: 9, lockingScript: try emptyScript())
        let id = try TransactionID(wireBytes: Array(repeating: 1, count: 32))
        let input = TransactionInput(
            previousOutput: Outpoint(transactionID: id, outputIndex: 0),
            unlockingScript: try emptyScript(),
            sourceOutput: source
        )
        var transaction = Transaction(inputs: [input])
        let index = try transaction.inscribe(
            arguments(),
            inscriptionLimits: inscriptionLimits(),
            transactionLimits: transactionLimits()
        )
        #expect(index == 0)
        #expect(transaction.outputs.count == 1)
        #expect(transaction.outputs[0].satoshis == 1)
        #expect(transaction.inputs[0].sourceOutput == source)
    }

    @Test("simple inscription failures leave transaction wire bytes unchanged")
    func inscribeAtomicFailures() throws {
        var transaction = Transaction(inputs: [try input(idByte: 9, outputIndex: 0, satoshis: 9)])
        let before = try wireBytes(transaction)
        #expect(throws: InscriptionError.contentTooLarge(actual: 2, maximum: 1)) {
            try transaction.inscribe(
                arguments(),
                inscriptionLimits: inscriptionLimits(content: 1),
                transactionLimits: transactionLimits()
            )
        }
        #expect(try wireBytes(transaction) == before)

        #expect(throws: TransactionError.outputCountExceedsLimit(actual: 1, maximum: 0)) {
            try transaction.inscribe(
                arguments(),
                inscriptionLimits: inscriptionLimits(),
                transactionLimits: transactionLimits(outputs: 0)
            )
        }
        #expect(try wireBytes(transaction) == before)
    }

    @Test("specific ordinal uses preceding hydrated inputs and returns exact output indices")
    func specificOrdinal() throws {
        let empty = try emptyScript()
        let id = try TransactionID(wireBytes: Array(repeating: 2, count: 32))
        let inputs = [UInt64(3), 5].enumerated().map { index, satoshis in
            TransactionInput(
                previousOutput: Outpoint(transactionID: id, outputIndex: UInt32(index)),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: satoshis, lockingScript: empty)
            )
        }
        var transaction = Transaction(inputs: inputs)
        let indices = try transaction.inscribeSpecificOrdinal(
            arguments(),
            inputIndex: 1,
            satoshiIndex: 2,
            precedingSatoshisLockingScript: empty,
            inscriptionLimits: inscriptionLimits(),
            transactionLimits: transactionLimits()
        )
        #expect(indices == SpecificOrdinalOutputIndices(
            precedingSatoshisOutputIndex: 0,
            inscriptionOutputIndex: 1
        ))
        #expect(transaction.outputs.map(\.satoshis) == [5, 1])
    }

    @Test("specific ordinal accepts the first and last satoshi")
    func specificOrdinalEndpoints() throws {
        let empty = try emptyScript()
        let original = Transaction(inputs: [try input(idByte: 10, outputIndex: 0, satoshis: 3)])

        var first = original
        _ = try first.inscribeSpecificOrdinal(
            arguments(),
            inputIndex: 0,
            satoshiIndex: 0,
            precedingSatoshisLockingScript: empty,
            inscriptionLimits: inscriptionLimits(),
            transactionLimits: transactionLimits()
        )
        #expect(first.outputs.map(\.satoshis) == [0, 1])

        var last = original
        _ = try last.inscribeSpecificOrdinal(
            arguments(),
            inputIndex: 0,
            satoshiIndex: 2,
            precedingSatoshisLockingScript: empty,
            inscriptionLimits: inscriptionLimits(),
            transactionLimits: transactionLimits()
        )
        #expect(last.outputs.map(\.satoshis) == [2, 1])
    }

    @Test("invalid indices and source-output failures are byte-atomic")
    func specificOrdinalInputMatrix() throws {
        let empty = try emptyScript()
        let hydrated = Transaction(inputs: [try input(idByte: 11, outputIndex: 0, satoshis: 2)])
        for invalidIndex in [-1, 1] {
            var transaction = hydrated
            let before = try wireBytes(transaction)
            #expect(throws: TransactionInscriptionError.invalidInputIndex(invalidIndex)) {
                try transaction.inscribeSpecificOrdinal(
                    arguments(), inputIndex: invalidIndex, satoshiIndex: 0,
                    precedingSatoshisLockingScript: empty,
                    inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
                )
            }
            #expect(try wireBytes(transaction) == before)
        }

        let cases: [(Transaction, Int, TransactionInscriptionError)] = [
            (Transaction(inputs: [try input(idByte: 12, outputIndex: 0, satoshis: nil)]), 0,
             .missingSourceOutput(inputIndex: 0)),
            (Transaction(inputs: [try input(idByte: 13, outputIndex: 0, satoshis: 0)]), 0,
             .emptySourceOutput(inputIndex: 0)),
            (Transaction(inputs: [
                try input(idByte: 14, outputIndex: 0, satoshis: nil),
                try input(idByte: 14, outputIndex: 1, satoshis: 2),
            ]), 1, .missingSourceOutput(inputIndex: 0)),
            (Transaction(inputs: [
                try input(idByte: 15, outputIndex: 0, satoshis: 0),
                try input(idByte: 15, outputIndex: 1, satoshis: 2),
            ]), 1, .emptySourceOutput(inputIndex: 0)),
            (Transaction(inputs: [
                try input(idByte: 16, outputIndex: 0, satoshis: 2),
                try input(idByte: 16, outputIndex: 1, satoshis: nil),
            ]), 1, .missingSourceOutput(inputIndex: 1)),
            (Transaction(inputs: [
                try input(idByte: 17, outputIndex: 0, satoshis: 2),
                try input(idByte: 17, outputIndex: 1, satoshis: 0),
            ]), 1, .emptySourceOutput(inputIndex: 1)),
        ]
        for (original, selectedInput, expectedError) in cases {
            var transaction = original
            let before = try wireBytes(transaction)
            #expect(throws: expectedError) {
                try transaction.inscribeSpecificOrdinal(
                    arguments(), inputIndex: selectedInput, satoshiIndex: 0,
                    precedingSatoshisLockingScript: empty,
                    inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
                )
            }
            #expect(try wireBytes(transaction) == before)
        }
    }

    @Test("specific ordinal UInt64 arithmetic failures are byte-atomic")
    func specificOrdinalArithmeticOverflow() throws {
        let empty = try emptyScript()
        let cases: [(Transaction, Int, UInt64)] = [
            (Transaction(inputs: [
                try input(idByte: 18, outputIndex: 0, satoshis: .max),
                try input(idByte: 18, outputIndex: 1, satoshis: 1),
                try input(idByte: 18, outputIndex: 2, satoshis: 1),
            ]), 2, 0),
            (Transaction(inputs: [
                try input(idByte: 19, outputIndex: 0, satoshis: .max),
                try input(idByte: 19, outputIndex: 1, satoshis: 2),
            ]), 1, 1),
        ]
        for (original, selectedInput, satoshiIndex) in cases {
            var transaction = original
            let before = try wireBytes(transaction)
            #expect(throws: TransactionInscriptionError.precedingSatoshiCountOverflow) {
                try transaction.inscribeSpecificOrdinal(
                    arguments(), inputIndex: selectedInput, satoshiIndex: satoshiIndex,
                    precedingSatoshisLockingScript: empty,
                    inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
                )
            }
            #expect(try wireBytes(transaction) == before)
        }
    }

    @Test("out-of-range selected satoshis are byte-atomic")
    func specificOrdinalSatoshiRange() throws {
        let empty = try emptyScript()
        let original = Transaction(inputs: [try input(idByte: 20, outputIndex: 0, satoshis: 2)])
        for index: UInt64 in [2, .max] {
            var transaction = original
            let before = try wireBytes(transaction)
            #expect(throws: TransactionInscriptionError.satoshiIndexOutOfRange(
                index: index,
                sourceSatoshis: 2
            )) {
                try transaction.inscribeSpecificOrdinal(
                    arguments(), inputIndex: 0, satoshiIndex: index,
                    precedingSatoshisLockingScript: empty,
                    inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
                )
            }
            #expect(try wireBytes(transaction) == before)
        }
    }

    @Test("all specific-ordinal failures are atomic")
    func atomicFailures() throws {
        let empty = try emptyScript()
        let id = try TransactionID(wireBytes: Array(repeating: 3, count: 32))
        let input = TransactionInput(
            previousOutput: Outpoint(transactionID: id, outputIndex: 0),
            unlockingScript: empty,
            sourceOutput: TransactionOutput(satoshis: 2, lockingScript: empty)
        )
        let original = Transaction(inputs: [input])
        var transaction = original
        let originalBytes = try wireBytes(original)
        #expect(throws: TransactionInscriptionError.satoshiIndexOutOfRange(index: 2, sourceSatoshis: 2)) {
            try transaction.inscribeSpecificOrdinal(
                arguments(), inputIndex: 0, satoshiIndex: 2,
                precedingSatoshisLockingScript: empty,
                inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
            )
        }
        #expect(transaction == original)
        #expect(try wireBytes(transaction) == originalBytes)
        #expect(throws: TransactionError.outputCountExceedsLimit(actual: 2, maximum: 1)) {
            try transaction.inscribeSpecificOrdinal(
                arguments(), inputIndex: 0, satoshiIndex: 0,
                precedingSatoshisLockingScript: empty,
                inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits(outputs: 1)
            )
        }
        #expect(transaction == original)
        #expect(try wireBytes(transaction) == originalBytes)

        transaction.outputs = [TransactionOutput(satoshis: 1, lockingScript: empty)]
        let withOutput = transaction
        let withOutputBytes = try wireBytes(withOutput)
        #expect(throws: TransactionInscriptionError.outputsMustBeEmpty) {
            try transaction.inscribeSpecificOrdinal(
                arguments(), inputIndex: 0, satoshiIndex: 0,
                precedingSatoshisLockingScript: empty,
                inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
            )
        }
        #expect(transaction == withOutput)
        #expect(try wireBytes(transaction) == withOutputBytes)
    }

    @Test("pinned Go index-range artifacts and absent source metadata are fenced atomically")
    func sourceFailures() throws {
        let empty = try emptyScript()
        let id = try TransactionID(wireBytes: Array(repeating: 4, count: 32))
        let original = Transaction(inputs: [TransactionInput(
            previousOutput: Outpoint(transactionID: id, outputIndex: 0),
            unlockingScript: empty
        )])
        var transaction = original
        let originalBytes = try wireBytes(original)
        #expect(throws: TransactionInscriptionError.invalidInputIndex(1)) {
            try transaction.inscribeSpecificOrdinal(
                arguments(), inputIndex: 1, satoshiIndex: 0,
                precedingSatoshisLockingScript: empty,
                inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
            )
        }
        #expect(transaction == original)
        #expect(try wireBytes(transaction) == originalBytes)
        #expect(throws: TransactionInscriptionError.missingSourceOutput(inputIndex: 0)) {
            try transaction.inscribeSpecificOrdinal(
                arguments(), inputIndex: 0, satoshiIndex: 0,
                precedingSatoshisLockingScript: empty,
                inscriptionLimits: inscriptionLimits(), transactionLimits: transactionLimits()
            )
        }
        #expect(transaction == original)
        #expect(try wireBytes(transaction) == originalBytes)
    }

    @Test("argument and result models satisfy Sendable")
    func sendable() throws {
        func requireSendable<T: Sendable>(_: T) {}
        requireSendable(try arguments())
        requireSendable(EnrichedInscriptionArguments(opReturnData: []))
        requireSendable(try inscriptionLimits())
        requireSendable(SpecificOrdinalOutputIndices(
            precedingSatoshisOutputIndex: 0,
            inscriptionOutputIndex: 1
        ))
    }
}
