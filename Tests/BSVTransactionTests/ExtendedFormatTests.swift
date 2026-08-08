import BSVCore
import BSVScript
import BSVTransaction
import Testing

@Suite("BRC-30/BIP-239 Extended Format")
struct ExtendedFormatTests {
    @Test("repository-authored MIT known answer pins the 64-bit source amount")
    func knownAnswer() throws {
        // Repository-authored under this repository's MIT license. This is not
        // copied from the Go SDK or a BRC fixture.
        let expected = try Hex.decode(
            "123456780000000000ef01" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "1122334402aabba1b2c3d4" +
                "0807060504030201035100ac" +
                "010900000000000000026a000a0b0c0d",
            maximumDecodedByteCount: 1_000
        )
        let transaction = try makeKnownAnswerTransaction()
        let limits = try generousLimits(maximumBytes: expected.count)

        #expect(try transaction.serialized(format: .extended, limits: limits) == expected)
        #expect(try transaction.hex(format: .extended, limits: limits) == Hex.encode(expected))
        #expect(
            try transaction.serializedByteCount(format: .extended, limits: limits)
                == expected.count
        )

        let decoded = try Transaction(bytes: expected, format: .extended, limits: limits)
        #expect(decoded.version == 0x7856_3412)
        #expect(decoded.inputs[0].sourceOutput?.satoshis == 0x0102_0304_0506_0708)
        #expect(decoded.inputs[0].sourceOutput?.lockingScript.bytes == [0x51, 0x00, 0xac])
        #expect(decoded.inputs[0].sourceOutput?.isChange == false)
        #expect(decoded.inputs[0].estimatedUnlockingScriptByteCount == nil)
        #expect(try decoded.serialized(format: .extended, limits: limits) == expected)
    }

    @Test("empty EF packet is exactly sixteen bytes and accepts every UInt32 version")
    func emptyAndVersion() throws {
        let limits = try generousLimits(maximumBytes: 16)
        for version: UInt32 in [0, 1, 2, .max] {
            let transaction = Transaction(version: version)
            let bytes = try transaction.serialized(format: .extended, limits: limits)
            #expect(bytes.count == 16)
            #expect(Array(bytes[4..<10]) == [0, 0, 0, 0, 0, 0xef])
            #expect(
                try Transaction(bytes: bytes, format: .extended, limits: limits)
                    == transaction
            )
        }
    }

    @Test("multiple inputs preserve zero and maximum source amounts")
    func multipleInputs() throws {
        let script = try Script(bytes: [0x51], maximumByteCount: 1)
        let empty = try Script(bytes: [], maximumByteCount: 0)
        var transaction = Transaction(version: .max, lockTime: .max)
        transaction.inputs = [
            TransactionInput(
                previousOutput: try outpoint(fill: 1, index: 2),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: 0, lockingScript: empty)
            ),
            TransactionInput(
                previousOutput: try outpoint(fill: 2, index: 3),
                unlockingScript: script,
                sequence: 7,
                sourceOutput: TransactionOutput(satoshis: .max, lockingScript: script)
            ),
        ]
        transaction.outputs = [TransactionOutput(satoshis: .max, lockingScript: script)]
        let limits = try generousLimits(maximumBytes: 1_000)
        let bytes = try transaction.serialized(format: .extended, limits: limits)
        let decoded = try Transaction(bytes: bytes, format: .extended, limits: limits)
        #expect(decoded.inputs.map { $0.sourceOutput?.satoshis } == [0, .max])
        #expect(try decoded.serialized(format: .extended, limits: limits) == bytes)
    }

    @Test("source satoshis straddle the UInt32 boundary without narrowing")
    func sourceAmountUInt32Boundary() throws {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let amounts = [UInt64(UInt32.max), UInt64(UInt32.max) + 1]
        let transaction = Transaction(inputs: try amounts.enumerated().map { index, amount in
            TransactionInput(
                previousOutput: try outpoint(fill: UInt8(index + 8), index: UInt32(index)),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: amount, lockingScript: empty)
            )
        })
        let limits = try generousLimits(maximumBytes: 1_000)
        let bytes = try transaction.serialized(format: .extended, limits: limits)
        let decoded = try Transaction(bytes: bytes, format: .extended, limits: limits)
        #expect(decoded.inputs.map { $0.sourceOutput?.satoshis } == amounts.map(Optional.some))
    }

    @Test("all CompactSize script width transitions canonicalize")
    func compactSizeWidths() throws {
        for length in [0xfc, 0xfd, 0xffff, 0x1_0000] {
            let payload = Array(repeating: UInt8(length & 0xff), count: length)
            let script = try Script(bytes: payload, maximumByteCount: length)
            let transaction = Transaction(
                inputs: [TransactionInput(
                    previousOutput: try outpoint(fill: 3, index: 0),
                    unlockingScript: script,
                    sourceOutput: TransactionOutput(satoshis: 1, lockingScript: script)
                )],
                outputs: [TransactionOutput(satoshis: 1, lockingScript: script)]
            )
            let maximum = 4 + 6 + 9 + 41 + 8 + (9 + length) * 3 + 9 + 4
            let limits = try TransactionLimits(
                maximumTransactionByteCount: maximum,
                maximumInputCount: 1,
                maximumOutputCount: 1,
                maximumScriptByteCount: UInt64(length)
            )
            let bytes = try transaction.serialized(format: .extended, limits: limits)
            let decoded = try Transaction(bytes: bytes, format: .extended, limits: limits)
            #expect(decoded.inputs[0].unlockingScript.byteCount == length)
            #expect(decoded.inputs[0].sourceOutput?.lockingScript.byteCount == length)
            #expect(decoded.outputs[0].lockingScript.byteCount == length)
        }
    }

    @Test("source locking scripts use the exact 252/253 CompactSize boundary")
    func sourceScript252And253() throws {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        for length in [252, 253] {
            let sourceScript = try Script(
                bytes: Array(repeating: 0x51, count: length),
                maximumByteCount: length
            )
            let transaction = Transaction(inputs: [TransactionInput(
                previousOutput: try outpoint(fill: 0x33, index: 0),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: 1, lockingScript: sourceScript)
            )])
            let limits = try generousLimits(maximumBytes: 1_000)
            let bytes = try transaction.serialized(format: .extended, limits: limits)
            let decoded = try Transaction(bytes: bytes, format: .extended, limits: limits)
            #expect(decoded.inputs[0].sourceOutput?.lockingScript.byteCount == length)
            #expect(try decoded.serialized(format: .extended, limits: limits) == bytes)
        }
    }

    @Test("input-count width transition is canonical")
    func inputCountWidths() throws {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        for count in [252, 253] {
            let input = TransactionInput(
                previousOutput: try outpoint(fill: 4, index: 0),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: 1, lockingScript: empty)
            )
            let transaction = Transaction(inputs: Array(repeating: input, count: count))
            let limits = try TransactionLimits(
                maximumTransactionByteCount: 20_000,
                maximumInputCount: UInt64(count),
                maximumOutputCount: 0,
                maximumScriptByteCount: 0
            )
            let bytes = try transaction.serialized(format: .extended, limits: limits)
            #expect(try Transaction(bytes: bytes, format: .extended, limits: limits).inputs.count == count)
        }
    }

    @Test("every known-answer prefix and trailing data are rejected")
    func truncationAndTrailing() throws {
        let transaction = try makeKnownAnswerTransaction()
        let limits = try generousLimits(maximumBytes: 1_000)
        let bytes = try transaction.serialized(format: .extended, limits: limits)
        for length in 0..<bytes.count {
            #expect(throws: TransactionError.self) {
                try Transaction(bytes: Array(bytes.prefix(length)), format: .extended, limits: limits)
            }
        }
        #expect(throws: TransactionError.self) {
            try Transaction(bytes: bytes + [0], format: .extended, limits: limits)
        }
    }

    @Test("marker truncation and literal mismatches are distinct")
    func markerErrors() throws {
        let limits = try generousLimits(maximumBytes: 100)
        for length in 4..<10 {
            do {
                _ = try Transaction(
                    bytes: [1, 0, 0, 0] + Array([UInt8](repeating: 0, count: 6).prefix(length - 4)),
                    format: .extended,
                    limits: limits
                )
                Issue.record("expected marker truncation")
            } catch TransactionError.malformed(let field, _, _) {
                #expect(field == .extendedFormatMarker)
            }
        }

        let marker = [UInt8]([0, 0, 0, 0, 0, 0xef])
        for index in marker.indices {
            var mutated = marker
            mutated[index] ^= 1
            #expect(throws: TransactionError.invalidExtendedFormatMarker(actual: mutated)) {
                try Transaction(
                    bytes: [1, 0, 0, 0] + mutated + [0, 0, 0, 0, 0, 0],
                    format: .extended,
                    limits: limits
                )
            }
        }
    }

    @Test("raw collision remains raw while explicit EF parsing reports truncation")
    func rawCollision() throws {
        let collision: [UInt8] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0xef]
        let limits = try generousLimits(maximumBytes: collision.count)
        let raw = try Transaction(bytes: collision, limits: limits)
        #expect(raw.inputs.isEmpty && raw.outputs.isEmpty)
        #expect(raw.lockTime == 0xef00_0000)
        do {
            _ = try Transaction(bytes: collision, format: .extended, limits: limits)
            Issue.record("expected truncated EF input count")
        } catch TransactionError.malformed(let field, _, _) {
            #expect(field == .inputCount)
        }
    }

    @Test("permissive parsing accepts nonminimal values and re-encodes minimally")
    func nonminimalCanonicalization() throws {
        let canonical: [UInt8] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0xef, 0, 0, 0, 0, 0, 0]
        let nonminimal = Array(canonical.prefix(10)) + [0xfd, 0, 0] + Array(canonical.suffix(5))
        let limits = try generousLimits(maximumBytes: nonminimal.count)
        #expect(throws: TransactionError.self) {
            try Transaction(bytes: nonminimal, format: .extended, limits: limits)
        }
        let decoded = try Transaction(
            bytes: nonminimal,
            format: .extended,
            limits: limits,
            compactSizeCanonicality: .permissive
        )
        #expect(try decoded.serialized(format: .extended, limits: limits) == canonical)
    }

    @Test("every EF CompactSize field requires minimal encoding unless explicitly permissive")
    func everyNonminimalCompactSizeField() throws {
        let canonical = try makeKnownAnswerTransaction().serialized(
            format: .extended,
            limits: generousLimits(maximumBytes: 1_000)
        )
        // Offsets in the repository-authored known answer: input count,
        // unlocking length, source-locking length, output count, output-locking length.
        let fields: [(String, Int, UInt8)] = [
            ("input count", 10, 1),
            ("unlocking length", 47, 2),
            ("source-script length", 62, 3),
            ("output count", 66, 1),
            ("output-script length", 75, 2),
        ]
        for (name, offset, value) in fields {
            var nonminimal = canonical
            nonminimal.replaceSubrange(offset...offset, with: [0xfd, value, 0])
            let limits = try generousLimits(maximumBytes: nonminimal.count)
            do {
                _ = try Transaction(bytes: nonminimal, format: .extended, limits: limits)
                Issue.record("required accepted nonminimal \(name)")
            } catch is TransactionError {
                // Expected typed structural rejection.
            }
            let decoded = try Transaction(
                bytes: nonminimal,
                format: .extended,
                limits: limits,
                compactSizeCanonicality: .permissive
            )
            #expect(
                try decoded.serialized(format: .extended, limits: limits) == canonical,
                "permissive \(name) did not canonicalize"
            )
        }
    }

    @Test("extended encoding preflights missing sources in index order")
    func missingSources() throws {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let base = TransactionInput(
            previousOutput: try outpoint(fill: 5, index: 0),
            unlockingScript: empty,
            sourceOutput: TransactionOutput(satoshis: 1, lockingScript: empty)
        )
        let limits = try generousLimits(maximumBytes: 1_000)
        for missing in [0, 1, 2] {
            var inputs = Array(repeating: base, count: 3)
            inputs[missing].sourceOutput = nil
            let transaction = Transaction(inputs: inputs)
            #expect(throws: TransactionError.missingSourceOutput(inputIndex: missing)) {
                try transaction.serialized(format: .extended, limits: limits)
            }
            #expect(throws: TransactionError.missingSourceOutput(inputIndex: missing)) {
                try transaction.serializedByteCount(format: .extended, limits: limits)
            }
        }
    }

    @Test("source metadata changes EF bytes but not equality, raw bytes, or txid")
    func metadataSemantics() throws {
        let limits = try generousLimits(maximumBytes: 1_000)
        let lhs = try makeKnownAnswerTransaction()
        var rhs = lhs
        rhs.inputs[0].sourceOutput = TransactionOutput(
            satoshis: 99,
            lockingScript: try Script(bytes: [0x52], maximumByteCount: 1),
            isChange: true
        )
        rhs.inputs[0].estimatedUnlockingScriptByteCount = 999

        #expect(lhs == rhs)
        #expect(lhs.hashValue == rhs.hashValue)
        #expect(try lhs.serialized(limits: limits) == rhs.serialized(limits: limits))
        #expect(try lhs.transactionID(limits: limits) == rhs.transactionID(limits: limits))
        #expect(
            try lhs.serialized(format: .extended, limits: limits)
                != rhs.serialized(format: .extended, limits: limits)
        )
        #expect(try rhs.totalInputSatoshis() == 99)
    }

    @Test("complete image, counts, and all three script categories obey limits")
    func limits() throws {
        let transaction = try makeKnownAnswerTransaction()
        let generous = try generousLimits(maximumBytes: 1_000)
        let bytes = try transaction.serialized(format: .extended, limits: generous)
        let exact = try TransactionLimits(
            maximumTransactionByteCount: bytes.count,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 3
        )
        #expect(try transaction.serialized(format: .extended, limits: exact) == bytes)
        #expect(try Transaction(bytes: bytes, format: .extended, limits: exact) == transaction)

        let byteShort = try TransactionLimits(
            maximumTransactionByteCount: bytes.count - 1,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 3
        )
        #expect(throws: TransactionError.transactionTooLarge(
            actual: bytes.count,
            maximum: bytes.count - 1
        )) {
            try Transaction(bytes: bytes, format: .extended, limits: byteShort)
        }
        #expect(throws: TransactionError.self) {
            try transaction.serialized(format: .extended, limits: byteShort)
        }

        for (inputLimit, outputLimit) in [(0 as UInt64, 1 as UInt64), (1, 0)] {
            let limits = try TransactionLimits(
                maximumTransactionByteCount: bytes.count,
                maximumInputCount: inputLimit,
                maximumOutputCount: outputLimit,
                maximumScriptByteCount: 3
            )
            #expect(throws: TransactionError.self) {
                try Transaction(bytes: bytes, format: .extended, limits: limits)
            }
        }

        for category in 0..<3 {
            var changed = transaction
            let longScript = try Script(bytes: [1, 2, 3, 4], maximumByteCount: 4)
            if category == 0 { changed.inputs[0].unlockingScript = longScript }
            if category == 1 { changed.inputs[0].sourceOutput?.lockingScript = longScript }
            if category == 2 { changed.outputs[0].lockingScript = longScript }
            #expect(throws: TransactionError.scriptTooLarge(actual: 4, maximum: 3)) {
                try changed.serialized(format: .extended, limits: exact)
            }
        }
    }

    @Test("hostile counts and lengths fail without allocation amplification")
    func hostileDeclarations() throws {
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 100,
            maximumInputCount: 1_000_000,
            maximumOutputCount: 1_000_000,
            maximumScriptByteCount: 1_000_000
        )
        let header: [UInt8] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0xef]
        #expect(throws: TransactionError.self) {
            try Transaction(
                bytes: header + CompactSize.encode(1_000_000),
                format: .extended,
                limits: limits
            )
        }
        let oneInputPrefix = header + [1] + Array(repeating: UInt8(0), count: 36)
        #expect(throws: TransactionError.self) {
            try Transaction(
                bytes: oneInputPrefix + CompactSize.encode(UInt64.max),
                format: .extended,
                limits: limits
            )
        }
    }
}

private func makeKnownAnswerTransaction() throws -> Transaction {
    Transaction(
        version: 0x7856_3412,
        inputs: [TransactionInput(
            previousOutput: Outpoint(
                transactionID: try TransactionID(wireBytes: Array(0...31)),
                outputIndex: 0x4433_2211
            ),
            unlockingScript: try Script(bytes: [0xaa, 0xbb], maximumByteCount: 2),
            sequence: 0xd4c3_b2a1,
            sourceOutput: TransactionOutput(
                satoshis: 0x0102_0304_0506_0708,
                lockingScript: try Script(bytes: [0x51, 0x00, 0xac], maximumByteCount: 3)
            )
        )],
        outputs: [TransactionOutput(
            satoshis: 9,
            lockingScript: try Script(bytes: [0x6a, 0x00], maximumByteCount: 2)
        )],
        lockTime: 0x0d0c_0b0a
    )
}

private func outpoint(fill: UInt8, index: UInt32) throws -> Outpoint {
    Outpoint(
        transactionID: try TransactionID(wireBytes: Array(repeating: fill, count: 32)),
        outputIndex: index
    )
}

private func generousLimits(maximumBytes: Int) throws -> TransactionLimits {
    try TransactionLimits(
        maximumTransactionByteCount: maximumBytes,
        maximumInputCount: 10_000,
        maximumOutputCount: 10_000,
        maximumScriptByteCount: UInt64(maximumBytes)
    )
}
