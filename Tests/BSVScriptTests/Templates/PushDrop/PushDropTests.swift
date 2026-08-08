import BSVKeys
import BSVScript
import Testing

@Suite("BRC-48 PushDrop scripts")
struct PushDropTests {
    private let keyBytes = [UInt8](repeating: 0, count: 31) + [1]

    @Test("zero, odd, and even field counts use the exact lock-after drop suffix")
    func fieldCountsAndDrops() throws {
        let key = try PrivateKey(keyBytes).publicKey
        let cases: [([[UInt8]], [UInt8])] = [
            ([], []),
            ([[0xaa]], [Opcode.drop.rawValue]),
            ([[0xaa], [0xbb]], [Opcode.twoDrop.rawValue]),
            ([[0xaa], [0xbb], [0xcc]], [Opcode.twoDrop.rawValue, Opcode.drop.rawValue]),
            ([[0xaa], [0xbb], [0xcc], [0xdd]], [Opcode.twoDrop.rawValue, Opcode.twoDrop.rawValue]),
        ]

        for (fields, drops) in cases {
            let script = try PushDrop.lockingScript(fields: fields, publicKey: key)
            let keyOffset = script.byteCount - 35
            #expect(Array(script.bytes[(keyOffset - drops.count)..<keyOffset]) == drops)
            let decoded = try PushDrop.decode(script)
            #expect(decoded.fields == fields)
            #expect(decoded.publicKey == key)
            #expect(decoded.lockPosition == .after)
        }
    }

    @Test("minimal numeric pushes decode with the documented zero ambiguity")
    func minimalNumericFields() throws {
        let key = try PrivateKey(keyBytes).publicKey
        let original: [[UInt8]] = [[], [0], [1], [16], [0x81], [0x11, 0x22]]
        let script = try PushDrop.lockingScript(fields: original, publicKey: key)
        let decoded = try PushDrop.decode(script)
        #expect(decoded.fields == [[0], [0], [1], [16], [0x81], [0x11, 0x22]])
        #expect(script.bytes[0] == Opcode.zero.rawValue)
        #expect(script.bytes[1] == Opcode.zero.rawValue)
        #expect(script.bytes[2] == Opcode.one.rawValue)
        #expect(script.bytes[3] == Opcode.sixteen.rawValue)
        #expect(script.bytes[4] == Opcode.oneNegate.rawValue)
    }

    @Test("all PUSHDATA boundaries round-trip canonically", arguments: [75, 76, 255, 256, 65_535, 65_536])
    func pushBoundaries(byteCount: Int) throws {
        let key = try PrivateKey(keyBytes).publicKey
        let limits = try PushDropLimits(
            maximumFieldCount: 1,
            maximumFieldByteCount: 70_000,
            maximumScriptByteCount: 70_100
        )
        let field = [UInt8](repeating: 0xa5, count: byteCount)
        let script = try PushDrop.lockingScript(fields: [field], publicKey: key, limits: limits)
        #expect(try PushDrop.decode(script, limits: limits).fields == [field])

        let expectedOpcode: UInt8 = switch byteCount {
        case 75: 75
        case 76, 255: Opcode.pushData1.rawValue
        case 256, 65_535: Opcode.pushData2.rawValue
        default: Opcode.pushData4.rawValue
        }
        #expect(script.bytes[0] == expectedOpcode)
    }

    @Test("field count, field bytes, and script bytes honor exact limits")
    func exactLimits() throws {
        let key = try PrivateKey(keyBytes).publicKey
        let fields: [[UInt8]] = [[0xaa, 0xbb], [0xcc, 0xdd]]
        let script = try PushDrop.lockingScript(fields: fields, publicKey: key)
        let exact = try PushDropLimits(
            maximumFieldCount: 2,
            maximumFieldByteCount: 2,
            maximumScriptByteCount: script.byteCount
        )
        #expect(try PushDrop.decode(
            PushDrop.lockingScript(fields: fields, publicKey: key, limits: exact),
            limits: exact
        ).fields == fields)

        let oneField = try PushDropLimits(
            maximumFieldCount: 1,
            maximumFieldByteCount: 2,
            maximumScriptByteCount: script.byteCount
        )
        #expect(throws: PushDropError.fieldCountExceedsLimit(actual: 2, maximum: 1)) {
            try PushDrop.lockingScript(fields: fields, publicKey: key, limits: oneField)
        }
        let oneByte = try PushDropLimits(
            maximumFieldCount: 2,
            maximumFieldByteCount: 1,
            maximumScriptByteCount: script.byteCount
        )
        #expect(throws: PushDropError.fieldByteCountExceedsLimit(index: 0, actual: 2, maximum: 1)) {
            try PushDrop.lockingScript(fields: fields, publicKey: key, limits: oneByte)
        }
        let shortScript = try PushDropLimits(
            maximumFieldCount: 2,
            maximumFieldByteCount: 2,
            maximumScriptByteCount: script.byteCount - 1
        )
        #expect(throws: PushDropError.scriptByteCountExceedsLimit(
            actual: script.byteCount,
            maximum: script.byteCount - 1
        )) {
            try PushDrop.lockingScript(fields: fields, publicKey: key, limits: shortScript)
        }
        #expect(throws: PushDropError.self) {
            try PushDrop.decode(script, limits: shortScript)
        }
    }

    @Test("every proper truncation of a representative lock-after script is rejected")
    func truncations() throws {
        let key = try PrivateKey(keyBytes).publicKey
        let script = try PushDrop.lockingScript(
            fields: [[0xaa], [UInt8](repeating: 0xbb, count: 76), [0xcc]],
            publicKey: key
        )
        for byteCount in 0..<script.byteCount {
            let truncated = try Script(
                bytes: Array(script.bytes.prefix(byteCount)),
                maximumByteCount: script.byteCount
            )
            #expect(throws: PushDropError.self) {
                try PushDrop.decode(truncated)
            }
        }
    }

    @Test("the decoder rejects every non-exact structural variation")
    func strictStructure() throws {
        let key = try PrivateKey(keyBytes).publicKey
        let canonical = try PushDrop.lockingScript(
            fields: [[0xaa], [0xbb], [0xcc]],
            publicKey: key
        )
        let keyOffset = canonical.byteCount - 35
        let fields = Array(canonical.bytes[..<(keyOffset - 2)])
        let keyLock = Array(canonical.bytes[keyOffset...])
        let badDrops: [[UInt8]] = [
            [],
            [Opcode.drop.rawValue],
            [Opcode.twoDrop.rawValue],
            [Opcode.drop.rawValue, Opcode.twoDrop.rawValue],
            [Opcode.twoDrop.rawValue, Opcode.twoDrop.rawValue],
            [Opcode.twoDrop.rawValue, Opcode.drop.rawValue, Opcode.drop.rawValue],
        ]
        for drops in badDrops {
            try expectDecodeFailure(fields + drops + keyLock)
        }

        try expectDecodeFailure(canonical.bytes + [Opcode.nop.rawValue])
        var wrongFinal = canonical.bytes
        wrongFinal[wrongFinal.count - 1] = Opcode.checkSigVerify.rawValue
        try expectDecodeFailure(wrongFinal)

        let uncompressedKey = key.uncompressedBytes
        try expectDecodeFailure(
            fields + [Opcode.twoDrop.rawValue, Opcode.drop.rawValue]
                + [UInt8(uncompressedKey.count)] + uncompressedKey + [Opcode.checkSig.rawValue]
        )
        var hybridKey = uncompressedKey
        hybridKey[0] = hybridKey[64] & 1 == 0 ? 0x06 : 0x07
        try expectDecodeFailure(
            fields + [Opcode.twoDrop.rawValue, Opcode.drop.rawValue]
                + [UInt8(hybridKey.count)] + hybridKey + [Opcode.checkSig.rawValue]
        )

        let nonminimalPushes: [[UInt8]] = [
            [Opcode.pushData1.rawValue, 1, 0xaa, Opcode.drop.rawValue] + keyLock,
            [1, 1, Opcode.drop.rawValue] + keyLock,
            [1, 0, Opcode.drop.rawValue] + keyLock,
            [1, 0x81, Opcode.drop.rawValue] + keyLock,
        ]
        for bytes in nonminimalPushes { try expectDecodeFailure(bytes) }

        let malformedPushes: [[UInt8]] = [
            [Opcode.pushData1.rawValue] + keyLock,
            [Opcode.pushData2.rawValue, 1] + keyLock,
            [Opcode.pushData4.rawValue, 1, 0, 0] + keyLock,
            [2, 0xaa] + keyLock,
        ]
        for bytes in malformedPushes { try expectDecodeFailure(bytes) }
    }

    @Test("lock-before compatibility is explicit and never auto-detected")
    func compatibilityLayout() throws {
        let key = try PrivateKey(keyBytes).publicKey
        let fields: [[UInt8]] = [[0xaa], [0xbb]]
        let after = try PushDrop.lockingScript(fields: fields, publicKey: key)
        let before = try PushDrop.lockingScript(
            fields: fields,
            publicKey: key,
            lockPosition: .beforeCompatibility
        )
        #expect(try PushDrop.decode(after).fields == fields)
        #expect(try PushDrop.decode(before, lockPosition: .beforeCompatibility).fields == fields)
        #expect(throws: PushDropError.self) { try PushDrop.decode(before) }
        #expect(throws: PushDropError.self) {
            try PushDrop.decode(after, lockPosition: .beforeCompatibility)
        }
    }

    @Test("negative limits are rejected")
    func invalidLimits() {
        #expect(throws: PushDropError.invalidMaximumFieldCount(-1)) {
            try PushDropLimits(maximumFieldCount: -1, maximumFieldByteCount: 0, maximumScriptByteCount: 0)
        }
        #expect(throws: PushDropError.invalidMaximumFieldByteCount(-1)) {
            try PushDropLimits(maximumFieldCount: 0, maximumFieldByteCount: -1, maximumScriptByteCount: 0)
        }
        #expect(throws: PushDropError.invalidMaximumScriptByteCount(-1)) {
            try PushDropLimits(maximumFieldCount: 0, maximumFieldByteCount: 0, maximumScriptByteCount: -1)
        }
    }

    private func expectDecodeFailure(_ bytes: [UInt8]) throws {
        let script = try Script(bytes: bytes, maximumByteCount: 100_000)
        #expect(throws: PushDropError.self) { try PushDrop.decode(script) }
    }
}
