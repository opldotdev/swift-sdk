import BSVCore
import BSVScript
import Testing

@Suite("Bitcoin Script bytes and operations")
struct ScriptTests {
    @Test("Hex and bytes preserve value semantics")
    func construction() throws {
        let script = try Script(hex: "76A91400FF88AC", maximumByteCount: 7)
        #expect(script.bytes == [0x76, 0xa9, 0x14, 0x00, 0xff, 0x88, 0xac])
        #expect(script.hex == "76a91400ff88ac")
        #expect(script.byteCount == 7)
        #expect(!script.isEmpty)

        #expect(throws: ScriptError.invalidMaximumScriptByteCount(-1)) {
            try Script(bytes: [], maximumByteCount: -1)
        }
        #expect(throws: ScriptError.scriptTooLarge(actual: 2, maximum: 1)) {
            try Script(bytes: [1, 2], maximumByteCount: 1)
        }
        #expect(throws: ScriptError.invalidHex(.oddLength)) {
            try Script(hex: "0", maximumByteCount: 1)
        }
    }

    @Test("All push-prefix thresholds are explicit")
    func pushPrefixes() throws {
        #expect(try Script.pushDataPrefix(forByteCount: 0) == [0x00])
        #expect(try Script.pushDataPrefix(forByteCount: 75) == [0x4b])
        #expect(try Script.pushDataPrefix(forByteCount: 76) == [0x4c, 0x4c])
        #expect(try Script.pushDataPrefix(forByteCount: 255) == [0x4c, 0xff])
        #expect(try Script.pushDataPrefix(forByteCount: 256) == [0x4d, 0x00, 0x01])
        #expect(try Script.pushDataPrefix(forByteCount: 65_535) == [0x4d, 0xff, 0xff])
        #expect(
            try Script.pushDataPrefix(forByteCount: 65_536)
                == [0x4e, 0x00, 0x00, 0x01, 0x00]
        )
        #expect(throws: ScriptError.dataTooLargeForPush(actual: -1)) {
            try Script.pushDataPrefix(forByteCount: -1)
        }
    }

    @Test("Builder emits SDK and policy-minimal forms")
    func building() throws {
        var sdkStyle = try Script(bytes: [], maximumByteCount: 32)
        try sdkStyle.appendPushData([], maximumScriptByteCount: 32)
        try sdkStyle.appendPushData([1], maximumScriptByteCount: 32)
        try sdkStyle.appendPushData([0x81], maximumScriptByteCount: 32)
        try sdkStyle.append(.dup, maximumScriptByteCount: 32)
        #expect(sdkStyle.bytes == [0x00, 0x01, 0x01, 0x01, 0x81, 0x76])

        var minimal = try Script(bytes: [], maximumByteCount: 32)
        try minimal.appendMinimalPush([], maximumScriptByteCount: 32)
        try minimal.appendMinimalPush([1], maximumScriptByteCount: 32)
        try minimal.appendMinimalPush([16], maximumScriptByteCount: 32)
        try minimal.appendMinimalPush([0x81], maximumScriptByteCount: 32)
        try minimal.appendMinimalPush([17], maximumScriptByteCount: 32)
        #expect(minimal.bytes == [0x00, 0x51, 0x60, 0x4f, 0x01, 0x11])
    }

    @Test("Failed appends are transactional")
    func appendFailures() throws {
        var script = try Script(bytes: [Opcode.dup.rawValue], maximumByteCount: 1)
        let original = script
        #expect(throws: ScriptError.pushOpcodeRequiresData(.pushData1)) {
            try script.append(.pushData1, maximumScriptByteCount: 10)
        }
        #expect(script == original)
        #expect(throws: ScriptError.scriptTooLarge(actual: 3, maximum: 2)) {
            try script.appendPushData([0xaa], maximumScriptByteCount: 2)
        }
        #expect(script == original)
    }

    @Test("Parser preserves opcode form and pushed bytes")
    func parsing() throws {
        let bytes: [UInt8] = [
            0x01, 0xaa,
            0x4c, 0x02, 0xbb, 0xcc,
            0x4d, 0x03, 0x00, 1, 2, 3,
            0x4e, 0x01, 0x00, 0x00, 0x00, 0xdd,
            Opcode.checkSig.rawValue,
            0xff,
        ]
        let script = try Script(bytes: bytes, maximumByteCount: bytes.count)
        let operations = try script.operations(maximumPushDataByteCount: 3)
        #expect(operations == [
            .push(opcode: Opcode(rawValue: 1), data: [0xaa]),
            .push(opcode: .pushData1, data: [0xbb, 0xcc]),
            .push(opcode: .pushData2, data: [1, 2, 3]),
            .push(opcode: .pushData4, data: [0xdd]),
            .opcode(.checkSig),
            .opcode(Opcode(rawValue: 0xff)),
        ])
    }

    @Test("Every truncated push length and payload has a typed offset")
    func truncation() throws {
        let lengthCases: [([UInt8], ScriptError)] = [
            ([0x4c], .truncatedPushDataLength(offset: 0, expected: 1, remaining: 0)),
            ([0x4d], .truncatedPushDataLength(offset: 0, expected: 2, remaining: 0)),
            ([0x4d, 1], .truncatedPushDataLength(offset: 0, expected: 2, remaining: 1)),
            ([0x4e, 1, 0, 0], .truncatedPushDataLength(offset: 0, expected: 4, remaining: 3)),
        ]
        for (bytes, error) in lengthCases {
            let script = try Script(bytes: bytes, maximumByteCount: bytes.count)
            #expect(throws: error) {
                try script.operations(maximumPushDataByteCount: Int.max)
            }
        }

        let payloadCases: [([UInt8], ScriptError)] = [
            ([2, 0xaa], .truncatedPushData(offset: 0, expected: 2, remaining: 1)),
            ([0x4c, 2, 0xaa], .truncatedPushData(offset: 0, expected: 2, remaining: 1)),
            ([0x4d, 2, 0, 0xaa], .truncatedPushData(offset: 0, expected: 2, remaining: 1)),
            ([0x4e, 2, 0, 0, 0, 0xaa], .truncatedPushData(offset: 0, expected: 2, remaining: 1)),
        ]
        for (bytes, error) in payloadCases {
            let script = try Script(bytes: bytes, maximumByteCount: bytes.count)
            #expect(throws: error) {
                try script.operations(maximumPushDataByteCount: 2)
            }
        }
    }

    @Test("Push resource ceiling is independent from script size")
    func pushLimit() throws {
        let script = try Script(bytes: [0x02, 1, 2], maximumByteCount: 3)
        #expect(throws: ScriptError.invalidMaximumPushDataByteCount(-1)) {
            try script.operations(maximumPushDataByteCount: -1)
        }
        #expect(throws: ScriptError.pushDataTooLarge(actual: 2, maximum: 1)) {
            try script.operations(maximumPushDataByteCount: 1)
        }
    }

    @Test("Standard output classifiers require exact byte structure")
    func classifiers() throws {
        let hash = Array(0..<UInt8(20))
        let p2pkhBytes = [Opcode.dup.rawValue, Opcode.hash160.rawValue, 20]
            + hash
            + [Opcode.equalVerify.rawValue, Opcode.checkSig.rawValue]
        let p2pkh = try Script(bytes: p2pkhBytes, maximumByteCount: 25)
        #expect(p2pkh.isPayToPublicKeyHash)
        #expect(!p2pkh.isPayToScriptHash)
        #expect(p2pkh.publicKeyHash == hash)

        let p2sh = try Script(
            bytes: [Opcode.hash160.rawValue, 20] + hash + [Opcode.equal.rawValue],
            maximumByteCount: 23
        )
        #expect(p2sh.isPayToScriptHash)
        #expect(!p2sh.isPayToPublicKeyHash)
        #expect(p2sh.publicKeyHash == nil)

        let data = try Script(bytes: [0, Opcode.return.rawValue, 1, 0xaa], maximumByteCount: 4)
        #expect(data.isData)
        #expect(try data.isPushOnly(maximumPushDataByteCount: 1) == false)
    }
}
