import BSVCore
import BSVScript
import Testing

@Suite("Bitcoin Script JSON")
struct ScriptJSONTests {
    @Test("Empty and all-byte scripts round trip canonically")
    func canonicalRoundTrips() throws {
        let emptyLimits = try ScriptJSONLimits(
            maximumJSONByteCount: 2,
            maximumScriptByteCount: 0
        )
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let emptyJSON = Array("\"\"".utf8)
        #expect(try empty.jsonBytes(limits: emptyLimits) == emptyJSON)
        #expect(try Script(jsonBytes: emptyJSON, limits: emptyLimits) == empty)

        let allBytes = (UInt8.min...UInt8.max).map { $0 }
        let expectedHex = Hex.encode(allBytes)
        let expectedJSON = Array("\"\(expectedHex)\"".utf8)
        let allByteLimits = try ScriptJSONLimits(
            maximumJSONByteCount: expectedJSON.count,
            maximumScriptByteCount: allBytes.count
        )
        let script = try Script(bytes: allBytes, maximumByteCount: allBytes.count)

        #expect(try script.jsonBytes(limits: allByteLimits) == expectedJSON)
        #expect(try Script(jsonBytes: expectedJSON, limits: allByteLimits) == script)
    }

    @Test("Only RFC JSON whitespace may surround the string")
    func surroundingWhitespace() throws {
        let bytes = Array(" \t\r\n\"00ff\"\n\r\t ".utf8)
        let limits = try ScriptJSONLimits(
            maximumJSONByteCount: bytes.count,
            maximumScriptByteCount: 2
        )
        #expect(
            try Script(jsonBytes: bytes, limits: limits).bytes == [0x00, 0xff]
        )

        let nonJSONWhitespace = Array("\u{00a0}\"00\"".utf8)
        #expect(throws: ScriptError.invalidJSON) {
            try Script(jsonBytes: nonJSONWhitespace, limits: limits)
        }
    }

    @Test("JSON and script limits accept exact size and reject max plus one")
    func exactLimits() throws {
        let json = Array(#""0001""#.utf8)
        let exact = try ScriptJSONLimits(
            maximumJSONByteCount: json.count,
            maximumScriptByteCount: 2
        )
        let script = try Script(jsonBytes: json, limits: exact)
        #expect(try script.jsonBytes(limits: exact) == json)

        let shortJSON = try ScriptJSONLimits(
            maximumJSONByteCount: json.count - 1,
            maximumScriptByteCount: 2
        )
        #expect(throws: ScriptError.jsonTooLarge(actual: json.count, maximum: json.count - 1)) {
            try Script(jsonBytes: json, limits: shortJSON)
        }
        #expect(throws: ScriptError.jsonTooLarge(actual: json.count, maximum: json.count - 1)) {
            try script.jsonBytes(limits: shortJSON)
        }

        let shortScript = try ScriptJSONLimits(
            maximumJSONByteCount: json.count,
            maximumScriptByteCount: 1
        )
        #expect(throws: ScriptError.scriptTooLarge(actual: 2, maximum: 1)) {
            try Script(jsonBytes: json, limits: shortScript)
        }
        #expect(throws: ScriptError.scriptTooLarge(actual: 2, maximum: 1)) {
            try script.jsonBytes(limits: shortScript)
        }

        let zeroJSON = try ScriptJSONLimits(
            maximumJSONByteCount: 0,
            maximumScriptByteCount: 0
        )
        let empty = try Script(bytes: [], maximumByteCount: 0)
        #expect(throws: ScriptError.jsonTooLarge(actual: 2, maximum: 0)) {
            try Script(jsonBytes: Array(#""""#.utf8), limits: zeroJSON)
        }
        #expect(throws: ScriptError.jsonTooLarge(actual: 2, maximum: 0)) {
            try empty.jsonBytes(limits: zeroJSON)
        }
    }

    @Test("Negative limits are rejected independently")
    func negativeLimits() {
        #expect(throws: ScriptError.invalidMaximumJSONByteCount(-1)) {
            try ScriptJSONLimits(maximumJSONByteCount: -1, maximumScriptByteCount: 0)
        }
        #expect(throws: ScriptError.invalidMaximumScriptByteCount(-1)) {
            try ScriptJSONLimits(maximumJSONByteCount: 0, maximumScriptByteCount: -1)
        }
    }

    @Test("Noncanonical and non-string JSON fail closed")
    func malformedJSON() throws {
        let limits = try ScriptJSONLimits(
            maximumJSONByteCount: 64,
            maximumScriptByteCount: 16
        )
        let invalidJSONValues = [
            "",
            " \t\r\n ",
            "00",
            "null",
            "{}",
            "[]",
            #""\u0030\u0030""#,
            #""00" true"#,
            #""00"""#,
            "\"00\n\"",
            "\"00",
            "\"00\"\u{00a0}",
            #""AA""#,
            #""aA""#,
        ]
        for value in invalidJSONValues {
            #expect(throws: ScriptError.invalidJSON, "Accepted \(value)") {
                try Script(jsonBytes: Array(value.utf8), limits: limits)
            }
        }

        #expect(throws: ScriptError.invalidHex(.oddLength)) {
            try Script(jsonBytes: Array(#""0""#.utf8), limits: limits)
        }
        #expect(throws: ScriptError.invalidHex(.invalidCharacter(index: 1))) {
            try Script(jsonBytes: Array(#""0g""#.utf8), limits: limits)
        }
        #expect(throws: ScriptError.invalidJSON) {
            try Script(jsonBytes: [0x22, 0x80, 0x22], limits: limits)
        }

        let malformedButOversized = Array(#"{"not":"script"}"#.utf8)
        let tinyLimit = try ScriptJSONLimits(
            maximumJSONByteCount: malformedButOversized.count - 1,
            maximumScriptByteCount: 16
        )
        #expect(
            throws: ScriptError.jsonTooLarge(
                actual: malformedButOversized.count,
                maximum: malformedButOversized.count - 1
            )
        ) {
            try Script(jsonBytes: malformedButOversized, limits: tinyLimit)
        }
    }
}
