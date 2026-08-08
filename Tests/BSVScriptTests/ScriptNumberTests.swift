import BSVScript
import Testing

@Suite("Bitcoin Script numbers")
struct ScriptNumberTests {
    private let canonicalCases: [(Int64, [UInt8])] = [
        (0, []),
        (1, [0x01]),
        (-1, [0x81]),
        (127, [0x7f]),
        (-127, [0xff]),
        (128, [0x80, 0x00]),
        (-128, [0x80, 0x80]),
        (129, [0x81, 0x00]),
        (-129, [0x81, 0x80]),
        (256, [0x00, 0x01]),
        (-256, [0x00, 0x81]),
        (32_767, [0xff, 0x7f]),
        (-32_767, [0xff, 0xff]),
        (32_768, [0x00, 0x80, 0x00]),
        (-32_768, [0x00, 0x80, 0x80]),
        (2_147_483_647, [0xff, 0xff, 0xff, 0x7f]),
        (-2_147_483_647, [0xff, 0xff, 0xff, 0xff]),
        (Int64.max, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
        (-Int64.max, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        (Int64.min, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80]),
    ]

    @Test("Canonical signed-magnitude encodings round trip")
    func canonicalRoundTrips() throws {
        for (integer, bytes) in canonicalCases {
            let value = ScriptNumber(integer)
            #expect(try value.serialized(maximumByteCount: 9) == bytes)
            let decoded = try ScriptNumber(
                encoded: bytes,
                maximumByteCount: 9,
                requireMinimal: true
            )
            #expect(decoded == value)
            #expect(decoded.int64Clamped() == integer)
            #expect(ScriptNumber.isMinimallyEncoded(bytes))
        }
    }

    @Test("Minimality rejects redundant forms and every negative zero")
    func minimality() {
        let nonminimal: [[UInt8]] = [
            [0x00],
            [0x80],
            [0x01, 0x00],
            [0x01, 0x80],
            [0x7f, 0x00],
            [0x80, 0x00, 0x00],
            [0x80, 0x00, 0x80],
        ]
        for bytes in nonminimal {
            #expect(!ScriptNumber.isMinimallyEncoded(bytes))
            #expect(throws: ScriptNumberError.nonMinimalEncoding) {
                try ScriptNumber(
                    encoded: bytes,
                    maximumByteCount: bytes.count,
                    requireMinimal: true
                )
            }
        }
    }

    @Test("Permissive decoding preserves numeric value but canonicalizes output")
    func permissiveDecoding() throws {
        let cases: [([UInt8], [UInt8], Int64)] = [
            ([0x00], [], 0),
            ([0x80], [], 0),
            ([0x01, 0x00], [0x01], 1),
            ([0x01, 0x80], [0x81], -1),
            ([0x80, 0x00, 0x00], [0x80, 0x00], 128),
            ([0x80, 0x00, 0x80], [0x80, 0x80], -128),
        ]

        for (input, canonical, integer) in cases {
            let value = try ScriptNumber(
                encoded: input,
                maximumByteCount: input.count,
                requireMinimal: false
            )
            #expect(value.int64Clamped() == integer)
            #expect(try value.serialized(maximumByteCount: canonical.count) == canonical)
            #expect(ScriptNumber.minimallyEncoded(input) == canonical)
        }
    }

    @Test("Length limits cover parsing and sign-extension serialization")
    func lengthLimits() throws {
        #expect(throws: ScriptNumberError.invalidMaximumByteCount(-1)) {
            try ScriptNumber(encoded: [], maximumByteCount: -1)
        }
        #expect(
            throws: ScriptNumberError.numberTooLarge(actual: 5, maximum: 4)
        ) {
            try ScriptNumber(
                encoded: [0, 0, 0, 0x80, 0],
                maximumByteCount: ScriptNumber.beforeGenesisMaximumByteCount
            )
        }

        let needsSignExtension = ScriptNumber(128)
        #expect(
            throws: ScriptNumberError.numberTooLarge(actual: 2, maximum: 1)
        ) {
            try needsSignExtension.serialized(maximumByteCount: 1)
        }
        #expect(try needsSignExtension.serialized(maximumByteCount: 2) == [0x80, 0])
    }

    @Test("Native conversions clamp instead of truncating")
    func clamping() throws {
        let positiveHuge = try ScriptNumber(
            encoded: [0, 0, 0, 0, 0, 0, 0, 0, 1],
            maximumByteCount: 9
        )
        let negativeHuge = try ScriptNumber(
            encoded: [0, 0, 0, 0, 0, 0, 0, 0, 0x81],
            maximumByteCount: 9
        )
        #expect(positiveHuge.int64Clamped() == Int64.max)
        #expect(negativeHuge.int64Clamped() == Int64.min)
        #expect(positiveHuge.int32Clamped() == Int32.max)
        #expect(negativeHuge.int32Clamped() == Int32.min)
        #expect(ScriptNumber(Int64(Int32.max) + 1).int32Clamped() == Int32.max)
        #expect(ScriptNumber(Int64(Int32.min) - 1).int32Clamped() == Int32.min)
    }

    @Test("Serialization is pure")
    func serializationDoesNotMutate() throws {
        let value = ScriptNumber(-32_768)
        let first = try value.serialized(maximumByteCount: 3)
        let second = try value.serialized(maximumByteCount: 3)
        #expect(first == [0x00, 0x80, 0x80])
        #expect(second == first)
        #expect(value.int64Clamped() == -32_768)
    }
}
