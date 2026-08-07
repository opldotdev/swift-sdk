import BSVCore
import Testing

@Suite("CompactSize")
struct CompactSizeTests {
    private let canonicalCases: [(UInt64, [UInt8])] = [
        (0, [0x00]),
        (252, [0xfc]),
        (253, [0xfd, 0xfd, 0x00]),
        (65_535, [0xfd, 0xff, 0xff]),
        (65_536, [0xfe, 0x00, 0x00, 0x01, 0x00]),
        (UInt64(UInt32.max), [0xfe, 0xff, 0xff, 0xff, 0xff]),
        (UInt64(UInt32.max) + 1, [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        (UInt64.max, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    ]

    @Test("Boundary values have canonical images and lengths")
    func canonicalBoundaries() throws {
        for (value, image) in canonicalCases {
            #expect(CompactSize.encodedLength(of: value) == image.count)
            #expect(CompactSize.encode(value) == image)
            let decoded = try CompactSize.decode(image)
            #expect(decoded.value == value)
            #expect(decoded.bytesConsumed == image.count)
            #expect(decoded.isCanonical)
        }
    }

    @Test("Every nonminimal prefix is rejected or explicitly reported")
    func nonminimalPrefixes() throws {
        let cases: [(UInt64, [UInt8])] = [
            (0, [0xfd, 0x00, 0x00]),
            (252, [0xfd, 0xfc, 0x00]),
            (0, [0xfe, 0x00, 0x00, 0x00, 0x00]),
            (65_535, [0xfe, 0xff, 0xff, 0x00, 0x00]),
            (0, [0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (UInt64(UInt32.max), [0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
        ]

        for (value, image) in cases {
            #expect(throws: BinaryDecodingError.nonCanonicalCompactSize) {
                try CompactSize.decode(image)
            }
            let decoded = try CompactSize.decode(image, canonicality: .permissive)
            #expect(decoded.value == value)
            #expect(decoded.bytesConsumed == image.count)
            #expect(!decoded.isCanonical)
        }
    }

    @Test("Truncation at every prefix/body boundary is typed")
    func everyTruncationBoundary() {
        #expect(throws: BinaryDecodingError.truncatedInput(expected: 1, remaining: 0)) {
            try CompactSize.decode([])
        }

        let cases: [(prefix: UInt8, width: Int)] = [
            (0xfd, 2),
            (0xfe, 4),
            (0xff, 8),
        ]
        for testCase in cases {
            for supplied in 0..<testCase.width {
                let image = [testCase.prefix] + Array(repeating: UInt8(0), count: supplied)
                #expect(
                    throws: BinaryDecodingError.truncatedInput(
                        expected: testCase.width,
                        remaining: supplied
                    )
                ) {
                    try CompactSize.decode(image)
                }
            }
        }
    }

    @Test("Full-input decoding rejects trailing bytes")
    func trailingBytes() {
        #expect(throws: BinaryDecodingError.trailingBytes(2)) {
            try CompactSize.decode([0xfc, 0xaa, 0xbb])
        }
        #expect(throws: BinaryDecodingError.trailingBytes(1)) {
            try CompactSize.decodeVarBytes([0x01, 0xaa, 0xbb], maximumLength: 1)
        }
    }

    @Test("Length-prefixed bytes encode and decode including empty")
    func varBytesRoundTrips() throws {
        let cases: [[UInt8]] = [
            [],
            [0xaa],
            Array(0...255),
        ]
        for value in cases {
            let encoded = CompactSize.encodeVarBytes(value)
            let decoded = try CompactSize.decodeVarBytes(
                encoded,
                maximumLength: UInt64(value.count)
            )
            #expect(decoded.bytes == value)
            #expect(decoded.bytesConsumed == encoded.count)
            #expect(decoded.isCanonical)
        }
        #expect(CompactSize.encodeVarBytes([]) == [0x00])
    }

    @Test("VarBytes checks maximum, Swift representation, and remaining bytes")
    func varBytesBounds() {
        #expect(
            throws: BinaryDecodingError.lengthExceedsLimit(length: 2, maximum: 1)
        ) {
            try CompactSize.decodeVarBytes([0x02, 0xaa, 0xbb], maximumLength: 1)
        }
        #expect(
            throws: BinaryDecodingError.truncatedInput(expected: 2, remaining: 1)
        ) {
            try CompactSize.decodeVarBytes([0x02, 0xaa], maximumLength: 2)
        }
        #expect(
            throws: BinaryDecodingError.lengthNotRepresentable(UInt64.max)
        ) {
            try CompactSize.decodeVarBytes(
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                maximumLength: UInt64.max
            )
        }
    }

    @Test("Permissive VarBytes preserves prefix canonicality")
    func permissiveVarBytes() throws {
        let image: [UInt8] = [0xfd, 0x01, 0x00, 0xaa]
        #expect(throws: BinaryDecodingError.nonCanonicalCompactSize) {
            try CompactSize.decodeVarBytes(image, maximumLength: 1)
        }
        let decoded = try CompactSize.decodeVarBytes(
            image,
            maximumLength: 1,
            canonicality: .permissive
        )
        #expect(decoded.bytes == [0xaa])
        #expect(decoded.bytesConsumed == 4)
        #expect(!decoded.isCanonical)
    }

    @Test("Cursor CompactSize and VarBytes failures are transactional")
    func cursorFailuresAreTransactional() throws {
        var truncated = ByteCursor([0xaa, 0xfe, 1, 2, 3])
        _ = try truncated.read(count: 1)
        #expect(throws: BinaryDecodingError.truncatedInput(expected: 4, remaining: 3)) {
            try truncated.readCompactSize(canonicality: .required)
        }
        #expect(truncated.position == 1)

        var noncanonical = ByteCursor([0xfd, 0xfc, 0x00])
        #expect(throws: BinaryDecodingError.nonCanonicalCompactSize) {
            try noncanonical.readCompactSize(canonicality: .required)
        }
        #expect(noncanonical.position == 0)

        var overLimit = ByteCursor([0x02, 0xaa, 0xbb])
        #expect(throws: BinaryDecodingError.lengthExceedsLimit(length: 2, maximum: 1)) {
            try overLimit.readVarBytes(maximumLength: 1, canonicality: .required)
        }
        #expect(overLimit.position == 0)

        var unrepresentable = ByteCursor([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        #expect(throws: BinaryDecodingError.lengthNotRepresentable(UInt64.max)) {
            try unrepresentable.readVarBytes(
                maximumLength: UInt64.max,
                canonicality: .required
            )
        }
        #expect(unrepresentable.position == 0)
    }

    @Test("Writer CompactSize and VarBytes round trip through the cursor")
    func packageWriterParserRoundTrips() throws {
        var writer = ByteWriter()
        for (value, _) in canonicalCases {
            writer.writeCompactSize(value)
        }
        writer.writeVarBytes([1, 2, 3])

        var cursor = ByteCursor(writer.bytes)
        for (value, image) in canonicalCases {
            let decoded = try cursor.readCompactSize(canonicality: .required)
            #expect(decoded.value == value)
            #expect(decoded.bytesConsumed == image.count)
            #expect(decoded.isCanonical)
        }
        let decodedBytes = try cursor.readVarBytes(
            maximumLength: 3,
            canonicality: .required
        )
        #expect(decodedBytes.bytes == [1, 2, 3])
        #expect(decodedBytes.bytesConsumed == 4)
        #expect(decodedBytes.isCanonical)
        try cursor.requireFinished()
    }

    @Test("Independent deterministic values round trip")
    func deterministicPropertyRoundTrips() throws {
        var state: UInt64 = 0x6a09_e667_f3bc_c909
        for _ in 0..<512 {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            let image = CompactSize.encode(state)
            let decoded = try CompactSize.decode(image)
            #expect(decoded.value == state)
            #expect(decoded.bytesConsumed == image.count)
            #expect(decoded.isCanonical)
        }
    }
}
