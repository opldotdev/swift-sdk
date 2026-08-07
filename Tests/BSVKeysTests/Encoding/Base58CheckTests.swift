import BSVCore
import BSVKeys
import Testing

@Suite("Bitcoin Base58Check")
struct Base58CheckTests {
    @Test("known cases include empty payload, leading zeros, and arbitrary bytes")
    func knownCases() throws {
        let cases: [([UInt8], String)] = [
            ([], "3QJmnh"),
            ([20], "3MNQE1X"),
            ([20, 0x20], "B2Kr6dBE"),
            ([20, 0x61, 0x62, 0x63], "4QiVtDjUdeq"),
            ([0] + [UInt8](repeating: 0, count: 20), "1111111111111111111114oLvT2"),
            ([0xff, 0x00, 0x80, 0x01, 0xfe], "4FG1dC3NRXyjU"),
        ]

        for (payload, text) in cases {
            #expect(Base58Check.encode(payload) == text)
            #expect(
                try Base58Check.decode(
                    text,
                    maximumPayloadByteCount: payload.count
                ) == payload
            )
        }
    }

    @Test("payload limits cover minus one, exact, plus one, and invalid bounds")
    func payloadLimits() throws {
        let payload: [UInt8] = [0x14, 0x61, 0x62, 0x63]
        let text = Base58Check.encode(payload)

        #expect(
            throws: Base58CheckError.payloadSizeLimitExceeded(
                maximum: payload.count - 1
            )
        ) {
            try Base58Check.decode(
                text,
                maximumPayloadByteCount: payload.count - 1
            )
        }
        #expect(
            try Base58Check.decode(
                text,
                maximumPayloadByteCount: payload.count
            ) == payload
        )
        #expect(
            try Base58Check.decode(
                text,
                maximumPayloadByteCount: payload.count + 1
            ) == payload
        )
        #expect(throws: Base58CheckError.invalidMaximumPayloadByteCount) {
            try Base58Check.decode(text, maximumPayloadByteCount: -1)
        }
        #expect(throws: Base58CheckError.invalidMaximumPayloadByteCount) {
            try Base58Check.decode(text, maximumPayloadByteCount: Int.max - 3)
        }
        #expect(
            try Base58Check.decode(
                text,
                maximumPayloadByteCount: Int.max - 4
            ) == payload
        )
    }

    @Test("empty text and every incomplete checksum report missing checksum")
    func missingChecksum() {
        let incompleteChecksums: [[UInt8]] = [[], [0], [1, 2], [1, 2, 3]]
        for bytes in incompleteChecksums {
            let text = Base58.encode(bytes)
            #expect(throws: Base58CheckError.missingChecksum) {
                try Base58Check.decode(text, maximumPayloadByteCount: 16)
            }
        }
    }

    @Test("every checksum byte participates in verification")
    func checksumByteFlips() throws {
        let text = Base58Check.encode([0x14, 0x61, 0x62, 0x63])
        let checked = try Base58.decode(text, maximumDecodedByteCount: 8)

        for checksumOffset in 0..<4 {
            var corrupted = checked
            corrupted[corrupted.count - 4 + checksumOffset] ^= 1
            #expect(throws: Base58CheckError.checksumMismatch) {
                try Base58Check.decode(
                    Base58.encode(corrupted),
                    maximumPayloadByteCount: 4
                )
            }
        }
    }

    @Test("raw Base58 failures retain their exact UTF-8 byte offset")
    func wrappedInvalidAlphabetOffset() {
        #expect(
            throws: Base58CheckError.invalidEncoding(
                .invalidCharacter(index: 2)
            )
        ) {
            try Base58Check.decode("12é3", maximumPayloadByteCount: 8)
        }
    }

    @Test("deterministic round trips")
    func deterministicRoundTrips() throws {
        var state: UInt64 = 0x243f_6a88_85a3_08d3
        for length in 0...128 {
            var payload: [UInt8] = []
            payload.reserveCapacity(length)
            for _ in 0..<length {
                state = state &* 6_364_136_223_846_793_005 &+ 1
                payload.append(UInt8(truncatingIfNeeded: state >> 23))
            }
            if length.isMultiple(of: 9), !payload.isEmpty {
                payload[0] = 0
            }

            #expect(
                try Base58Check.decode(
                    Base58Check.encode(payload),
                    maximumPayloadByteCount: length
                ) == payload
            )
        }
    }
}
