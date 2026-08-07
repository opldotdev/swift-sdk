import BSVCore
import Testing

@Suite("Bitcoin Base58")
struct Base58Tests {
    @Test("empty, zero, leading zeros, and large carries")
    func knownCases() throws {
        let cases: [([UInt8], String)] = [
            ([], ""),
            ([0], "1"),
            ([0, 0, 0], "111"),
            ([0, 1], "12"),
            ([0x61], "2g"),
            ([0x62, 0x62, 0x62], "a3gV"),
            (Array("simply a long string".utf8), "2cFupjhnEsSn59qHXstmK2ffpLv2"),
            (
                [0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60, 0x92, 0x58,
                 0x86, 0xb6, 0x7d, 0x06, 0x52, 0x99, 0x92, 0x59, 0x15, 0xae,
                 0xb1, 0x72, 0xc0, 0x66, 0x47],
                "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"
            ),
        ]
        for (bytes, text) in cases {
            #expect(Base58.encode(bytes) == text)
            #expect(
                try Base58.decode(text, maximumDecodedByteCount: bytes.count) == bytes
            )
        }
    }

    @Test("every forbidden alphabet byte and non-ASCII input is indexed")
    func forbiddenCharacters() {
        let forbidden = Array("0OIl !@#$%^&*()-_=+~`\t\r\n".utf8)
        for byte in forbidden {
            let text = String(decoding: [50, byte, 50], as: UTF8.self)
            #expect(throws: TextEncodingError.invalidCharacter(index: 1)) {
                try Base58.decode(text, maximumDecodedByteCount: 8)
            }
        }
        #expect(throws: TextEncodingError.invalidCharacter(index: 1)) {
            try Base58.decode("2é2", maximumDecodedByteCount: 8)
        }
        #expect(throws: TextEncodingError.invalidCharacter(index: 0)) {
            try Base58.decode("🙂2", maximumDecodedByteCount: 8)
        }
    }

    @Test("decoded-size limits include leading-zero and impossible-length fast paths")
    func limits() throws {
        #expect(throws: TextEncodingError.invalidMaximumDecodedByteCount) {
            try Base58.decode("", maximumDecodedByteCount: -1)
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 2)) {
            try Base58.decode("a3gV", maximumDecodedByteCount: 2)
        }
        #expect(try Base58.decode("a3gV", maximumDecodedByteCount: 3) == [0x62, 0x62, 0x62])
        #expect(try Base58.decode("a3gV", maximumDecodedByteCount: 4) == [0x62, 0x62, 0x62])
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 2)) {
            try Base58.decode("111", maximumDecodedByteCount: 2)
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 1)) {
            try Base58.decode(String(repeating: "z", count: 100), maximumDecodedByteCount: 1)
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 1)) {
            try Base58.decode("zz", maximumDecodedByteCount: 1)
        }
        #expect(try Base58.decode("2", maximumDecodedByteCount: .max) == [1])
    }

    @Test("deterministic round trips")
    func deterministicRoundTrips() throws {
        var state: UInt64 = 0xa409_3822_299f_31d0
        for length in 0...96 {
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0..<length {
                state = state &* 3_202_034_522_624_059_733 &+ 1
                bytes.append(UInt8(truncatingIfNeeded: state >> 19))
            }
            if length.isMultiple(of: 7), !bytes.isEmpty {
                bytes[0] = 0
            }
            #expect(
                try Base58.decode(
                    Base58.encode(bytes),
                    maximumDecodedByteCount: length
                ) == bytes
            )
        }
    }

    @Test("conversion workspace ratio boundaries round trip")
    func capacityFormulaBoundaries() throws {
        for length in [99, 100, 101, 732, 733, 734, 999, 1_000, 1_001] {
            let bytes = (0..<length).map { index in
                UInt8(truncatingIfNeeded: index &* 73 &+ 19)
            }
            let text = Base58.encode(bytes)
            #expect(
                try Base58.decode(text, maximumDecodedByteCount: length) == bytes
            )
        }
    }
}
