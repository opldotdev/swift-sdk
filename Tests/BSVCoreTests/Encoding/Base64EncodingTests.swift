import BSVCore
import Testing

@Suite("Base64Encoding")
struct Base64EncodingTests {
    private let rfcCases: [([UInt8], String)] = [
        ([], ""),
        (Array("f".utf8), "Zg=="),
        (Array("fo".utf8), "Zm8="),
        (Array("foo".utf8), "Zm9v"),
        (Array("foob".utf8), "Zm9vYg=="),
        (Array("fooba".utf8), "Zm9vYmE="),
        (Array("foobar".utf8), "Zm9vYmFy"),
    ]

    @Test("RFC 4648 standard padded and raw cases")
    func standardCases() throws {
        for (bytes, padded) in rfcCases {
            let raw = String(padded.prefix { $0 != "=" })
            #expect(Base64Encoding.encode(bytes) == padded)
            #expect(
                Base64Encoding.encode(bytes, padding: .omitted) == raw
            )
            #expect(
                try Base64Encoding.decode(
                    padded,
                    maximumDecodedByteCount: bytes.count
                ) == bytes
            )
            #expect(
                try Base64Encoding.decode(
                    raw,
                    padding: .omitted,
                    maximumDecodedByteCount: bytes.count
                ) == bytes
            )
        }
    }

    @Test("standard and URL-safe alphabets remain distinct")
    func alphabets() throws {
        let bytes: [UInt8] = [0xfb, 0xff, 0xfe]
        #expect(Base64Encoding.encode(bytes) == "+//+")
        #expect(Base64Encoding.encode(bytes, alphabet: .urlSafe) == "-__-")
        #expect(
            try Base64Encoding.decode("+//+", maximumDecodedByteCount: 3) == bytes
        )
        #expect(
            try Base64Encoding.decode(
                "-__-",
                alphabet: .urlSafe,
                maximumDecodedByteCount: 3
            ) == bytes
        )
        #expect(throws: TextEncodingError.invalidCharacter(index: 0)) {
            try Base64Encoding.decode("-__-", maximumDecodedByteCount: 3)
        }
        #expect(throws: TextEncodingError.invalidCharacter(index: 0)) {
            try Base64Encoding.decode(
                "+//+",
                alphabet: .urlSafe,
                maximumDecodedByteCount: 3
            )
        }
    }

    @Test("padding policy and impossible lengths are typed")
    func invalidPaddingAndLengths() {
        for text in ["=", "==", "Zg", "Zg=", "Zg===", "=m9v", "Zm=v", "Zm9v=", "Zg==Zg=="] {
            #expect(throws: TextEncodingError.invalidPadding) {
                try Base64Encoding.decode(text, maximumDecodedByteCount: 16)
            }
        }
        for text in ["Zg==", "Zm8="] {
            #expect(throws: TextEncodingError.invalidPadding) {
                try Base64Encoding.decode(
                    text,
                    padding: .omitted,
                    maximumDecodedByteCount: 16
                )
            }
        }
        for text in ["A", "AAAAA"] {
            #expect(throws: TextEncodingError.invalidLength) {
                try Base64Encoding.decode(text, maximumDecodedByteCount: 16)
            }
            #expect(throws: TextEncodingError.invalidLength) {
                try Base64Encoding.decode(
                    text,
                    padding: .omitted,
                    maximumDecodedByteCount: 16
                )
            }
        }
    }

    @Test("non-zero discarded bits are noncanonical")
    func discardedBits() {
        for text in ["Zh==", "Zm9="] {
            #expect(throws: TextEncodingError.nonCanonicalEncoding) {
                try Base64Encoding.decode(text, maximumDecodedByteCount: 3)
            }
        }
        for text in ["Zh", "Zm9"] {
            #expect(throws: TextEncodingError.nonCanonicalEncoding) {
                try Base64Encoding.decode(
                    text,
                    padding: .omitted,
                    maximumDecodedByteCount: 3
                )
            }
        }
    }

    @Test("unknown characters and whitespace are never ignored")
    func invalidCharacters() {
        for (text, index) in [(" Zm9v", 0), ("Zm 9v", 2), ("Zm9v\n", 4), ("Zmé9v", 2)] {
            #expect(throws: TextEncodingError.invalidCharacter(index: index)) {
                try Base64Encoding.decode(text, maximumDecodedByteCount: 16)
            }
        }
    }

    @Test("decoded-size limits reject before allocation")
    func limits() throws {
        #expect(throws: TextEncodingError.invalidMaximumDecodedByteCount) {
            try Base64Encoding.decode("", maximumDecodedByteCount: -1)
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 2)) {
            try Base64Encoding.decode("Zm9v", maximumDecodedByteCount: 2)
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 0)) {
            try Base64Encoding.decode("Zg==", maximumDecodedByteCount: 0)
        }
        #expect(try Base64Encoding.decode("Zm9v", maximumDecodedByteCount: 3) == Array("foo".utf8))
        #expect(try Base64Encoding.decode("Zm9v", maximumDecodedByteCount: 4) == Array("foo".utf8))
    }

    @Test("deterministic round trips across every policy")
    func deterministicRoundTrips() throws {
        var state: UInt64 = 0x1319_8a2e_0370_7344
        for length in 0...128 {
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0..<length {
                state = state &* 2_862_933_555_777_941_757 &+ 3_037_000_493
                bytes.append(UInt8(truncatingIfNeeded: state >> 31))
            }
            for alphabet in [Base64Alphabet.standard, .urlSafe] {
                for padding in [Base64Padding.included, .omitted] {
                    let text = Base64Encoding.encode(
                        bytes,
                        alphabet: alphabet,
                        padding: padding
                    )
                    #expect(
                        try Base64Encoding.decode(
                            text,
                            alphabet: alphabet,
                            padding: padding,
                            maximumDecodedByteCount: length
                        ) == bytes
                    )
                }
            }
        }
    }
}
