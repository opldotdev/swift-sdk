import BSVCore
import Testing

@Suite("Hex")
struct HexTests {
    @Test("lowercase encoding and mixed-case decoding")
    func knownCases() throws {
        #expect(Hex.encode([]) == "")
        #expect(Hex.encode([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]) == "00017f80feff")
        #expect(try Hex.decode("", maximumDecodedByteCount: 0) == [])
        #expect(
            try Hex.decode("00017F80fEfF", maximumDecodedByteCount: 6)
                == [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]
        )
    }

    @Test("invalid hex is indexed at every UTF-8 byte position")
    func invalidCharacterAtEveryPosition() {
        let valid = Array("00112233".utf8)
        for index in valid.indices {
            var invalid = valid
            invalid[index] = 103
            let text = String(decoding: invalid, as: UTF8.self)
            #expect(throws: TextEncodingError.invalidCharacter(index: index)) {
                try Hex.decode(text, maximumDecodedByteCount: 4)
            }
        }
        #expect(throws: TextEncodingError.invalidCharacter(index: 2)) {
            try Hex.decode("00é", maximumDecodedByteCount: 2)
        }
        #expect(throws: TextEncodingError.invalidCharacter(index: 0)) {
            try Hex.decode("g", maximumDecodedByteCount: 1)
        }
    }

    @Test("odd length and decoded-size policy")
    func lengthAndLimits() throws {
        #expect(throws: TextEncodingError.oddLength) {
            try Hex.decode("0", maximumDecodedByteCount: 1)
        }
        #expect(throws: TextEncodingError.invalidMaximumDecodedByteCount) {
            try Hex.decode("", maximumDecodedByteCount: -1)
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 2)) {
            try Hex.decode("001122", maximumDecodedByteCount: 2)
        }
        #expect(try Hex.decode("001122", maximumDecodedByteCount: 3) == [0, 0x11, 0x22])
        #expect(try Hex.decode("001122", maximumDecodedByteCount: 4) == [0, 0x11, 0x22])
    }

    @Test("deterministic round trips")
    func deterministicRoundTrips() throws {
        var state: UInt64 = 0x243f_6a88_85a3_08d3
        for length in 0...128 {
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0..<length {
                state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                bytes.append(UInt8(truncatingIfNeeded: state >> 24))
            }
            #expect(
                try Hex.decode(Hex.encode(bytes), maximumDecodedByteCount: length) == bytes
            )
        }
    }
}
