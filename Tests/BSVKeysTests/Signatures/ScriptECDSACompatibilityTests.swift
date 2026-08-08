import BSVCore
import BSVKeys
import Testing

@Suite("Bitcoin Script ECDSA compatibility")
struct ScriptECDSACompatibilityTests {
    @Test("permissive BER normalizes unsigned padding and declared trailing bytes")
    func permissiveBER() throws {
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        let digest = try Hash256(Array(repeating: 0x42, count: 32))
        let signature = try key.sign(digest: digest)
        let der = signature.derBytes

        let rCount = Int(der[3])
        let sMarker = 4 + rCount
        let sCount = Int(der[sMarker + 1])
        let r = Array(der[4..<(4 + rCount)])
        let s = Array(der[(sMarker + 2)..<(sMarker + 2 + sCount)])
        let padded = [UInt8(0x30), UInt8(5 + r.count + s.count)]
            + [0x02, UInt8(r.count + 1), 0x00] + r
            + [0x02, UInt8(s.count)] + s
        let withTrailingBytes = padded + [0xde, 0xad]

        let parsed = try ECDSASignature(
            scriptBytes: withTrailingBytes,
            strict: false
        )
        #expect(parsed.compactBytes == signature.compactBytes)
        #expect(throws: ECDSASignatureError.invalidDEREncoding) {
            try ECDSASignature(scriptBytes: withTrailingBytes, strict: true)
        }
    }

    @Test("interpreter verification accepts high-S without changing public policy")
    func highSCompatibility() throws {
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        let digest = try Hash256(Array(repeating: 0x24, count: 32))
        let low = try key.sign(digest: digest)
        let highCompact = Array(low.compactBytes[..<32])
            + subtract(Array(low.compactBytes[32..<64]), from: curveOrder)
        let high = try ECDSASignature(compactBytes: highCompact)

        #expect(low.isLowS)
        #expect(!high.isLowS)
        #expect(!key.publicKey.verify(high, digest: digest))
        #expect(high.verifiesInScript(publicKey: key.publicKey, digest: digest))
    }

    private let curveOrder: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    private func subtract(_ value: [UInt8], from minuend: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var difference = Int(minuend[index]) - Int(value[index]) - borrow
            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(difference)
        }
        return result
    }
}
