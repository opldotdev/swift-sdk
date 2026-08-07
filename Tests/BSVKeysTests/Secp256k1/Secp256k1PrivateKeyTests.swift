import BSVCore
import BSVKeys
import Testing

@Suite("Secp256k1PrivateKey")
struct Secp256k1PrivateKeyTests {
    @Test("private scalar boundaries and exact byte counts")
    func validationBoundaries() throws {
        let order = try Hex.decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            maximumDecodedByteCount: 32
        )
        #expect(throws: Secp256k1KeyError.invalidPrivateKeyByteCount(31)) {
            try PrivateKey([UInt8](repeating: 1, count: 31))
        }
        #expect(throws: Secp256k1KeyError.invalidPrivateKeyByteCount(33)) {
            try PrivateKey([UInt8](repeating: 1, count: 33))
        }
        #expect(throws: Secp256k1KeyError.invalidPrivateKey) {
            try PrivateKey([UInt8](repeating: 0, count: 32))
        }
        #expect(throws: Secp256k1KeyError.invalidPrivateKey) {
            try PrivateKey(order)
        }
        #expect(throws: Secp256k1KeyError.invalidPrivateKey) {
            try PrivateKey([UInt8](repeating: 0xff, count: 32))
        }

        var maximum = order
        maximum[31] -= 1
        #expect(try PrivateKey(maximum).bytes == maximum)
    }

    @Test("leading zeroes and serialization are preserved exactly")
    func exactSerialization() throws {
        var scalar = [UInt8](repeating: 0, count: 32)
        scalar[30] = 0x01
        scalar[31] = 0x23

        let key = try PrivateKey(scalar)
        let reparsed = try PrivateKey(scalar)
        var otherScalar = scalar
        otherScalar[31] += 1
        let other = try PrivateKey(otherScalar)
        #expect(key.bytes == scalar)
        #expect(key == reparsed)
        #expect(key != other)
        #expect(Set([key, reparsed, other]).count == 2)
    }

    @Test("scalar one derives the SEC1 generator point")
    func generatorDerivation() throws {
        var scalar = [UInt8](repeating: 0, count: 32)
        scalar[31] = 1
        let key = try PrivateKey(scalar)

        #expect(
            Hex.encode(key.publicKey.compressedBytes)
                == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        #expect(
            Hex.encode(key.publicKey.uncompressedBytes)
                == "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
    }
}
