import BSVCore
import BSVCrypto
import Testing

@Suite("BSVHashing")
struct BSVHashingTests {
    @Test("SHA-2, double-SHA-256, and HASH160 known answers")
    func hashKnownAnswers() throws {
        let expectedSHA256 = try bytes(
            "e3b0c44298fc1c149afbf4c8996fb924"
                + "27ae41e4649b934ca495991b7852b855"
        )
        let expectedSHA256d = try bytes(
            "5df6e0e2761359d30a8275058e299fcc"
                + "0381534545f55cf43e41983f5d4c9456"
        )
        let expectedSHA512 = try bytes(
            "cf83e1357eefb8bdf1542850d66d8007"
                + "d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f"
                + "63b931bd47417a81a538327af927da3e"
        )
        let expectedHash160 = try bytes(
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        )
        #expect(BSVHashing.sha256([]).bytes == expectedSHA256)
        #expect(BSVHashing.sha256d([]).bytes == expectedSHA256d)
        #expect(BSVHashing.sha512([]).bytes == expectedSHA512)
        #expect(BSVHashing.hash160([]).bytes == expectedHash160)
    }

    @Test("RIPEMD-160 canonical and multi-block known answers")
    func ripemd160KnownAnswers() throws {
        let vectors = [
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "b0e20b6e3116640286ed3a87a5713079b21f5189"
            ),
            (
                "123456789012345678901234567890123456789012345678901234567890"
                    + "12345678901234567890",
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
            ),
        ]

        for (message, expected) in vectors {
            let expectedBytes = try bytes(expected)
            #expect(BSVHashing.ripemd160(Array(message.utf8)).bytes == expectedBytes)
        }

        let millionAExpected = try bytes("52783243c1697bdbe16d37f97f68f08325dc1528")
        #expect(
            BSVHashing.ripemd160(Array(repeating: UInt8(ascii: "a"), count: 1_000_000)).bytes
                == millionAExpected
        )
    }

    @Test("RFC 4231 HMAC known answers, including over-block keys")
    func hmacKnownAnswers() throws {
        let cases: [HMACCase] = [
            HMACCase(
                key: Array(repeating: 0x0b, count: 20),
                message: Array("Hi There".utf8),
                sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ),
            HMACCase(
                key: Array("Jefe".utf8),
                message: Array("what do ya want for nothing?".utf8),
                sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                    + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
            HMACCase(
                key: Array(repeating: 0xaa, count: 131),
                message: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8),
                sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                    + "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
            ),
        ]

        for testCase in cases {
            let expectedSHA256 = try bytes(testCase.sha256)
            let expectedSHA512 = try bytes(testCase.sha512)
            #expect(
                BSVHashing.hmacSHA256(testCase.message, key: testCase.key).bytes
                    == expectedSHA256
            )
            #expect(
                BSVHashing.hmacSHA512(testCase.message, key: testCase.key).bytes
                    == expectedSHA512
            )
        }

        let emptySHA256 = try bytes(
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        )
        let emptySHA512 = try bytes(
            "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673"
                + "0c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
        )
        #expect(BSVHashing.hmacSHA256([], key: []).bytes == emptySHA256)
        #expect(BSVHashing.hmacSHA512([], key: []).bytes == emptySHA512)
    }

    @Test("block boundaries and multiple blocks are deterministic and width-safe")
    func blockBoundaries() {
        for length in [63, 64, 65, 128, 129, 257] {
            let message = deterministicBytes(count: length)
            #expect(BSVHashing.sha256(message).bytes.count == 32)
            #expect(BSVHashing.ripemd160(message).bytes.count == 20)
            #expect(BSVHashing.sha256(message) == BSVHashing.sha256(message))
            #expect(BSVHashing.ripemd160(message) == BSVHashing.ripemd160(message))
        }
        for length in [127, 128, 129, 256, 257] {
            let message = deterministicBytes(count: length)
            #expect(BSVHashing.sha512(message).bytes.count == 64)
            #expect(BSVHashing.sha512(message) == BSVHashing.sha512(message))
        }
        for keyLength in [63, 64, 65, 127, 128, 129, 257] {
            let key = deterministicBytes(count: keyLength)
            let message = deterministicBytes(count: keyLength + 1)
            #expect(BSVHashing.hmacSHA256(message, key: key).bytes.count == 32)
            #expect(BSVHashing.hmacSHA512(message, key: key).bytes.count == 64)
        }
    }

    @Test("HMAC validation rejects message, key, tag, and all truncation tampering")
    func hmacValidation() {
        let message = deterministicBytes(count: 193)
        let key = deterministicBytes(count: 131)
        let otherMessage = message + [0]
        let otherKey = key + [0]
        let sha256 = BSVHashing.hmacSHA256(message, key: key).bytes
        let sha512 = BSVHashing.hmacSHA512(message, key: key).bytes

        #expect(BSVHashing.isValidHMACSHA256(sha256, authenticating: message, key: key))
        #expect(BSVHashing.isValidHMACSHA512(sha512, authenticating: message, key: key))
        #expect(!BSVHashing.isValidHMACSHA256(sha256, authenticating: otherMessage, key: key))
        #expect(!BSVHashing.isValidHMACSHA512(sha512, authenticating: otherMessage, key: key))
        #expect(!BSVHashing.isValidHMACSHA256(sha256, authenticating: message, key: otherKey))
        #expect(!BSVHashing.isValidHMACSHA512(sha512, authenticating: message, key: otherKey))

        for index in sha256.indices {
            var tampered = sha256
            tampered[index] ^= 1
            #expect(!BSVHashing.isValidHMACSHA256(tampered, authenticating: message, key: key))
        }
        for index in sha512.indices {
            var tampered = sha512
            tampered[index] ^= 1
            #expect(!BSVHashing.isValidHMACSHA512(tampered, authenticating: message, key: key))
        }
        for length in 0..<sha256.count {
            #expect(
                !BSVHashing.isValidHMACSHA256(
                    Array(sha256.prefix(length)),
                    authenticating: message,
                    key: key
                )
            )
        }
        for length in 0..<sha512.count {
            #expect(
                !BSVHashing.isValidHMACSHA512(
                    Array(sha512.prefix(length)),
                    authenticating: message,
                    key: key
                )
            )
        }
        #expect(!BSVHashing.isValidHMACSHA256(sha256 + [0], authenticating: message, key: key))
        #expect(!BSVHashing.isValidHMACSHA512(sha512 + [0], authenticating: message, key: key))
    }
}

private struct HMACCase {
    let key: [UInt8]
    let message: [UInt8]
    let sha256: String
    let sha512: String
}

private func bytes(_ hexadecimal: String) throws -> [UInt8] {
    try Hex.decode(
        hexadecimal,
        maximumDecodedByteCount: hexadecimal.utf8.count / 2
    )
}

private func deterministicBytes(count: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ 7) }
}
