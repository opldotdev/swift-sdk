import BSVCore
import BSVCrypto
import BSVCompat
import BSVKeys
import Testing

@Suite("BitcoinSignedMessage")
struct BitcoinSignedMessageTests {
    private let privateKeyHex =
        "0000000000000000000000000000000000000000000000000000000000000001"

    @Test("canonical prefix and CompactSize message boundaries produce exact digests")
    func digestFramingAndBoundaries() throws {
        let prefix = Array("Bitcoin Signed Message:\n".utf8)
        #expect(prefix.count == 24)

        let cases: [([UInt8], [UInt8], String)] = [
            (
                [],
                [0x18] + prefix + [0x00],
                "80e795d4a4caadd7047af389d9f7f220562feb6196032e2131e10563352c4bcc"
            ),
            (
                [UInt8](repeating: 0x61, count: 252),
                [0x18] + prefix + [0xfc] + [UInt8](repeating: 0x61, count: 252),
                "b7b164ef991d52735c6bb888642ad7eb6b6939dc984a7fceff4376be041d142f"
            ),
            (
                [UInt8](repeating: 0x61, count: 253),
                [0x18] + prefix + [0xfd, 0xfd, 0x00]
                    + [UInt8](repeating: 0x61, count: 253),
                "df167ad249ff5837e6acada677118b2ecc6757ab4cdade39caead99ef0220230"
            ),
        ]

        for (message, independentlyFramedPreimage, expectedDigestHex) in cases {
            let digest = BitcoinSignedMessage.digest(message)
            #expect(digest == BSVHashing.sha256d(independentlyFramedPreimage))
            #expect(digest.bytes == (try decodeHex(expectedDigestHex)))
        }
    }

    @Test("compressed and uncompressed signatures recover and round-trip through Base64")
    func signingRecoveryAndBase64RoundTrip() throws {
        let key = try PrivateKey(decodeHex(privateKeyHex))
        let message: [UInt8] = [0x00, 0xff, 0x42, 0x00, 0x80]

        let compressed = try BitcoinSignedMessage.sign(message, using: key)
        let uncompressed = try BitcoinSignedMessage.sign(
            message,
            using: key,
            compressed: false
        )

        #expect(compressed.bytes.count == BitcoinMessageSignature.byteCount)
        #expect((31...34).contains(compressed.bytes[0]))
        #expect(compressed.usesCompressedPublicKey)
        #expect((27...30).contains(uncompressed.bytes[0]))
        #expect(!uncompressed.usesCompressedPublicKey)
        #expect(compressed.recoveryID == uncompressed.recoveryID)
        #expect(compressed.bytes.dropFirst() == uncompressed.bytes.dropFirst())
        #expect(try compressed.recoverPublicKey(message: message) == key.publicKey)
        #expect(try uncompressed.recoverPublicKey(message: message) == key.publicKey)

        let parsed = try BitcoinMessageSignature(base64Encoded: compressed.base64Encoded)
        #expect(parsed == compressed)
        #expect(parsed.bytes == compressed.bytes)
        #expect(parsed.base64Encoded == compressed.base64Encoded)
        #expect(Set([compressed, parsed, uncompressed]).count == 2)
    }

    @Test("verification respects mainnet, testnet, and signature key serialization")
    func addressVerification() throws {
        let key = try PrivateKey(decodeHex(privateKeyHex))
        let message = Array("network-aware verification".utf8)
        let compressed = try BitcoinSignedMessage.sign(message, using: key)
        let uncompressed = try BitcoinSignedMessage.sign(
            message,
            using: key,
            compressed: false
        )

        for network in [BitcoinNetwork.mainnet, .testnet] {
            let compressedAddress = Address(
                publicKey: key.publicKey,
                network: network,
                compressed: true
            )
            let uncompressedAddress = Address(
                publicKey: key.publicKey,
                network: network,
                compressed: false
            )

            #expect(try compressed.verifies(message: message, address: compressedAddress))
            #expect(try uncompressed.verifies(message: message, address: uncompressedAddress))
            #expect(try !compressed.verifies(message: message, address: uncompressedAddress))
            #expect(try !uncompressed.verifies(message: message, address: compressedAddress))
        }
    }

    @Test("wrong messages and addresses return false")
    func verificationMismatches() throws {
        let key = try PrivateKey(decodeHex(privateKeyHex))
        let otherKey = try PrivateKey(
            decodeHex("0000000000000000000000000000000000000000000000000000000000000002")
        )
        let message = Array("authentic message".utf8)
        let signature = try BitcoinSignedMessage.sign(message, using: key)
        let address = Address(publicKey: key.publicKey, network: .mainnet)
        let otherAddress = Address(publicKey: otherKey.publicKey, network: .mainnet)

        #expect(try signature.verifies(message: message, address: address))
        #expect(try !signature.verifies(message: Array("altered message".utf8), address: address))
        #expect(try !signature.verifies(message: message, address: otherAddress))
    }

    @Test("string APIs preserve UTF-8, embedded NULs, and normalization distinctions")
    func exactStringBytes() throws {
        let key = try PrivateKey(decodeHex(privateKeyHex))
        let composed = "caf\u{00e9} \u{0000} \u{8061}\u{4e2d}\u{672c}"
        let decomposed = "cafe\u{0301} \u{0000} \u{8061}\u{4e2d}\u{672c}"
        let address = Address(publicKey: key.publicKey, network: .testnet)

        let signature = try BitcoinSignedMessage.sign(composed, using: key)
        let decomposedSignature = try BitcoinSignedMessage.sign(decomposed, using: key)

        #expect(try BitcoinSignedMessage.verify(signature, message: composed, address: address))
        #expect(try !BitcoinSignedMessage.verify(signature, message: decomposed, address: address))
        #expect(signature != decomposedSignature)
        #expect(
            BitcoinSignedMessage.digest(Array(composed.utf8)).bytes
                == (try decodeHex(
                    "acbe7900cab9d279481ca7747e6dd1447a5ed7a5261493c940416791b884c323"
                ))
        )
    }

    @Test("all BSM header values parse and adjacent boundaries are rejected")
    func headerBoundaries() throws {
        let key = try PrivateKey(decodeHex(privateKeyHex))
        let compact = Array(
            try BitcoinSignedMessage.sign([], using: key).bytes.dropFirst()
        )

        for header in UInt8(27)...UInt8(34) {
            let signature = try BitcoinMessageSignature([header] + compact)
            let headerValue = Int(header) - 27
            #expect(signature.recoveryID == headerValue & 3)
            #expect(signature.usesCompressedPublicKey == (headerValue >= 4))
            #expect(signature.bytes == [header] + compact)
        }

        for header: UInt8 in [0, 26, 35, 255] {
            #expect(throws: BitcoinSignedMessageError.invalidHeader(header)) {
                try BitcoinMessageSignature([header] + compact)
            }
        }
    }

    @Test("wrong wire lengths and invalid compact scalars are typed errors")
    func malformedWireSignatures() throws {
        #expect(throws: BitcoinSignedMessageError.invalidByteCount(0)) {
            try BitcoinMessageSignature([])
        }
        #expect(throws: BitcoinSignedMessageError.invalidByteCount(64)) {
            try BitcoinMessageSignature([UInt8](repeating: 0, count: 64))
        }
        #expect(throws: BitcoinSignedMessageError.invalidByteCount(66)) {
            try BitcoinMessageSignature([UInt8](repeating: 0, count: 66))
        }

        let zero = [UInt8](repeating: 0, count: 32)
        let one = [UInt8](repeating: 0, count: 31) + [1]
        let order = try decodeHex(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        for compact in [zero + one, one + zero, order + one, one + order] {
            #expect(throws: BitcoinSignedMessageError.invalidCompactSignature) {
                try BitcoinMessageSignature([27] + compact)
            }
        }
    }

    @Test("strict standard-padded Base64 rejects malformed text")
    func malformedBase64() throws {
        let key = try PrivateKey(decodeHex(privateKeyHex))
        let canonical = try BitcoinSignedMessage.sign([], using: key).base64Encoded
        #expect(canonical.hasSuffix("="))

        let malformed = [
            String(canonical.dropLast()),
            canonical + "=",
            " " + canonical,
            canonical + "\n",
            String(canonical.dropLast(2)) + "-_",
            String(canonical.dropLast(2)) + "B=",
            Base64Encoding.encode([UInt8](repeating: 1, count: 66)),
        ]
        for text in malformed {
            #expect(throws: BitcoinSignedMessageError.invalidBase64Encoding) {
                try BitcoinMessageSignature(base64Encoded: text)
            }
        }
        #expect(throws: BitcoinSignedMessageError.invalidByteCount(0)) {
            try BitcoinMessageSignature(base64Encoded: "")
        }
    }

    @Test("mathematically unrecoverable signatures fail without trapping")
    func recoveryFailureIsTyped() throws {
        let compact = try decodeHex(
            "000000000000000000000000000000014551231950b75fc4402da1722fc9baee"
                + "0000000000000000000000000000000000000000000000000000000000000001"
        )
        let signature = try BitcoinMessageSignature([29] + compact)

        #expect(throws: BitcoinSignedMessageError.recoveryFailed) {
            try signature.recoverPublicKey(message: Array("safe failure".utf8))
        }
    }

    @Test("public values are Sendable")
    func sendableSurface() {
        requireSendable(BitcoinMessageSignature.self)
        requireSendable(BitcoinSignedMessageError.self)
    }

    private func decodeHex(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 256)
    }

    private func requireSendable<T: Sendable>(_: T.Type) {}
}
