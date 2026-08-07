import BSVCore
import BSVCrypto
import BSVKeys
import Testing

@Suite("Legacy P2PKH address")
struct LegacyAddressTests {
    @Test("round trips exact hashes on both networks")
    func deterministicRoundTrips() throws {
        let hash = try Hash160((0..<20).map { UInt8($0) })

        for network in [BitcoinNetwork.mainnet, .testnet] {
            let original = LegacyAddress(publicKeyHash: hash, network: network)
            let text = original.description
            let decoded = try LegacyAddress(text)

            #expect(decoded == original)
            #expect(decoded.description == text)
            #expect(decoded.publicKeyHash.bytes == hash.bytes)
            #expect(decoded.network == network)
        }
    }

    @Test("uses the selected canonical public-key serialization")
    func publicKeyCompressionChoice() throws {
        let privateKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [0x01])
        let publicKey = privateKey.publicKey
        let compressed = LegacyAddress(
            publicKey: publicKey,
            network: .mainnet,
            compressed: true
        )
        let uncompressed = LegacyAddress(
            publicKey: publicKey,
            network: .mainnet,
            compressed: false
        )

        #expect(
            compressed.publicKeyHash
                == BSVHashing.hash160(publicKey.compressedBytes)
        )
        #expect(
            uncompressed.publicKeyHash
                == BSVHashing.hash160(publicKey.uncompressedBytes)
        )
        #expect(compressed.description == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        #expect(uncompressed.description == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
    }

    @Test("preserves decoding causes and enforces exact payload bounds")
    func decodingPolicy() {
        #expect(
            throws: KeyFormatError.invalidEncoding(
                .invalidEncoding(.invalidCharacter(index: 0))
            )
        ) {
            try LegacyAddress("O")
        }
        #expect(throws: KeyFormatError.invalidPayloadByteCount(20)) {
            try LegacyAddress(Base58Check.encode([0x00] + [UInt8](repeating: 1, count: 19)))
        }
        #expect(
            throws: KeyFormatError.invalidEncoding(
                .payloadSizeLimitExceeded(maximum: 21)
            )
        ) {
            try LegacyAddress(Base58Check.encode([0x00] + [UInt8](repeating: 1, count: 21)))
        }
        #expect(throws: KeyFormatError.unsupportedVersion(0x05)) {
            try LegacyAddress(Base58Check.encode([0x05] + [UInt8](repeating: 1, count: 20)))
        }
        #expect(throws: KeyFormatError.invalidEncoding(.checksumMismatch)) {
            try LegacyAddress("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gY")
        }
    }
}
