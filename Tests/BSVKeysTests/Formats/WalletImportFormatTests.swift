import BSVCore
import BSVKeys
import Testing

@Suite("Wallet Import Format")
struct WalletImportFormatTests {
    @Test("round trips both networks and compression choices deterministically")
    func deterministicRoundTrips() throws {
        let privateKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [0x01])

        for network in [BitcoinNetwork.mainnet, .testnet] {
            for compressed in [false, true] {
                let original = WalletImportFormat(
                    privateKey: privateKey,
                    network: network,
                    isCompressed: compressed
                )
                let text = original.description
                let decoded = try WalletImportFormat(text)

                #expect(decoded == original)
                #expect(decoded.description == text)
                #expect(decoded.privateKey.bytes == privateKey.bytes)
                #expect(decoded.network == network)
                #expect(decoded.isCompressed == compressed)
            }
        }
    }

    @Test("preserves Base58Check failures including every checksum-byte flip")
    func base58CheckFailures() throws {
        #expect(
            throws: KeyFormatError.invalidEncoding(
                .invalidEncoding(.invalidCharacter(index: 0))
            )
        ) {
            try WalletImportFormat("O")
        }

        let valid = WalletImportFormat(
            privateKey: try PrivateKey([UInt8](repeating: 0, count: 31) + [0x01]),
            network: .mainnet
        ).description
        let checkedBytes = try Base58.decode(valid, maximumDecodedByteCount: 38)

        for checksumOffset in 0..<4 {
            var corrupted = checkedBytes
            corrupted[corrupted.count - 4 + checksumOffset] ^= 0x01
            #expect(
                throws: KeyFormatError.invalidEncoding(.checksumMismatch)
            ) {
                try WalletImportFormat(Base58.encode(corrupted))
            }
        }
    }

    @Test("enforces exact payload length, bound, version, and compression marker")
    func structuralValidation() {
        let scalar = [UInt8](repeating: 0, count: 31) + [0x01]

        #expect(throws: KeyFormatError.invalidPayloadByteCount(32)) {
            try WalletImportFormat(Base58Check.encode([0x80] + Array(scalar.dropFirst())))
        }
        #expect(
            throws: KeyFormatError.invalidEncoding(
                .payloadSizeLimitExceeded(maximum: 34)
            )
        ) {
            try WalletImportFormat(Base58Check.encode([0x80] + scalar + [0x01, 0x00]))
        }
        #expect(throws: KeyFormatError.unsupportedVersion(0x81)) {
            try WalletImportFormat(Base58Check.encode([0x81] + scalar))
        }
        #expect(throws: KeyFormatError.invalidCompressionMarker(0x02)) {
            try WalletImportFormat(Base58Check.encode([0x80] + scalar + [0x02]))
        }
    }

    @Test("rejects zero and curve order after checksum validation")
    func scalarRangeValidation() {
        let zero = [UInt8](repeating: 0, count: 32)
        let curveOrder: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        ]

        for scalar in [zero, curveOrder] {
            #expect(
                throws: KeyFormatError.invalidPrivateKey(.invalidPrivateKey)
            ) {
                try WalletImportFormat(Base58Check.encode([0x80] + scalar))
            }
        }
    }
}
