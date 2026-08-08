import BSVCore
import BSVKeys
import Testing

@Suite("Wallet Import Format")
struct WIFTests {
    @Test("round trips both networks and compression choices deterministically")
    func deterministicRoundTrips() throws {
        let privateKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [0x01])

        for network in [BitcoinNetwork.mainnet, .testnet] {
            for compressed in [false, true] {
                let original = WIF(
                    privateKey: privateKey,
                    network: network,
                    isCompressed: compressed
                )
                let text = original.encoded
                let decoded = try WIF(text)

                #expect(decoded == original)
                #expect(decoded.encoded == text)
                #expect(decoded.privateKey.bytes == privateKey.bytes)
                #expect(decoded.network == network)
                #expect(decoded.isCompressed == compressed)
            }
        }
    }

    @Test("explicit encoding round trips while diagnostics and reflection redact WIF")
    func diagnosticRedaction() throws {
        let original = WIF(
            privateKey: try PrivateKey([UInt8](repeating: 0xab, count: 32)),
            network: .mainnet
        )
        let encoded = original.encoded
        let decoded = try WIF(encoded)
        let described = String(describing: decoded)
        let reflected = String(reflecting: decoded)
        var dumped = ""
        dump(decoded, to: &dumped)

        #expect(decoded.encoded == encoded)
        #expect(described == "<redacted wallet import format>")
        #expect(reflected == "<redacted wallet import format>")
        #expect(dumped.contains("<redacted wallet import format>"))
        #expect(Mirror(reflecting: decoded).children.isEmpty)
        for diagnostic in [described, reflected, dumped] {
            #expect(!diagnostic.contains(encoded))
            #expect(!diagnostic.contains("171"))
        }
    }

    @Test("preserves Base58Check failures including every checksum-byte flip")
    func base58CheckFailures() throws {
        #expect(
            throws: KeyFormatError.invalidEncoding(
                .invalidEncoding(.invalidCharacter(index: 0))
            )
        ) {
            try WIF("O")
        }

        let valid = WIF(
            privateKey: try PrivateKey([UInt8](repeating: 0, count: 31) + [0x01]),
            network: .mainnet
        ).encoded
        let checkedBytes = try Base58.decode(valid, maximumDecodedByteCount: 38)

        for checksumOffset in 0..<4 {
            var corrupted = checkedBytes
            corrupted[corrupted.count - 4 + checksumOffset] ^= 0x01
            #expect(
                throws: KeyFormatError.invalidEncoding(.checksumMismatch)
            ) {
                try WIF(Base58.encode(corrupted))
            }
        }
    }

    @Test("enforces exact payload length, bound, version, and compression marker")
    func structuralValidation() {
        let scalar = [UInt8](repeating: 0, count: 31) + [0x01]

        #expect(throws: KeyFormatError.invalidPayloadByteCount(32)) {
            try WIF(Base58Check.encode([0x80] + Array(scalar.dropFirst())))
        }
        #expect(
            throws: KeyFormatError.invalidEncoding(
                .payloadSizeLimitExceeded(maximum: 34)
            )
        ) {
            try WIF(Base58Check.encode([0x80] + scalar + [0x01, 0x00]))
        }
        #expect(throws: KeyFormatError.unsupportedVersion(0x81)) {
            try WIF(Base58Check.encode([0x81] + scalar))
        }
        #expect(throws: KeyFormatError.invalidCompressionMarker(0x02)) {
            try WIF(Base58Check.encode([0x80] + scalar + [0x02]))
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
                try WIF(Base58Check.encode([0x80] + scalar))
            }
        }
    }
}
