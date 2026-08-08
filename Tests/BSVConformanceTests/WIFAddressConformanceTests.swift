import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("WIFAddressConformance", .serialized)
struct WIFAddressConformanceTests {
    @Test("direct ISC bsvutil WIF and legacy P2PKH vectors")
    func directBSVUtilVectors() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "bsvutil-wif-address-1d77cf353ea9" }
        )
        #expect(group.source.revision == "v0.0.0-20181216182056-1d77cf353ea9")
        #expect(group.license.identifier == "ISC")
        #expect(group.license.file == "Licenses/bsvutil-isc.txt")

        let root = try fixtureRoot()
        let wifVectors = try decode(
            [WIFVector].self,
            at: "WIFAddress/wif.json",
            root: root
        )
        #expect(wifVectors.count == 2)
        for vector in wifVectors {
            let privateKeyBytes = try Hex.decode(
                vector.privateKey,
                maximumDecodedByteCount: 32
            )
            let expected = WalletImportFormat(
                privateKey: try PrivateKey(privateKeyBytes),
                network: try network(vector.network),
                isCompressed: vector.compressed
            )

            #expect(expected.encoded == vector.encoded)
            #expect(try WalletImportFormat(vector.encoded) == expected)
        }

        let addressVectors = try decode(
            LegacyAddressVectors.self,
            at: "WIFAddress/legacy-address.json",
            root: root
        )
        #expect(addressVectors.hashAddresses.count == 3)
        for vector in addressVectors.hashAddresses {
            let hashBytes = try Hex.decode(vector.hash, maximumDecodedByteCount: 20)
            let expected = LegacyAddress(
                publicKeyHash: try Hash160(hashBytes),
                network: try network(vector.network)
            )

            #expect(expected.description == vector.encoded)
            #expect(try LegacyAddress(vector.encoded) == expected)
        }

        #expect(addressVectors.publicKeyAddresses.count == 3)
        for vector in addressVectors.publicKeyAddresses {
            let publicKeyBytes = try Hex.decode(
                vector.publicKey,
                maximumDecodedByteCount: 65
            )
            let expected = LegacyAddress(
                publicKey: try PublicKey(publicKeyBytes),
                network: try network(vector.network),
                compressed: vector.compressed
            )

            #expect(expected.description == vector.encoded)
            #expect(try LegacyAddress(vector.encoded) == expected)
        }

        #expect(throws: KeyFormatError.invalidEncoding(.checksumMismatch)) {
            try LegacyAddress(addressVectors.invalidChecksum)
        }
    }

    @Test("direct ISC bsvutil malformed Base58 and Base58Check vectors")
    func directBSVUtilNegativeVectors() throws {
        let root = try fixtureRoot()
        let base58Vectors = try decode(
            Base58NegativeVectors.self,
            at: "WIFAddress/base58-negative.json",
            root: root
        )
        #expect(base58Vectors.invalidAlphabet.count == 10)
        for text in base58Vectors.invalidAlphabet {
            #expect(throws: KeyFormatError.self) {
                try WalletImportFormat(text)
            }
        }

        let checkVectors = try decode(
            Base58CheckNegativeVectors.self,
            at: "WIFAddress/base58check-negative.json",
            root: root
        )
        #expect(throws: KeyFormatError.invalidEncoding(.checksumMismatch)) {
            try WalletImportFormat(checkVectors.invalidChecksum)
        }
        #expect(checkVectors.shortEncodings.count == 4)
        for text in checkVectors.shortEncodings {
            #expect(throws: KeyFormatError.invalidEncoding(.missingChecksum)) {
                try WalletImportFormat(text)
            }
        }
    }

    @Test("strict WIF policy rejects valid-checksum length, version, and marker cases")
    func strictWIFPolicy() {
        let scalar = [UInt8](repeating: 0, count: 31) + [0x01]

        #expect(throws: KeyFormatError.invalidPayloadByteCount(32)) {
            try WalletImportFormat(Base58Check.encode([0x80] + Array(scalar.dropFirst())))
        }
        #expect(throws: KeyFormatError.unsupportedVersion(0x81)) {
            try WalletImportFormat(Base58Check.encode([0x81] + scalar))
        }
        #expect(throws: KeyFormatError.invalidCompressionMarker(0x02)) {
            try WalletImportFormat(Base58Check.encode([0x80] + scalar + [0x02]))
        }
    }
}

private func fixtureRoot() throws -> URL {
    let fixtures = try #require(
        Bundle.module.url(forResource: "Fixtures", withExtension: nil)
    )
    return fixtures.appendingPathComponent("Permissive/BSVUtil")
}

private func decode<Value: Decodable>(
    _ type: Value.Type,
    at path: String,
    root: URL
) throws -> Value {
    try JSONDecoder().decode(
        type,
        from: Data(contentsOf: root.appendingPathComponent(path))
    )
}

private func network(_ name: String) throws -> BitcoinNetwork {
    switch name {
    case "mainnet":
        .mainnet
    case "testnet":
        .testnet
    default:
        try #require(nil as BitcoinNetwork?)
    }
}

private struct WIFVector: Decodable {
    let privateKey: String
    let network: String
    let compressed: Bool
    let encoded: String
}

private struct LegacyAddressVectors: Decodable {
    let hashAddresses: [HashAddressVector]
    let publicKeyAddresses: [PublicKeyAddressVector]
    let invalidChecksum: String
}

private struct HashAddressVector: Decodable {
    let hash: String
    let network: String
    let encoded: String
}

private struct PublicKeyAddressVector: Decodable {
    let publicKey: String
    let network: String
    let compressed: Bool
    let encoded: String
}

private struct Base58NegativeVectors: Decodable {
    let invalidAlphabet: [String]
}

private struct Base58CheckNegativeVectors: Decodable {
    let invalidChecksum: String
    let shortEncodings: [String]
}
