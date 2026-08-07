import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("Secp256k1KeyConformance", .serialized)
struct Secp256k1KeyConformanceTests {
    @Test("pinned MIT key fixtures and license hashes verify")
    func permissiveFixtureProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "swift-secp256k1-keys-0.23.2" }
        )
        #expect(group.source.url == "https://github.com/21-DOT-DEV/swift-secp256k1")
        #expect(group.source.revision == "e70a10e036a55fffea31568f0af92d69b6d449cd")
        #expect(group.license.identifier == "MIT")
        #expect(group.license.file == "Licenses/swift-secp256k1-mit.txt")
        #expect(
            group.license.sha256
                == "3f662f0afc2c5a0702de996e3b89dd43d66e5d22c6dade94010f99afbce09486"
        )
        #expect(group.files.count == 2)
    }

    @Test("exact private derivation and SEC1 conversion bytes match upstream")
    func exactKeyBytes() throws {
        let fixture: KeyFixture = try loadFixture("key-vectors.json")

        for pair in fixture.privatePublicPairs {
            let privateBytes = try decode(pair.privateKey, maximum: 32)
            let key = try PrivateKey(privateBytes)
            #expect(key.bytes == privateBytes)

            if let compressedHex = pair.compressedPublicKey {
                let compressed = try decode(compressedHex, maximum: 33)
                #expect(key.publicKey.compressedBytes == compressed)
                #expect(try PublicKey(compressed) == key.publicKey)
            }
            if let uncompressedHex = pair.uncompressedPublicKey {
                let uncompressed = try decode(uncompressedHex, maximum: 65)
                #expect(key.publicKey.uncompressedBytes == uncompressed)
                #expect(try PublicKey(uncompressed) == key.publicKey)
            }
        }

        for forms in fixture.publicKeyForms {
            let compressed = try decode(forms.compressedPublicKey, maximum: 33)
            let uncompressed = try decode(forms.uncompressedPublicKey, maximum: 65)
            let compressedKey = try PublicKey(compressed)
            let uncompressedKey = try PublicKey(uncompressed)

            #expect(compressedKey == uncompressedKey)
            #expect(compressedKey.compressedBytes == compressed)
            #expect(compressedKey.uncompressedBytes == uncompressed)
        }
    }

    @Test("upstream scalar boundary bytes map to stable SDK behavior")
    func exactScalarBoundaries() throws {
        let fixture: ScalarFixture = try loadFixture("scalar-validation.json")
        let zero = try decode(fixture.zero, maximum: 32)
        let order = try decode(fixture.order, maximum: 32)
        let maximum = try decode(fixture.maximum, maximum: 32)

        #expect(throws: Secp256k1KeyError.invalidPrivateKey) {
            try PrivateKey(zero)
        }
        #expect(throws: Secp256k1KeyError.invalidPrivateKey) {
            try PrivateKey(order)
        }
        #expect(try PrivateKey(maximum).bytes == maximum)
    }

    private func loadFixture<T: Decodable>(_ name: String) throws -> T {
        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        return try JSONDecoder().decode(
            T.self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/SwiftSecp256k1/Keys/\(name)"
                )
            )
        )
    }

    private func decode(_ text: String, maximum: Int) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: maximum)
    }
}

private struct KeyFixture: Decodable {
    let privatePublicPairs: [PrivatePublicPair]
    let publicKeyForms: [PublicKeyForms]
}

private struct PrivatePublicPair: Decodable {
    let privateKey: String
    let compressedPublicKey: String?
    let uncompressedPublicKey: String?
}

private struct PublicKeyForms: Decodable {
    let compressedPublicKey: String
    let uncompressedPublicKey: String
}

private struct ScalarFixture: Decodable {
    let zero: String
    let order: String
    let maximum: String
}
