import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("Secp256k1OperationConformance", .serialized)
struct Secp256k1OperationConformanceTests {
    @Test("pinned MIT operation fixture and license hashes verify")
    func permissiveFixtureProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "swift-secp256k1-key-operations-0.23.2" }
        )

        #expect(group.source.url == "https://github.com/21-DOT-DEV/swift-secp256k1")
        #expect(group.source.revision == "e70a10e036a55fffea31568f0af92d69b6d449cd")
        #expect(group.license.identifier == "MIT")
        #expect(
            group.license.file
                == "Licenses/swift-secp256k1-key-operations-mit.txt"
        )
        #expect(
            group.license.sha256
                == "3f662f0afc2c5a0702de996e3b89dd43d66e5d22c6dade94010f99afbce09486"
        )
        #expect(group.files.count == 3)
    }

    @Test("pinned tweak addition bytes match the dependency vector")
    func exactTweakAddition() throws {
        let vector: TweakAdditionVector = try loadFixture("tweak-addition-vector.json")
        let privateKey = try PrivateKey(decode(vector.privateKey, maximum: 32))
        let tweak = try decode(vector.tweak, maximum: 32)
        let expectedPublicKey = try decode(vector.publicKey, maximum: 33)
        let expectedTweakedPrivateKey = try decode(vector.tweakedPrivateKey, maximum: 32)

        #expect(privateKey.publicKey.compressedBytes == expectedPublicKey)

        let tweakedPrivate = try privateKey.adding(tweak: tweak)
        let tweakedPublic = try privateKey.publicKey.adding(tweak: tweak)
        #expect(tweakedPrivate.bytes == expectedTweakedPrivateKey)
        #expect(tweakedPrivate.publicKey == tweakedPublic)
    }

    @Test("pinned ECDH inputs are symmetric and preserve the full known point")
    func exactECDH() throws {
        let vector: ECDHVector = try loadFixture("ecdh-private-inputs.json")
        let point: KnownPointVector = try loadFixture("exact-point-vector.json")
        let alice = try PrivateKey(decode(vector.alicePrivateKey, maximum: 32))
        let bob = try PrivateKey(decode(vector.bobPrivateKey, maximum: 32))
        let aliceSecret = try alice.sharedSecret(with: bob.publicKey)
        let bobSecret = try bob.sharedSecret(with: alice.publicKey)

        #expect(aliceSecret == bobSecret)

        var identityScalar = [UInt8](repeating: 0, count: 32)
        identityScalar[31] = 1
        let identity = try PrivateKey(identityScalar)
        let knownPeer = try PrivateKey(decode(point.privateKey, maximum: 32))
        let expectedUncompressed = try decode(point.uncompressedPublicKey, maximum: 65)

        let sharedPoint = try identity.sharedSecret(with: knownPeer.publicKey)
        #expect(sharedPoint.uncompressedBytes == expectedUncompressed)
        #expect(sharedPoint.serialized(as: .uncompressed) == expectedUncompressed)
        #expect(
            sharedPoint.serialized(as: .compressed)
                == knownPeer.publicKey.compressedBytes
        )
    }

    private func loadFixture<T: Decodable>(_ name: String) throws -> T {
        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        return try JSONDecoder().decode(
            T.self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/SwiftSecp256k1/KeyOperations/\(name)"
                )
            )
        )
    }

    private func decode(_ text: String, maximum: Int) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: maximum)
    }
}

private struct TweakAdditionVector: Decodable {
    let privateKey: String
    let publicKey: String
    let tweak: String
    let tweakedPrivateKey: String
}

private struct ECDHVector: Decodable {
    let alicePrivateKey: String
    let bobPrivateKey: String
}

private struct KnownPointVector: Decodable {
    let privateKey: String
    let uncompressedPublicKey: String
}
