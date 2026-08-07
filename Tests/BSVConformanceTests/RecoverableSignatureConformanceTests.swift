import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("RecoverableSignatureConformance", .serialized)
struct RecoverableSignatureConformanceTests {
    @Test("permissive recovery fixture provenance and hashes verify")
    func permissiveFixtureProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()

        let swiftGroup = try #require(
            manifest.groups.first { $0.id == "swift-secp256k1-recovery-e70a10e0" }
        )
        #expect(swiftGroup.source.url == "https://github.com/21-DOT-DEV/swift-secp256k1")
        #expect(swiftGroup.source.revision == "e70a10e036a55fffea31568f0af92d69b6d449cd")
        #expect(swiftGroup.license.identifier == "MIT")
        #expect(swiftGroup.license.file == "Licenses/swift-secp256k1-recovery-mit.txt")
        #expect(swiftGroup.license.sha256 == "3f662f0afc2c5a0702de996e3b89dd43d66e5d22c6dade94010f99afbce09486")
        #expect(swiftGroup.files.count == 1)

        let coreGroup = try #require(
            manifest.groups.first { $0.id == "bitcoin-core-secp256k1-recovery-1a53f496" }
        )
        #expect(coreGroup.source.url == "https://github.com/bitcoin-core/secp256k1")
        #expect(coreGroup.source.revision == "1a53f4961f337b4d166c25fce72ef0dc88806618")
        #expect(coreGroup.license.identifier == "MIT")
        #expect(coreGroup.license.file == "Licenses/bitcoin-core-secp256k1-recovery-mit.txt")
        #expect(coreGroup.license.sha256 == "a735999c7e5649df6fcda6fb06ab97435851c392b1b93494ae8725f37441632f")
        #expect(coreGroup.files.count == 1)
    }

    @Test("pinned P256K RFC 6979 known answer signs the exact digest and recovers")
    func exactSigningAndRecoveryVector() throws {
        let fixture: SigningFixture = try loadFixture(
            "Permissive/SwiftSecp256k1/Recovery/recoverable-signature-vectors.json"
        )

        for vector in fixture.signingVectors {
            let key = try PrivateKey(decode(vector.privateKey))
            let digest = try Hash256(decode(vector.digest))
            let expectedCompact = try decode(vector.compact)
            let signature = try key.signRecoverable(digest: digest)

            #expect(Array(vector.messageUTF8.utf8).count > 32)
            #expect(signature.compactBytes == expectedCompact)
            #expect(signature.recoveryID == vector.recoveryID)
            #expect(signature.ecdsaSignature.derBytes == (try decode(vector.der)))
            #expect(try signature.recoverPublicKey(digest: digest) == key.publicKey)

            let parsed = try RecoverableSignature(
                compactBytes: expectedCompact,
                recoveryID: vector.recoveryID
            )
            #expect(parsed == signature)
            #expect(try parsed.recoverPublicKey(digest: digest) == key.publicKey)
        }
    }

    @Test("direct libsecp256k1 edge vectors fail safely for the asserted IDs")
    func upstreamRecoveryEdgeVector() throws {
        let fixture: EdgeFixture = try loadFixture(
            "Permissive/BitcoinCoreSecp256k1/Recovery/recovery-edge-vectors.json"
        )

        for vector in fixture.recoveryEdgeVectors {
            let compact = try decode(vector.compact)
            let digest = try Hash256(decode(vector.digest))

            for recoveryID in vector.failedRecoveryIDs {
                let signature = try RecoverableSignature(
                    compactBytes: compact,
                    recoveryID: recoveryID
                )
                #expect(throws: RecoverableSignatureError.recoveryFailed) {
                    try signature.recoverPublicKey(digest: digest)
                }
            }

            for recoveryID in vector.successfulRecoveryIDs {
                let signature = try RecoverableSignature(
                    compactBytes: compact,
                    recoveryID: recoveryID
                )
                _ = try signature.recoverPublicKey(digest: digest)
            }
        }
    }

    private func loadFixture<T: Decodable>(_ relativePath: String) throws -> T {
        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        return try JSONDecoder().decode(
            T.self,
            from: Data(contentsOf: fixtureRoot.appendingPathComponent(relativePath))
        )
    }

    private func decode(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 256)
    }
}

private struct SigningFixture: Decodable {
    let signingVectors: [SigningVector]
}

private struct SigningVector: Decodable {
    let privateKey: String
    let messageUTF8: String
    let digest: String
    let compact: String
    let recoveryID: Int
    let der: String
}

private struct EdgeFixture: Decodable {
    let recoveryEdgeVectors: [RecoveryEdgeVector]
}

private struct RecoveryEdgeVector: Decodable {
    let digest: String
    let compact: String
    let successfulRecoveryIDs: [Int]
    let failedRecoveryIDs: [Int]
}
