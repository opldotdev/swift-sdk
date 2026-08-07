import BSVCore
import BSVCrypto
import Crypto
import Foundation
import Testing

@Suite("AES conformance")
struct AESConformanceTests {
    @Test("strict AES fixture manifest and dependency provenance verify")
    func manifestVerification() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "swift-crypto-aes-4.5.1" }
        )

        #expect(group.schema == FixtureManifestLoader.schema)
        #expect(group.source.url == "https://github.com/apple/swift-crypto")
        #expect(group.source.revision == "47d3869a7291f085c1fb9fb1e6d3b97a793f45c6")
        #expect(group.license.identifier == "Apache-2.0")
        #expect(
            group.license.sha256
                == "b3ddc2ae068e76b3beb71be03c0400f90090f9469aa491bf7b1ac42320af37b8"
        )
        #expect(
            Set(group.files.map(\.localPath)) == [
                "Permissive/SwiftCrypto/AES/aes-cbc-pkcs7.json",
                "Permissive/SwiftCrypto/AES/aes-gcm.json",
            ]
        )
    }

    @Test("permissive CBC vectors match exact encryption, decryption, and padding behavior")
    func cbcVectors() throws {
        let fixture = try loadFixture(
            AESCBCCorpus.self,
            path: "Permissive/SwiftCrypto/AES/aes-cbc-pkcs7.json"
        )
        #expect(fixture.algorithm == "AES-CBC-PKCS7")
        #expect(Set(fixture.vectors.map(\.keySize)) == [128, 192, 256])

        for vector in fixture.vectors {
            let key = try decodeHex(vector.key)
            let iv = try decodeHex(vector.iv)
            let message = try decodeHex(vector.msg)
            let ciphertext = try decodeHex(vector.ct)

            if vector.result == "valid" {
                #expect(
                    try AESCBC.encrypt(message, key: key, initializationVector: iv)
                        == ciphertext,
                    "CBC encryption case \(vector.tcId)"
                )
                #expect(
                    try AESCBC.decrypt(ciphertext, key: key, initializationVector: iv)
                        == message,
                    "CBC decryption case \(vector.tcId)"
                )
            } else {
                #expect(vector.flags.contains("BadPadding"))
                #expect(throws: AESPrimitiveError.invalidPadding) {
                    try AESCBC.decrypt(ciphertext, key: key, initializationVector: iv)
                }
            }
        }
    }

    @Test("permissive GCM vectors match exact detached encryption and authenticated open")
    func gcmVectors() throws {
        let fixture = try loadFixture(
            AESGCMCorpus.self,
            path: "Permissive/SwiftCrypto/AES/aes-gcm.json"
        )
        #expect(fixture.algorithm == "AES-GCM")
        #expect(Set(fixture.vectors.map(\.keySize)) == [128, 192, 256])
        #expect(fixture.vectors.contains { $0.ivSize == 96 })
        #expect(fixture.vectors.contains { $0.ivSize == 256 })

        for vector in fixture.vectors where vector.ivSize >= 96 {
            let key = try decodeHex(vector.key)
            let nonce = try decodeHex(vector.iv)
            let aad = try decodeHex(vector.aad)
            let message = try decodeHex(vector.msg)
            let expectedCiphertext = try decodeHex(vector.ct)
            let expectedTag = try decodeHex(vector.tag)

            let sealedBox = try AESGCM.seal(
                message,
                key: key,
                nonce: nonce,
                authenticating: aad
            )
            #expect(
                sealedBox.ciphertext == expectedCiphertext,
                "GCM ciphertext case \(vector.tcId)"
            )
            #expect(
                sealedBox.authenticationTag == expectedTag,
                "GCM tag case \(vector.tcId)"
            )
            #expect(
                try AESGCM.open(
                    AESGCMSealedBox(
                        ciphertext: expectedCiphertext,
                        authenticationTag: expectedTag
                    ),
                    key: key,
                    nonce: nonce,
                    authenticating: aad
                ) == message,
                "GCM open case \(vector.tcId)"
            )
        }
    }

    @Test("the official 8-byte GCM nonce case is an explicit typed compatibility rejection")
    func unsupportedEightByteGCMNonce() throws {
        let fixture = try loadFixture(
            AESGCMCorpus.self,
            path: "Permissive/SwiftCrypto/AES/aes-gcm.json"
        )
        let vector = try #require(fixture.vectors.first { $0.ivSize == 64 })
        let key = try decodeHex(vector.key)
        let nonce = try decodeHex(vector.iv)
        let message = try decodeHex(vector.msg)
        let aad = try decodeHex(vector.aad)

        #expect(nonce.count == 8)
        #expect(throws: AESPrimitiveError.invalidNonceByteCount(minimum: 12, actual: 8)) {
            try AESGCM.seal(message, key: key, nonce: nonce, authenticating: aad)
        }
        #expect(throws: CryptoKitError.self) {
            try AES.GCM.Nonce(data: nonce)
        }
    }

    @Test("the pinned dependency and wrapper both accept the Go envelope's 32-byte nonce")
    func thirtyTwoByteDependencyNonce() throws {
        let nonceBytes = Array(repeating: UInt8(0x42), count: 32)
        let dependencyNonce = try AES.GCM.Nonce(data: nonceBytes)
        #expect(Array(dependencyNonce) == nonceBytes)

        let sealedBox = try AESGCM.seal(
            [],
            key: Array(repeating: 0, count: 16),
            nonce: nonceBytes
        )
        #expect(
            try AESGCM.open(
                sealedBox,
                key: Array(repeating: 0, count: 16),
                nonce: nonceBytes
            ) == []
        )
    }
}

private struct AESCBCCorpus: Decodable {
    let algorithm: String
    let vectors: [AESCBCTestVector]
}

private struct AESCBCTestVector: Decodable {
    let keySize: Int
    let tcId: Int
    let comment: String
    let key: String
    let iv: String
    let msg: String
    let ct: String
    let result: String
    let flags: [String]
}

private struct AESGCMCorpus: Decodable {
    let algorithm: String
    let vectors: [AESGCMTestVector]
}

private struct AESGCMTestVector: Decodable {
    let keySize: Int
    let ivSize: Int
    let tagSize: Int
    let tcId: Int
    let comment: String
    let flags: [String]
    let key: String
    let iv: String
    let aad: String
    let msg: String
    let ct: String
    let tag: String
    let result: String
}

private enum AESFixtureError: Error {
    case fixtureRootUnavailable
}

private func loadFixture<T: Decodable>(_ type: T.Type, path: String) throws -> T {
    guard let fixtureRoot = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw AESFixtureError.fixtureRootUnavailable
    }
    return try JSONDecoder().decode(
        type,
        from: Data(contentsOf: fixtureRoot.appendingPathComponent(path))
    )
}

private func decodeHex(_ text: String) throws -> [UInt8] {
    try Hex.decode(text, maximumDecodedByteCount: text.utf8.count / 2)
}
