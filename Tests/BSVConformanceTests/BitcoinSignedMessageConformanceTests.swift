import BSVCore
import BSVCompat
import BSVKeys
import Foundation
import Testing

@Suite("BitcoinSignedMessageConformance", .serialized)
struct BitcoinSignedMessageConformanceTests {
    @Test("bitcoinj fixture provenance and hashes verify")
    func permissiveFixtureProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "bitcoinj-legacy-bsm-2840ea16" }
        )

        #expect(group.source.url == "https://github.com/bitcoinj/bitcoinj")
        #expect(group.source.revision == "2840ea16304b1e3d97826623e4077f5cf4ed04f7")
        #expect(group.license.identifier == "Apache-2.0")
        #expect(group.license.file == "Licenses/bitcoinj-bsm-apache-2.0.txt")
        #expect(
            group.license.sha256
                == "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
        )
        #expect(group.files.count == 1)
        #expect(
            group.files[0].localPath
                == "Permissive/BitcoinJ/BitcoinSignedMessage/legacy-p2pkh-vectors.json"
        )
        #expect(
            group.files[0].sha256
                == "3c20e4bac83f7d7f408cd3c326ff85558090c1310302d0d6317535f4ad229d1e"
        )
    }

    @Test("bitcoinj compressed and uncompressed BSM vectors verify")
    func upstreamBSMVectors() throws {
        let fixture: BitcoinJBSMFixture = try loadFixture(
            "Permissive/BitcoinJ/BitcoinSignedMessage/legacy-p2pkh-vectors.json"
        )
        #expect(fixture.schema == "bitcoinj-legacy-bsm-vectors/1")
        #expect(fixture.vectors.count == 2)

        for vector in fixture.vectors {
            let signature = try BitcoinMessageSignature(
                base64Encoded: vector.signatureBase64
            )
            let address = try Address(vector.address)
            let message = Array(vector.messageUTF8.utf8)

            #expect(signature.base64Encoded == vector.signatureBase64)
            #expect(signature.usesCompressedPublicKey == vector.compressed)
            #expect(try signature.verifies(message: message, address: address))

            let recovered = try signature.recoverPublicKey(message: message)
            #expect(
                Address(
                    publicKey: recovered,
                    network: address.network,
                    compressed: vector.compressed
                ) == address
            )
        }
    }

    @Test("required pinned Go signing and recovery agree bidirectionally")
    func requiredGoOracleDifferential() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let availableClient):
            client = availableClient
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Bitcoin Signed Message Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        let privateKeyBytes = [UInt8](repeating: 0, count: 31) + [1]
        let privateKey = try PrivateKey(privateKeyBytes)
        let messages: [[UInt8]] = [
            [],
            (0..<253).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ 7) },
        ]

        var sequence = 0
        for message in messages {
            for compressed in [true, false] {
                let swiftSignature = try BitcoinSignedMessage.sign(
                    message,
                    using: privateKey,
                    compressed: compressed
                )
                let goSigning = try client.request(
                    id: "bsm-sign-\(sequence)",
                    operation: "bsm.sign",
                    arguments: [
                        "privateKey": .string(Hex.encode(privateKeyBytes)),
                        "message": .string(Hex.encode(message)),
                        "compressed": .bool(compressed),
                    ]
                )
                #expect(goSigning.result == .object([
                    "signature": .string(Hex.encode(swiftSignature.bytes)),
                ]))

                guard case .object(let signingObject) = goSigning.result,
                      case .string(let goSignatureHex) = signingObject["signature"] else {
                    throw BitcoinSignedMessageConformanceError.unexpectedOracleResult
                }
                let goSignature = try BitcoinMessageSignature(
                    Hex.decode(goSignatureHex, maximumDecodedByteCount: 65)
                )
                #expect(goSignature.usesCompressedPublicKey == compressed)
                #expect(
                    try goSignature.recoverPublicKey(message: message)
                        == privateKey.publicKey
                )

                let goRecovery = try client.request(
                    id: "bsm-recover-\(sequence)",
                    operation: "bsm.recover",
                    arguments: [
                        "signature": .string(Hex.encode(swiftSignature.bytes)),
                        "message": .string(Hex.encode(message)),
                    ]
                )
                #expect(goRecovery.result == .object([
                    "publicKey": .string(Hex.encode(privateKey.publicKey.compressedBytes)),
                    "compressed": .bool(compressed),
                ]))
                sequence += 1
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
}

private enum BitcoinSignedMessageConformanceError: Error {
    case unexpectedOracleResult
}

private struct BitcoinJBSMFixture: Decodable {
    let schema: String
    let vectors: [BitcoinJBSMVector]
}

private struct BitcoinJBSMVector: Decodable {
    let messageUTF8: String
    let signatureBase64: String
    let address: String
    let compressed: Bool
}
