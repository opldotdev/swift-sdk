import BSVCore
@testable import BSVKeys
import Testing

@Suite("BRC-42 and BRC-94 conformance", .serialized)
struct BRC42And94ConformanceTests {
    @Test("BRC-42 private and public derivation exactly match pinned Go")
    func brc42Differential() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BRC-42 Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let cases: [(UInt8, UInt8, String)] = [
                (2, 3, ""),
                (7, 19, "independent-1"),
                (29, 31, "2-authentication-key"),
                (41, 43, "caf\u{00E9}"),
                (47, 53, "cafe\u{0301}"),
                (59, 61, "embedded\0nul"),
            ]

            for (index, item) in cases.enumerated() {
                let sender = try PrivateKey(scalar(item.0))
                let recipient = try PrivateKey(scalar(item.1))
                let privateChild = try recipient.derivedChild(
                    with: sender.publicKey,
                    invoiceNumber: item.2
                )
                let publicChild = try recipient.publicKey.derivedChild(
                    with: sender,
                    invoiceNumber: item.2
                )
                #expect(privateChild.publicKey == publicChild)

                let privateResponse = try client.request(
                    id: "brc42-private-\(index)",
                    operation: "brc42.private.derive",
                    arguments: [
                        "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
                        "senderPublicKey": .string(Hex.encode(sender.publicKey.compressedBytes)),
                        "invoiceNumber": .string(item.2),
                    ]
                )
                #expect(privateResponse.result == .object([
                    "privateKey": .string(Hex.encode(privateChild.bytes)),
                ]))

                let publicResponse = try client.request(
                    id: "brc42-public-\(index)",
                    operation: "brc42.public.derive",
                    arguments: [
                        "recipientPublicKey": .string(Hex.encode(recipient.publicKey.compressedBytes)),
                        "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                        "invoiceNumber": .string(item.2),
                    ]
                )
                #expect(publicResponse.result == .object([
                    "publicKey": .string(Hex.encode(publicChild.compressedBytes)),
                ]))
            }
        }
    }

    @Test("Swift deterministic BRC-94 proof verifies in pinned Go")
    func swiftProofGoVerification() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BRC-94 Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let prover = try PrivateKey(scalar(7))
            let counterparty = try PrivateKey(scalar(13))
            let sharedSecret = try prover.sharedSecret(with: counterparty.publicKey)
            let proof = try prover.sharedSecretProof(
                with: counterparty.publicKey,
                nonce: PrivateKey(scalar(23))
            )

            let response = try client.request(
                id: "brc94-swift-proof",
                operation: "brc94.verify",
                arguments: proofArguments(
                    proof: proof,
                    proverPublicKey: prover.publicKey,
                    counterpartyPublicKey: counterparty.publicKey,
                    sharedSecret: sharedSecret
                )
            )
            #expect(response.result == .object(["valid": .bool(true)]))

            var changed = proof.response
            changed[31] ^= 1
            var tamperedArguments = proofArguments(
                proof: proof,
                proverPublicKey: prover.publicKey,
                counterpartyPublicKey: counterparty.publicKey,
                sharedSecret: sharedSecret
            )
            tamperedArguments["response"] = .string(Hex.encode(changed))
            let rejected = try client.request(
                id: "brc94-swift-proof-tampered",
                operation: "brc94.verify",
                arguments: tamperedArguments
            )
            #expect(rejected.result == .object(["valid": .bool(false)]))
        }
    }

    @Test("fresh pinned Go BRC-94 proof verifies in Swift")
    func goProofSwiftVerification() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BRC-94 Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let prover = try PrivateKey(scalar(11))
            let counterparty = try PrivateKey(scalar(17))
            let response = try client.request(
                id: "brc94-go-proof",
                operation: "brc94.generate",
                arguments: [
                    "proverPrivateKey": .string(Hex.encode(prover.bytes)),
                    "counterpartyPublicKey": .string(Hex.encode(counterparty.publicKey.compressedBytes)),
                ]
            )
            let fields = try object(response.result)
            let proof = try SharedSecretProof(
                noncePublicKey: PublicKey(try bytes(fields, "noncePublicKey", maximum: 33)),
                nonceSharedSecret: PublicKey(try bytes(fields, "nonceSharedSecret", maximum: 33)),
                response: try bytes(fields, "response", maximum: 32)
            )
            let proverPublicKey = try PublicKey(try bytes(fields, "proverPublicKey", maximum: 33))
            let sharedSecret = try PublicKey(try bytes(fields, "sharedSecret", maximum: 33))

            #expect(proof.verify(
                proverPublicKey: proverPublicKey,
                counterpartyPublicKey: counterparty.publicKey,
                sharedSecret: sharedSecret
            ))
        }
    }

    private func proofArguments(
        proof: SharedSecretProof,
        proverPublicKey: PublicKey,
        counterpartyPublicKey: PublicKey,
        sharedSecret: PublicKey
    ) -> [String: GoOracleJSON] {
        [
            "proverPublicKey": .string(Hex.encode(proverPublicKey.compressedBytes)),
            "counterpartyPublicKey": .string(Hex.encode(counterpartyPublicKey.compressedBytes)),
            "sharedSecret": .string(Hex.encode(sharedSecret.compressedBytes)),
            "noncePublicKey": .string(Hex.encode(proof.noncePublicKey.compressedBytes)),
            "nonceSharedSecret": .string(Hex.encode(proof.nonceSharedSecret.compressedBytes)),
            "response": .string(Hex.encode(proof.response)),
        ]
    }

    private func object(_ value: GoOracleJSON?) throws -> [String: GoOracleJSON] {
        guard case .object(let fields) = value else {
            throw ConformanceError.unexpectedOracleResult
        }
        return fields
    }

    private func bytes(
        _ fields: [String: GoOracleJSON],
        _ key: String,
        maximum: Int
    ) throws -> [UInt8] {
        guard case .string(let text) = fields[key] else {
            throw ConformanceError.unexpectedOracleResult
        }
        return try Hex.decode(text, maximumDecodedByteCount: maximum)
    }

    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }
}

private enum ConformanceError: Error {
    case unexpectedOracleResult
}
