import BSVMessage
import BSVCore
import BSVCrypto
import BSVKeys
import Foundation
import Testing

@Suite("PortableMessage live Go oracle", .serialized)
struct PortableMessageGoOracleTests {
    @Test("one persistent pinned-Go child covers BRC-77 and BRC-78 bidirectionally")
    func bidirectionalPortableMessages() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let availableClient):
            client = availableClient
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Portable-message Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        var sequence = 0
        try checkSignedBidirectionally(client: client, sequence: &sequence)
        try checkEncryptedBidirectionally(client: client, sequence: &sequence)
        try checkTamperingAndBoundaries(client: client, sequence: &sequence)
        #expect(sequence > 40)
    }

    private func checkSignedBidirectionally(
        client: GoOracleClient,
        sequence: inout Int
    ) throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let unrelated = try Self.privateKey(22)
        let messages: [[UInt8]] = [[], Array("Grüße, 世界 👋".utf8)]

        for (messageIndex, message) in messages.enumerated() {
            for recipientMode in 0..<2 {
                let keyID = [UInt8](
                    repeating: UInt8(0x20 + messageIndex * 2 + recipientMode),
                    count: 32
                )
                let specific = recipientMode == 1
                let swiftPacket = try SignedMessage.sign(
                    message,
                    using: sender,
                    for: specific ? recipient.publicKey : nil,
                    randomSource: PortableOracleRandomSource([
                        .success(keyID),
                    ])
                )
                var verifyArguments: [String: GoOracleJSON] = [
                    "message": .string(Hex.encode(message)),
                    "envelope": .string(Hex.encode(swiftPacket.bytes)),
                ]
                if specific {
                    verifyArguments["recipientPrivateKey"] = .string(
                        Hex.encode(recipient.bytes)
                    )
                }
                let goVerification = try Self.request(
                    client,
                    sequence: &sequence,
                    operation: "portable.signed.verify",
                    arguments: verifyArguments
                )
                #expect(try Self.bool(goVerification, field: "valid"))

                var signArguments: [String: GoOracleJSON] = [
                    "message": .string(Hex.encode(message)),
                    "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                ]
                if specific {
                    signArguments["recipientPublicKey"] = .string(
                        Hex.encode(recipient.publicKey.compressedBytes)
                    )
                } else if messageIndex == 1 {
                    // Both omitted and explicit null name the anyone mode.
                    signArguments["recipientPublicKey"] = .null
                }
                let goSigning = try Self.request(
                    client,
                    sequence: &sequence,
                    operation: "portable.signed.sign",
                    arguments: signArguments
                )
                let goBytes = try Self.bytes(
                    goSigning,
                    field: "envelope",
                    maximum: 256
                )
                let parsed = try SignedMessage(goBytes)
                #expect(parsed.bytes == goBytes)
                #expect(parsed.senderPublicKey == sender.publicKey)
                #expect(parsed.keyID.bytes.count == 32)
                if specific {
                    #expect(parsed.recipient == .publicKey(recipient.publicKey))
                    #expect(try parsed.verify(message, using: recipient))
                } else {
                    #expect(parsed.recipient == .anyone)
                    #expect(try parsed.verify(message))
                }
            }
        }

        let goAnyone = try Self.request(
            client,
            sequence: &sequence,
            operation: "portable.signed.sign",
            arguments: [
                "message": .string(""),
                "senderPrivateKey": .string(Hex.encode(sender.bytes)),
            ]
        )
        let anyoneBytes = try Self.bytes(goAnyone, field: "envelope", maximum: 256)
        let goIgnoredRecipient = try Self.request(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: [
                "message": .string(""),
                "envelope": .string(Hex.encode(anyoneBytes)),
                "recipientPrivateKey": .string(Hex.encode(unrelated.bytes)),
            ]
        )
        #expect(try Self.bool(goIgnoredRecipient, field: "valid"))
        let swiftAnyone = try SignedMessage(anyoneBytes)
        #expect(try swiftAnyone.verify([], using: unrelated))
    }

    private func checkEncryptedBidirectionally(
        client: GoOracleClient,
        sequence: inout Int
    ) throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let plaintexts: [[UInt8]] = [
            [],
            (0..<129).map { UInt8(($0 * 29 + 7) & 0xff) },
        ]

        for (index, plaintext) in plaintexts.enumerated() {
            let swiftPacket = try EncryptedMessage.encrypt(
                plaintext,
                from: sender,
                to: recipient.publicKey,
                randomSource: PortableOracleRandomSource([
                    .success([UInt8](repeating: UInt8(0x60 + index), count: 32)),
                    .success([UInt8](repeating: UInt8(0xa0 + index), count: 32)),
                ])
            )
            let goDecryption = try Self.request(
                client,
                sequence: &sequence,
                operation: "portable.encrypted.decrypt",
                arguments: [
                    "envelope": .string(Hex.encode(swiftPacket.bytes)),
                    "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
                ]
            )
            #expect(
                try Self.bytes(
                    goDecryption,
                    field: "plaintext",
                    maximum: plaintext.count
                ) == plaintext
            )

            let goEncryption = try Self.request(
                client,
                sequence: &sequence,
                operation: "portable.encrypted.encrypt",
                arguments: [
                    "plaintext": .string(Hex.encode(plaintext)),
                    "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                    "recipientPublicKey": .string(
                        Hex.encode(recipient.publicKey.compressedBytes)
                    ),
                ]
            )
            let goBytes = try Self.bytes(
                goEncryption,
                field: "envelope",
                maximum: 150 + plaintext.count
            )
            let parsed = try EncryptedMessage(goBytes)
            #expect(parsed.bytes == goBytes)
            #expect(parsed.bytes.count == 150 + plaintext.count)
            #expect(parsed.senderPublicKey == sender.publicKey)
            #expect(parsed.recipientPublicKey == recipient.publicKey)
            #expect(parsed.keyID.bytes.count == 32)
            #expect(try parsed.decrypt(using: recipient) == plaintext)
        }
    }

    private func checkTamperingAndBoundaries(
        client: GoOracleClient,
        sequence: inout Int
    ) throws {
        let sender = try Self.privateKey(15)
        let otherSender = try Self.privateKey(16)
        let recipient = try Self.privateKey(21)
        let wrongRecipient = try Self.privateKey(22)
        let message = Array("signed tamper target".utf8)
        let keyID = [UInt8](repeating: 0x35, count: 32)
        let signed = try SignedMessage.sign(
            message,
            using: sender,
            for: recipient.publicKey,
            randomSource: PortableOracleRandomSource([.success(keyID)])
        )

        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: [
                "message": .string(Hex.encode(message)),
                "envelope": .string(Hex.encode(signed.bytes)),
            ],
            category: "recipientMismatch"
        )
        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: [
                "message": .string(Hex.encode(message)),
                "envelope": .string(Hex.encode(signed.bytes)),
                "recipientPrivateKey": .string(Hex.encode(wrongRecipient.bytes)),
            ],
            category: "recipientMismatch"
        )
        #expect(throws: PortableMessageError.recipientPublicKeyMismatch) {
            try signed.verify(message, using: wrongRecipient)
        }

        var signedVersion = signed.bytes
        signedVersion[0] ^= 1
        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: Self.signedVerifyArguments(
                message: message,
                envelope: signedVersion,
                recipient: recipient
            ),
            category: "unsupportedVersion"
        )
        #expect(throws: PortableMessageError.invalidVersion) {
            try SignedMessage(signedVersion)
        }

        var signedHeader = signed.bytes
        signedHeader.replaceSubrange(4..<37, with: otherSender.publicKey.compressedBytes)
        try Self.expectGoFalse(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: Self.signedVerifyArguments(
                message: message,
                envelope: signedHeader,
                recipient: recipient
            )
        )
        #expect(!(try SignedMessage(signedHeader).verify(message, using: recipient)))

        var signedKeyID = signed.bytes
        signedKeyID[70] ^= 1
        try Self.expectGoFalse(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: Self.signedVerifyArguments(
                message: message,
                envelope: signedKeyID,
                recipient: recipient
            )
        )
        #expect(!(try SignedMessage(signedKeyID).verify(message, using: recipient)))

        let otherSignature = try SignedMessage.sign(
            Array("different signed payload".utf8),
            using: sender,
            for: recipient.publicKey,
            randomSource: PortableOracleRandomSource([.success(keyID)])
        )
        var signedSignature = signed.bytes
        signedSignature.replaceSubrange(102..., with: otherSignature.bytes[102...])
        try Self.expectGoFalse(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: Self.signedVerifyArguments(
                message: message,
                envelope: signedSignature,
                recipient: recipient
            )
        )
        #expect(!(try SignedMessage(signedSignature).verify(message, using: recipient)))

        try Self.expectGoFalse(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: Self.signedVerifyArguments(
                message: message + [0],
                envelope: signed.bytes,
                recipient: recipient
            )
        )
        #expect(!(try signed.verify(message + [0], using: recipient)))

        var trailingDER = signed.bytes
        trailingDER.append(0)
        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.signed.verify",
            arguments: Self.signedVerifyArguments(
                message: message,
                envelope: trailingDER,
                recipient: recipient
            ),
            category: "invalidSignature"
        )
        #expect(throws: PortableMessageError.invalidSignature) {
            try SignedMessage(trailingDER)
        }

        let signedTruncations = Set([
            0, 3, 4, 36, 37, 69, 70, 101, 102, 109, 110,
            signed.bytes.count - 1,
        ]).sorted()
        for count in signedTruncations {
            let truncated = Array(signed.bytes.prefix(count))
            let response = try Self.request(
                client,
                sequence: &sequence,
                operation: "portable.signed.verify",
                arguments: Self.signedVerifyArguments(
                    message: message,
                    envelope: truncated,
                    recipient: recipient
                )
            )
            #expect(!response.ok)
            #expect(["invalidLength", "invalidSignature"].contains(response.error?.category))
            #expect(response.error?.category != "oraclePanic")
            #expect(throws: PortableMessageError.self) {
                try SignedMessage(truncated)
            }
        }

        let plaintext = (0..<65).map { UInt8(($0 * 17 + 3) & 0xff) }
        let encrypted = try EncryptedMessage.encrypt(
            plaintext,
            from: sender,
            to: recipient.publicKey,
            randomSource: PortableOracleRandomSource([
                .success([UInt8](repeating: 0x49, count: 32)),
                .success([UInt8](repeating: 0x94, count: 32)),
            ])
        )

        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.encrypted.decrypt",
            arguments: Self.encryptedDecryptArguments(
                envelope: encrypted.bytes,
                recipient: wrongRecipient
            ),
            category: "recipientMismatch"
        )
        #expect(throws: PortableMessageError.recipientPublicKeyMismatch) {
            try encrypted.decrypt(using: wrongRecipient)
        }

        var encryptedVersion = encrypted.bytes
        encryptedVersion[0] ^= 1
        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.encrypted.decrypt",
            arguments: Self.encryptedDecryptArguments(
                envelope: encryptedVersion,
                recipient: recipient
            ),
            category: "unsupportedVersion"
        )
        #expect(throws: PortableMessageError.invalidVersion) {
            try EncryptedMessage(encryptedVersion)
        }

        for offset in [70, 102, 134, encrypted.bytes.count - 1] {
            var tampered = encrypted.bytes
            tampered[offset] ^= 1
            try Self.expectGoError(
                client,
                sequence: &sequence,
                operation: "portable.encrypted.decrypt",
                arguments: Self.encryptedDecryptArguments(
                    envelope: tampered,
                    recipient: recipient
                ),
                category: "authenticationFailed"
            )
            #expect(throws: PortableMessageError.authenticationFailed) {
                try EncryptedMessage(tampered).decrypt(using: recipient)
            }
        }

        var encryptedHeader = encrypted.bytes
        encryptedHeader.replaceSubrange(4..<37, with: otherSender.publicKey.compressedBytes)
        try Self.expectGoError(
            client,
            sequence: &sequence,
            operation: "portable.encrypted.decrypt",
            arguments: Self.encryptedDecryptArguments(
                envelope: encryptedHeader,
                recipient: recipient
            ),
            category: "authenticationFailed"
        )
        #expect(throws: PortableMessageError.authenticationFailed) {
            try EncryptedMessage(encryptedHeader).decrypt(using: recipient)
        }

        for count in [0, 3, 4, 36, 37, 69, 70, 101, 102, 133, 134, 149] {
            let truncated = Array(encrypted.bytes.prefix(count))
            try Self.expectGoError(
                client,
                sequence: &sequence,
                operation: "portable.encrypted.decrypt",
                arguments: Self.encryptedDecryptArguments(
                    envelope: truncated,
                    recipient: recipient
                ),
                category: "invalidLength"
            )
            #expect(throws: PortableMessageError.invalidEnvelopeByteCount(count)) {
                try EncryptedMessage(truncated)
            }
        }

        let tagStart = encrypted.bytes.count - SymmetricKey.authenticationTagByteCount
        let authenticatedTruncations = Set([
            150, tagStart - 1, tagStart, encrypted.bytes.count - 1,
        ]).sorted()
        for count in authenticatedTruncations {
            let truncated = Array(encrypted.bytes.prefix(count))
            try Self.expectGoError(
                client,
                sequence: &sequence,
                operation: "portable.encrypted.decrypt",
                arguments: Self.encryptedDecryptArguments(
                    envelope: truncated,
                    recipient: recipient
                ),
                category: "authenticationFailed"
            )
            let parsed = try EncryptedMessage(truncated)
            #expect(throws: PortableMessageError.authenticationFailed) {
                try parsed.decrypt(using: recipient)
            }
        }
    }

    private static func signedVerifyArguments(
        message: [UInt8],
        envelope: [UInt8],
        recipient: PrivateKey
    ) -> [String: GoOracleJSON] {
        [
            "message": .string(Hex.encode(message)),
            "envelope": .string(Hex.encode(envelope)),
            "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
        ]
    }

    private static func encryptedDecryptArguments(
        envelope: [UInt8],
        recipient: PrivateKey
    ) -> [String: GoOracleJSON] {
        [
            "envelope": .string(Hex.encode(envelope)),
            "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
        ]
    }

    private static func request(
        _ client: GoOracleClient,
        sequence: inout Int,
        operation: String,
        arguments: [String: GoOracleJSON]
    ) throws -> GoOracleResponse {
        defer { sequence += 1 }
        return try client.request(
            id: "portable-message-\(sequence)",
            operation: operation,
            arguments: arguments
        )
    }

    private static func bytes(
        _ response: GoOracleResponse,
        field: String,
        maximum: Int
    ) throws -> [UInt8] {
        guard response.ok,
              case .object(let object) = response.result,
              case .string(let encoded) = object[field]
        else {
            throw PortableMessageOracleConformanceError.unexpectedResult
        }
        return try Hex.decode(encoded, maximumDecodedByteCount: maximum)
    }

    private static func bool(
        _ response: GoOracleResponse,
        field: String
    ) throws -> Bool {
        guard response.ok,
              case .object(let object) = response.result,
              case .bool(let value) = object[field]
        else {
            throw PortableMessageOracleConformanceError.unexpectedResult
        }
        return value
    }

    private static func expectGoFalse(
        _ client: GoOracleClient,
        sequence: inout Int,
        operation: String,
        arguments: [String: GoOracleJSON]
    ) throws {
        let response = try request(
            client,
            sequence: &sequence,
            operation: operation,
            arguments: arguments
        )
        #expect(try !bool(response, field: "valid"))
    }

    private static func expectGoError(
        _ client: GoOracleClient,
        sequence: inout Int,
        operation: String,
        arguments: [String: GoOracleJSON],
        category: String
    ) throws {
        let response = try request(
            client,
            sequence: &sequence,
            operation: operation,
            arguments: arguments
        )
        #expect(!response.ok)
        #expect(response.error?.category == category)
        #expect(response.result == nil)
    }

    private static func privateKey(_ scalar: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
    }
}

private enum PortableMessageOracleConformanceError: Error {
    case unexpectedResult
}

private enum PortableOracleRandomFailure: Error {
    case exhausted
}

private final class PortableOracleRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var script: [Result<[UInt8], PortableOracleRandomFailure>]

    init(_ script: [Result<[UInt8], PortableOracleRandomFailure>]) {
        self.script = script
    }

    func randomBytes(count _: Int) throws -> [UInt8] {
        try lock.withLock {
            guard !script.isEmpty else {
                throw PortableOracleRandomFailure.exhausted
            }
            return try script.removeFirst().get()
        }
    }
}
