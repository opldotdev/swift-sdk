import BSVMessage
import BSVCore
import BSVCrypto
import BSVKeys
import Foundation
import Testing

@Suite("PortableMessage BRC-78 encrypted messages")
struct PortableMessageEncryptedTests {
    @Test("empty, multibyte, and multiblock plaintexts round-trip canonically")
    func roundTrips() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let plaintexts: [[UInt8]] = [
            [],
            Array("Grüße, 世界 👋".utf8),
            Array(0..<129).map { UInt8($0 & 0xff) },
        ]

        for (index, plaintext) in plaintexts.enumerated() {
            let keyID = [UInt8](repeating: UInt8(index + 1), count: 32)
            let nonce = [UInt8](repeating: UInt8(0x80 + index), count: 32)
            let encrypted = try EncryptedMessage.encrypt(
                plaintext,
                from: sender,
                to: recipient.publicKey,
                randomSource: EncryptedScriptedRandomSource([
                    .success(keyID), .success(nonce),
                ])
            )
            #expect(encrypted.senderPublicKey == sender.publicKey)
            #expect(encrypted.recipientPublicKey == recipient.publicKey)
            #expect(encrypted.keyID.bytes == keyID)
            #expect(encrypted.bytes.count == 150 + plaintext.count)
            #expect(try encrypted.decrypt(using: recipient) == plaintext)
            #expect(try EncryptedMessage(encrypted.bytes) == encrypted)
            #expect(try EncryptedMessage(encrypted.bytes).bytes == encrypted.bytes)
        }
    }

    @Test("two random draws, wire fields, nonce, and BRC-42 derivation are exact")
    func exactWireAndDerivation() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let keyID = Array(0..<32).map(UInt8.init)
        let nonce = Array(32..<64).map(UInt8.init)
        let plaintext = Array("derived encryption key".utf8)
        let source = EncryptedScriptedRandomSource([
            .success(keyID), .success(nonce),
        ])

        let encrypted = try EncryptedMessage.encrypt(
            plaintext,
            from: sender,
            to: recipient.publicKey,
            randomSource: source
        )
        let bytes = encrypted.bytes
        #expect(source.requestedCounts == [32, 32])
        #expect(Array(bytes[0..<4]) == [0x42, 0x42, 0x10, 0x33])
        #expect(Array(bytes[4..<37]) == sender.publicKey.compressedBytes)
        #expect(Array(bytes[37..<70]) == recipient.publicKey.compressedBytes)
        #expect(Array(bytes[70..<102]) == keyID)
        #expect(Array(bytes[102..<134]) == nonce)

        let invoice = "2-message encryption-" + Base64Encoding.encode(keyID)
        #expect(invoice.hasSuffix("Hh8="))
        let senderChild = try sender.derivedChild(
            with: recipient.publicKey,
            invoiceNumber: invoice
        )
        let recipientChild = try recipient.publicKey.derivedChild(
            with: sender,
            invoiceNumber: invoice
        )
        let sharedPoint = try senderChild.sharedSecret(with: recipientChild)
        let symmetricKey = try SymmetricKey(
            Array(sharedPoint.compressedBytes.dropFirst())
        )
        #expect(try symmetricKey.open(Array(bytes[102...])) == plaintext)

        let senderChildPublic = try sender.publicKey.derivedChild(
            with: recipient,
            invoiceNumber: invoice
        )
        let recipientChildPrivate = try recipient.derivedChild(
            with: sender.publicKey,
            invoiceNumber: invoice
        )
        #expect(senderChild.publicKey == senderChildPublic)
        #expect(recipientChildPrivate.publicKey == recipientChild)
        #expect(
            try recipientChildPrivate.sharedSecret(with: senderChildPublic)
                == sharedPoint
        )
    }

    @Test("wrong recipient and wrong version fail with typed errors")
    func identityFailures() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let wrongRecipient = try Self.privateKey(22)
        let encrypted = try Self.encrypted(
            Array("identity".utf8),
            sender: sender,
            recipient: recipient
        )

        #expect(throws: PortableMessageError.recipientPublicKeyMismatch) {
            try encrypted.decrypt(using: wrongRecipient)
        }
        var wrongVersion = encrypted.bytes
        wrongVersion[0] ^= 1
        #expect(throws: PortableMessageError.invalidVersion) {
            try EncryptedMessage(wrongVersion)
        }

        var staleExampleVersion = encrypted.bytes
        staleExampleVersion.replaceSubrange(0..<4, with: [0x10, 0x33, 0x42, 0x42])
        #expect(throws: PortableMessageError.invalidVersion) {
            try EncryptedMessage(staleExampleVersion)
        }
    }

    @Test("header, keyID, nonce, ciphertext, and tag tampering is detected")
    func tampering() throws {
        let sender = try Self.privateKey(15)
        let otherSender = try Self.privateKey(16)
        let recipient = try Self.privateKey(21)
        let otherRecipient = try Self.privateKey(22)
        let plaintext = Array("tamper-resistant payload".utf8)
        let encrypted = try Self.encrypted(
            plaintext,
            sender: sender,
            recipient: recipient
        )

        var senderTamper = encrypted.bytes
        senderTamper.replaceSubrange(4..<37, with: otherSender.publicKey.compressedBytes)
        #expect(throws: PortableMessageError.authenticationFailed) {
            try EncryptedMessage(senderTamper).decrypt(using: recipient)
        }

        var recipientTamper = encrypted.bytes
        recipientTamper.replaceSubrange(37..<70, with: otherRecipient.publicKey.compressedBytes)
        #expect(throws: PortableMessageError.recipientPublicKeyMismatch) {
            try EncryptedMessage(recipientTamper).decrypt(using: recipient)
        }

        for offset in [70, 102, 134, encrypted.bytes.count - 1] {
            var tampered = encrypted.bytes
            tampered[offset] ^= 1
            #expect(throws: PortableMessageError.authenticationFailed) {
                try EncryptedMessage(tampered).decrypt(using: recipient)
            }
        }
    }

    @Test("every sub-minimum truncation and partial authenticated payload fails safely")
    func truncation() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let encrypted = try Self.encrypted(
            [UInt8](repeating: 0x11, count: 65),
            sender: sender,
            recipient: recipient
        )

        for count in 0..<150 {
            #expect(throws: PortableMessageError.invalidEnvelopeByteCount(count)) {
                try EncryptedMessage(Array(encrypted.bytes.prefix(count)))
            }
        }
        for count in 150..<encrypted.bytes.count {
            let partial = try EncryptedMessage(Array(encrypted.bytes.prefix(count)))
            #expect(throws: PortableMessageError.authenticationFailed) {
                try partial.decrypt(using: recipient)
            }
        }
    }

    @Test("malformed compressed sender and recipient keys are rejected")
    func malformedSEC1() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let encrypted = try Self.encrypted(
            [1, 2, 3],
            sender: sender,
            recipient: recipient
        )

        for prefix in [UInt8(0), 0x04, 0x06, 0x07, 0xff] {
            var malformedSender = encrypted.bytes
            malformedSender[4] = prefix
            #expect(throws: PortableMessageError.invalidSenderPublicKey) {
                try EncryptedMessage(malformedSender)
            }

            var malformedRecipient = encrypted.bytes
            malformedRecipient[37] = prefix
            #expect(throws: PortableMessageError.invalidRecipientPublicKey) {
                try EncryptedMessage(malformedRecipient)
            }
        }
    }

    @Test("failure or wrong count on either random draw normalizes")
    func randomFailures() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let valid = [UInt8](repeating: 7, count: 32)
        let invalids: [Result<[UInt8], EncryptedRandomFailure>] = [
            .failure(.failed),
            .success([]),
            .success([UInt8](repeating: 1, count: 31)),
            .success([UInt8](repeating: 1, count: 33)),
        ]

        for invalid in invalids {
            #expect(throws: PortableMessageError.randomGenerationFailed) {
                try EncryptedMessage.encrypt(
                    [1],
                    from: sender,
                    to: recipient.publicKey,
                    randomSource: EncryptedScriptedRandomSource([invalid])
                )
            }
            #expect(throws: PortableMessageError.randomGenerationFailed) {
                try EncryptedMessage.encrypt(
                    [1],
                    from: sender,
                    to: recipient.publicKey,
                    randomSource: EncryptedScriptedRandomSource([
                        .success(valid), invalid,
                    ])
                )
            }
        }
    }

    @Test("message and envelope bounds accept exact and reject max plus one preflight")
    func resourceBounds() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let wrongRecipient = try Self.privateKey(22)
        let limits = try PortableMessageLimits(maximumMessageByteCount: 64)
        let exact = [UInt8](repeating: 0x61, count: 64)
        let exactSource = EncryptedScriptedRandomSource([
            .success([UInt8](repeating: 0x62, count: 32)),
            .success([UInt8](repeating: 0x63, count: 32)),
        ])
        let encrypted = try EncryptedMessage.encrypt(
            exact,
            from: sender,
            to: recipient.publicKey,
            limits: limits,
            randomSource: exactSource
        )
        #expect(exactSource.requestedCounts == [32, 32])
        #expect(encrypted.bytes.count == limits.maximumEnvelopeByteCount)
        let parsed = try EncryptedMessage(encrypted.bytes, limits: limits)
        #expect(try parsed.decrypt(using: recipient, limits: limits) == exact)

        let oversized = exact + [0x64]
        let untouchedSource = EncryptedScriptedRandomSource([
            .success([UInt8](repeating: 0x65, count: 32)),
            .success([UInt8](repeating: 0x66, count: 32)),
        ])
        #expect(
            throws: PortableMessageError.messageByteCountLimitExceeded(
                actual: 65,
                maximum: 64
            )
        ) {
            try EncryptedMessage.encrypt(
                oversized,
                from: sender,
                to: recipient.publicKey,
                limits: limits,
                randomSource: untouchedSource
            )
        }
        #expect(untouchedSource.requestedCounts.isEmpty)

        var oversizedEnvelope = encrypted.bytes
        oversizedEnvelope.append(0)
        #expect(
            throws: PortableMessageError.envelopeByteCountLimitExceeded(
                actual: 215,
                maximum: 214
            )
        ) {
            try EncryptedMessage(oversizedEnvelope, limits: limits)
        }

        let largerLimits = try PortableMessageLimits(maximumMessageByteCount: 65)
        let larger = try EncryptedMessage.encrypt(
            oversized,
            from: sender,
            to: recipient.publicKey,
            limits: largerLimits,
            randomSource: EncryptedScriptedRandomSource([
                .success([UInt8](repeating: 0x67, count: 32)),
                .success([UInt8](repeating: 0x68, count: 32)),
            ])
        )
        // The bound failure precedes recipient matching, derivation, and AES-GCM.
        #expect(
            throws: PortableMessageError.encryptedPayloadByteCountLimitExceeded(
                actual: 113,
                maximum: 112
            )
        ) {
            try larger.decrypt(using: wrongRecipient, limits: limits)
        }
    }

    @Test("parsed encrypted messages are safe for concurrent Sendable use")
    func concurrentDecryption() async throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let plaintext = Array("concurrent encrypted message".utf8)
        let parsed = try EncryptedMessage(
            Self.encrypted(
                plaintext,
                sender: sender,
                recipient: recipient
            ).bytes
        )

        let results = try await withThrowingTaskGroup(of: [UInt8].self) { group in
            for _ in 0..<64 {
                group.addTask {
                    try parsed.decrypt(using: recipient)
                }
            }
            var values: [[UInt8]] = []
            for try await value in group { values.append(value) }
            return values
        }
        #expect(results.count == 64)
        #expect(results.allSatisfy { $0 == plaintext })
    }

    private static func encrypted(
        _ plaintext: [UInt8],
        sender: PrivateKey,
        recipient: PrivateKey
    ) throws -> EncryptedMessage {
        try EncryptedMessage.encrypt(
            plaintext,
            from: sender,
            to: recipient.publicKey,
            randomSource: EncryptedScriptedRandomSource([
                .success([UInt8](repeating: 0x5a, count: 32)),
                .success([UInt8](repeating: 0xa5, count: 32)),
            ])
        )
    }

    private static func privateKey(_ scalar: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
    }
}

private enum EncryptedRandomFailure: Error {
    case failed
}

private final class EncryptedScriptedRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var script: [Result<[UInt8], EncryptedRandomFailure>]
    private var counts: [Int] = []

    init(_ script: [Result<[UInt8], EncryptedRandomFailure>]) {
        self.script = script
    }

    var requestedCounts: [Int] {
        lock.withLock { counts }
    }

    func randomBytes(count: Int) throws -> [UInt8] {
        try lock.withLock {
            counts.append(count)
            guard !script.isEmpty else { throw EncryptedRandomFailure.failed }
            return try script.removeFirst().get()
        }
    }
}
