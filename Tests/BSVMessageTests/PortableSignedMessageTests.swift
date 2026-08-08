import BSVMessage
import BSVCore
import BSVCrypto
import BSVKeys
import Foundation
import Testing

@Suite("PortableMessage BRC-77 signed messages")
struct PortableMessageSignedTests {
    @Test("anyone and recipient-specific messages round-trip canonically")
    func roundTrips() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let messages: [[UInt8]] = [
            [],
            [1, 2, 4, 8, 16, 32],
            Array("Grüße, 世界 👋".utf8),
        ]

        for (index, message) in messages.enumerated() {
            let keyID = [UInt8](repeating: UInt8(index + 1), count: 32)
            let anyone = try SignedMessage.sign(
                message,
                using: sender,
                randomSource: SignedScriptedRandomSource([.success(keyID)])
            )
            #expect(anyone.senderPublicKey == sender.publicKey)
            #expect(anyone.recipient == .anyone)
            #expect(anyone.keyID.bytes == keyID)
            #expect(try anyone.verify(message))
            #expect(try anyone.verify(message, using: recipient))
            #expect(try SignedMessage(anyone.bytes) == anyone)
            #expect(try SignedMessage(anyone.bytes).bytes == anyone.bytes)

            let specific = try SignedMessage.sign(
                message,
                using: sender,
                for: recipient.publicKey,
                randomSource: SignedScriptedRandomSource([.success(keyID)])
            )
            #expect(specific.senderPublicKey == sender.publicKey)
            #expect(specific.recipient == .publicKey(recipient.publicKey))
            #expect(specific.keyID.bytes == keyID)
            #expect(try specific.verify(message, using: recipient))
            #expect(try SignedMessage(specific.bytes) == specific)
            #expect(try SignedMessage(specific.bytes).bytes == specific.bytes)
        }
    }

    @Test("anyone mode ignores every supplied recipient private key")
    func anyoneIgnoresSuppliedPrivateKey() throws {
        let sender = try Self.privateKey(15)
        let unrelatedRecipient = try Self.privateKey(255)
        let message = Array("public verification".utf8)
        let signed = try SignedMessage.sign(
            message,
            using: sender,
            randomSource: SignedScriptedRandomSource([
                .success([UInt8](repeating: 0x19, count: 32))
            ])
        )

        #expect(signed.recipient == .anyone)
        #expect(signed.bytes[37] == 0)
        #expect(try signed.verify(message))
        #expect(try signed.verify(message, using: unrelatedRecipient))
    }

    @Test("wire fields and the padded-Base64 BRC-42 invoice are exact")
    func exactWireAndDerivation() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let keyID = Array(0..<32).map(UInt8.init)
        let message = Array("invoice check".utf8)
        let source = SignedScriptedRandomSource([.success(keyID)])

        let signed = try SignedMessage.sign(
            message,
            using: sender,
            for: recipient.publicKey,
            randomSource: source
        )
        let bytes = signed.bytes
        #expect(source.requestedCounts == [32])
        #expect(Array(bytes[0..<4]) == [0x42, 0x42, 0x33, 0x01])
        #expect(Array(bytes[4..<37]) == sender.publicKey.compressedBytes)
        #expect(Array(bytes[37..<70]) == recipient.publicKey.compressedBytes)
        #expect(Array(bytes[70..<102]) == keyID)

        let signature = try ECDSASignature(derBytes: Array(bytes[102...]))
        let invoice = "2-message signing-" + Base64Encoding.encode(keyID)
        #expect(invoice.hasSuffix("Hh8="))
        let derivedSigner = try sender.derivedChild(
            with: recipient.publicKey,
            invoiceNumber: invoice
        )
        let derivedVerifier = try sender.publicKey.derivedChild(
            with: recipient,
            invoiceNumber: invoice
        )
        #expect(derivedSigner.publicKey == derivedVerifier)
        #expect(
            derivedVerifier.verify(signature, digest: BSVHashing.sha256(message))
        )
        #expect(
            !derivedVerifier.verify(signature, digest: BSVHashing.sha256d(message))
        )
    }

    @Test("recipient selection failures are typed")
    func recipientFailures() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let wrongRecipient = try Self.privateKey(22)
        let signed = try SignedMessage.sign(
            [1, 2, 3],
            using: sender,
            for: recipient.publicKey,
            randomSource: SignedScriptedRandomSource([
                .success([UInt8](repeating: 7, count: 32))
            ])
        )

        #expect(throws: PortableMessageError.recipientPrivateKeyRequired) {
            try signed.verify([1, 2, 3])
        }
        #expect(throws: PortableMessageError.recipientPublicKeyMismatch) {
            try signed.verify([1, 2, 3], using: wrongRecipient)
        }
    }

    @Test("message, sender, recipient, keyID, and signature tampering is detected")
    func tampering() throws {
        let sender = try Self.privateKey(15)
        let otherSender = try Self.privateKey(16)
        let recipient = try Self.privateKey(21)
        let otherRecipient = try Self.privateKey(22)
        let keyID = [UInt8](repeating: 0x41, count: 32)
        let message = Array("unaltered".utf8)
        let signed = try SignedMessage.sign(
            message,
            using: sender,
            for: recipient.publicKey,
            randomSource: SignedScriptedRandomSource([.success(keyID)])
        )
        #expect(!(try signed.verify(Array("altered".utf8), using: recipient)))

        var senderTamper = signed.bytes
        senderTamper.replaceSubrange(4..<37, with: otherSender.publicKey.compressedBytes)
        #expect(!(try SignedMessage(senderTamper).verify(message, using: recipient)))

        var recipientTamper = signed.bytes
        recipientTamper.replaceSubrange(37..<70, with: otherRecipient.publicKey.compressedBytes)
        #expect(throws: PortableMessageError.recipientPublicKeyMismatch) {
            try SignedMessage(recipientTamper).verify(message, using: recipient)
        }

        var keyIDTamper = signed.bytes
        keyIDTamper[70] ^= 1
        #expect(!(try SignedMessage(keyIDTamper).verify(message, using: recipient)))

        let differentSignature = try SignedMessage.sign(
            Array("different".utf8),
            using: sender,
            for: recipient.publicKey,
            randomSource: SignedScriptedRandomSource([.success(keyID)])
        )
        var signatureTamper = signed.bytes
        signatureTamper.replaceSubrange(102..., with: differentSignature.bytes[102...])
        #expect(!(try SignedMessage(signatureTamper).verify(message, using: recipient)))
    }

    @Test("wrong versions, every truncation, and malformed SEC1 are rejected")
    func structuralFailures() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let signed = try SignedMessage.sign(
            [1, 2, 3],
            using: sender,
            for: recipient.publicKey,
            randomSource: SignedScriptedRandomSource([
                .success([UInt8](repeating: 9, count: 32))
            ])
        )

        let anyone = try SignedMessage.sign(
            [1, 2, 3],
            using: sender,
            randomSource: SignedScriptedRandomSource([
                .success([UInt8](repeating: 10, count: 32))
            ])
        )
        for packet in [signed.bytes, anyone.bytes] {
            for count in 0..<packet.count {
                #expect(throws: PortableMessageError.self) {
                    try SignedMessage(Array(packet.prefix(count)))
                }
            }
        }

        var wrongVersion = signed.bytes
        wrongVersion[0] ^= 1
        #expect(throws: PortableMessageError.invalidVersion) {
            try SignedMessage(wrongVersion)
        }

        for prefix in [UInt8(0), 0x04, 0x06, 0x07, 0xff] {
            var malformedSender = signed.bytes
            malformedSender[4] = prefix
            #expect(throws: PortableMessageError.invalidSenderPublicKey) {
                try SignedMessage(malformedSender)
            }

            var malformedRecipient = signed.bytes
            malformedRecipient[37] = prefix
            if prefix == 0 {
                // `00` is the exact anyone discriminator and consumes only one
                // byte, so the displaced specific-recipient bytes make the DER
                // suffix malformed rather than making `00` an invalid prefix.
                #expect(throws: PortableMessageError.invalidSignature) {
                    try SignedMessage(malformedRecipient)
                }
            } else {
                #expect(throws: PortableMessageError.invalidRecipientPublicKey) {
                    try SignedMessage(malformedRecipient)
                }
            }
        }
    }

    @Test("DER must be complete and minimal; high-S remains parseable but does not verify")
    func strictDERAndHighS() throws {
        let sender = try Self.privateKey(15)
        let keyID = [UInt8](repeating: 0x73, count: 32)
        let message = Array("DER".utf8)
        let signed = try SignedMessage.sign(
            message,
            using: sender,
            randomSource: SignedScriptedRandomSource([.success(keyID)])
        )
        let signatureOffset = 70

        // Pinned Go's `FromDER` ignores returned ASN.1 trailing data. Swift's
        // strict complete-DER requirement deliberately rejects it.
        var trailing = signed.bytes
        trailing.append(0)
        #expect(throws: PortableMessageError.invalidSignature) {
            try SignedMessage(trailing)
        }

        var nonminimalDER = Array(signed.bytes[signatureOffset...])
        nonminimalDER.insert(0, at: 4)
        nonminimalDER[1] += 1
        nonminimalDER[3] += 1
        let nonminimal = Array(signed.bytes[..<signatureOffset]) + nonminimalDER
        #expect(throws: PortableMessageError.invalidSignature) {
            try SignedMessage(nonminimal)
        }

        let lowSignature = try ECDSASignature(
            derBytes: Array(signed.bytes[signatureOffset...])
        )
        let compact = lowSignature.compactBytes
        let highS = Self.subtract(
            Array(compact[32..<64]),
            from: Self.curveOrder
        )
        let highSignature = try ECDSASignature(
            compactBytes: Array(compact[..<32]) + highS
        )
        let highPacketBytes = Array(signed.bytes[..<signatureOffset])
            + highSignature.derBytes
        let highPacket = try SignedMessage(highPacketBytes)
        #expect(highPacket.bytes == highPacketBytes)
        // Pinned Go delegates to crypto/ecdsa and accepts this equivalent
        // high-S form. The SDK's existing strict verifier returns false.
        #expect(!(try highPacket.verify(message)))
    }

    @Test("random-source failures and wrong byte counts normalize")
    func randomFailures() throws {
        let sender = try Self.privateKey(15)
        let cases: [[Result<[UInt8], SignedRandomFailure>]] = [
            [.failure(.failed)],
            [.success([])],
            [.success([UInt8](repeating: 1, count: 31))],
            [.success([UInt8](repeating: 1, count: 33))],
        ]
        for script in cases {
            #expect(throws: PortableMessageError.randomGenerationFailed) {
                try SignedMessage.sign(
                    [1],
                    using: sender,
                    randomSource: SignedScriptedRandomSource(script)
                )
            }
        }
    }

    @Test("message bounds accept exact and reject max plus one before randomness or crypto")
    func messageResourceBounds() throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let limits = try PortableMessageLimits(maximumMessageByteCount: 3)
        let exact = [UInt8](repeating: 0x51, count: 3)
        let exactSource = SignedScriptedRandomSource([
            .success([UInt8](repeating: 0x52, count: 32))
        ])
        let signed = try SignedMessage.sign(
            exact,
            using: sender,
            for: recipient.publicKey,
            limits: limits,
            randomSource: exactSource
        )
        #expect(exactSource.requestedCounts == [32])
        #expect(try signed.verify(exact, using: recipient, limits: limits))

        let oversized = exact + [0x53]
        let untouchedSource = SignedScriptedRandomSource([
            .success([UInt8](repeating: 0x54, count: 32))
        ])
        #expect(
            throws: PortableMessageError.messageByteCountLimitExceeded(
                actual: 4,
                maximum: 3
            )
        ) {
            try SignedMessage.sign(
                oversized,
                using: sender,
                for: recipient.publicKey,
                limits: limits,
                randomSource: untouchedSource
            )
        }
        #expect(untouchedSource.requestedCounts.isEmpty)

        let oversizedEnvelope = [UInt8](
            repeating: 0,
            count: limits.maximumEnvelopeByteCount + 1
        )
        #expect(
            throws: PortableMessageError.envelopeByteCountLimitExceeded(
                actual: 175,
                maximum: 174
            )
        ) {
            try SignedMessage(oversizedEnvelope, limits: limits)
        }

        // The size failure precedes recipient selection, key derivation, and hashing.
        #expect(
            throws: PortableMessageError.messageByteCountLimitExceeded(
                actual: 4,
                maximum: 3
            )
        ) {
            try signed.verify(oversized, limits: limits)
        }
    }

    @Test("parsed messages are safe for concurrent Sendable verification")
    func concurrentVerification() async throws {
        let sender = try Self.privateKey(15)
        let recipient = try Self.privateKey(21)
        let message = Array("concurrent signed message".utf8)
        let parsed = try SignedMessage(
            SignedMessage.sign(
                message,
                using: sender,
                for: recipient.publicKey,
                randomSource: SignedScriptedRandomSource([
                    .success([UInt8](repeating: 0xa5, count: 32))
                ])
            ).bytes
        )

        let results = try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    try parsed.verify(message, using: recipient)
                }
            }
            var values: [Bool] = []
            for try await value in group { values.append(value) }
            return values
        }
        #expect(results.count == 64)
        #expect(results.allSatisfy { $0 })
    }

    private static let curveOrder: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    private static func privateKey(_ scalar: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
    }

    private static func subtract(_ value: [UInt8], from minuend: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: minuend.count)
        var borrow = 0
        for index in stride(from: minuend.count - 1, through: 0, by: -1) {
            var difference = Int(minuend[index]) - Int(value[index]) - borrow
            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(difference)
        }
        return result
    }
}

private enum SignedRandomFailure: Error {
    case failed
}

private final class SignedScriptedRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var script: [Result<[UInt8], SignedRandomFailure>]
    private var counts: [Int] = []

    init(_ script: [Result<[UInt8], SignedRandomFailure>]) {
        self.script = script
    }

    var requestedCounts: [Int] {
        lock.withLock { counts }
    }

    func randomBytes(count: Int) throws -> [UInt8] {
        try lock.withLock {
            counts.append(count)
            guard !script.isEmpty else { throw SignedRandomFailure.failed }
            return try script.removeFirst().get()
        }
    }
}
