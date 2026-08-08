import BSVCrypto
import BSVKeys
@testable import BSVCompat
import Foundation
import Testing

@Suite("Electrum and Bitcore ECIES compatibility")
struct ECIESTests {
    private let recipientBytes = ECIESTests.scalar(3)
    private let senderBytes = ECIESTests.scalar(7)

    @Test("Electrum round trips every PKCS#7 boundary with an embedded sender")
    func electrumEmbeddedPlaintextBoundaries() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)

        for count in [0, 15, 16, 17, 31, 32, 33, 80] {
            let plaintext = Self.message(count)
            let envelope = try ElectrumECIES.encryptCompatibility(
                plaintext,
                to: recipient.publicKey,
                from: sender
            )
            #expect(
                try ElectrumECIES.encryptCompatibility(
                    plaintext,
                    to: recipient.publicKey,
                    from: sender
                ) == envelope
            )
            #expect(Array(envelope[0 ..< 4]) == Array("BIE1".utf8))
            #expect(Array(envelope[4 ..< 37]) == sender.publicKey.compressedBytes)
            #expect(
                try ElectrumECIES.decrypt(envelope, with: recipient) == plaintext
            )
        }
    }

    @Test("Electrum omitted layout is explicit and supports messages over 32 bytes")
    func electrumOmittedSender() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)

        for count in [0, 15, 16, 17, 31, 32, 33, 80] {
            let plaintext = Self.message(count)
            let envelope = try ElectrumECIES.encryptCompatibility(
                plaintext,
                to: recipient.publicKey,
                from: sender,
                senderPublicKeyPlacement: .omitted
            )
            #expect(Array(envelope[0 ..< 4]) == Array("BIE1".utf8))
            #expect(
                try ElectrumECIES.decrypt(
                    envelope,
                    with: recipient,
                    sender: .external(sender.publicKey)
                ) == plaintext
            )
        }

    }

    @Test("Electrum can pin an expected embedded sender")
    func electrumExpectedSender() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)
        let unexpected = try PrivateKey(Self.scalar(8))
        let envelope = try ElectrumECIES.encryptCompatibility(
            Self.message(17),
            to: recipient.publicKey,
            from: sender
        )

        #expect(
            try ElectrumECIES.decrypt(
                envelope,
                with: recipient,
                sender: .embeddedAndExpected(sender.publicKey)
            ) == Self.message(17)
        )
        #expect(throws: ECIESError.senderPublicKeyMismatch) {
            try ElectrumECIES.decrypt(
                envelope,
                with: recipient,
                sender: .embeddedAndExpected(unexpected.publicKey)
            )
        }
    }

    @Test("Electrum validates layout, magic, sender SEC1, and block alignment")
    func electrumStructuralFailures() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)

        for count in [0, 3, 4, 36, 37, 51, 52, 68, 69, 84] {
            #expect(throws: ECIESError.invalidEnvelopeByteCount(count)) {
                try ElectrumECIES.decrypt(
                    [UInt8](repeating: 0, count: count),
                    with: recipient
                )
            }
        }
        for count in [0, 3, 4, 19, 20, 35, 36, 51] {
            #expect(throws: ECIESError.invalidEnvelopeByteCount(count)) {
                try ElectrumECIES.decrypt(
                    [UInt8](repeating: 0, count: count),
                    with: recipient,
                    sender: .external(sender.publicKey)
                )
            }
        }

        var envelope = try ElectrumECIES.encryptCompatibility(
            Self.message(16),
            to: recipient.publicKey,
            from: sender
        )
        envelope[0] ^= 1
        #expect(throws: ECIESError.invalidMagic) {
            try ElectrumECIES.decrypt(envelope, with: recipient)
        }

        envelope = try ElectrumECIES.encryptCompatibility(
            Self.message(16),
            to: recipient.publicKey,
            from: sender
        )
        envelope[4] = 0x04
        #expect(throws: ECIESError.invalidSenderPublicKey) {
            try ElectrumECIES.decrypt(envelope, with: recipient)
        }

        envelope = try ElectrumECIES.encryptCompatibility(
            Self.message(16),
            to: recipient.publicKey,
            from: sender
        )
        envelope.insert(0, at: envelope.count - 32)
        #expect(throws: ECIESError.invalidCiphertextByteCount(33)) {
            try ElectrumECIES.decrypt(envelope, with: recipient)
        }

        var omitted = try ElectrumECIES.encryptCompatibility(
            [],
            to: recipient.publicKey,
            from: sender,
            senderPublicKeyPlacement: .omitted
        )
        omitted.insert(0, at: omitted.count - 32)
        #expect(throws: ECIESError.invalidCiphertextByteCount(17)) {
            try ElectrumECIES.decrypt(
                omitted,
                with: recipient,
                sender: .external(sender.publicKey)
            )
        }
    }

    @Test("Electrum authenticates before CBC and rejects every MAC-byte mutation")
    func electrumAuthenticationAndPadding() throws {
        let recipient = try PrivateKey(recipientBytes)
        let wrongRecipient = try PrivateKey(Self.scalar(4))
        let sender = try PrivateKey(senderBytes)
        let wrongSender = try PrivateKey(Self.scalar(9))
        let envelope = try ElectrumECIES.encryptCompatibility(
            Self.message(16),
            to: recipient.publicKey,
            from: sender
        )

        #expect(throws: ECIESError.authenticationFailed) {
            try ElectrumECIES.decrypt(envelope, with: wrongRecipient)
        }

        for offset in 0 ..< 32 {
            var mutated = envelope
            mutated[mutated.count - 32 + offset] ^= 1
            #expect(throws: ECIESError.authenticationFailed) {
                try ElectrumECIES.decrypt(mutated, with: recipient)
            }
        }

        let omitted = try ElectrumECIES.encryptCompatibility(
            Self.message(16),
            to: recipient.publicKey,
            from: sender,
            senderPublicKeyPlacement: .omitted
        )
        #expect(throws: ECIESError.authenticationFailed) {
            try ElectrumECIES.decrypt(
                omitted,
                with: recipient,
                sender: .external(wrongSender.publicKey)
            )
        }

        let sharedPoint = try recipient.sharedSecret(with: sender.publicKey)
        let material = ECIESKeyDerivation.electrum(sharedPoint: sharedPoint)
        var badPadding = envelope
        badPadding[37 + 15] ^= 1
        let macStart = badPadding.count - 32
        let mac = BSVHashing.hmacSHA256(
            Array(badPadding[..<macStart]),
            key: material.authenticationKey
        ).bytes
        badPadding.replaceSubrange(macStart..., with: mac)
        #expect(throws: ECIESError.invalidPadding) {
            try ElectrumECIES.decrypt(badPadding, with: recipient)
        }
    }

    @Test("Electrum Base64 is strict, canonical, and bounded")
    func electrumBase64() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)
        let plaintext = Self.message(17)
        let encoded = try ElectrumECIES.encryptBase64Compatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender
        )
        let safeEncoded = try ElectrumECIES.encryptBase64(
            plaintext,
            to: recipient.publicKey,
            randomSource: FixedRandomSource(bytes: sender.bytes)
        )
        #expect(safeEncoded == encoded)
        let decoded = try ElectrumECIES.decryptBase64(
            encoded,
            with: recipient,
            maximumEnvelopeByteCount: 101
        )
        #expect(decoded == plaintext)

        for malformed in ["Zm\n9v", "Zh==", "A===", String(encoded.dropLast())] {
            #expect(throws: ECIESError.invalidBase64) {
                try ElectrumECIES.decryptBase64(
                    malformed,
                    with: recipient,
                    maximumEnvelopeByteCount: 1_024
                )
            }
        }
        #expect(throws: ECIESError.invalidBase64) {
            try ElectrumECIES.decryptBase64(
                encoded,
                with: recipient,
                maximumEnvelopeByteCount: 100
            )
        }
        #expect(throws: ECIESError.invalidBase64) {
            try ElectrumECIES.decryptBase64(
                encoded,
                with: recipient,
                maximumEnvelopeByteCount: -1
            )
        }
    }

    @Test("Compatibility seams repeat exactly for identical inputs")
    func compatibilitySeamsAreDeterministic() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)
        let plaintext = Self.message(33)
        let initializationVector = Array(0 ..< 16).map(UInt8.init)

        let electrumFirst = try ElectrumECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            senderPublicKeyPlacement: .omitted
        )
        let electrumSecond = try ElectrumECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            senderPublicKeyPlacement: .omitted
        )
        #expect(electrumFirst == electrumSecond)

        let bitcoreFirst = try BitcoreECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            initializationVector: initializationVector
        )
        let bitcoreSecond = try BitcoreECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            initializationVector: initializationVector
        )
        #expect(bitcoreFirst == bitcoreSecond)
    }

    @Test("Bitcore compatibility seam is deterministic across padding boundaries")
    func bitcoreDeterministicBoundaries() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)
        let iv = Array(0 ..< 16).map(UInt8.init)

        for count in [0, 15, 16, 17, 31, 32, 33, 80] {
            let plaintext = Self.message(count)
            let first = try BitcoreECIES.encryptCompatibility(
                plaintext,
                to: recipient.publicKey,
                from: sender,
                initializationVector: iv
            )
            let second = try BitcoreECIES.encryptCompatibility(
                plaintext,
                to: recipient.publicKey,
                from: sender,
                initializationVector: iv
            )
            #expect(first == second)
            #expect(Array(first[..<33]) == sender.publicKey.compressedBytes)
            #expect(Array(first[33 ..< 49]) == iv)
            #expect(try BitcoreECIES.decrypt(first, with: recipient) == plaintext)
        }

        for count in [0, 1, 15, 17, 31] {
            #expect(throws: ECIESError.invalidInitializationVectorByteCount(count)) {
                try BitcoreECIES.encryptCompatibility(
                    [],
                    to: recipient.publicKey,
                    from: sender,
                    initializationVector: [UInt8](repeating: 0, count: count)
                )
            }
        }
    }

    @Test("Safe ECIES encryption uses fresh ephemeral sender keys")
    func safeEphemeralFreshness() throws {
        let recipient = try PrivateKey(recipientBytes)
        let bitcoreSource = SequenceRandomSource([
            Self.scalar(10),
            Self.scalar(11),
        ])
        let first = try BitcoreECIES.encrypt(
            Self.message(17),
            to: recipient.publicKey,
            randomSource: bitcoreSource
        )
        let second = try BitcoreECIES.encrypt(
            Self.message(17),
            to: recipient.publicKey,
            randomSource: bitcoreSource
        )

        #expect(first != second)
        #expect(Array(first[33 ..< 49]) == [UInt8](repeating: 0, count: 16))
        #expect(Array(second[33 ..< 49]) == [UInt8](repeating: 0, count: 16))
        #expect(try BitcoreECIES.decrypt(first, with: recipient) == Self.message(17))
        #expect(try BitcoreECIES.decrypt(second, with: recipient) == Self.message(17))

        let electrumSource = SequenceRandomSource([
            Self.scalar(10),
            Self.scalar(11),
        ])
        let electrumFirst = try ElectrumECIES.encrypt(
            Self.message(17),
            to: recipient.publicKey,
            randomSource: electrumSource
        )
        let electrumSecond = try ElectrumECIES.encrypt(
            Self.message(17),
            to: recipient.publicKey,
            randomSource: electrumSource
        )
        #expect(electrumFirst != electrumSecond)
        #expect(Array(electrumFirst[4 ..< 37]) != Array(electrumSecond[4 ..< 37]))
        #expect(try ElectrumECIES.decrypt(electrumFirst, with: recipient) == Self.message(17))
        #expect(try ElectrumECIES.decrypt(electrumSecond, with: recipient) == Self.message(17))
    }

    @Test("Bitcore validates packet boundaries, SEC1, and block alignment")
    func bitcoreStructuralFailures() throws {
        let recipient = try PrivateKey(recipientBytes)
        let sender = try PrivateKey(senderBytes)
        let iv = [UInt8](repeating: 0, count: 16)

        for count in [0, 32, 33, 48, 49, 64, 65, 80, 81, 96] {
            #expect(throws: ECIESError.invalidEnvelopeByteCount(count)) {
                try BitcoreECIES.decrypt(
                    [UInt8](repeating: 0, count: count),
                    with: recipient
                )
            }
        }

        var envelope = try BitcoreECIES.encryptCompatibility(
            [],
            to: recipient.publicKey,
            from: sender,
            initializationVector: iv
        )
        envelope[0] = 0x04
        #expect(throws: ECIESError.invalidSenderPublicKey) {
            try BitcoreECIES.decrypt(envelope, with: recipient)
        }

        envelope = try BitcoreECIES.encryptCompatibility(
            [],
            to: recipient.publicKey,
            from: sender,
            initializationVector: iv
        )
        envelope.insert(0, at: envelope.count - 32)
        #expect(throws: ECIESError.invalidCiphertextByteCount(17)) {
            try BitcoreECIES.decrypt(envelope, with: recipient)
        }
    }

    @Test("Bitcore authenticates before CBC and rejects every MAC-byte mutation")
    func bitcoreAuthenticationAndPadding() throws {
        let recipient = try PrivateKey(recipientBytes)
        let wrongRecipient = try PrivateKey(Self.scalar(4))
        let sender = try PrivateKey(senderBytes)
        let iv = Array(16 ..< 32).map(UInt8.init)
        let envelope = try BitcoreECIES.encryptCompatibility(
            Self.message(16),
            to: recipient.publicKey,
            from: sender,
            initializationVector: iv
        )

        #expect(throws: ECIESError.authenticationFailed) {
            try BitcoreECIES.decrypt(envelope, with: wrongRecipient)
        }
        for offset in 0 ..< 32 {
            var mutated = envelope
            mutated[mutated.count - 32 + offset] ^= 1
            #expect(throws: ECIESError.authenticationFailed) {
                try BitcoreECIES.decrypt(mutated, with: recipient)
            }
        }

        let sharedPoint = try recipient.sharedSecret(with: sender.publicKey)
        let material = ECIESKeyDerivation.bitcore(sharedPoint: sharedPoint)
        var badPadding = envelope
        badPadding[33 + 16 + 15] ^= 1
        let macStart = badPadding.count - 32
        let authenticatedPayload = Array(badPadding[33 ..< macStart])
        let mac = BSVHashing.hmacSHA256(
            authenticatedPayload,
            key: material.authenticationKey
        ).bytes
        badPadding.replaceSubrange(macStart..., with: mac)
        #expect(throws: ECIESError.invalidPadding) {
            try BitcoreECIES.decrypt(badPadding, with: recipient)
        }
    }

    @Test("Bitcore strips leading zeroes from the shared X KDF input")
    func bitcoreLeadingZeroSharedX() throws {
        let fixedX = [UInt8](repeating: 0, count: 3) + [1, 2, 3]
            + [UInt8](repeating: 0, count: 26)
        let direct = ECIESKeyDerivation.bitcore(sharedX: fixedX)
        let expected = BSVHashing.sha512(
            [1, 2, 3] + [UInt8](repeating: 0, count: 26)
        ).bytes
        #expect(direct.encryptionKey == Array(expected[..<32]))
        #expect(direct.authenticationKey == Array(expected[32...]))

        let recipient = try PrivateKey(Self.scalar(1))
        var constructedSender: PrivateKey?
        for candidate in 1 ... 2_048 {
            let key = try PrivateKey(Self.scalar(candidate))
            if key.publicKey.compressedBytes[1] == 0 {
                constructedSender = key
                break
            }
        }
        let sender = try #require(constructedSender)
        let sharedPoint = try recipient.sharedSecret(with: sender.publicKey)
        #expect(sharedPoint.compressedBytes[1] == 0)

        let actualMaterial = ECIESKeyDerivation.bitcore(sharedPoint: sharedPoint)
        let minimalX = Array(sharedPoint.compressedBytes.dropFirst(2))
        let expectedDigest = BSVHashing.sha512(minimalX).bytes
        #expect(actualMaterial.encryptionKey == Array(expectedDigest[..<32]))
        #expect(actualMaterial.authenticationKey == Array(expectedDigest[32...]))

        let plaintext = Self.message(33)
        let envelope = try BitcoreECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            initializationVector: [UInt8](repeating: 0x5a, count: 16)
        )
        #expect(try BitcoreECIES.decrypt(envelope, with: recipient) == plaintext)
    }

    @Test("Ephemeral scalar generation maps failures and has a finite retry limit")
    func randomGenerationFailuresAndRetries() throws {
        let recipient = try PrivateKey(recipientBytes)

        #expect(throws: ECIESError.randomGenerationFailed) {
            try BitcoreECIES.encrypt(
                [],
                to: recipient.publicKey,
                randomSource: ThrowingRandomSource()
            )
        }
        #expect(throws: ECIESError.randomGenerationFailed) {
            try BitcoreECIES.encrypt(
                [],
                to: recipient.publicKey,
                randomSource: FixedRandomSource(bytes: [UInt8](repeating: 1, count: 31))
            )
        }

        let exhausted = CountingRandomSource(bytes: [UInt8](repeating: 0, count: 32))
        #expect(throws: ECIESError.randomGenerationFailed) {
            try ElectrumECIES.encrypt(
                [],
                to: recipient.publicKey,
                randomSource: exhausted
            )
        }
        #expect(exhausted.callCount == ECIESPrivateKeyGenerator.attemptLimit)

        let retrying = SequenceRandomSource([
            [UInt8](repeating: 0, count: 32),
            Self.scalar(12),
        ])
        let envelope = try ElectrumECIES.encrypt(
            [],
            to: recipient.publicKey,
            randomSource: retrying
        )
        #expect(
            Array(envelope[4 ..< 37])
                == (try PrivateKey(Self.scalar(12))).publicKey.compressedBytes
        )
        #expect(try ElectrumECIES.decrypt(envelope, with: recipient).isEmpty)
    }

    private static func scalar(_ value: Int) -> [UInt8] {
        precondition((0 ... 65_535).contains(value))
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[30] = UInt8(value >> 8)
        bytes[31] = UInt8(value & 0xff)
        return bytes
    }

    private static func message(_ count: Int) -> [UInt8] {
        (0 ..< count).map { UInt8(($0 * 29 + 7) & 0xff) }
    }
}

private struct FixedRandomSource: SecureRandomSource {
    let bytes: [UInt8]

    func randomBytes(count: Int) throws -> [UInt8] { bytes }
}

private struct ThrowingRandomSource: SecureRandomSource {
    struct Failure: Error {}

    func randomBytes(count: Int) throws -> [UInt8] { throw Failure() }
}

private final class SequenceRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private let sequence: [[UInt8]]
    private var index = 0

    init(_ sequence: [[UInt8]]) {
        self.sequence = sequence
    }

    func randomBytes(count: Int) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        let selected = sequence[min(index, sequence.count - 1)]
        index += 1
        return selected
    }
}

private final class CountingRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private let bytes: [UInt8]
    private(set) var callCount = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    func randomBytes(count: Int) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        callCount += 1
        return bytes
    }
}
