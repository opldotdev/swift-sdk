import BSVCore
import BSVCrypto
import BSVKeys

/// A canonical BRC-78 portable encrypted-message packet.
public struct EncryptedMessage: Hashable, Sendable {
    /// The selected BRC-78 magic bytes `42 42 10 33`.
    public static let version: [UInt8] = [0x42, 0x42, 0x10, 0x33]

    private static let publicKeyByteCount = 33
    private static let keyIDByteCount = 32
    private static let headerByteCount = version.count
        + publicKeyByteCount
        + publicKeyByteCount
        + keyIDByteCount
    private static let minimumByteCount = headerByteCount
        + SymmetricKey.minimumEnvelopeByteCount
    private static let invoicePrefix = "2-message encryption-"

    /// The identity public key that encrypted the message.
    public let senderPublicKey: PublicKey

    /// The identity public key for the only intended recipient.
    public let recipientPublicKey: PublicKey

    /// The random BRC-42 key identifier used by this packet.
    public let keyID: Hash256

    private let encryptedPayload: [UInt8]

    /// Parses one complete BRC-78 packet and validates all structural fields.
    public init(
        _ bytes: [UInt8],
        limits: PortableMessageLimits = .standard
    ) throws {
        try limits.validateEnvelopeByteCount(bytes.count)
        guard bytes.count >= Self.minimumByteCount else {
            throw PortableMessageError.invalidEnvelopeByteCount(bytes.count)
        }
        guard Array(bytes[0..<Self.version.count]) == Self.version else {
            throw PortableMessageError.invalidVersion
        }

        var cursor = Self.version.count
        let senderEnd = cursor + Self.publicKeyByteCount
        do {
            self.senderPublicKey = try PublicKey(Array(bytes[cursor..<senderEnd]))
        } catch {
            throw PortableMessageError.invalidSenderPublicKey
        }
        cursor = senderEnd

        let recipientEnd = cursor + Self.publicKeyByteCount
        do {
            self.recipientPublicKey = try PublicKey(Array(bytes[cursor..<recipientEnd]))
        } catch {
            throw PortableMessageError.invalidRecipientPublicKey
        }
        cursor = recipientEnd

        let keyIDEnd = cursor + Self.keyIDByteCount
        self.keyID = try Hash256(Array(bytes[cursor..<keyIDEnd]))
        cursor = keyIDEnd
        self.encryptedPayload = Array(bytes[cursor...])
    }

    private init(
        senderPublicKey: PublicKey,
        recipientPublicKey: PublicKey,
        keyID: Hash256,
        encryptedPayload: [UInt8]
    ) {
        self.senderPublicKey = senderPublicKey
        self.recipientPublicKey = recipientPublicKey
        self.keyID = keyID
        self.encryptedPayload = encryptedPayload
    }

    /// The canonical BRC-78 wire representation.
    public var bytes: [UInt8] {
        Self.version
            + senderPublicKey.compressedBytes
            + recipientPublicKey.compressedBytes
            + keyID.bytes
            + encryptedPayload
    }

    /// Encrypts plaintext for exactly one recipient using BRC-42-derived ECDH.
    public static func encrypt(
        _ plaintext: [UInt8],
        from senderPrivateKey: PrivateKey,
        to recipientPublicKey: PublicKey,
        limits: PortableMessageLimits = .standard,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> EncryptedMessage {
        try limits.validateMessageByteCount(plaintext.count)
        let keyIDBytes = try drawKeyID(using: randomSource)
        let keyID = try Hash256(keyIDBytes)
        let invoiceNumber = invoice(for: keyIDBytes)

        let senderChildPrivateKey: PrivateKey
        let recipientChildPublicKey: PublicKey
        do {
            senderChildPrivateKey = try senderPrivateKey.derivedChild(
                with: recipientPublicKey,
                invoiceNumber: invoiceNumber
            )
            recipientChildPublicKey = try recipientPublicKey.derivedChild(
                with: senderPrivateKey,
                invoiceNumber: invoiceNumber
            )
        } catch {
            throw PortableMessageError.keyDerivationFailed
        }

        let sharedPoint: PublicKey
        do {
            sharedPoint = try senderChildPrivateKey.sharedSecret(
                with: recipientChildPublicKey
            )
        } catch {
            throw PortableMessageError.keyAgreementFailed
        }

        let symmetricKey: SymmetricKey
        do {
            symmetricKey = try SymmetricKey(Array(sharedPoint.compressedBytes.dropFirst()))
        } catch {
            throw PortableMessageError.keyAgreementFailed
        }

        let encryptedPayload: [UInt8]
        do {
            encryptedPayload = try symmetricKey.seal(plaintext, using: randomSource)
        } catch SymmetricKeyError.randomGenerationFailed {
            throw PortableMessageError.randomGenerationFailed
        } catch {
            throw PortableMessageError.encryptionFailed
        }

        return EncryptedMessage(
            senderPublicKey: senderPrivateKey.publicKey,
            recipientPublicKey: recipientPublicKey,
            keyID: keyID,
            encryptedPayload: encryptedPayload
        )
    }

    /// Authenticates and decrypts this message for its exact intended recipient.
    public func decrypt(
        using recipientPrivateKey: PrivateKey,
        limits: PortableMessageLimits = .standard
    ) throws -> [UInt8] {
        try limits.validateEncryptedPayloadByteCount(encryptedPayload.count)
        guard recipientPrivateKey.publicKey == recipientPublicKey else {
            throw PortableMessageError.recipientPublicKeyMismatch
        }

        let invoiceNumber = Self.invoice(for: keyID.bytes)
        let senderChildPublicKey: PublicKey
        let recipientChildPrivateKey: PrivateKey
        do {
            senderChildPublicKey = try senderPublicKey.derivedChild(
                with: recipientPrivateKey,
                invoiceNumber: invoiceNumber
            )
            recipientChildPrivateKey = try recipientPrivateKey.derivedChild(
                with: senderPublicKey,
                invoiceNumber: invoiceNumber
            )
        } catch {
            throw PortableMessageError.keyDerivationFailed
        }

        let sharedPoint: PublicKey
        do {
            sharedPoint = try recipientChildPrivateKey.sharedSecret(
                with: senderChildPublicKey
            )
        } catch {
            throw PortableMessageError.keyAgreementFailed
        }

        let symmetricKey: SymmetricKey
        do {
            symmetricKey = try SymmetricKey(Array(sharedPoint.compressedBytes.dropFirst()))
        } catch {
            throw PortableMessageError.keyAgreementFailed
        }

        do {
            return try symmetricKey.open(encryptedPayload)
        } catch SymmetricKeyError.authenticationFailed {
            throw PortableMessageError.authenticationFailed
        } catch {
            // Parsed packets always meet SymmetricKey's minimum envelope. Keep
            // any backend open failure on the single authentication boundary.
            throw PortableMessageError.authenticationFailed
        }
    }

    private static func drawKeyID(
        using randomSource: any SecureRandomSource
    ) throws -> [UInt8] {
        let bytes: [UInt8]
        do {
            bytes = try randomSource.randomBytes(count: keyIDByteCount)
        } catch {
            throw PortableMessageError.randomGenerationFailed
        }
        guard bytes.count == keyIDByteCount else {
            throw PortableMessageError.randomGenerationFailed
        }
        return bytes
    }

    private static func invoice(for keyID: [UInt8]) -> String {
        invoicePrefix + Base64Encoding.encode(keyID)
    }
}
