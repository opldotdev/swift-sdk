import BSVCore
import BSVCrypto
import BSVKeys

/// The intended verifier encoded by a BRC-77 signed message.
public enum SignedMessageRecipient: Hashable, Sendable {
    /// The message can be verified without recipient-specific secret material.
    case anyone

    /// Verification requires the private key corresponding to this public key.
    case publicKey(PublicKey)
}

/// A canonical BRC-77 portable signed-message packet.
public struct SignedMessage: Hashable, Sendable {
    /// The BRC-77 magic and version bytes `42 42 33 01`.
    public static let version: [UInt8] = [0x42, 0x42, 0x33, 0x01]

    private static let publicKeyByteCount = 33
    private static let keyIDByteCount = 32
    private static let minimumDERByteCount = 8
    private static let anyonePrivateKeyBytes = [UInt8](repeating: 0, count: 31) + [1]
    private static let invoicePrefix = "2-message signing-"

    /// The identity public key that created the signature.
    public let senderPublicKey: PublicKey

    /// The recipient mode encoded by the packet.
    public let recipient: SignedMessageRecipient

    /// The random BRC-42 key identifier used by this packet.
    public let keyID: Hash256

    private let signature: ECDSASignature

    /// Parses one complete, canonical BRC-77 packet.
    ///
    /// This intentionally rejects ASN.1 trailing bytes that the pinned Go
    /// implementation's `FromDER` currently ignores.
    public init(
        _ bytes: [UInt8],
        limits: PortableMessageLimits = .standard
    ) throws {
        try limits.validateEnvelopeByteCount(bytes.count)
        let anyoneMinimum = Self.version.count
            + Self.publicKeyByteCount
            + 1
            + Self.keyIDByteCount
            + Self.minimumDERByteCount
        guard bytes.count >= anyoneMinimum else {
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

        if bytes[cursor] == 0 {
            self.recipient = .anyone
            cursor += 1
        } else {
            let specificMinimum = cursor
                + Self.publicKeyByteCount
                + Self.keyIDByteCount
                + Self.minimumDERByteCount
            guard bytes.count >= specificMinimum else {
                throw PortableMessageError.invalidEnvelopeByteCount(bytes.count)
            }
            let recipientEnd = cursor + Self.publicKeyByteCount
            let recipientPublicKey: PublicKey
            do {
                recipientPublicKey = try PublicKey(Array(bytes[cursor..<recipientEnd]))
            } catch {
                throw PortableMessageError.invalidRecipientPublicKey
            }
            self.recipient = .publicKey(recipientPublicKey)
            cursor = recipientEnd
        }

        let keyIDEnd = cursor + Self.keyIDByteCount
        guard bytes.count >= keyIDEnd + Self.minimumDERByteCount else {
            throw PortableMessageError.invalidEnvelopeByteCount(bytes.count)
        }
        self.keyID = try Hash256(Array(bytes[cursor..<keyIDEnd]))
        cursor = keyIDEnd

        let signatureBytes = Array(bytes[cursor...])
        let parsedSignature: ECDSASignature
        do {
            parsedSignature = try ECDSASignature(derBytes: signatureBytes)
        } catch {
            throw PortableMessageError.invalidSignature
        }
        guard parsedSignature.derBytes == signatureBytes else {
            throw PortableMessageError.invalidSignature
        }
        self.signature = parsedSignature
    }

    private init(
        senderPublicKey: PublicKey,
        recipient: SignedMessageRecipient,
        keyID: Hash256,
        signature: ECDSASignature
    ) {
        self.senderPublicKey = senderPublicKey
        self.recipient = recipient
        self.keyID = keyID
        self.signature = signature
    }

    /// The canonical BRC-77 wire representation.
    public var bytes: [UInt8] {
        var result = Self.version + senderPublicKey.compressedBytes
        switch recipient {
        case .anyone:
            result.append(0)
        case .publicKey(let publicKey):
            result.append(contentsOf: publicKey.compressedBytes)
        }
        result.append(contentsOf: keyID.bytes)
        result.append(contentsOf: signature.derBytes)
        return result
    }

    /// Signs a message for anyone or for one recipient using BRC-42 derivation.
    public static func sign(
        _ message: [UInt8],
        using senderPrivateKey: PrivateKey,
        for recipientPublicKey: PublicKey? = nil,
        limits: PortableMessageLimits = .standard,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> SignedMessage {
        try limits.validateMessageByteCount(message.count)
        let keyIDBytes = try drawKeyID(using: randomSource)
        let keyID = try Hash256(keyIDBytes)

        let derivationPublicKey: PublicKey
        let encodedRecipient: SignedMessageRecipient
        if let recipientPublicKey {
            derivationPublicKey = recipientPublicKey
            encodedRecipient = .publicKey(recipientPublicKey)
        } else {
            derivationPublicKey = try anyonePrivateKey().publicKey
            encodedRecipient = .anyone
        }

        let derivedPrivateKey: PrivateKey
        do {
            derivedPrivateKey = try senderPrivateKey.derivedChild(
                with: derivationPublicKey,
                invoiceNumber: invoice(for: keyIDBytes)
            )
        } catch {
            throw PortableMessageError.keyDerivationFailed
        }

        let signature: ECDSASignature
        do {
            signature = try derivedPrivateKey.sign(digest: BSVHashing.sha256(message))
        } catch {
            throw PortableMessageError.signingFailed
        }

        return SignedMessage(
            senderPublicKey: senderPrivateKey.publicKey,
            recipient: encodedRecipient,
            keyID: keyID,
            signature: signature
        )
    }

    /// Verifies the external message against this packet's derived signing key.
    ///
    /// A well-formed signature mismatch returns `false`. In particular, the
    /// existing strict ECDSA verifier rejects high-S signatures, while pinned
    /// Go's `crypto/ecdsa` verification accepts the mathematically equivalent
    /// high-S form. Produced signatures are low-S in both implementations.
    /// Structural and recipient-selection failures throw typed errors.
    public func verify(
        _ message: [UInt8],
        using recipientPrivateKey: PrivateKey? = nil,
        limits: PortableMessageLimits = .standard
    ) throws -> Bool {
        try limits.validateMessageByteCount(message.count)
        let verifierPrivateKey: PrivateKey
        switch recipient {
        case .anyone:
            verifierPrivateKey = try Self.anyonePrivateKey()
        case .publicKey(let requiredPublicKey):
            guard let recipientPrivateKey else {
                throw PortableMessageError.recipientPrivateKeyRequired
            }
            guard recipientPrivateKey.publicKey == requiredPublicKey else {
                throw PortableMessageError.recipientPublicKeyMismatch
            }
            verifierPrivateKey = recipientPrivateKey
        }

        let derivedPublicKey: PublicKey
        do {
            derivedPublicKey = try senderPublicKey.derivedChild(
                with: verifierPrivateKey,
                invoiceNumber: Self.invoice(for: keyID.bytes)
            )
        } catch {
            throw PortableMessageError.keyDerivationFailed
        }
        return derivedPublicKey.verify(signature, digest: BSVHashing.sha256(message))
    }

    private static func anyonePrivateKey() throws -> PrivateKey {
        // Scalar one is valid by construction. Keep construction throwable so a
        // future key backend cannot turn this protocol constant into a trap.
        do {
            return try PrivateKey(anyonePrivateKeyBytes)
        } catch {
            throw PortableMessageError.keyDerivationFailed
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
