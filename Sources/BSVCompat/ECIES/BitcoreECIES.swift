import BSVCrypto
import BSVKeys

/// Bitcore-compatible ECIES packets for compatibility applications.
///
/// New applications should use BRC-78 `EncryptedMessage` from `BSVMessage`.
public enum BitcoreECIES {
    private static let publicKeyByteCount = 33
    private static let initializationVectorByteCount = 16
    private static let blockByteCount = 16
    private static let macByteCount = 32
    private static let compatibilityInitializationVector = [UInt8](
        repeating: 0,
        count: initializationVectorByteCount
    )

    /// Encrypts with a fresh ephemeral key and Bitcore's compatibility zero IV.
    public static func encrypt(
        _ plaintext: [UInt8],
        to recipientPublicKey: PublicKey,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> [UInt8] {
        let senderPrivateKey = try ECIESPrivateKeyGenerator.generate(using: randomSource)
        return try encryptCompatibility(
            plaintext,
            to: recipientPublicKey,
            from: senderPrivateKey,
            initializationVector: compatibilityInitializationVector
        )
    }

    /// Deterministic compatibility seam for a caller-supplied sender and IV.
    ///
    /// - Warning: Never reuse `senderPrivateKey` or `initializationVector` for
    ///   distinct messages. This API exists only for wire compatibility.
    public static func encryptCompatibility(
        _ plaintext: [UInt8],
        to recipientPublicKey: PublicKey,
        from senderPrivateKey: PrivateKey,
        initializationVector: [UInt8]
    ) throws -> [UInt8] {
        guard initializationVector.count == initializationVectorByteCount else {
            throw ECIESError.invalidInitializationVectorByteCount(
                initializationVector.count
            )
        }

        let sharedPoint = try eciesSharedPoint(
            privateKey: senderPrivateKey,
            publicKey: recipientPublicKey
        )
        let material = ECIESKeyDerivation.bitcore(sharedPoint: sharedPoint)
        let ciphertext: [UInt8]
        do {
            ciphertext = try AESCBC.encrypt(
                plaintext,
                key: material.encryptionKey,
                initializationVector: initializationVector
            )
        } catch {
            throw ECIESError.encryptionFailed
        }

        let authenticatedPayload = initializationVector + ciphertext
        let mac = BSVHashing.hmacSHA256(
            authenticatedPayload,
            key: material.authenticationKey
        ).bytes
        return senderPrivateKey.publicKey.compressedBytes + authenticatedPayload + mac
    }

    public static func decrypt(
        _ envelope: [UInt8],
        with recipientPrivateKey: PrivateKey
    ) throws -> [UInt8] {
        let minimumByteCount = publicKeyByteCount
            + initializationVectorByteCount
            + blockByteCount
            + macByteCount
        guard envelope.count >= minimumByteCount else {
            throw ECIESError.invalidEnvelopeByteCount(envelope.count)
        }

        let senderPublicKey: PublicKey
        do {
            senderPublicKey = try PublicKey(Array(envelope[..<publicKeyByteCount]))
        } catch {
            throw ECIESError.invalidSenderPublicKey
        }

        let macStart = envelope.count - macByteCount
        let authenticatedPayload = Array(envelope[publicKeyByteCount ..< macStart])
        let ciphertextByteCount = authenticatedPayload.count - initializationVectorByteCount
        guard ciphertextByteCount > 0,
              ciphertextByteCount.isMultiple(of: blockByteCount)
        else {
            throw ECIESError.invalidCiphertextByteCount(max(ciphertextByteCount, 0))
        }

        let sharedPoint = try eciesSharedPoint(
            privateKey: recipientPrivateKey,
            publicKey: senderPublicKey
        )
        let material = ECIESKeyDerivation.bitcore(sharedPoint: sharedPoint)
        let mac = Array(envelope[macStart...])
        guard BSVHashing.isValidHMACSHA256(
            mac,
            authenticating: authenticatedPayload,
            key: material.authenticationKey
        ) else {
            throw ECIESError.authenticationFailed
        }

        let initializationVector = Array(
            authenticatedPayload[..<initializationVectorByteCount]
        )
        let ciphertext = Array(authenticatedPayload[initializationVectorByteCount...])
        do {
            return try AESCBC.decrypt(
                ciphertext,
                key: material.encryptionKey,
                initializationVector: initializationVector
            )
        } catch {
            throw ECIESError.invalidPadding
        }
    }
}
