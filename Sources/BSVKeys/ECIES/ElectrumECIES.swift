import BSVCore
import BSVCrypto

/// Controls whether an Electrum ECIES packet carries its sender public key.
public enum ElectrumECIESPublicKeyPlacement: Sendable {
    case embedded
    case omitted
}

/// Selects the sender key and unambiguously declares the packet layout.
public enum ElectrumECIESSender: Hashable, Sendable {
    /// Read and use the compressed public key embedded after `BIE1`.
    case embedded

    /// Read the embedded key and require it to equal the supplied key.
    case embeddedAndExpected(PublicKey)

    /// Use a supplied sender key; the packet has no embedded key field.
    case external(PublicKey)
}

/// Electrum-compatible, byte-oriented ECIES packets.
public enum ElectrumECIES {
    private static let magic = Array("BIE1".utf8)
    private static let macByteCount = 32
    private static let publicKeyByteCount = 33
    private static let blockByteCount = 16

    /// Encrypts with a fresh ephemeral sender key embedded in the packet.
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
            senderPublicKeyPlacement: .embedded
        )
    }

    /// Produces legacy deterministic packets with a caller-supplied sender key.
    ///
    /// - Warning: Reusing `senderPrivateKey` for distinct messages to the same
    ///   recipient reuses the Electrum IV and both symmetric keys. Never use
    ///   this compatibility seam for distinct messages with the same sender key.
    public static func encryptCompatibility(
        _ plaintext: [UInt8],
        to recipientPublicKey: PublicKey,
        from senderPrivateKey: PrivateKey,
        senderPublicKeyPlacement: ElectrumECIESPublicKeyPlacement = .embedded
    ) throws -> [UInt8] {
        let sharedPoint = try eciesSharedPoint(
            privateKey: senderPrivateKey,
            publicKey: recipientPublicKey
        )
        let material = ECIESKeyDerivation.electrum(sharedPoint: sharedPoint)

        let ciphertext: [UInt8]
        do {
            ciphertext = try AESCBC.encrypt(
                plaintext,
                key: material.encryptionKey,
                initializationVector: material.initializationVector
            )
        } catch {
            throw ECIESError.encryptionFailed
        }

        var authenticatedFrame = magic
        if case .embedded = senderPublicKeyPlacement {
            authenticatedFrame.append(contentsOf: senderPrivateKey.publicKey.compressedBytes)
        }
        authenticatedFrame.append(contentsOf: ciphertext)
        let mac = BSVHashing.hmacSHA256(
            authenticatedFrame,
            key: material.authenticationKey
        ).bytes
        return authenticatedFrame + mac
    }

    public static func decrypt(
        _ envelope: [UInt8],
        with recipientPrivateKey: PrivateKey,
        sender: ElectrumECIESSender = .embedded
    ) throws -> [UInt8] {
        let includesPublicKey: Bool
        switch sender {
        case .embedded, .embeddedAndExpected:
            includesPublicKey = true
        case .external:
            includesPublicKey = false
        }

        let headerByteCount = magic.count + (includesPublicKey ? publicKeyByteCount : 0)
        let minimumByteCount = headerByteCount + blockByteCount + macByteCount
        guard envelope.count >= minimumByteCount else {
            throw ECIESError.invalidEnvelopeByteCount(envelope.count)
        }
        guard Array(envelope[0 ..< magic.count]) == magic else {
            throw ECIESError.invalidMagic
        }

        let senderPublicKey: PublicKey
        switch sender {
        case .embedded:
            senderPublicKey = try parseSenderKey(envelope)
        case let .embeddedAndExpected(expected):
            senderPublicKey = try parseSenderKey(envelope)
            guard senderPublicKey == expected else {
                throw ECIESError.senderPublicKeyMismatch
            }
        case let .external(external):
            senderPublicKey = external
        }

        let ciphertextEnd = envelope.count - macByteCount
        let ciphertext = Array(envelope[headerByteCount ..< ciphertextEnd])
        guard !ciphertext.isEmpty, ciphertext.count.isMultiple(of: blockByteCount) else {
            throw ECIESError.invalidCiphertextByteCount(ciphertext.count)
        }

        let sharedPoint = try eciesSharedPoint(
            privateKey: recipientPrivateKey,
            publicKey: senderPublicKey
        )
        let material = ECIESKeyDerivation.electrum(sharedPoint: sharedPoint)
        let authenticatedFrame = Array(envelope[..<ciphertextEnd])
        let mac = Array(envelope[ciphertextEnd...])
        guard BSVHashing.isValidHMACSHA256(
            mac,
            authenticating: authenticatedFrame,
            key: material.authenticationKey
        ) else {
            throw ECIESError.authenticationFailed
        }

        do {
            return try AESCBC.decrypt(
                ciphertext,
                key: material.encryptionKey,
                initializationVector: material.initializationVector
            )
        } catch {
            throw ECIESError.invalidPadding
        }
    }

    public static func encryptBase64(
        _ plaintext: [UInt8],
        to recipientPublicKey: PublicKey,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> String {
        let envelope = try encrypt(
            plaintext,
            to: recipientPublicKey,
            randomSource: randomSource
        )
        return Base64Encoding.encode(
            envelope,
            alphabet: .standard,
            padding: .included
        )
    }

    /// Base64-encodes a packet from ``encryptCompatibility(_:to:from:senderPublicKeyPlacement:)``.
    ///
    /// - Warning: Never reuse `senderPrivateKey` for distinct messages to the
    ///   same recipient. Doing so reuses the Electrum IV and symmetric keys.
    public static func encryptBase64Compatibility(
        _ plaintext: [UInt8],
        to recipientPublicKey: PublicKey,
        from senderPrivateKey: PrivateKey,
        senderPublicKeyPlacement: ElectrumECIESPublicKeyPlacement = .embedded
    ) throws -> String {
        let envelope = try encryptCompatibility(
            plaintext,
            to: recipientPublicKey,
            from: senderPrivateKey,
            senderPublicKeyPlacement: senderPublicKeyPlacement
        )
        return Base64Encoding.encode(
            envelope,
            alphabet: .standard,
            padding: .included
        )
    }

    public static func decryptBase64(
        _ envelope: String,
        with recipientPrivateKey: PrivateKey,
        sender: ElectrumECIESSender = .embedded,
        maximumEnvelopeByteCount: Int
    ) throws -> [UInt8] {
        let decoded: [UInt8]
        do {
            decoded = try Base64Encoding.decode(
                envelope,
                alphabet: .standard,
                padding: .included,
                maximumDecodedByteCount: maximumEnvelopeByteCount
            )
        } catch {
            throw ECIESError.invalidBase64
        }
        return try decrypt(
            decoded,
            with: recipientPrivateKey,
            sender: sender
        )
    }

    private static func parseSenderKey(_ envelope: [UInt8]) throws -> PublicKey {
        let keyStart = magic.count
        let keyEnd = keyStart + publicKeyByteCount
        do {
            return try PublicKey(Array(envelope[keyStart ..< keyEnd]))
        } catch {
            throw ECIESError.invalidSenderPublicKey
        }
    }
}
