import Crypto

/// The detached ciphertext and authentication tag produced by AES-GCM.
public struct AESGCMSealedBox: Equatable, Sendable {
    public let ciphertext: [UInt8]
    public let authenticationTag: [UInt8]

    public init(ciphertext: [UInt8], authenticationTag: [UInt8]) {
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }
}

/// Byte-oriented AES-GCM authenticated encryption with detached output.
public enum AESGCM {
    private static let minimumNonceByteCount = 12
    private static let authenticationTagByteCount = 16

    /// Encrypts and authenticates plaintext using an explicit nonce.
    public static func seal(
        _ plaintext: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        authenticating additionalAuthenticatedData: [UInt8] = []
    ) throws -> AESGCMSealedBox {
        try validateKey(key)
        try validateNonce(nonce)

        do {
            let cryptoNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: cryptoNonce,
                authenticating: additionalAuthenticatedData
            )
            return AESGCMSealedBox(
                ciphertext: Array(sealedBox.ciphertext),
                authenticationTag: Array(sealedBox.tag)
            )
        } catch {
            throw AESPrimitiveError.encryptionFailed
        }
    }

    /// Authenticates and decrypts detached AES-GCM ciphertext.
    public static func open(
        _ sealedBox: AESGCMSealedBox,
        key: [UInt8],
        nonce: [UInt8],
        authenticating additionalAuthenticatedData: [UInt8] = []
    ) throws -> [UInt8] {
        try validateKey(key)
        try validateNonce(nonce)
        guard sealedBox.authenticationTag.count == authenticationTagByteCount else {
            throw AESPrimitiveError.invalidAuthenticationTagByteCount(
                sealedBox.authenticationTag.count
            )
        }

        do {
            let cryptoNonce = try AES.GCM.Nonce(data: nonce)
            let cryptoSealedBox = try AES.GCM.SealedBox(
                nonce: cryptoNonce,
                ciphertext: sealedBox.ciphertext,
                tag: sealedBox.authenticationTag
            )
            return Array(
                try AES.GCM.open(
                    cryptoSealedBox,
                    using: SymmetricKey(data: key),
                    authenticating: additionalAuthenticatedData
                )
            )
        } catch {
            throw AESPrimitiveError.authenticationFailed
        }
    }

    private static func validateKey(_ key: [UInt8]) throws {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw AESPrimitiveError.invalidKeyByteCount(key.count)
        }
    }

    private static func validateNonce(_ nonce: [UInt8]) throws {
        guard nonce.count >= minimumNonceByteCount else {
            throw AESPrimitiveError.invalidNonceByteCount(
                minimum: minimumNonceByteCount,
                actual: nonce.count
            )
        }
    }
}
