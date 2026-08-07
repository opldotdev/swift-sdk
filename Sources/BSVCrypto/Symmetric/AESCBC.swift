import Crypto
import CryptoExtras

/// Byte-oriented AES-CBC encryption and decryption with PKCS#7 padding.
public enum AESCBC {
    private static let blockByteCount = 16

    /// Encrypts plaintext with an explicit key and initialization vector.
    public static func encrypt(
        _ plaintext: [UInt8],
        key: [UInt8],
        initializationVector: [UInt8],
        prependInitializationVector: Bool = false
    ) throws -> [UInt8] {
        try validateKey(key)
        try validateInitializationVector(initializationVector)

        let ciphertext: [UInt8]
        do {
            let iv = try AES._CBC.IV(ivBytes: initializationVector)
            ciphertext = Array(
                try AES._CBC.encrypt(
                    plaintext,
                    using: SymmetricKey(data: key),
                    iv: iv
                )
            )
        } catch {
            throw AESPrimitiveError.encryptionFailed
        }

        if prependInitializationVector {
            return initializationVector + ciphertext
        }
        return ciphertext
    }

    /// Decrypts block-aligned ciphertext with an explicit initialization vector.
    public static func decrypt(
        _ ciphertext: [UInt8],
        key: [UInt8],
        initializationVector: [UInt8]
    ) throws -> [UInt8] {
        try validateKey(key)
        try validateInitializationVector(initializationVector)
        guard !ciphertext.isEmpty, ciphertext.count.isMultiple(of: blockByteCount) else {
            throw AESPrimitiveError.invalidCiphertextByteCount(ciphertext.count)
        }

        do {
            let iv = try AES._CBC.IV(ivBytes: initializationVector)
            return Array(
                try AES._CBC.decrypt(
                    ciphertext,
                    using: SymmetricKey(data: key),
                    iv: iv
                )
            )
        } catch {
            throw AESPrimitiveError.invalidPadding
        }
    }

    private static func validateKey(_ key: [UInt8]) throws {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw AESPrimitiveError.invalidKeyByteCount(key.count)
        }
    }

    private static func validateInitializationVector(_ initializationVector: [UInt8]) throws {
        guard initializationVector.count == blockByteCount else {
            throw AESPrimitiveError.invalidInitializationVectorByteCount(
                initializationVector.count
            )
        }
    }
}
