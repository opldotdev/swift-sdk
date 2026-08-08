import BSVCore

/// Stable validation and envelope failures for a Go-compatible symmetric key.
public enum SymmetricKeyError: Error, Equatable, Sendable {
    case invalidKeyByteCount(Int)
    case invalidBase64Encoding
    case invalidEnvelopeByteCount(Int)
    case randomGenerationFailed
    case authenticationFailed
}

/// A 256-bit AES key with the Go SDK's `nonce || ciphertext || tag` envelope.
///
/// Keys shorter than 32 bytes are left-zero-padded for compatibility with
/// secp256k1 X-coordinate key material. Empty and oversized keys are rejected.
/// Swift arrays cannot guarantee zeroization; avoid retaining copies returned
/// by ``bytes`` longer than necessary.
public struct SymmetricKey:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public static let keyByteCount = 32
    public static let nonceByteCount = 32
    public static let authenticationTagByteCount = 16
    public static let minimumEnvelopeByteCount = nonceByteCount + authenticationTagByteCount

    private let keyBytes: [UInt8]

    /// Creates an AES-256 key, left-zero-padding inputs from 1 through 31 bytes.
    public init(_ bytes: [UInt8]) throws {
        guard (1...Self.keyByteCount).contains(bytes.count) else {
            throw SymmetricKeyError.invalidKeyByteCount(bytes.count)
        }
        self.keyBytes = [UInt8](
            repeating: 0,
            count: Self.keyByteCount - bytes.count
        ) + bytes
    }

    /// Parses a strict, standard-padded Base64 key within the 32-byte limit.
    public init(base64Encoded text: String) throws {
        let decoded: [UInt8]
        do {
            decoded = try Base64Encoding.decode(
                text,
                maximumDecodedByteCount: Self.keyByteCount
            )
        } catch {
            throw SymmetricKeyError.invalidBase64Encoding
        }
        try self.init(decoded)
    }

    /// Generates a cryptographically random 256-bit key.
    public static func random(
        using randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> SymmetricKey {
        let bytes: [UInt8]
        do {
            bytes = try randomSource.randomBytes(count: Self.keyByteCount)
        } catch {
            throw SymmetricKeyError.randomGenerationFailed
        }
        guard bytes.count == Self.keyByteCount else {
            throw SymmetricKeyError.randomGenerationFailed
        }
        return try SymmetricKey(bytes)
    }

    /// The exact 32-byte AES key after compatibility padding.
    public var bytes: [UInt8] { keyBytes }

    /// A canonical standard-padded Base64 representation of the key.
    public var base64Encoded: String { Base64Encoding.encode(keyBytes) }

    /// A redacted description suitable for interpolation and diagnostic logging.
    public var description: String { "<redacted symmetric key>" }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(reflecting: description) }

    /// Encrypts plaintext with a fresh 32-byte nonce and no AAD.
    ///
    /// The returned bytes are `nonce || ciphertext || 16-byte tag` and match
    /// the pinned Go SDK's `primitives.SymmetricKey` envelope.
    public func seal(
        _ plaintext: [UInt8],
        using randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> [UInt8] {
        let nonce: [UInt8]
        do {
            nonce = try randomSource.randomBytes(count: Self.nonceByteCount)
        } catch {
            throw SymmetricKeyError.randomGenerationFailed
        }
        guard nonce.count == Self.nonceByteCount else {
            throw SymmetricKeyError.randomGenerationFailed
        }
        return try seal(plaintext, nonce: nonce)
    }

    /// Authenticates and decrypts a `nonce || ciphertext || tag` envelope.
    public func open(_ envelope: [UInt8]) throws -> [UInt8] {
        guard envelope.count >= Self.minimumEnvelopeByteCount else {
            throw SymmetricKeyError.invalidEnvelopeByteCount(envelope.count)
        }
        let nonce = Array(envelope[..<Self.nonceByteCount])
        let ciphertextEnd = envelope.count - Self.authenticationTagByteCount
        let sealedBox = AESGCMSealedBox(
            ciphertext: Array(envelope[Self.nonceByteCount..<ciphertextEnd]),
            authenticationTag: Array(envelope[ciphertextEnd...])
        )
        do {
            return try AESGCM.open(sealedBox, key: keyBytes, nonce: nonce)
        } catch {
            throw SymmetricKeyError.authenticationFailed
        }
    }

    /// Deterministic construction seam for conformance tests. Production
    /// callers use ``seal(_:)`` so nonce reuse is not possible through public API.
    package func seal(_ plaintext: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        guard nonce.count == Self.nonceByteCount else {
            throw AESPrimitiveError.invalidNonceByteCount(
                minimum: Self.nonceByteCount,
                actual: nonce.count
            )
        }
        let box = try AESGCM.seal(plaintext, key: keyBytes, nonce: nonce)
        return nonce + box.ciphertext + box.authenticationTag
    }
}
