import BSVCore
import BSVKeys

/// A 32-byte HMAC value. Swift arrays and their value copies cannot guarantee
/// zeroization; retain explicit byte exports only as long as needed.
public struct WalletHMAC:
    Equatable,
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public static let byteCount = 32

    /// Explicit export. JSON uses an integer byte array.
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) throws {
        guard bytes.count == Self.byteCount else {
            throw WalletValidationError.invalidLimit(name: "hmacByteCount", value: bytes.count)
        }
        self.bytes = bytes
    }

    public init(from decoder: Decoder) throws {
        let decoded = try WalletBoundedBytes(
            from: decoder,
            maximum: Self.byteCount + 1,
            limitKind: .invalidJSON
        ).bytes
        try self.init(bytes: decoded)
    }

    public func encode(to encoder: Encoder) throws {
        try WalletBoundedBytes(bytes).encode(to: encoder)
    }

    public var description: String { "<redacted wallet HMAC>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

private enum WalletResultCodingKeys: String, CodingKey {
    case publicKey
    case ciphertext
    case plaintext
    case hmac
    case signature
    case valid
}

public struct WalletGetPublicKeyResult: Codable, Sendable {
    public let publicKey: PublicKey
    public init(publicKey: PublicKey) { self.publicKey = publicKey }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: WalletResultCodingKeys.self)
        let text = try container.decode(String.self, forKey: .publicKey)
        guard text.utf8.count == 66,
              let bytes = try? Hex.decode(text, maximumDecodedByteCount: 33),
              Hex.encode(bytes) == text,
              let key = try? PublicKey(bytes),
              key.compressedBytes == bytes else {
            throw DecodingError.dataCorruptedError(
                forKey: .publicKey,
                in: container,
                debugDescription: "publicKey must be canonical lowercase compressed SEC1 hex"
            )
        }
        self.publicKey = key
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WalletResultCodingKeys.self)
        try container.encode(Hex.encode(publicKey.compressedBytes), forKey: .publicKey)
    }
}

public struct WalletEncryptResult:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let ciphertext: [UInt8]
    public init(ciphertext: [UInt8]) { self.ciphertext = ciphertext }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletResultCodingKeys.self)
        self.ciphertext = try container.decodeWalletBytes(
            forKey: .ciphertext,
            maximum: limits.maximumCiphertextByteCount,
            limitKind: .ciphertext
        )
        try walletRequireCiphertextLimit(ciphertext.count, limits: limits)
    }

    public func encode(to encoder: Encoder) throws {
        try walletRequireCiphertextLimit(ciphertext.count, limits: WalletCodingContext.limits(from: encoder))
        var container = encoder.container(keyedBy: WalletResultCodingKeys.self)
        try container.encodeWalletBytes(ciphertext, forKey: .ciphertext)
    }

    public var description: String { "<redacted wallet encrypt result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletDecryptResult:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let plaintext: [UInt8]
    public init(plaintext: [UInt8]) { self.plaintext = plaintext }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletResultCodingKeys.self)
        self.plaintext = try container.decodeWalletBytes(
            forKey: .plaintext,
            maximum: limits.maximumPayloadByteCount
        )
    }

    public func encode(to encoder: Encoder) throws {
        try walletRequirePayloadLimit(plaintext.count, limits: WalletCodingContext.limits(from: encoder))
        var container = encoder.container(keyedBy: WalletResultCodingKeys.self)
        try container.encodeWalletBytes(plaintext, forKey: .plaintext)
    }

    public var description: String { "<redacted wallet decrypt result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletCreateHMACResult:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let hmac: WalletHMAC
    public init(hmac: WalletHMAC) { self.hmac = hmac }

    public var description: String { "<redacted wallet create-HMAC result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletVerifyHMACResult: Codable, Sendable {
    public let valid: Bool
    public init(valid: Bool) { self.valid = valid }
}

public struct WalletCreateSignatureResult:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let signature: ECDSASignature
    public init(signature: ECDSASignature) { self.signature = signature }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: WalletResultCodingKeys.self)
        let bytes = try container.decodeWalletBytes(
            forKey: .signature,
            maximum: 72,
            limitKind: .invalidJSON
        )
        do {
            self.signature = try ECDSASignature(derBytes: bytes)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: container,
                debugDescription: "signature must use strict DER"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WalletResultCodingKeys.self)
        try container.encodeWalletBytes(signature.derBytes, forKey: .signature)
    }

    public var description: String { "<redacted wallet create-signature result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletVerifySignatureResult: Codable, Sendable {
    public let valid: Bool
    public init(valid: Bool) { self.valid = valid }
}
