import BSVCore
import BSVKeys
import BSVTransaction

/// Resource bounds applied before BRC-52 certificate data is copied or decoded.
public struct CertificateLimits: Hashable, Sendable {
    /// BRC-52 field names are capped by the protocol, not merely by policy.
    public static let maximumProtocolFieldNameUTF8ByteCount = 50

    public static let standard = CertificateLimits(
        validatedFieldCount: 256,
        fieldName: 50,
        plaintext: 1_048_576,
        ciphertext: 1_048_624,
        ciphertextBase64: 1_398_168,
        keyring: 4_096,
        binary: 8_388_608,
        json: 8_388_608
    )

    public let maximumFieldCount: Int
    public let maximumFieldNameUTF8ByteCount: Int
    public let maximumFieldPlaintextByteCount: Int
    public let maximumFieldCiphertextByteCount: Int
    package let maximumFieldCiphertextBase64UTF8ByteCount: Int
    public let maximumKeyringCiphertextByteCount: Int
    public let maximumBinaryByteCount: Int
    public let maximumJSONByteCount: Int

    public init(
        maximumFieldCount: Int = 256,
        maximumFieldNameUTF8ByteCount: Int = 50,
        maximumFieldPlaintextByteCount: Int = 1_048_576,
        maximumFieldCiphertextByteCount: Int = 1_048_624,
        maximumKeyringCiphertextByteCount: Int = 4_096,
        maximumBinaryByteCount: Int = 8_388_608,
        maximumJSONByteCount: Int = 8_388_608
    ) throws {
        let values = [
            maximumFieldCount,
            maximumFieldNameUTF8ByteCount,
            maximumFieldPlaintextByteCount,
            maximumFieldCiphertextByteCount,
            maximumKeyringCiphertextByteCount,
            maximumBinaryByteCount,
            maximumJSONByteCount,
        ]
        let (ciphertextPlusTwo, additionOverflow) =
            maximumFieldCiphertextByteCount.addingReportingOverflow(2)
        let base64Groups = ciphertextPlusTwo / 3
        let (base64ByteCount, multiplicationOverflow) =
            base64Groups.multipliedReportingOverflow(by: 4)
        guard values.allSatisfy({ $0 >= 0 }),
              maximumFieldCount <= 256,
              maximumFieldNameUTF8ByteCount <= Self.maximumProtocolFieldNameUTF8ByteCount,
              !additionOverflow,
              !multiplicationOverflow else {
            throw CertificateError.invalidLimits
        }
        self.init(
            validatedFieldCount: maximumFieldCount,
            fieldName: maximumFieldNameUTF8ByteCount,
            plaintext: maximumFieldPlaintextByteCount,
            ciphertext: maximumFieldCiphertextByteCount,
            ciphertextBase64: base64ByteCount,
            keyring: maximumKeyringCiphertextByteCount,
            binary: maximumBinaryByteCount,
            json: maximumJSONByteCount
        )
    }

    private init(
        validatedFieldCount: Int,
        fieldName: Int,
        plaintext: Int,
        ciphertext: Int,
        ciphertextBase64: Int,
        keyring: Int,
        binary: Int,
        json: Int
    ) {
        self.maximumFieldCount = validatedFieldCount
        self.maximumFieldNameUTF8ByteCount = fieldName
        self.maximumFieldPlaintextByteCount = plaintext
        self.maximumFieldCiphertextByteCount = ciphertext
        self.maximumFieldCiphertextBase64UTF8ByteCount = ciphertextBase64
        self.maximumKeyringCiphertextByteCount = keyring
        self.maximumBinaryByteCount = binary
        self.maximumJSONByteCount = json
    }
}

public enum CertificateError: Error, Equatable, Sendable {
    case invalidLimits
    case sizeOverflow
    case invalidIdentifierByteCount(expected: Int, actual: Int)
    case invalidCanonicalBase64
    case invalidPublicKey
    case invalidRevocationOutpoint
    case emptyFieldName
    case fieldNameTooLong(actual: Int, maximum: Int)
    case tooManyFields(actual: Int, maximum: Int)
    case duplicateFieldName
    case fieldsNotInCanonicalOrder
    case fieldValueTooLarge(actual: Int, maximum: Int)
    case keyringValueTooLarge(actual: Int, maximum: Int)
    case certificateTooLarge(actual: Int, maximum: Int)
    case certificateJSONTooLarge(actual: Int, maximum: Int)
    case truncatedCertificate
    case nonCanonicalCompactSize
    case invalidOutputIndex
    case invalidUTF8
    case invalidSignature
    case missingSignature
    case alreadySigned
    case requirementMismatch
    case signatureMismatch
    case keyringMismatch
    case fieldNotFound
    case randomGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case walletIdentityMismatch
    case invalidJSON
}

/// An exact 32-byte BRC-52 certificate type identifier.
public struct CertificateTypeID: Hashable, Codable, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw CertificateError.invalidIdentifierByteCount(expected: 32, actual: bytes.count)
        }
        self.bytes = bytes
    }

    public init(base64: String) throws {
        let decoded = try certificateDecodeCanonicalBase64(base64, maximum: 32)
        try self.init(decoded)
    }

    public var base64: String { Base64Encoding.encode(bytes) }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        do { try self.init(base64: container.decode(String.self)) }
        catch { throw DecodingError.dataCorruptedError(in: container, debugDescription: "certificate type must be canonical padded Base64 of exactly 32 bytes") }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64)
    }
}

/// An exact 32-byte BRC-52 certificate serial number.
public struct CertificateSerialNumber: Hashable, Codable, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw CertificateError.invalidIdentifierByteCount(expected: 32, actual: bytes.count)
        }
        self.bytes = bytes
    }

    public init(base64: String) throws {
        let decoded = try certificateDecodeCanonicalBase64(base64, maximum: 32)
        try self.init(decoded)
    }

    public var base64: String { Base64Encoding.encode(bytes) }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        do { try self.init(base64: container.decode(String.self)) }
        catch { throw DecodingError.dataCorruptedError(in: container, debugDescription: "certificate serial number must be canonical padded Base64 of exactly 32 bytes") }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64)
    }
}

/// A non-empty BRC-52 field name bounded by its raw UTF-8 byte length.
public struct CertificateFieldName: Hashable, Codable, Sendable, Comparable {
    public let value: String
    public let utf8Bytes: [UInt8]

    public init(_ value: String, limits: CertificateLimits = .standard) throws {
        let byteCount = value.utf8.count
        guard byteCount > 0 else { throw CertificateError.emptyFieldName }
        guard byteCount <= Self.maximumProtocolUTF8ByteCount,
              byteCount <= limits.maximumFieldNameUTF8ByteCount else {
            throw CertificateError.fieldNameTooLong(
                actual: byteCount,
                maximum: min(
                    limits.maximumFieldNameUTF8ByteCount,
                    Self.maximumProtocolUTF8ByteCount
                )
            )
        }
        let bytes = Array(value.utf8)
        self.value = value
        self.utf8Bytes = bytes
    }

    private static let maximumProtocolUTF8ByteCount =
        CertificateLimits.maximumProtocolFieldNameUTF8ByteCount

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.utf8Bytes.lexicographicallyPrecedes(rhs.utf8Bytes)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(container.decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

/// Canonical standard-padded Base64 containing a BRC-52 encrypted value.
public struct CertificateCiphertext:
    Hashable, Codable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8], maximumByteCount: Int = CertificateLimits.standard.maximumFieldCiphertextByteCount) throws {
        guard bytes.count <= maximumByteCount else {
            throw CertificateError.fieldValueTooLarge(actual: bytes.count, maximum: maximumByteCount)
        }
        self.bytes = bytes
    }

    public init(base64: String, maximumByteCount: Int = CertificateLimits.standard.maximumFieldCiphertextByteCount) throws {
        let decoded = try certificateDecodeCanonicalBase64(base64, maximum: maximumByteCount)
        try self.init(decoded, maximumByteCount: maximumByteCount)
    }

    public var base64: String { Base64Encoding.encode(bytes) }
    public var description: String { "<redacted certificate ciphertext>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        do { try self.init(base64: container.decode(String.self)) }
        catch { throw DecodingError.dataCorruptedError(in: container, debugDescription: "certificate ciphertext must use canonical padded Base64") }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64)
    }
}

/// The signed BRC-52 core certificate. Keyrings and decrypted values are never members.
public struct Certificate:
    Equatable, Encodable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let type: CertificateTypeID
    public let serialNumber: CertificateSerialNumber
    public let subject: PublicKey
    public let certifier: PublicKey
    public let revocationOutpoint: Outpoint
    public let fields: [CertificateFieldName: CertificateCiphertext]
    public let signature: ECDSASignature?

    public init(
        type: CertificateTypeID,
        serialNumber: CertificateSerialNumber,
        subject: PublicKey,
        certifier: PublicKey,
        revocationOutpoint: Outpoint,
        fields: [CertificateFieldName: CertificateCiphertext],
        signature: ECDSASignature? = nil,
        limits: CertificateLimits = .standard
    ) throws {
        guard fields.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(actual: fields.count, maximum: limits.maximumFieldCount)
        }
        var jsonFieldNames = Set<String>()
        for (name, value) in fields {
            _ = try CertificateFieldName(name.value, limits: limits)
            guard jsonFieldNames.insert(name.value).inserted else {
                throw CertificateError.duplicateFieldName
            }
            guard value.bytes.count <= limits.maximumFieldCiphertextByteCount else {
                throw CertificateError.fieldValueTooLarge(actual: value.bytes.count, maximum: limits.maximumFieldCiphertextByteCount)
            }
        }
        self.type = type
        self.serialNumber = serialNumber
        self.subject = subject
        self.certifier = certifier
        self.revocationOutpoint = revocationOutpoint
        self.fields = fields
        self.signature = signature
    }

    public var signatureKeyID: String { type.base64 + " " + serialNumber.base64 }
    public var description: String { "<redacted certificate>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    public func replacingSignature(
        _ signature: ECDSASignature,
        limits: CertificateLimits = .standard
    ) throws -> Certificate {
        guard self.signature == nil else { throw CertificateError.alreadySigned }
        return try Certificate(
            type: type, serialNumber: serialNumber, subject: subject, certifier: certifier,
            revocationOutpoint: revocationOutpoint, fields: fields, signature: signature,
            limits: limits
        )
    }

    private enum CodingKeys: String, CodingKey {
        case type, serialNumber, subject, certifier, revocationOutpoint, fields, signature
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(serialNumber, forKey: .serialNumber)
        try container.encode(Hex.encode(subject.compressedBytes), forKey: .subject)
        try container.encode(Hex.encode(certifier.compressedBytes), forKey: .certifier)
        try container.encode(revocationOutpoint.description, forKey: .revocationOutpoint)
        var rawFields: [String: String] = [:]
        for (name, value) in fields { rawFields[name.value] = value.base64 }
        try container.encode(rawFields, forKey: .fields)
        if let signature { try container.encode(Hex.encode(signature.derBytes), forKey: .signature) }
    }

}

package func certificateDecodeCanonicalBase64(_ text: String, maximum: Int) throws -> [UInt8] {
    do {
        let decoded = try Base64Encoding.decode(text, maximumDecodedByteCount: maximum)
        guard Base64Encoding.encode(decoded) == text else { throw CertificateError.invalidCanonicalBase64 }
        return decoded
    } catch let error as CertificateError {
        throw error
    } catch {
        throw CertificateError.invalidCanonicalBase64
    }
}

package func certificateCheckedAdd(_ value: Int, to total: inout Int) throws {
    let (sum, overflow) = total.addingReportingOverflow(value)
    guard value >= 0, !overflow else { throw CertificateError.sizeOverflow }
    total = sum
}

package func certificateBase64EncodedByteCount(_ decodedByteCount: Int) throws -> Int {
    guard decodedByteCount >= 0 else { throw CertificateError.sizeOverflow }
    let (plusTwo, additionOverflow) = decodedByteCount.addingReportingOverflow(2)
    let groups = plusTwo / 3
    let (encoded, multiplicationOverflow) = groups.multipliedReportingOverflow(by: 4)
    guard !additionOverflow, !multiplicationOverflow else { throw CertificateError.sizeOverflow }
    return encoded
}
