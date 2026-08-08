import Foundation
import BSVCore
import BSVKeys
import BSVTransaction

extension Certificate {
    /// Parses one complete BRC-52 JSON certificate without first materializing
    /// an unbounded Foundation object graph. Duplicate and unknown object keys
    /// are rejected before their values are accepted.
    public init(json data: Data, limits: CertificateLimits = .standard) throws {
        guard data.count <= limits.maximumJSONByteCount else {
            throw CertificateError.certificateJSONTooLarge(
                actual: data.count,
                maximum: limits.maximumJSONByteCount
            )
        }
        self = try data.withUnsafeBytes { bytes in
            var parser = CertificateJSONParser(bytes: bytes, limits: limits)
            return try parser.parse()
        }
    }

    /// Parses one complete BRC-52 JSON certificate from UTF-8 bytes.
    public init(json bytes: [UInt8], limits: CertificateLimits = .standard) throws {
        guard bytes.count <= limits.maximumJSONByteCount else {
            throw CertificateError.certificateJSONTooLarge(
                actual: bytes.count,
                maximum: limits.maximumJSONByteCount
            )
        }
        self = try bytes.withUnsafeBytes { buffer in
            var parser = CertificateJSONParser(bytes: buffer, limits: limits)
            return try parser.parse()
        }
    }

    /// Returns the stable JSON representation used by the BRC-52 model.
    public func jsonData(limits: CertificateLimits = .standard) throws -> Data {
        _ = try Certificate(
            type: type,
            serialNumber: serialNumber,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: revocationOutpoint,
            fields: fields,
            signature: signature,
            limits: limits
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard data.count <= limits.maximumJSONByteCount else {
            throw CertificateError.certificateJSONTooLarge(
                actual: data.count,
                maximum: limits.maximumJSONByteCount
            )
        }
        return data
    }

    /// Returns the stable JSON representation as UTF-8 bytes.
    public func jsonBytes(limits: CertificateLimits = .standard) throws -> [UInt8] {
        Array(try jsonData(limits: limits))
    }
}

private struct CertificateJSONParser {
    private enum Member: String {
        case type
        case serialNumber
        case subject
        case certifier
        case revocationOutpoint
        case fields
        case signature
    }

    private let bytes: UnsafeRawBufferPointer
    private let limits: CertificateLimits
    private var offset = 0

    init(bytes: UnsafeRawBufferPointer, limits: CertificateLimits) {
        self.bytes = bytes
        self.limits = limits
    }

    mutating func parse() throws -> Certificate {
        try skipWhitespace()
        try consume(0x7b)
        var seen = Set<Member>()
        var typeText: String?
        var serialText: String?
        var subjectText: String?
        var certifierText: String?
        var revocationText: String?
        var fields: [CertificateFieldName: CertificateCiphertext]?
        var signatureText: String?

        try skipWhitespace()
        if consumeIfPresent(0x7d) {
            throw CertificateError.invalidJSON
        }
        while true {
            let key = try parseString(maximumUTF8ByteCount: 18) { _ in .invalidJSON }
            guard let member = Member(rawValue: key), seen.insert(member).inserted else {
                throw CertificateError.invalidJSON
            }
            try skipWhitespace()
            try consume(0x3a)
            try skipWhitespace()
            switch member {
            case .type:
                typeText = try parseString(maximumUTF8ByteCount: 44) { _ in .invalidJSON }
            case .serialNumber:
                serialText = try parseString(maximumUTF8ByteCount: 44) { _ in .invalidJSON }
            case .subject:
                subjectText = try parseString(maximumUTF8ByteCount: 66) { _ in .invalidJSON }
            case .certifier:
                certifierText = try parseString(maximumUTF8ByteCount: 66) { _ in .invalidJSON }
            case .revocationOutpoint:
                revocationText = try parseString(maximumUTF8ByteCount: 75) { _ in
                    .invalidRevocationOutpoint
                }
            case .fields:
                fields = try parseFields()
            case .signature:
                if nextByte == 0x6e {
                    try parseNull()
                    signatureText = nil
                } else {
                    signatureText = try parseString(maximumUTF8ByteCount: 144) { _ in
                        .invalidSignature
                    }
                }
            }
            try skipWhitespace()
            if consumeIfPresent(0x7d) { break }
            try consume(0x2c)
            try skipWhitespace()
        }
        try skipWhitespace()
        guard offset == bytes.count,
              let typeText,
              let serialText,
              let subjectText,
              let certifierText,
              let revocationText,
              let fields else {
            throw CertificateError.invalidJSON
        }

        let type = try CertificateTypeID(base64: typeText)
        let serial = try CertificateSerialNumber(base64: serialText)
        let subject = try decodePublicKey(subjectText)
        let certifier = try decodePublicKey(certifierText)
        let revocation: Outpoint
        do {
            revocation = try Outpoint(revocationText)
        } catch {
            throw CertificateError.invalidRevocationOutpoint
        }
        let signature: ECDSASignature?
        if let signatureText {
            do {
                let signatureBytes = try Hex.decode(
                    signatureText,
                    maximumDecodedByteCount: 72
                )
                guard Hex.encode(signatureBytes) == signatureText else {
                    throw CertificateError.invalidSignature
                }
                let decoded = try ECDSASignature(derBytes: signatureBytes)
                guard decoded.derBytes == signatureBytes else {
                    throw CertificateError.invalidSignature
                }
                signature = decoded
            } catch {
                throw CertificateError.invalidSignature
            }
        } else {
            signature = nil
        }
        return try Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: revocation,
            fields: fields,
            signature: signature,
            limits: limits
        )
    }

    private mutating func parseFields() throws
        -> [CertificateFieldName: CertificateCiphertext] {
        try consume(0x7b)
        var result: [CertificateFieldName: CertificateCiphertext] = [:]
        var seen = Set<String>()
        try skipWhitespace()
        if consumeIfPresent(0x7d) { return result }
        let maximumNameByteCount = limits.maximumFieldNameUTF8ByteCount
        let maximumCiphertextByteCount = limits.maximumFieldCiphertextByteCount
        let maximumCiphertextBase64ByteCount =
            limits.maximumFieldCiphertextBase64UTF8ByteCount
        while true {
            let nameText = try parseString(
                maximumUTF8ByteCount: maximumNameByteCount
            ) { actual in
                .fieldNameTooLong(
                    actual: actual,
                    maximum: maximumNameByteCount
                )
            }
            guard seen.insert(nameText).inserted else {
                throw CertificateError.duplicateFieldName
            }
            guard seen.count <= limits.maximumFieldCount else {
                throw CertificateError.tooManyFields(
                    actual: seen.count,
                    maximum: limits.maximumFieldCount
                )
            }
            try skipWhitespace()
            try consume(0x3a)
            try skipWhitespace()
            let valueText = try parseString(
                maximumUTF8ByteCount: maximumCiphertextBase64ByteCount
            ) { _ in
                .fieldValueTooLarge(
                    actual: maximumCiphertextByteCount + 1,
                    maximum: maximumCiphertextByteCount
                )
            }
            let name = try CertificateFieldName(nameText, limits: limits)
            let value = try CertificateCiphertext(
                base64: valueText,
                maximumByteCount: maximumCiphertextByteCount
            )
            result[name] = value
            try skipWhitespace()
            if consumeIfPresent(0x7d) { break }
            try consume(0x2c)
            try skipWhitespace()
        }
        return result
    }

    private func decodePublicKey(_ text: String) throws -> PublicKey {
        do {
            let keyBytes = try Hex.decode(text, maximumDecodedByteCount: 33)
            guard keyBytes.count == 33, Hex.encode(keyBytes) == text else {
                throw CertificateError.invalidPublicKey
            }
            let publicKey = try PublicKey(keyBytes)
            guard publicKey.compressedBytes == keyBytes else {
                throw CertificateError.invalidPublicKey
            }
            return publicKey
        } catch {
            throw CertificateError.invalidPublicKey
        }
    }

    private mutating func parseString(
        maximumUTF8ByteCount maximum: Int,
        tooLarge: (Int) -> CertificateError
    ) throws -> String {
        try consume(0x22)
        var decoded: [UInt8] = []
        decoded.reserveCapacity(min(maximum, 144))
        while offset < bytes.count {
            let byte = bytes[offset]
            offset += 1
            switch byte {
            case 0x22:
                guard let text = String(bytes: decoded, encoding: .utf8) else {
                    throw CertificateError.invalidJSON
                }
                return text
            case 0x00...0x1f:
                throw CertificateError.invalidJSON
            case 0x5c:
                guard offset < bytes.count else { throw CertificateError.invalidJSON }
                let escaped = bytes[offset]
                offset += 1
                switch escaped {
                case 0x22, 0x2f, 0x5c:
                    try append(escaped, to: &decoded, maximum: maximum, tooLarge: tooLarge)
                case 0x62:
                    try append(0x08, to: &decoded, maximum: maximum, tooLarge: tooLarge)
                case 0x66:
                    try append(0x0c, to: &decoded, maximum: maximum, tooLarge: tooLarge)
                case 0x6e:
                    try append(0x0a, to: &decoded, maximum: maximum, tooLarge: tooLarge)
                case 0x72:
                    try append(0x0d, to: &decoded, maximum: maximum, tooLarge: tooLarge)
                case 0x74:
                    try append(0x09, to: &decoded, maximum: maximum, tooLarge: tooLarge)
                case 0x75:
                    let first = try parseHexQuad()
                    let scalarValue: UInt32
                    if (0xd800...0xdbff).contains(first) {
                        guard offset + 2 <= bytes.count,
                              bytes[offset] == 0x5c,
                              bytes[offset + 1] == 0x75 else {
                            throw CertificateError.invalidJSON
                        }
                        offset += 2
                        let second = try parseHexQuad()
                        guard (0xdc00...0xdfff).contains(second) else {
                            throw CertificateError.invalidJSON
                        }
                        scalarValue = 0x10000
                            + ((UInt32(first) - 0xd800) << 10)
                            + (UInt32(second) - 0xdc00)
                    } else {
                        guard !(0xdc00...0xdfff).contains(first) else {
                            throw CertificateError.invalidJSON
                        }
                        scalarValue = UInt32(first)
                    }
                    guard let scalar = Unicode.Scalar(scalarValue) else {
                        throw CertificateError.invalidJSON
                    }
                    for utf8Byte in scalar.utf8 {
                        try append(
                            utf8Byte,
                            to: &decoded,
                            maximum: maximum,
                            tooLarge: tooLarge
                        )
                    }
                default:
                    throw CertificateError.invalidJSON
                }
            default:
                try append(byte, to: &decoded, maximum: maximum, tooLarge: tooLarge)
            }
        }
        throw CertificateError.invalidJSON
    }

    private mutating func parseHexQuad() throws -> UInt16 {
        guard offset + 4 <= bytes.count else { throw CertificateError.invalidJSON }
        var value: UInt16 = 0
        for _ in 0..<4 {
            let byte = bytes[offset]
            offset += 1
            let digit: UInt16
            switch byte {
            case 0x30...0x39: digit = UInt16(byte - 0x30)
            case 0x41...0x46: digit = UInt16(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt16(byte - 0x61 + 10)
            default: throw CertificateError.invalidJSON
            }
            value = (value << 4) | digit
        }
        return value
    }

    private func append(
        _ byte: UInt8,
        to decoded: inout [UInt8],
        maximum: Int,
        tooLarge: (Int) -> CertificateError
    ) throws {
        guard decoded.count < maximum else { throw tooLarge(decoded.count + 1) }
        decoded.append(byte)
    }

    private mutating func parseNull() throws {
        for expected in [UInt8]("null".utf8) { try consume(expected) }
    }

    private mutating func skipWhitespace() throws {
        while let byte = nextByte, byte == 0x20 || byte == 0x09
            || byte == 0x0a || byte == 0x0d {
            offset += 1
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard offset < bytes.count, bytes[offset] == expected else {
            throw CertificateError.invalidJSON
        }
        offset += 1
    }

    private mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard offset < bytes.count, bytes[offset] == expected else { return false }
        offset += 1
        return true
    }

    private var nextByte: UInt8? {
        offset < bytes.count ? bytes[offset] : nil
    }
}
