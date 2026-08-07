/// Lowercase hexadecimal encoding and bounded ASCII hexadecimal decoding.
public enum Hex {
    private static let alphabet = Array("0123456789abcdef".utf8)

    /// Encodes bytes as lowercase hexadecimal.
    /// - Parameter bytes: The bytes to encode.
    /// - Returns: Two lowercase hexadecimal characters per input byte.
    public static func encode(_ bytes: [UInt8]) -> String {
        var encoded: [UInt8] = []
        encoded.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            encoded.append(alphabet[Int(byte >> 4)])
            encoded.append(alphabet[Int(byte & 0x0f)])
        }
        return String(decoding: encoded, as: UTF8.self)
    }

    /// Decodes upper- or lowercase ASCII hexadecimal within an explicit output limit.
    /// - Parameters:
    ///   - text: The hexadecimal text. Non-ASCII and non-hexadecimal bytes are rejected.
    ///   - maximumDecodedByteCount: The required nonnegative maximum output size.
    /// - Returns: The decoded bytes.
    public static func decode(
        _ text: String,
        maximumDecodedByteCount: Int
    ) throws -> [UInt8] {
        guard maximumDecodedByteCount >= 0 else {
            throw TextEncodingError.invalidMaximumDecodedByteCount
        }

        let byteCount = text.utf8.count
        for (index, byte) in text.utf8.enumerated() where nibble(for: byte) == nil {
            throw TextEncodingError.invalidCharacter(index: index)
        }
        guard byteCount.isMultiple(of: 2) else {
            throw TextEncodingError.oddLength
        }

        let decodedByteCount = byteCount / 2
        guard decodedByteCount <= maximumDecodedByteCount else {
            throw TextEncodingError.decodedSizeLimitExceeded(maximum: maximumDecodedByteCount)
        }

        var decoded: [UInt8] = []
        decoded.reserveCapacity(decodedByteCount)
        var highNibble: UInt8?
        for byte in text.utf8 {
            guard let nibble = nibble(for: byte) else {
                // The validation pass above makes this branch unreachable, but
                // decoding hostile input remains free of trapping operations.
                throw TextEncodingError.invalidCharacter(index: 0)
            }
            if let high = highNibble {
                decoded.append((high << 4) | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }
        return decoded
    }

    private static func nibble(for byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: byte - 48
        case 65...70: byte - 55
        case 97...102: byte - 87
        default: nil
        }
    }
}
