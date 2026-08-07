import BSVCore
import BSVCrypto

/// A stable error reported by bounded Base58Check decoding.
public enum Base58CheckError: Error, Equatable, Sendable {
    /// The caller supplied a payload limit outside `0...(Int.max - 4)`.
    case invalidMaximumPayloadByteCount
    /// The underlying Base58 text is invalid or exceeds the requested limit.
    case invalidEncoding(TextEncodingError)
    /// The decoded payload exceeds the caller's requested payload limit.
    case payloadSizeLimitExceeded(maximum: Int)
    /// The decoded value does not contain a complete four-byte checksum.
    case missingChecksum
    /// The decoded checksum does not match the payload.
    case checksumMismatch
}

/// Generic Bitcoin Base58Check encoding and bounded decoding.
public enum Base58Check {
    /// Encodes a payload followed by the first four bytes of its double-SHA-256 digest.
    public static func encode(_ payload: [UInt8]) -> String {
        let checksum = BSVHashing.sha256d(payload).bytes
        var checkedPayload = payload
        checkedPayload.append(contentsOf: checksum.prefix(4))
        return Base58.encode(checkedPayload)
    }

    /// Decodes and verifies Base58Check text within an explicit payload limit.
    public static func decode(
        _ text: String,
        maximumPayloadByteCount: Int
    ) throws -> [UInt8] {
        guard maximumPayloadByteCount >= 0,
              maximumPayloadByteCount <= Int.max - 4 else {
            throw Base58CheckError.invalidMaximumPayloadByteCount
        }

        let decoded: [UInt8]
        do {
            decoded = try Base58.decode(
                text,
                maximumDecodedByteCount: maximumPayloadByteCount + 4
            )
        } catch let error as TextEncodingError {
            if case .decodedSizeLimitExceeded = error {
                throw Base58CheckError.payloadSizeLimitExceeded(
                    maximum: maximumPayloadByteCount
                )
            }
            throw Base58CheckError.invalidEncoding(error)
        }

        guard decoded.count >= 4 else {
            throw Base58CheckError.missingChecksum
        }

        let payload = Array(decoded.dropLast(4))
        let expectedChecksum = BSVHashing.sha256d(payload).bytes
        var checksumDifference: UInt8 = 0
        for (actual, expected) in zip(decoded.suffix(4), expectedChecksum.prefix(4)) {
            checksumDifference |= actual ^ expected
        }
        guard checksumDifference == 0 else {
            throw Base58CheckError.checksumMismatch
        }
        return payload
    }
}
