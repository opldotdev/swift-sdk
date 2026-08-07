/// Bitcoin-alphabet Base58 encoding and bounded decoding.
public enum Base58 {
    private static let alphabet = Array(
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8
    )

    /// Encodes bytes with the Bitcoin Base58 alphabet, preserving each leading zero as `1`.
    /// - Parameter bytes: The bytes to encode.
    /// - Returns: The Bitcoin Base58 text.
    public static func encode(_ bytes: [UInt8]) -> String {
        let leadingZeroCount = bytes.prefix { $0 == 0 }.count
        guard leadingZeroCount < bytes.count else {
            return String(repeating: "1", count: leadingZeroCount)
        }

        let significantByteCount = bytes.count - leadingZeroCount
        let capacity = scaledCeiling(significantByteCount, numerator: 138, denominator: 100)
        var digits = [UInt8](repeating: 0, count: capacity)
        var digitCount = 0

        for byte in bytes.dropFirst(leadingZeroCount) {
            var carry = Int(byte)
            var processed = 0
            var index = digits.count - 1
            while carry != 0 || processed < digitCount {
                carry += Int(digits[index]) * 256
                digits[index] = UInt8(carry % 58)
                carry /= 58
                processed += 1
                index -= 1
            }
            digitCount = processed
        }

        var encoded: [UInt8] = []
        encoded.reserveCapacity(leadingZeroCount + digitCount)
        encoded.append(contentsOf: repeatElement(49, count: leadingZeroCount))
        for digit in digits.suffix(digitCount) {
            encoded.append(alphabet[Int(digit)])
        }
        return String(decoding: encoded, as: UTF8.self)
    }

    /// Decodes Bitcoin Base58 within an explicit output limit.
    /// - Parameters:
    ///   - text: Bitcoin Base58 text with no whitespace or non-alphabet characters.
    ///   - maximumDecodedByteCount: The required nonnegative maximum output size.
    /// - Returns: The decoded bytes, including every leading zero represented by `1`.
    public static func decode(
        _ text: String,
        maximumDecodedByteCount: Int
    ) throws -> [UInt8] {
        guard maximumDecodedByteCount >= 0 else {
            throw TextEncodingError.invalidMaximumDecodedByteCount
        }

        var leadingZeroCount = 0
        var significantDigitCount = 0
        var foundSignificantDigit = false
        for (index, byte) in text.utf8.enumerated() {
            guard digit(for: byte) != nil else {
                throw TextEncodingError.invalidCharacter(index: index)
            }
            if !foundSignificantDigit && byte == 49 {
                leadingZeroCount += 1
            } else {
                foundSignificantDigit = true
                significantDigitCount += 1
            }
        }

        guard leadingZeroCount <= maximumDecodedByteCount else {
            throw TextEncodingError.decodedSizeLimitExceeded(maximum: maximumDecodedByteCount)
        }
        guard significantDigitCount > 0 else {
            return [UInt8](repeating: 0, count: leadingZeroCount)
        }

        let significantByteLimit = maximumDecodedByteCount - leadingZeroCount
        guard significantByteLimit > 0 else {
            throw TextEncodingError.decodedSizeLimitExceeded(maximum: maximumDecodedByteCount)
        }

        // 137/100 is a safe upper bound for log(256)/log(58). Any longer
        // string cannot fit in the configured number of significant bytes.
        let maximumPossibleDigits = scaledCeiling(
            significantByteLimit,
            numerator: 137,
            denominator: 100
        )
        guard significantDigitCount <= maximumPossibleDigits else {
            throw TextEncodingError.decodedSizeLimitExceeded(maximum: maximumDecodedByteCount)
        }

        // 733/1000 is a safe upper bound for log(58)/log(256). The conversion
        // workspace is additionally capped by the caller's decoded-byte limit.
        let naturalCapacity = scaledCeiling(
            significantDigitCount,
            numerator: 733,
            denominator: 1000
        )
        let capacity = min(significantByteLimit, naturalCapacity)
        var bytes = [UInt8](repeating: 0, count: capacity)
        var byteCount = 0

        for byte in text.utf8.dropFirst(leadingZeroCount) {
            guard let value = digit(for: byte) else {
                // The validation pass above makes this branch unreachable, but
                // decoding hostile input remains free of trapping operations.
                throw TextEncodingError.invalidCharacter(index: 0)
            }
            var carry = Int(value)
            var processed = 0
            var index = bytes.count - 1
            while (carry != 0 || processed < byteCount) && index >= 0 {
                carry += Int(bytes[index]) * 58
                bytes[index] = UInt8(carry & 0xff)
                carry >>= 8
                processed += 1
                index -= 1
            }
            guard carry == 0 else {
                throw TextEncodingError.decodedSizeLimitExceeded(maximum: maximumDecodedByteCount)
            }
            byteCount = processed
        }

        var decoded: [UInt8] = []
        decoded.reserveCapacity(leadingZeroCount + byteCount)
        decoded.append(contentsOf: repeatElement(0, count: leadingZeroCount))
        decoded.append(contentsOf: bytes.suffix(byteCount))
        return decoded
    }

    private static func scaledCeiling(
        _ value: Int,
        numerator: Int,
        denominator: Int
    ) -> Int {
        let (whole, wholeOverflow) = (value / denominator)
            .multipliedReportingOverflow(by: numerator)
        guard !wholeOverflow else { return .max }
        let remainderProduct = (value % denominator) * numerator
        let remainder = (remainderProduct + denominator - 1) / denominator
        let (result, resultOverflow) = whole.addingReportingOverflow(remainder)
        return resultOverflow ? .max : result
    }

    private static func digit(for byte: UInt8) -> UInt8? {
        switch byte {
        case 49...57: byte - 49
        case 65...72: byte - 56
        case 74...78: byte - 57
        case 80...90: byte - 58
        case 97...107: byte - 64
        case 109...122: byte - 65
        default: nil
        }
    }
}
