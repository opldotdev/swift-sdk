/// A stable error reported by the bounded text decoders in `BSVCore`.
public enum TextEncodingError: Error, Equatable, Sendable {
    /// The input contains an unsupported byte at the zero-based UTF-8 byte offset.
    case invalidCharacter(index: Int)
    /// A hexadecimal input contains an odd number of digits.
    case oddLength
    /// The encoded length cannot represent a complete value under the selected policy.
    case invalidLength
    /// Base64 padding is missing, excessive, misplaced, or forbidden by the selected policy.
    case invalidPadding
    /// Base64's final symbol contains non-zero discarded bits.
    case nonCanonicalEncoding
    /// The caller supplied a negative maximum decoded byte count.
    case invalidMaximumDecodedByteCount
    /// The decoded output would exceed the caller's explicit byte limit.
    case decodedSizeLimitExceeded(maximum: Int)
}
