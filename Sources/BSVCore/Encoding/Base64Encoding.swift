/// The RFC 4648 symbol alphabet used by Base64 encoding and decoding.
public enum Base64Alphabet: Sendable {
    /// The standard alphabet ending in `+` and `/`.
    case standard
    /// The URL-safe alphabet ending in `-` and `_`.
    case urlSafe
}

/// The Base64 terminal-padding policy.
public enum Base64Padding: Sendable {
    /// Emit and require `=` when the final quantum needs padding; no `=` is used for full quanta.
    case included
    /// Never emit or accept `=`; final two- or three-symbol quanta are accepted directly.
    case omitted
}

/// Strict, canonical RFC 4648 Base64 encoding and bounded decoding.
public enum Base64Encoding {
    private static let standardAlphabet = Array(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8
    )
    private static let urlSafeAlphabet = Array(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8
    )

    /// Encodes bytes using the selected alphabet and explicit padding policy.
    /// - Parameters:
    ///   - bytes: The bytes to encode.
    ///   - alphabet: The RFC 4648 symbol alphabet.
    ///   - padding: Whether terminal `=` characters are included or omitted.
    /// - Returns: The canonical Base64 text for the selected policies.
    public static func encode(
        _ bytes: [UInt8],
        alphabet: Base64Alphabet = .standard,
        padding: Base64Padding = .included
    ) -> String {
        let symbols = symbols(for: alphabet)
        let completeGroups = bytes.count / 3
        let remainder = bytes.count % 3
        let trailingCount: Int
        switch (remainder, padding) {
        case (0, _): trailingCount = 0
        case (_, .included): trailingCount = 4
        case (1, .omitted): trailingCount = 2
        case (2, .omitted): trailingCount = 3
        default: trailingCount = 0
        }

        var encoded: [UInt8] = []
        encoded.reserveCapacity(completeGroups * 4 + trailingCount)

        var offset = 0
        for _ in 0..<completeGroups {
            let first = bytes[offset]
            let second = bytes[offset + 1]
            let third = bytes[offset + 2]
            encoded.append(symbols[Int(first >> 2)])
            encoded.append(symbols[Int(((first & 0x03) << 4) | (second >> 4))])
            encoded.append(symbols[Int(((second & 0x0f) << 2) | (third >> 6))])
            encoded.append(symbols[Int(third & 0x3f)])
            offset += 3
        }

        if remainder == 1 {
            let first = bytes[offset]
            encoded.append(symbols[Int(first >> 2)])
            encoded.append(symbols[Int((first & 0x03) << 4)])
            if includesPadding(padding) {
                encoded.append(61)
                encoded.append(61)
            }
        } else if remainder == 2 {
            let first = bytes[offset]
            let second = bytes[offset + 1]
            encoded.append(symbols[Int(first >> 2)])
            encoded.append(symbols[Int(((first & 0x03) << 4) | (second >> 4))])
            encoded.append(symbols[Int((second & 0x0f) << 2)])
            if includesPadding(padding) {
                encoded.append(61)
            }
        }

        return String(decoding: encoded, as: UTF8.self)
    }

    /// Decodes strict Base64 within an explicit output limit.
    ///
    /// Whitespace and unknown characters are rejected. Final symbols must have zero
    /// discarded bits, and padding must exactly match the selected policy.
    /// - Parameters:
    ///   - text: The Base64 text to decode.
    ///   - alphabet: The only symbol alphabet accepted.
    ///   - padding: Whether required terminal padding is included or omitted.
    ///   - maximumDecodedByteCount: The required nonnegative maximum output size.
    /// - Returns: The decoded bytes.
    public static func decode(
        _ text: String,
        alphabet: Base64Alphabet = .standard,
        padding: Base64Padding = .included,
        maximumDecodedByteCount: Int
    ) throws -> [UInt8] {
        guard maximumDecodedByteCount >= 0 else {
            throw TextEncodingError.invalidMaximumDecodedByteCount
        }

        let encodedByteCount = text.utf8.count
        var paddingCount = 0
        var encounteredPadding = false
        var finalSextet: UInt8 = 0

        for (index, byte) in text.utf8.enumerated() {
            if byte == 61 {
                guard includesPadding(padding) else {
                    throw TextEncodingError.invalidPadding
                }
                guard index >= encodedByteCount - min(2, encodedByteCount) else {
                    throw TextEncodingError.invalidPadding
                }
                encounteredPadding = true
                paddingCount += 1
                continue
            }
            guard let value = sextet(for: byte, alphabet: alphabet) else {
                throw TextEncodingError.invalidCharacter(index: index)
            }
            guard !encounteredPadding else {
                throw TextEncodingError.invalidPadding
            }
            finalSextet = value
        }

        let remainder = encodedByteCount % 4
        switch padding {
        case .included:
            guard paddingCount <= 2 else {
                throw TextEncodingError.invalidPadding
            }
            if paddingCount > 0 {
                guard remainder == 0, encodedByteCount >= 4 else {
                    throw TextEncodingError.invalidPadding
                }
                let dataRemainder = (encodedByteCount - paddingCount) % 4
                guard
                    (paddingCount == 1 && dataRemainder == 3)
                        || (paddingCount == 2 && dataRemainder == 2)
                else {
                    throw TextEncodingError.invalidPadding
                }
            } else {
                if remainder == 1 {
                    throw TextEncodingError.invalidLength
                }
                guard remainder == 0 else {
                    throw TextEncodingError.invalidPadding
                }
            }
        case .omitted:
            if remainder == 1 {
                throw TextEncodingError.invalidLength
            }
        }

        let decodedByteCount: Int
        switch padding {
        case .included:
            decodedByteCount = (encodedByteCount / 4) * 3 - paddingCount
        case .omitted:
            decodedByteCount = (encodedByteCount / 4) * 3 + max(0, remainder - 1)
        }
        guard decodedByteCount <= maximumDecodedByteCount else {
            throw TextEncodingError.decodedSizeLimitExceeded(maximum: maximumDecodedByteCount)
        }

        if paddingCount == 2 || (omitsPadding(padding) && remainder == 2) {
            guard finalSextet & 0x0f == 0 else {
                throw TextEncodingError.nonCanonicalEncoding
            }
        } else if paddingCount == 1 || (omitsPadding(padding) && remainder == 3) {
            guard finalSextet & 0x03 == 0 else {
                throw TextEncodingError.nonCanonicalEncoding
            }
        }

        var decoded: [UInt8] = []
        decoded.reserveCapacity(decodedByteCount)
        var accumulator: UInt16 = 0
        var bitCount = 0
        for byte in text.utf8 where byte != 61 {
            guard let value = sextet(for: byte, alphabet: alphabet) else {
                // The validation pass above makes this branch unreachable, but
                // decoding hostile input remains free of trapping operations.
                throw TextEncodingError.invalidCharacter(index: 0)
            }
            accumulator = (accumulator << 6) | UInt16(value)
            bitCount += 6
            if bitCount >= 8 {
                bitCount -= 8
                decoded.append(UInt8((accumulator >> UInt16(bitCount)) & 0xff))
                if bitCount == 0 {
                    accumulator = 0
                } else {
                    accumulator &= UInt16((1 << bitCount) - 1)
                }
            }
        }
        return decoded
    }

    private static func symbols(for alphabet: Base64Alphabet) -> [UInt8] {
        switch alphabet {
        case .standard: standardAlphabet
        case .urlSafe: urlSafeAlphabet
        }
    }

    private static func sextet(for byte: UInt8, alphabet: Base64Alphabet) -> UInt8? {
        switch byte {
        case 65...90: byte - 65
        case 97...122: byte - 71
        case 48...57: byte + 4
        case 43:
            if case .standard = alphabet { 62 } else { nil }
        case 47:
            if case .standard = alphabet { 63 } else { nil }
        case 45:
            if case .urlSafe = alphabet { 62 } else { nil }
        case 95:
            if case .urlSafe = alphabet { 63 } else { nil }
        default: nil
        }
    }

    private static func includesPadding(_ padding: Base64Padding) -> Bool {
        if case .included = padding { true } else { false }
    }

    private static func omitsPadding(_ padding: Base64Padding) -> Bool {
        if case .omitted = padding { true } else { false }
    }
}
