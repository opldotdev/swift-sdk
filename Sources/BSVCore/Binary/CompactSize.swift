/// Controls whether CompactSize decoding accepts nonminimal representations.
public enum CompactSizeCanonicality: Sendable {
    /// Reject nonminimal CompactSize representations.
    case required
    /// Accept nonminimal representations and report them through `isCanonical`.
    case permissive
}

/// A decoded CompactSize value and its representation metadata.
public struct DecodedCompactSize: Equatable, Sendable {
    /// The raw unsigned value, including `UInt64.max`.
    public let value: UInt64
    /// The number of bytes occupied by the decoded representation.
    public let bytesConsumed: Int
    /// Whether the decoded representation was minimal.
    public let isCanonical: Bool
}

/// A decoded CompactSize-prefixed byte sequence.
public struct DecodedVarBytes: Equatable, Sendable {
    /// The decoded payload bytes.
    public let bytes: [UInt8]
    /// The combined number of bytes occupied by the length and payload.
    public let bytesConsumed: Int
    /// Whether the length prefix was minimally encoded.
    public let isCanonical: Bool
}

/// Canonical Bitcoin CompactSize and VarBytes encoding operations.
public enum CompactSize {
    /// Returns the canonical encoded width of `value`.
    public static func encodedLength(of value: UInt64) -> Int {
        switch value {
        case 0...0xfc: 1
        case 0xfd...0xffff: 3
        case 0x1_0000...0xffff_ffff: 5
        default: 9
        }
    }

    /// Encodes `value` using its canonical CompactSize representation.
    public static func encode(_ value: UInt64) -> [UInt8] {
        var writer = ByteWriter()
        writer.writeCompactSize(value)
        return writer.bytes
    }

    /// Decodes exactly one CompactSize value and rejects trailing bytes.
    ///
    /// Required mode rejects nonminimal input. Permissive mode returns the raw
    /// value and reports whether the representation was canonical.
    public static func decode(
        _ bytes: [UInt8],
        canonicality: CompactSizeCanonicality = .required
    ) throws -> DecodedCompactSize {
        var cursor = ByteCursor(bytes)
        let decoded = try cursor.readCompactSize(canonicality: canonicality)
        try cursor.requireFinished()
        return decoded
    }

    /// Encodes bytes prefixed by their canonical CompactSize length.
    public static func encodeVarBytes(_ bytes: [UInt8]) -> [UInt8] {
        var writer = ByteWriter()
        writer.writeVarBytes(bytes)
        return writer.bytes
    }

    /// Decodes exactly one CompactSize-prefixed byte sequence.
    ///
    /// The declared length is checked against `maximumLength` and native
    /// collection representability before payload allocation or copying.
    /// Trailing bytes are rejected.
    public static func decodeVarBytes(
        _ encoded: [UInt8],
        maximumLength: UInt64,
        canonicality: CompactSizeCanonicality = .required
    ) throws -> DecodedVarBytes {
        var cursor = ByteCursor(encoded)
        let decoded = try cursor.readVarBytes(
            maximumLength: maximumLength,
            canonicality: canonicality
        )
        try cursor.requireFinished()
        return decoded
    }
}
