/// Errors produced while decoding bounded binary values.
public enum BinaryDecodingError: Error, Equatable, Sendable {
    /// A package-level read was requested with a negative byte count.
    case invalidCount(Int)
    /// Fewer bytes remain than the exact count requested.
    case truncatedInput(expected: Int, remaining: Int)
    /// A full-input decoder completed a value with the reported bytes left over.
    case trailingBytes(Int)
    /// CompactSize used a wider representation than its value requires.
    case nonCanonicalCompactSize
    /// A declared length exceeds the maximum accepted by the caller.
    case lengthExceedsLimit(length: UInt64, maximum: UInt64)
    /// A declared length cannot be represented by the native collection index type.
    case lengthNotRepresentable(UInt64)
}
