/// Failures while parsing or serializing Bitcoin Script numbers.
public enum ScriptNumberError: Error, Equatable, Sendable {
    /// A byte-count ceiling was negative.
    case invalidMaximumByteCount(Int)

    /// The encoded number is larger than the active consensus/resource limit.
    case numberTooLarge(actual: Int, maximum: Int)

    /// The byte string uses redundant sign/zero bytes or negative zero.
    case nonMinimalEncoding
}
