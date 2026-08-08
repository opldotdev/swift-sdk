import BSVScript

/// Strict transaction JSON parsing and serialization failures.
public enum TransactionJSONError: Error, Equatable, Sendable {
    case invalidMaximumJSONByteCount(Int)
    case documentTooLarge(actual: Int, maximum: Int)
    case invalidUTF8
    case malformedJSON(offset: Int)
    case duplicateKey(String)
    case unknownKey(String)
    case missingKey(String)
    case nonCanonicalHex(field: String)
    case valueTooLarge(field: String, actual: Int, maximum: Int)
    case numberOutOfRange(field: String)
    case unsafeJSONNumber(field: String, value: UInt64)
    case inputCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case outputCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case transactionIDMismatch(expected: String, actual: String)
    case versionMismatch(expected: UInt32, actual: UInt32)
    case lockTimeMismatch(expected: UInt32, actual: UInt32)
    case inputMismatch(index: Int)
    case outputMismatch(index: Int)
    case transaction(TransactionError)
    case script(ScriptError)
}
