import BSVCore

/// Typed structural and resource failures for Bitcoin Script bytes.
public enum ScriptError: Error, Equatable, Sendable {
    case invalidMaximumScriptByteCount(Int)
    case invalidMaximumPushDataByteCount(Int)
    case scriptTooLarge(actual: Int, maximum: Int)
    case pushDataTooLarge(actual: Int, maximum: Int)
    case truncatedPushDataLength(offset: Int, expected: Int, remaining: Int)
    case truncatedPushData(offset: Int, expected: Int, remaining: Int)
    case pushDataLengthNotRepresentable(UInt32)
    case dataTooLargeForPush(actual: Int)
    case pushOpcodeRequiresData(Opcode)
    case invalidHex(TextEncodingError)
    case invalidMaximumASMByteCount(Int)
    /// The bounded scan stops as soon as `observedAtLeast` exceeds `maximum`.
    case asmTooLarge(observedAtLeast: Int, maximum: Int)
    /// Invalid ASCII spacing at a zero-based UTF-8 byte offset.
    case invalidASMSpacing(byteOffset: Int)
    /// Unknown token at a zero-based, space-delimited token index.
    case invalidASMToken(index: Int)
    /// Invalid hexadecimal data at a zero-based, space-delimited token index.
    case invalidASMData(index: Int, TextEncodingError)
    case asmOutputTooLarge(actual: Int, maximum: Int)
    case nonDataOperationInFalseReturn(index: Int, Opcode)
}
