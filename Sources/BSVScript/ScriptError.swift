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
}
