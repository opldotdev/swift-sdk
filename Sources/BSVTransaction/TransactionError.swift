import BSVCore

/// The wire field being decoded when a transaction failed structurally.
public enum TransactionField: String, Equatable, Sendable {
    case version
    case inputCount
    case previousTransactionID
    case previousOutputIndex
    case unlockingScript
    case sequence
    case outputCount
    case satoshis
    case lockingScript
    case lockTime
    case trailingBytes
}

/// Typed structural, representation, and resource failures for transactions.
public enum TransactionError: Error, Equatable, Sendable {
    case invalidMaximumTransactionByteCount(Int)
    case transactionTooLarge(actual: Int, maximum: Int)
    case invalidMaximumInputCount(UInt64)
    case invalidMaximumOutputCount(UInt64)
    case invalidMaximumScriptByteCount(UInt64)
    case inputCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case outputCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case countNotRepresentable(UInt64)
    case scriptTooLarge(actual: UInt64, maximum: UInt64)
    case malformed(field: TransactionField, offset: Int, cause: BinaryDecodingError)
    case invalidHex(TextEncodingError)
    case serializedSizeOverflow
    case invalidInputIndex(Int)
    case missingSourceOutput(inputIndex: Int)
    case sourceOutputIsNotPayToPublicKeyHash(inputIndex: Int)
    case privateKeyDoesNotMatchSourceOutput(inputIndex: Int)
    case satoshiTotalOverflow
    case outputSatoshisExceedInputs(inputs: UInt64, outputs: UInt64)
    case missingUnlockingScriptEstimate(inputIndex: Int)
    case invalidUnlockingScriptEstimate(inputIndex: Int, byteCount: Int)
    case unlockingScriptEstimateExceedsLimit(inputIndex: Int, actual: UInt64, maximum: UInt64)
    case feeCalculationOverflow
    case insufficientInputSatoshis(inputs: UInt64, outputs: UInt64, fee: UInt64)
}
