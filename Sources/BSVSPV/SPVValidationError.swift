import BSVCore
import BSVInterpreter

/// A complete BRC-67 validation failure after an envelope has been decoded.
public enum SPVValidationError: Error, Equatable, Sendable {
    case rootTransactionMissing(TransactionID)
    case rootTransactionIDOnly(TransactionID)
    case missingSourceTransaction(
        transactionID: TransactionID,
        inputIndex: Int,
        sourceTransactionID: TransactionID
    )
    case sourceOutputIndexOutOfBounds(
        transactionID: TransactionID,
        inputIndex: Int,
        sourceTransactionID: TransactionID,
        outputIndex: UInt32,
        outputCount: Int
    )
    case satoshiTotalOverflow(transactionID: TransactionID)
    case outputsExceedInputs(
        transactionID: TransactionID,
        inputs: UInt64,
        outputs: UInt64
    )
    case nonPositiveFee(transactionID: TransactionID, satoshis: UInt64)
    case feeTooLow(paid: UInt64, required: UInt64)
    case scriptVerificationFailed(
        transactionID: TransactionID,
        inputIndex: Int,
        cause: ScriptExecutionError
    )
}
