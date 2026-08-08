import BSVTransaction

/// Transaction state required by signature and lock-time opcodes.
///
/// The value is intentionally all-or-nothing: an interpreter never executes a
/// signature opcode with only a transaction, amount, or locking script.
public struct ScriptExecutionContext: Hashable, Sendable {
    public let transaction: Transaction
    public let inputIndex: Int
    public let spentOutput: TransactionOutput
    public let transactionLimits: TransactionLimits

    public init(
        transaction: Transaction,
        inputIndex: Int,
        spentOutput: TransactionOutput,
        transactionLimits: TransactionLimits
    ) {
        self.transaction = transaction
        self.inputIndex = inputIndex
        self.spentOutput = spentOutput
        self.transactionLimits = transactionLimits
    }
}

public struct ScriptExecutionResult: Hashable, Sendable {
    /// Final primary stack, ordered from bottom to top.
    public let stack: [[UInt8]]
    public let operationCount: Int
    public let didEarlyReturn: Bool

    public init(
        stack: [[UInt8]],
        operationCount: Int,
        didEarlyReturn: Bool
    ) {
        self.stack = stack
        self.operationCount = operationCount
        self.didEarlyReturn = didEarlyReturn
    }
}
