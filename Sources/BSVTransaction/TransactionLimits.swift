/// Explicit hostile-input limits for transaction parsing and serialization.
///
/// Bitcoin SV does not impose one universal post-Genesis transaction-size
/// ceiling. Callers therefore choose limits appropriate to their environment.
public struct TransactionLimits: Hashable, Sendable {
    public let maximumTransactionByteCount: Int
    public let maximumInputCount: UInt64
    public let maximumOutputCount: UInt64
    public let maximumScriptByteCount: UInt64

    public init(
        maximumTransactionByteCount: Int,
        maximumInputCount: UInt64,
        maximumOutputCount: UInt64,
        maximumScriptByteCount: UInt64
    ) throws {
        guard maximumTransactionByteCount >= 0 else {
            throw TransactionError.invalidMaximumTransactionByteCount(
                maximumTransactionByteCount
            )
        }
        guard maximumInputCount <= UInt64(Int.max) else {
            throw TransactionError.invalidMaximumInputCount(maximumInputCount)
        }
        guard maximumOutputCount <= UInt64(Int.max) else {
            throw TransactionError.invalidMaximumOutputCount(maximumOutputCount)
        }
        guard maximumScriptByteCount <= UInt64(Int.max) else {
            throw TransactionError.invalidMaximumScriptByteCount(maximumScriptByteCount)
        }

        self.maximumTransactionByteCount = maximumTransactionByteCount
        self.maximumInputCount = maximumInputCount
        self.maximumOutputCount = maximumOutputCount
        self.maximumScriptByteCount = maximumScriptByteCount
    }
}
