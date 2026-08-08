/// Caller-selected resource limits for transaction JSON compatibility values.
public struct TransactionJSONLimits: Hashable, Sendable {
    public let maximumJSONByteCount: Int
    public let transactionLimits: TransactionLimits

    public init(
        maximumJSONByteCount: Int,
        transactionLimits: TransactionLimits
    ) throws {
        guard maximumJSONByteCount >= 0 else {
            throw TransactionJSONError.invalidMaximumJSONByteCount(maximumJSONByteCount)
        }
        self.maximumJSONByteCount = maximumJSONByteCount
        self.transactionLimits = transactionLimits
    }
}
