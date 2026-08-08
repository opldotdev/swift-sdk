/// Explicit hostile-input limits for BEEF and Atomic BEEF envelopes.
public struct BEEFLimits: Hashable, Sendable {
    public let maximumByteCount: Int
    public let maximumMerklePathCount: UInt64
    public let maximumTransactionCount: UInt64
    public let transactionLimits: TransactionLimits
    public let merklePathLimits: MerklePathLimits

    public init(
        maximumByteCount: Int,
        maximumMerklePathCount: UInt64,
        maximumTransactionCount: UInt64,
        transactionLimits: TransactionLimits,
        merklePathLimits: MerklePathLimits
    ) throws {
        guard maximumByteCount >= 0 else {
            throw BEEFError.invalidMaximumByteCount(maximumByteCount)
        }
        guard maximumMerklePathCount <= UInt64(Int.max) else {
            throw BEEFError.invalidMaximumMerklePathCount(maximumMerklePathCount)
        }
        guard maximumTransactionCount <= UInt64(Int.max) else {
            throw BEEFError.invalidMaximumTransactionCount(maximumTransactionCount)
        }

        self.maximumByteCount = maximumByteCount
        self.maximumMerklePathCount = maximumMerklePathCount
        self.maximumTransactionCount = maximumTransactionCount
        self.transactionLimits = transactionLimits
        self.merklePathLimits = merklePathLimits
    }
}
