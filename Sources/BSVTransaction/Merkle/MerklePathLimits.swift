/// Explicit hostile-input limits for BRC-74 parsing and serialization.
public struct MerklePathLimits: Hashable, Sendable {
    public let maximumByteCount: Int
    public let maximumLeavesPerLevel: UInt64
    public let maximumTotalLeaves: UInt64

    public init(
        maximumByteCount: Int,
        maximumLeavesPerLevel: UInt64,
        maximumTotalLeaves: UInt64
    ) throws {
        guard maximumByteCount >= 0 else {
            throw MerklePathError.invalidMaximumByteCount(maximumByteCount)
        }
        guard maximumLeavesPerLevel <= UInt64(Int.max) else {
            throw MerklePathError.invalidMaximumLeavesPerLevel(maximumLeavesPerLevel)
        }
        guard maximumTotalLeaves <= UInt64(Int.max) else {
            throw MerklePathError.invalidMaximumTotalLeaves(maximumTotalLeaves)
        }

        self.maximumByteCount = maximumByteCount
        self.maximumLeavesPerLevel = maximumLeavesPerLevel
        self.maximumTotalLeaves = maximumTotalLeaves
    }
}
