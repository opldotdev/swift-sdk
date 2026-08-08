/// Explicit resource ceilings for potentially expensive big-number operations.
package struct BigNumOperationBudget: Equatable, Sendable {
    package let maximumOperandByteCount: Int
    package let maximumResultByteCount: Int
    package let maximumShiftBitCount: Int

    package init(
        maximumOperandByteCount: Int,
        maximumResultByteCount: Int,
        maximumShiftBitCount: Int
    ) throws {
        guard maximumOperandByteCount >= 0 else {
            throw BigNumError.invalidLimit(maximumOperandByteCount)
        }
        guard maximumResultByteCount >= 0 else {
            throw BigNumError.invalidLimit(maximumResultByteCount)
        }
        guard maximumShiftBitCount >= 0 else {
            throw BigNumError.invalidLimit(maximumShiftBitCount)
        }
        self.maximumOperandByteCount = maximumOperandByteCount
        self.maximumResultByteCount = maximumResultByteCount
        self.maximumShiftBitCount = maximumShiftBitCount
    }
}
