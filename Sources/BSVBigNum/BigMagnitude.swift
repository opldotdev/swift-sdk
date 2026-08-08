import BigInt

/// A dependency-isolated, nonnegative arbitrary-precision integer.
///
/// Import, export, and every potentially expensive operation require an
/// explicit resource ceiling. The backing implementation is deliberately not
/// part of the SDK's public API and is variable-time.
package struct BigMagnitude: Hashable, Sendable {
    // Module-internal only: downstream package targets never see BigUInt.
    let storage: BigUInt

    package static let zero = BigMagnitude(storage: 0)
    package static let one = BigMagnitude(storage: 1)

    package init(_ value: UInt64) {
        storage = BigUInt(value)
    }

    package init(
        bigEndian bytes: [UInt8],
        maximumByteCount: Int
    ) throws {
        try self.init(
            bigEndian: bytes,
            maximumByteCount: maximumByteCount,
            constructionObserver: nil
        )
    }

    init(
        bigEndian bytes: [UInt8],
        maximumByteCount: Int,
        constructionObserver: (() -> Void)?
    ) throws {
        guard maximumByteCount >= 0 else {
            throw BigNumError.invalidLimit(maximumByteCount)
        }
        guard bytes.count <= maximumByteCount else {
            throw BigNumError.inputTooLarge(
                actual: bytes.count,
                maximum: maximumByteCount
            )
        }
        constructionObserver?()
        storage = bytes.withUnsafeBytes(BigUInt.init)
    }

    init(storage: BigUInt) {
        self.storage = storage
    }

    package var isZero: Bool { storage.isZero }
    package var bitWidth: Int { storage.bitWidth }
    package var byteCount: Int { (storage.bitWidth + 7) / 8 }

    package func compared(to other: Self) -> Int {
        if storage < other.storage { return -1 }
        if storage > other.storage { return 1 }
        return 0
    }

    package func bigEndianBytes(maximumByteCount: Int) throws -> [UInt8] {
        guard maximumByteCount >= 0 else {
            throw BigNumError.invalidLimit(maximumByteCount)
        }
        guard byteCount <= maximumByteCount else {
            throw BigNumError.resultTooLarge(
                estimated: byteCount,
                maximum: maximumByteCount
            )
        }
        let buffer = storage.serializeToBuffer()
        defer { buffer.deallocate() }
        return Array(buffer)
    }

    package func adding(
        _ other: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        try validateOperands(other, budget: budget)
        let (estimate, overflow) = max(byteCount, other.byteCount)
            .addingReportingOverflow(1)
        guard !overflow else {
            throw BigNumError.resultTooLarge(
                estimated: Int.max,
                maximum: budget.maximumResultByteCount
            )
        }
        try validateResultEstimate(estimate, budget: budget)
        return try checkedResult(storage + other.storage, budget: budget)
    }

    package func subtracting(
        _ other: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        try validateOperands(other, budget: budget)
        guard storage >= other.storage else {
            throw BigNumError.subtractionUnderflow
        }
        try validateResultEstimate(byteCount, budget: budget)
        return BigMagnitude(storage: storage - other.storage)
    }

    package func multiplied(
        by other: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        try validateOperands(other, budget: budget)
        let estimate = try estimatedSum(
            byteCount,
            other.byteCount,
            extra: 0,
            maximum: budget.maximumResultByteCount
        )
        try validateResultEstimate(estimate, budget: budget)
        return try checkedResult(storage * other.storage, budget: budget)
    }

    package func quotientAndRemainder(
        dividingBy divisor: Self,
        budget: BigNumOperationBudget
    ) throws -> (quotient: Self, remainder: Self) {
        try validateOperands(divisor, budget: budget)
        guard !divisor.isZero else {
            throw BigNumError.divisionByZero
        }
        try validateResultEstimate(byteCount, budget: budget)
        let result = storage.quotientAndRemainder(dividingBy: divisor.storage)
        return (
            BigMagnitude(storage: result.quotient),
            BigMagnitude(storage: result.remainder)
        )
    }

    package func shiftedLeft(
        by bitCount: Int,
        budget: BigNumOperationBudget
    ) throws -> Self {
        guard bitCount >= 0, bitCount <= budget.maximumShiftBitCount else {
            throw BigNumError.invalidShift(bitCount)
        }
        try validateOperand(byteCount, budget: budget)
        let (estimatedBits, overflow) = storage.bitWidth.addingReportingOverflow(bitCount)
        guard !overflow else {
            throw BigNumError.resultTooLarge(
                estimated: Int.max,
                maximum: budget.maximumResultByteCount
            )
        }
        let (roundedBits, roundingOverflow) = estimatedBits.addingReportingOverflow(7)
        guard !roundingOverflow else {
            throw BigNumError.resultTooLarge(
                estimated: Int.max,
                maximum: budget.maximumResultByteCount
            )
        }
        let estimatedBytes = roundedBits / 8
        try validateResultEstimate(estimatedBytes, budget: budget)
        return try checkedResult(storage << bitCount, budget: budget)
    }

    package func shiftedRight(
        by bitCount: Int,
        budget: BigNumOperationBudget
    ) throws -> Self {
        guard bitCount >= 0, bitCount <= budget.maximumShiftBitCount else {
            throw BigNumError.invalidShift(bitCount)
        }
        try validateOperand(byteCount, budget: budget)
        return BigMagnitude(storage: storage >> bitCount)
    }

    package func inverse(
        modulo modulus: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        try validateOperands(modulus, budget: budget)
        guard modulus.storage > 1 else {
            throw BigNumError.invalidModulus
        }
        try validateResultEstimate(modulus.byteCount, budget: budget)
        guard let inverse = storage.inverse(modulus.storage) else {
            throw BigNumError.notInvertible
        }
        return BigMagnitude(storage: inverse)
    }

    package func uint64() throws -> UInt64 {
        guard let value = UInt64(exactly: storage) else {
            throw BigNumError.nativeIntegerOverflow
        }
        return value
    }

    private func validateOperands(
        _ other: Self,
        budget: BigNumOperationBudget
    ) throws {
        try validateOperand(byteCount, budget: budget)
        try validateOperand(other.byteCount, budget: budget)
    }

    private func validateOperand(
        _ actual: Int,
        budget: BigNumOperationBudget
    ) throws {
        guard actual <= budget.maximumOperandByteCount else {
            throw BigNumError.operationBudgetExceeded(
                actual: actual,
                maximum: budget.maximumOperandByteCount
            )
        }
    }

    private func validateResultEstimate(
        _ estimate: Int,
        budget: BigNumOperationBudget
    ) throws {
        guard estimate <= budget.maximumResultByteCount else {
            throw BigNumError.resultTooLarge(
                estimated: estimate,
                maximum: budget.maximumResultByteCount
            )
        }
    }

    private func checkedResult(
        _ result: BigUInt,
        budget: BigNumOperationBudget
    ) throws -> Self {
        let value = BigMagnitude(storage: result)
        try validateResultEstimate(value.byteCount, budget: budget)
        return value
    }

    private func estimatedSum(
        _ lhs: Int,
        _ rhs: Int,
        extra: Int,
        maximum: Int
    ) throws -> Int {
        let (sum, firstOverflow) = lhs.addingReportingOverflow(rhs)
        let (estimate, secondOverflow) = sum.addingReportingOverflow(extra)
        guard !firstOverflow, !secondOverflow else {
            throw BigNumError.resultTooLarge(
                estimated: Int.max,
                maximum: maximum
            )
        }
        return estimate
    }
}
