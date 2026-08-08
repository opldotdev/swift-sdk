import BigInt

/// A signed arbitrary-precision value used for modular normalization.
package struct BigSigned: Hashable, Sendable {
    package enum Sign: Hashable, Sendable {
        case plus
        case minus
    }

    package let sign: Sign
    package let magnitude: BigMagnitude

    package init(sign: Sign, magnitude: BigMagnitude) {
        self.sign = magnitude.isZero ? .plus : sign
        self.magnitude = magnitude
    }

    package var isZero: Bool { magnitude.isZero }
    package var byteCount: Int { magnitude.byteCount }

    package func compared(to other: Self) -> Int {
        if sign != other.sign { return sign == .minus ? -1 : 1 }
        let magnitudeComparison = magnitude.compared(to: other.magnitude)
        return sign == .minus ? -magnitudeComparison : magnitudeComparison
    }

    package func negated() -> Self {
        Self(
            sign: isZero ? .plus : (sign == .plus ? .minus : .plus),
            magnitude: magnitude
        )
    }

    package func absoluteValue() -> Self {
        Self(sign: .plus, magnitude: magnitude)
    }

    package func adding(
        _ other: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        if sign == other.sign {
            return Self(
                sign: sign,
                magnitude: try magnitude.adding(other.magnitude, budget: budget)
            )
        }
        switch magnitude.compared(to: other.magnitude) {
        case 0:
            return Self(sign: .plus, magnitude: .zero)
        case 1:
            return Self(
                sign: sign,
                magnitude: try magnitude.subtracting(other.magnitude, budget: budget)
            )
        default:
            return Self(
                sign: other.sign,
                magnitude: try other.magnitude.subtracting(magnitude, budget: budget)
            )
        }
    }

    package func subtracting(
        _ other: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        try adding(other.negated(), budget: budget)
    }

    package func multiplied(
        by other: Self,
        budget: BigNumOperationBudget
    ) throws -> Self {
        Self(
            sign: sign == other.sign ? .plus : .minus,
            magnitude: try magnitude.multiplied(by: other.magnitude, budget: budget)
        )
    }

    package func quotientAndRemainder(
        dividingBy divisor: Self,
        budget: BigNumOperationBudget
    ) throws -> (quotient: Self, remainder: Self) {
        let values = try magnitude.quotientAndRemainder(
            dividingBy: divisor.magnitude,
            budget: budget
        )
        return (
            Self(
                sign: sign == divisor.sign ? .plus : .minus,
                magnitude: values.quotient
            ),
            Self(sign: sign, magnitude: values.remainder)
        )
    }

    package func shiftedLeft(
        by bitCount: Int,
        budget: BigNumOperationBudget
    ) throws -> Self {
        Self(
            sign: sign,
            magnitude: try magnitude.shiftedLeft(by: bitCount, budget: budget)
        )
    }

    /// Arithmetic right shift matching Go `big.Int.Rsh`, including floor
    /// behavior for negative values.
    package func shiftedRight(
        by bitCount: Int,
        budget: BigNumOperationBudget
    ) throws -> Self {
        let truncated = try magnitude.shiftedRight(by: bitCount, budget: budget)
        guard sign == .minus, !magnitude.isZero else {
            return Self(sign: sign, magnitude: truncated)
        }
        let restored = try truncated.shiftedLeft(by: bitCount, budget: budget)
        guard restored != magnitude else {
            return Self(sign: .minus, magnitude: truncated)
        }
        return Self(
            sign: .minus,
            magnitude: try truncated.adding(.one, budget: budget)
        )
    }

    /// Returns the canonical residue in `0..<modulus`, including for negative input.
    package func positiveModulo(
        _ modulus: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        guard !modulus.isZero else {
            throw BigNumError.divisionByZero
        }
        guard magnitude.byteCount <= budget.maximumOperandByteCount else {
            throw BigNumError.operationBudgetExceeded(
                actual: magnitude.byteCount,
                maximum: budget.maximumOperandByteCount
            )
        }
        guard modulus.byteCount <= budget.maximumOperandByteCount else {
            throw BigNumError.operationBudgetExceeded(
                actual: modulus.byteCount,
                maximum: budget.maximumOperandByteCount
            )
        }
        guard modulus.byteCount <= budget.maximumResultByteCount else {
            throw BigNumError.resultTooLarge(
                estimated: modulus.byteCount,
                maximum: budget.maximumResultByteCount
            )
        }

        let remainder = magnitude.storage % modulus.storage
        if sign == .minus, !remainder.isZero {
            return BigMagnitude(storage: modulus.storage - remainder)
        }
        return BigMagnitude(storage: remainder)
    }
}
