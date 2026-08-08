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
