import BSVBigNum
import Testing

@Suite("Signed modular normalization")
struct BigSignedTests {
    private func magnitude(_ value: UInt8) throws -> BigMagnitude {
        try BigMagnitude(bigEndian: [value], maximumByteCount: 1)
    }

    private func budget(_ maximum: Int = 8) throws -> BigNumOperationBudget {
        try BigNumOperationBudget(
            maximumOperandByteCount: maximum,
            maximumResultByteCount: maximum,
            maximumShiftBitCount: 64
        )
    }

    @Test("Positive modulo matches Euclidean residues")
    func positiveModulo() throws {
        let modulus = try magnitude(5)
        let positive = BigSigned(sign: .plus, magnitude: try magnitude(7))
        let negative = BigSigned(sign: .minus, magnitude: try magnitude(7))
        let exactNegative = BigSigned(sign: .minus, magnitude: try magnitude(10))

        #expect(try positive.positiveModulo(modulus, budget: budget()).uint64() == 2)
        #expect(try negative.positiveModulo(modulus, budget: budget()).uint64() == 3)
        #expect(try exactNegative.positiveModulo(modulus, budget: budget()).uint64() == 0)
    }

    @Test("Negative zero canonicalizes to positive zero")
    func negativeZero() {
        let value = BigSigned(sign: .minus, magnitude: .zero)
        #expect(value.sign == .plus)
        #expect(value.magnitude == .zero)
    }

    @Test("Modulo failures are typed and bounded")
    func failures() throws {
        let value = BigSigned(sign: .plus, magnitude: try magnitude(9))
        #expect(throws: BigNumError.divisionByZero) {
            try value.positiveModulo(.zero, budget: budget())
        }
        #expect(
            throws: BigNumError.operationBudgetExceeded(actual: 1, maximum: 0)
        ) {
            try value.positiveModulo(try magnitude(5), budget: budget(0))
        }
    }
}
