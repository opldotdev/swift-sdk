@testable import BSVBigNum
import Testing

@Suite("Bounded arbitrary-precision magnitude")
struct BigMagnitudeTests {
    private func budget(
        operands: Int = 64,
        results: Int = 64,
        shifts: Int = 512
    ) throws -> BigNumOperationBudget {
        try BigNumOperationBudget(
            maximumOperandByteCount: operands,
            maximumResultByteCount: results,
            maximumShiftBitCount: shifts
        )
    }

    private func value(_ bytes: [UInt8], maximum: Int = 64) throws -> BigMagnitude {
        try BigMagnitude(bigEndian: bytes, maximumByteCount: maximum)
    }

    @Test("Import and export are canonical and bounded")
    func boundedImportExport() throws {
        let zero = try value([])
        #expect(zero.isZero)
        #expect(zero.bitWidth == 0)
        #expect(zero.byteCount == 0)
        #expect(try zero.bigEndianBytes(maximumByteCount: 0) == [])

        let leadingZero = try value([0, 0, 1, 2, 3])
        #expect(leadingZero.byteCount == 3)
        #expect(try leadingZero.bigEndianBytes(maximumByteCount: 3) == [1, 2, 3])

        #expect(throws: BigNumError.invalidLimit(-1)) {
            try BigMagnitude(bigEndian: [], maximumByteCount: -1)
        }
        #expect(throws: BigNumError.inputTooLarge(actual: 2, maximum: 1)) {
            try BigMagnitude(bigEndian: [1, 2], maximumByteCount: 1)
        }
        #expect(throws: BigNumError.resultTooLarge(estimated: 3, maximum: 2)) {
            try leadingZero.bigEndianBytes(maximumByteCount: 2)
        }
    }

    @Test("Oversized input is rejected before dependency construction")
    func rejectionPrecedesConstruction() {
        var constructed = false
        #expect(throws: BigNumError.inputTooLarge(actual: 3, maximum: 2)) {
            try BigMagnitude(
                bigEndian: [1, 2, 3],
                maximumByteCount: 2,
                constructionObserver: { constructed = true }
            )
        }
        #expect(!constructed)
    }

    @Test("Arithmetic and shifts have exact values")
    func arithmetic() throws {
        let lhs = try value([0x01, 0x00])
        let rhs = try value([0x03])
        let operationBudget = try budget()

        #expect(try lhs.adding(rhs, budget: operationBudget).uint64() == 259)
        #expect(try lhs.subtracting(rhs, budget: operationBudget).uint64() == 253)
        #expect(try lhs.multiplied(by: rhs, budget: operationBudget).uint64() == 768)

        let division = try lhs.quotientAndRemainder(
            dividingBy: rhs,
            budget: operationBudget
        )
        #expect(try division.quotient.uint64() == 85)
        #expect(try division.remainder.uint64() == 1)
        #expect(try rhs.shiftedLeft(by: 9, budget: operationBudget).uint64() == 1_536)
        #expect(try lhs.shiftedRight(by: 4, budget: operationBudget).uint64() == 16)

        let carried = try value([0xff]).adding(
            value([1]),
            budget: budget(operands: 1, results: 2)
        )
        #expect(try carried.bigEndianBytes(maximumByteCount: 2) == [1, 0])
    }

    @Test("Modular inverse is typed and exact")
    func modularInverse() throws {
        let operationBudget = try budget()
        #expect(
            try value([3]).inverse(
                modulo: value([11]),
                budget: operationBudget
            ).uint64() == 4
        )
        #expect(throws: BigNumError.notInvertible) {
            try value([6]).inverse(modulo: value([9]), budget: operationBudget)
        }
        #expect(throws: BigNumError.invalidModulus) {
            try value([1]).inverse(modulo: .one, budget: operationBudget)
        }
    }

    @Test("Operation budgets fail before expensive work")
    func operationBudgets() throws {
        let fourBytes = try value([1, 2, 3, 4])
        let one = BigMagnitude.one

        #expect(
            throws: BigNumError.operationBudgetExceeded(actual: 4, maximum: 3)
        ) {
            try fourBytes.adding(one, budget: budget(operands: 3))
        }
        #expect(
            throws: BigNumError.resultTooLarge(estimated: 8, maximum: 7)
        ) {
            try fourBytes.multiplied(by: fourBytes, budget: budget(results: 7))
        }
        #expect(throws: BigNumError.invalidShift(513)) {
            try one.shiftedLeft(by: 513, budget: budget(shifts: 512))
        }
        #expect(throws: BigNumError.resultTooLarge(estimated: 2, maximum: 1)) {
            try one.shiftedLeft(by: 8, budget: budget(results: 1))
        }
    }

    @Test("Failure cases never rely on dependency preconditions")
    func typedFailures() throws {
        let operationBudget = try budget()
        #expect(throws: BigNumError.subtractionUnderflow) {
            try value([1]).subtracting(value([2]), budget: operationBudget)
        }
        #expect(throws: BigNumError.divisionByZero) {
            try value([1]).quotientAndRemainder(
                dividingBy: .zero,
                budget: operationBudget
            )
        }
        #expect(throws: BigNumError.invalidShift(-1)) {
            try value([1]).shiftedRight(by: -1, budget: operationBudget)
        }
        #expect(throws: BigNumError.nativeIntegerOverflow) {
            try value([1] + Array(repeating: 0, count: 8)).uint64()
        }
    }

    @Test("Budget construction rejects every negative ceiling")
    func invalidBudgets() {
        #expect(throws: BigNumError.invalidLimit(-1)) {
            try BigNumOperationBudget(
                maximumOperandByteCount: -1,
                maximumResultByteCount: 0,
                maximumShiftBitCount: 0
            )
        }
        #expect(throws: BigNumError.invalidLimit(-2)) {
            try BigNumOperationBudget(
                maximumOperandByteCount: 0,
                maximumResultByteCount: -2,
                maximumShiftBitCount: 0
            )
        }
        #expect(throws: BigNumError.invalidLimit(-3)) {
            try BigNumOperationBudget(
                maximumOperandByteCount: 0,
                maximumResultByteCount: 0,
                maximumShiftBitCount: -3
            )
        }
    }
}
