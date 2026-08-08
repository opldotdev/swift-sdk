@testable import BSVInterpreter
import BSVScript
import Testing

@Suite("InterpreterReference era number boundaries", .serialized)
struct InterpreterReferenceNumberBoundaryTests {
    @Test("before-Genesis, after-Genesis, and after-Chronicle consensus limits remain exact")
    func pinnedConsensusCeilings() {
        let beforeGenesis = ScriptConsensusLimits.forEra(.beforeGenesis)
        #expect(beforeGenesis.maximumScriptByteCount == 10_000)
        #expect(beforeGenesis.maximumPushDataByteCount == 520)
        #expect(beforeGenesis.maximumStackItemCount == 1_000)
        #expect(beforeGenesis.maximumOperationCountPerScript == 500)
        #expect(beforeGenesis.maximumScriptNumberByteCount == 4)

        let afterGenesis = ScriptConsensusLimits.forEra(.afterGenesis)
        #expect(afterGenesis.maximumScriptByteCount == Int(Int32.max))
        #expect(afterGenesis.maximumPushDataByteCount == Int(Int32.max))
        #expect(afterGenesis.maximumStackItemCount == Int(Int32.max))
        #expect(afterGenesis.maximumOperationCountPerScript == Int(Int32.max))
        #expect(afterGenesis.maximumScriptNumberByteCount == 750_000)
        #expect(afterGenesis.maximumScriptNumberByteCount + 1 == 750_001)

        let afterChronicle = ScriptConsensusLimits.forEra(.afterChronicle)
        #expect(afterChronicle.maximumScriptByteCount == Int(Int32.max))
        #expect(afterChronicle.maximumPushDataByteCount == Int(Int32.max))
        #expect(afterChronicle.maximumStackItemCount == Int(Int32.max))
        #expect(afterChronicle.maximumOperationCountPerScript == Int(Int32.max))
        let chronicleMaximum = 32 * 1_024 * 1_024
        let chroniclePlusOne = chronicleMaximum + 1
        #expect(afterChronicle.maximumScriptNumberByteCount == chronicleMaximum)
        #expect(afterChronicle.maximumScriptNumberByteCount + 1 == chroniclePlusOne)
    }

    @Test("after-Genesis executes the exact number ceiling and rejects plus one")
    func afterGenesisRuntimeBoundary() throws {
        let exactCount = 750_000
        let limits = ScriptResourceLimits(
            maximumScriptByteCount: 1_000_000,
            maximumPushDataByteCount: 1_000_000,
            maximumStackItemCount: 10,
            maximumStackMemoryByteCount: 2_000_000,
            maximumOperationCountPerScript: 10,
            maximumConditionalDepth: 10,
            maximumScriptNumberByteCount: 1_000_000
        )
        let exact = push(Array(repeating: 0, count: exactCount))
            + [Opcode.oneAdd.rawValue, Opcode.drop.rawValue, Opcode.one.rawValue]
        #expect(try run(exact, era: .afterGenesis, limits: limits).stack == [[1]])

        let plusOne = push(Array(repeating: 0, count: exactCount + 1))
            + [Opcode.oneAdd.rawValue]
        #expect(throws: ScriptExecutionError.consensus(
            .numberTooLarge(actual: exactCount + 1, maximum: exactCount)
        )) {
            try run(plusOne, era: .afterGenesis, limits: limits)
        }
    }

    @Test("after-Chronicle number operands preserve operational exact and plus-one typing")
    func afterChronicleOperationalBoundary() throws {
        let exactCount = 8
        let limits = ScriptResourceLimits(
            maximumScriptByteCount: 100,
            maximumPushDataByteCount: 100,
            maximumStackItemCount: 10,
            maximumStackMemoryByteCount: 100,
            maximumOperationCountPerScript: 10,
            maximumConditionalDepth: 10,
            maximumScriptNumberByteCount: exactCount
        )
        let exact = push(Array(repeating: 0, count: exactCount))
            + [Opcode.oneAdd.rawValue, Opcode.drop.rawValue, Opcode.one.rawValue]
        #expect(try run(exact, era: .afterChronicle, limits: limits).stack == [[1]])

        let plusOne = push(Array(repeating: 0, count: exactCount + 1))
            + [Opcode.oneAdd.rawValue]
        #expect(throws: ScriptExecutionError.resourceBudgetExceeded(
            .scriptNumberByteCount(actual: exactCount + 1, maximum: exactCount)
        )) {
            try run(plusOne, era: .afterChronicle, limits: limits)
        }
    }

    @Test("execution era raw values use exact upgrade-relative names")
    func executionEraRawValues() {
        #expect(ScriptExecutionEra.beforeGenesis.rawValue == "beforeGenesis")
        #expect(ScriptExecutionEra.afterGenesis.rawValue == "afterGenesis")
        #expect(ScriptExecutionEra.afterChronicle.rawValue == "afterChronicle")
    }

    private func run(
        _ lockingBytes: [UInt8],
        era: ScriptExecutionEra,
        limits: ScriptResourceLimits
    ) throws -> ScriptExecutionResult {
        let unlocking = try Script(bytes: [], maximumByteCount: 1)
        let locking = try Script(
            bytes: lockingBytes,
            maximumByteCount: lockingBytes.count
        )
        return try ScriptInterpreter.execute(
            unlockingScript: unlocking,
            lockingScript: locking,
            configuration: ScriptExecutionConfiguration(
                era: era,
                resourceLimits: limits
            )
        )
    }

    private func push(_ data: [UInt8]) -> [UInt8] {
        [
            Opcode.pushData4.rawValue,
            UInt8(data.count & 0xff),
            UInt8((data.count >> 8) & 0xff),
            UInt8((data.count >> 16) & 0xff),
            UInt8((data.count >> 24) & 0xff),
        ] + data
    }
}
