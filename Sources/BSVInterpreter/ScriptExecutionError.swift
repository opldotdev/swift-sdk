import BSVScript
import BSVTransaction

public enum ScriptPhase: String, Equatable, Sendable {
    case unlocking
    case locking
    case redeem
}

public enum ScriptConsensusFailure: Error, Equatable, Sendable {
    case evaluatedFalse
    case emptyFinalStack
    case cleanStackViolation(actualItemCount: Int)
    case scriptTooLarge(actual: Int, maximum: Int)
    case pushDataTooLarge(actual: Int, maximum: Int)
    case tooManyStackItems(actual: Int, maximum: Int)
    case tooManyOperations(actual: Int, maximum: Int)
    case stackUnderflow(required: Int, available: Int)
    case altStackUnderflow
    case invalidStackIndex(Int)
    case invalidInputLength(left: Int, right: Int)
    case invalidSplitPosition(position: Int64, byteCount: Int)
    case numberTooLarge(actual: Int, maximum: Int)
    case nonMinimalNumber
    case impossibleNumericEncoding(targetByteCount: Int, minimumByteCount: Int)
    case divisionByZero
    case invalidShiftAmount(Int64)
    case invalidTargetByteCount(Int64)
    case numericEqualVerifyFailed
    case verifyFailed
    case equalVerifyFailed
    case unbalancedConditional
    case multipleElse
    case minimalIf
    case nonMinimalPush
    case signatureScriptNotPushOnly
    case reservedOpcode(Opcode)
    case disabledOpcode(Opcode)
    case earlyReturn
    case discouragedUpgradeableNop(Opcode)
    case invalidSignatureEncoding
    case invalidPublicKeyEncoding
    case invalidSignatureHashType(UInt8)
    case illegalForkID(UInt8)
    case invalidPublicKeyCount(Int64)
    case invalidSignatureCount(Int64)
    case nullDummy
    case nullFail
    case checkSignatureVerifyFailed
    case checkMultiSignatureVerifyFailed
    case unsatisfiedLockTime
    case unsatisfiedSequence
}

public enum ScriptResourceFailure: Error, Equatable, Sendable {
    case scriptByteCount(actual: Int, maximum: Int)
    case pushDataByteCount(actual: Int, maximum: Int)
    case stackItemCount(actual: Int, maximum: Int)
    case stackMemoryByteCount(actual: Int, maximum: Int)
    case operationCount(actual: Int, maximum: Int)
    case conditionalDepth(actual: Int, maximum: Int)
    case scriptNumberByteCount(actual: Int, maximum: Int)
}

public enum ScriptDecodingFailure: Error, Equatable, Sendable {
    case truncatedPushLength(expected: Int, remaining: Int)
    case truncatedPushData(expected: Int, remaining: Int)
    case pushLengthNotRepresentable(UInt32)
}

public enum ScriptExecutionContextFailure: Error, Equatable, Sendable {
    case inputIndexOutOfBounds(index: Int, inputCount: Int)
    case unlockingScriptMismatch
    case lockingScriptMismatch
}

public enum ScriptExecutionError: Error, Equatable, Sendable {
    case consensus(ScriptConsensusFailure)
    case resourceBudgetExceeded(ScriptResourceFailure)
    case malformedScript(
        phase: ScriptPhase,
        offset: Int,
        cause: ScriptDecodingFailure
    )
    case invalidContext(ScriptExecutionContextFailure)
    case missingExecutionContext(opcode: Opcode)
    case unsupportedOpcode(Opcode)
    case scriptNumber(ScriptNumberError)
    case transaction(TransactionError)
}
