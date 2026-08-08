import BSVBigNum
import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction

package struct ScriptMachine {
    private enum ConditionalState {
        case active
        case inactive
        case skipped
    }

    private let configuration: ScriptExecutionConfiguration
    private let consensusLimits: ScriptConsensusLimits
    private let context: ScriptExecutionContext?
    private(set) var mainStack = ScriptStack()
    private var altStack = ScriptStack()
    private var conditions: [ConditionalState] = []
    private var elseSeen: [Bool] = []
    private(set) var operationCount = 0
    private var operationsInCurrentScript = 0
    private(set) var didEarlyReturn = false

    init(
        configuration: ScriptExecutionConfiguration,
        context: ScriptExecutionContext?
    ) {
        self.configuration = configuration
        self.context = context
        consensusLimits = .forEra(configuration.era)
    }

    mutating func execute(_ script: Script, phase: ScriptPhase) throws {
        try checkScriptSize(script.byteCount)
        operationsInCurrentScript = 0
        conditions.removeAll(keepingCapacity: true)
        elseSeen.removeAll(keepingCapacity: true)
        var offset = 0
        var lastCodeSeparatorOffset = 0
        var returnedAtTopLevel = false
        var returningWithinConditional = false

        while offset < script.byteCount {
            let instruction = try ScriptInstructionDecoder.next(
                bytes: script.bytes,
                offset: &offset,
                phase: phase,
                maximumConsensusPushByteCount: consensusLimits.maximumPushDataByteCount,
                maximumResourcePushByteCount: configuration.resourceLimits.maximumPushDataByteCount
            )
            let opcode = instruction.opcode
            if opcode.rawValue > Opcode.sixteen.rawValue {
                try countOperation()
            }

            let executing = isExecuting
                && (!returningWithinConditional || opcode == .return)
            if isLegacyDisabled(opcode), configuration.era != .chronicle,
               configuration.era == .legacy || executing {
                throw ScriptExecutionError.consensus(.disabledOpcode(opcode))
            }
            if isAlwaysIllegalBeforeGenesis(opcode), configuration.era == .legacy {
                throw ScriptExecutionError.consensus(.reservedOpcode(opcode))
            }

            if isConditional(opcode) {
                try executeConditional(
                    opcode,
                    mayEvaluateCondition: !returningWithinConditional
                )
                try enforceStackBudgets()
                continue
            }
            guard executing else { continue }

            if let data = instruction.data {
                if configuration.flags.contains(.minimalData),
                   !isMinimalPush(opcode: opcode, data: data) {
                    throw ScriptExecutionError.consensus(.nonMinimalPush)
                }
                mainStack.push(data)
                try enforceStackBudgets()
                continue
            }

            if let integer = opcode.smallIntegerValue {
                if integer == 0 {
                    mainStack.push([])
                } else if integer == -1 {
                    mainStack.push([0x81])
                } else {
                    mainStack.push([UInt8(integer)])
                }
                try enforceStackBudgets()
                continue
            }

            switch opcode.rawValue {
            case Opcode.nop.rawValue:
                break
            case Opcode.ver.rawValue:
                guard configuration.era == .chronicle else {
                    throw ScriptExecutionError.consensus(.reservedOpcode(opcode))
                }
                guard let context else {
                    throw ScriptExecutionError.missingExecutionContext(opcode: opcode)
                }
                mainStack.push(transactionVersionBytes(context.transaction.version))
            case Opcode.verify.rawValue:
                guard scriptBoolean(try mainStack.pop()) else {
                    throw ScriptExecutionError.consensus(.verifyFailed)
                }
            case Opcode.return.rawValue:
                guard configuration.era != .legacy else {
                    throw ScriptExecutionError.consensus(.earlyReturn)
                }
                didEarlyReturn = true
                if conditions.isEmpty {
                    returnedAtTopLevel = true
                } else {
                    returningWithinConditional = true
                }
            case Opcode.toAltStack.rawValue:
                altStack.push(try mainStack.pop())
            case Opcode.fromAltStack.rawValue:
                guard altStack.count > 0 else {
                    throw ScriptExecutionError.consensus(.altStackUnderflow)
                }
                mainStack.push(try altStack.pop())
            case Opcode.twoDrop.rawValue:
                try mainStack.require(2)
                _ = try mainStack.pop()
                _ = try mainStack.pop()
            case Opcode.twoDup.rawValue:
                try duplicateTop(2)
            case Opcode.threeDup.rawValue:
                try duplicateTop(3)
            case Opcode.twoOver.rawValue:
                try mainStack.require(4)
                mainStack.push(try mainStack.peek(3))
                mainStack.push(try mainStack.peek(3))
            case Opcode.twoRot.rawValue:
                try mainStack.require(6)
                let first = try mainStack.remove(depth: 5)
                let second = try mainStack.remove(depth: 4)
                mainStack.push(first)
                mainStack.push(second)
            case Opcode.twoSwap.rawValue:
                try mainStack.require(4)
                let first = try mainStack.remove(depth: 3)
                let second = try mainStack.remove(depth: 2)
                mainStack.push(first)
                mainStack.push(second)
            case Opcode.ifDup.rawValue:
                let top = try mainStack.peek()
                if scriptBoolean(top) { mainStack.push(top) }
            case Opcode.depth.rawValue:
                try pushNumber(Int64(mainStack.count))
            case Opcode.drop.rawValue:
                _ = try mainStack.pop()
            case Opcode.dup.rawValue:
                mainStack.push(try mainStack.peek())
            case Opcode.nip.rawValue:
                try mainStack.require(2)
                _ = try mainStack.remove(depth: 1)
            case Opcode.over.rawValue:
                mainStack.push(try mainStack.peek(1))
            case Opcode.pick.rawValue:
                let depth = try popStackDepth()
                mainStack.push(try mainStack.peek(depth))
            case Opcode.roll.rawValue:
                let depth = try popStackDepth()
                mainStack.push(try mainStack.remove(depth: depth))
            case Opcode.rot.rawValue:
                try mainStack.require(3)
                mainStack.push(try mainStack.remove(depth: 2))
            case Opcode.swap.rawValue:
                try mainStack.require(2)
                mainStack.push(try mainStack.remove(depth: 1))
            case Opcode.tuck.rawValue:
                try mainStack.require(2)
                let top = try mainStack.pop()
                let second = try mainStack.pop()
                mainStack.push(top)
                mainStack.push(second)
                mainStack.push(top)
            case Opcode.cat.rawValue:
                try mainStack.require(2)
                let right = try mainStack.pop()
                let left = try mainStack.pop()
                let (resultCount, overflow) = left.count.addingReportingOverflow(right.count)
                guard !overflow else {
                    throw ScriptExecutionError.resourceBudgetExceeded(.pushDataByteCount(
                        actual: Int.max,
                        maximum: configuration.resourceLimits.maximumPushDataByteCount
                    ))
                }
                try checkElementResultSize(resultCount)
                mainStack.push(left + right)
            case Opcode.split.rawValue:
                let position = try popNativeNumber()
                let value = try mainStack.pop()
                guard position >= 0, position <= Int64(value.count) else {
                    throw ScriptExecutionError.consensus(.invalidSplitPosition(
                        position: position,
                        byteCount: value.count
                    ))
                }
                let index = Int(position)
                mainStack.push(Array(value[..<index]))
                mainStack.push(Array(value[index...]))
            case Opcode.num2bin.rawValue:
                let target = try popNativeNumber()
                let source = try mainStack.pop()
                guard target >= 0, target <= Int64(Int.max) else {
                    throw ScriptExecutionError.consensus(.invalidTargetByteCount(target))
                }
                let targetCount = Int(target)
                try checkElementResultSize(targetCount)
                let minimal = ScriptNumber.minimallyEncoded(source)
                guard minimal.count <= targetCount else {
                    throw ScriptExecutionError.consensus(.impossibleNumericEncoding(
                        targetByteCount: targetCount,
                        minimumByteCount: minimal.count
                    ))
                }
                if minimal.count == targetCount {
                    mainStack.push(minimal)
                } else {
                    var encoded = minimal
                    var sign: UInt8 = 0
                    if !encoded.isEmpty {
                        sign = encoded[encoded.count - 1] & 0x80
                        encoded[encoded.count - 1] &= 0x7f
                    }
                    encoded.append(contentsOf: repeatElement(
                        0,
                        count: targetCount - encoded.count - 1
                    ))
                    encoded.append(sign)
                    mainStack.push(encoded)
                }
            case Opcode.bin2num.rawValue:
                let minimal = ScriptNumber.minimallyEncoded(try mainStack.pop())
                try checkNumberSize(minimal.count)
                mainStack.push(minimal)
            case Opcode.size.rawValue:
                try pushNumber(Int64(try mainStack.peek().count))
            case Opcode.invert.rawValue:
                mainStack.push(try mainStack.pop().map { ~$0 })
            case Opcode.and.rawValue, Opcode.or.rawValue, Opcode.xor.rawValue:
                try mainStack.require(2)
                let right = try mainStack.pop()
                let left = try mainStack.pop()
                guard left.count == right.count else {
                    throw ScriptExecutionError.consensus(.invalidInputLength(
                        left: left.count,
                        right: right.count
                    ))
                }
                let result = zip(left, right).map { lhs, rhs in
                    switch opcode.rawValue {
                    case Opcode.and.rawValue: lhs & rhs
                    case Opcode.or.rawValue: lhs | rhs
                    default: lhs ^ rhs
                    }
                }
                mainStack.push(result)
            case Opcode.equal.rawValue:
                try mainStack.require(2)
                let right = try mainStack.pop()
                let left = try mainStack.pop()
                mainStack.push(scriptBooleanBytes(left == right))
            case Opcode.equalVerify.rawValue:
                try mainStack.require(2)
                let right = try mainStack.pop()
                let left = try mainStack.pop()
                guard left == right else {
                    throw ScriptExecutionError.consensus(.equalVerifyFailed)
                }
            case Opcode.oneAdd.rawValue:
                let value = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try value.value.adding(ScriptNumber(1).value, budget: $0)
                })
            case Opcode.oneSub.rawValue:
                let value = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try value.value.subtracting(ScriptNumber(1).value, budget: $0)
                })
            case Opcode.twoMul.rawValue:
                let value = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try value.value.multiplied(by: ScriptNumber(2).value, budget: $0)
                })
            case Opcode.twoDiv.rawValue:
                let value = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try value.value.quotientAndRemainder(
                        dividingBy: ScriptNumber(2).value,
                        budget: $0
                    ).quotient
                })
            case Opcode.negate.rawValue:
                try pushScriptNumber(try popScriptNumber().value.negated())
            case Opcode.abs.rawValue:
                try pushScriptNumber(try popScriptNumber().value.absoluteValue())
            case Opcode.not.rawValue:
                try pushNumber(try popScriptNumber().isZero ? 1 : 0)
            case Opcode.zeroNotEqual.rawValue:
                try pushNumber(try popScriptNumber().isZero ? 0 : 1)
            case Opcode.add.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try left.value.adding(right.value, budget: $0)
                })
            case Opcode.sub.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try left.value.subtracting(right.value, budget: $0)
                })
            case Opcode.mul.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                try pushScriptNumber(try performBigNumberOperation {
                    try left.value.multiplied(by: right.value, budget: $0)
                })
            case Opcode.div.rawValue, Opcode.mod.rawValue:
                let divisor = try popScriptNumber()
                let dividend = try popScriptNumber()
                guard !divisor.isZero else {
                    throw ScriptExecutionError.consensus(.divisionByZero)
                }
                let values = try performBigNumberDivision(
                    dividend: dividend.value,
                    divisor: divisor.value
                )
                try pushScriptNumber(
                    opcode == .div ? values.quotient : values.remainder
                )
            case Opcode.leftShift.rawValue, Opcode.rightShift.rawValue:
                let shift = try popNativeNumber()
                guard shift >= 0 else {
                    throw ScriptExecutionError.consensus(.invalidShiftAmount(shift))
                }
                let value = try mainStack.pop()
                mainStack.push(shiftBytes(
                    value,
                    by: shift,
                    right: opcode == .rightShift
                ))
            case Opcode.boolAnd.rawValue, Opcode.boolOr.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                let value = opcode == .boolAnd
                    ? (!left.isZero && !right.isZero)
                    : (!left.isZero || !right.isZero)
                mainStack.push(scriptBooleanBytes(value))
            case Opcode.numEqual.rawValue,
                 Opcode.numNotEqual.rawValue,
                 Opcode.lessThan.rawValue,
                 Opcode.greaterThan.rawValue,
                 Opcode.lessThanOrEqual.rawValue,
                 Opcode.greaterThanOrEqual.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                let comparison = left.value.compared(to: right.value)
                let value: Bool = switch opcode.rawValue {
                case Opcode.numEqual.rawValue: comparison == 0
                case Opcode.numNotEqual.rawValue: comparison != 0
                case Opcode.lessThan.rawValue: comparison < 0
                case Opcode.greaterThan.rawValue: comparison > 0
                case Opcode.lessThanOrEqual.rawValue: comparison <= 0
                default: comparison >= 0
                }
                mainStack.push(scriptBooleanBytes(value))
            case Opcode.numEqualVerify.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                guard left.value.compared(to: right.value) == 0 else {
                    throw ScriptExecutionError.consensus(.numericEqualVerifyFailed)
                }
            case Opcode.min.rawValue, Opcode.max.rawValue:
                let right = try popScriptNumber()
                let left = try popScriptNumber()
                let comparison = left.value.compared(to: right.value)
                let selected = opcode == .min
                    ? (comparison <= 0 ? left.value : right.value)
                    : (comparison >= 0 ? left.value : right.value)
                try pushScriptNumber(selected)
            case Opcode.within.rawValue:
                let maximum = try popScriptNumber()
                let minimum = try popScriptNumber()
                let value = try popScriptNumber()
                let inside = minimum.value.compared(to: value.value) <= 0
                    && value.value.compared(to: maximum.value) < 0
                mainStack.push(scriptBooleanBytes(inside))
            case Opcode.ripemd160.rawValue:
                mainStack.push(BSVHashing.ripemd160(try mainStack.pop()).bytes)
            case Opcode.sha1.rawValue:
                mainStack.push(BSVHashing.sha1(try mainStack.pop()).bytes)
            case Opcode.sha256.rawValue:
                mainStack.push(BSVHashing.sha256(try mainStack.pop()).bytes)
            case Opcode.hash160.rawValue:
                mainStack.push(BSVHashing.hash160(try mainStack.pop()).bytes)
            case Opcode.hash256.rawValue:
                mainStack.push(BSVHashing.sha256d(try mainStack.pop()).bytes)
            case Opcode.codeSeparator.rawValue:
                lastCodeSeparatorOffset = offset
            case Opcode.checkSig.rawValue, Opcode.checkSigVerify.rawValue:
                let valid = try executeCheckSignature(
                    opcode: opcode,
                    script: script,
                    codeSeparatorOffset: lastCodeSeparatorOffset
                )
                if opcode == .checkSig {
                    mainStack.push(scriptBooleanBytes(valid))
                } else if !valid {
                    throw ScriptExecutionError.consensus(.checkSignatureVerifyFailed)
                }
            case Opcode.leftShiftNumber.rawValue, Opcode.rightShiftNumber.rawValue:
                if configuration.era == .chronicle {
                    let shift = try popNativeNumber()
                    guard shift >= 0 else {
                        throw ScriptExecutionError.consensus(.invalidShiftAmount(shift))
                    }
                    let value = try popScriptNumber()
                    let consensusMaximumBits = 32 * 1_024 * 1_024 * 8
                    let boundedShift = min(shift, Int64(consensusMaximumBits))
                    let shifted = try performBigNumberOperation { budget in
                        if opcode == .rightShiftNumber {
                            return try value.value.shiftedRight(
                                by: Int(boundedShift),
                                budget: budget
                            )
                        }
                        return try value.value.shiftedLeft(
                            by: Int(boundedShift),
                            budget: budget
                        )
                    }
                    try pushScriptNumber(shifted)
                    break
                }
                if configuration.flags.contains(.discourageUpgradeableNops) {
                    throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                }
            case Opcode.checkLockTimeVerify.rawValue:
                if configuration.era != .legacy
                    || !configuration.flags.contains(.checkLockTimeVerify) {
                    if configuration.flags.contains(.discourageUpgradeableNops) {
                        throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                    }
                    break
                }
                try executeCheckLockTime(opcode)
            case Opcode.checkSequenceVerify.rawValue:
                if configuration.era != .legacy
                    || !configuration.flags.contains(.checkSequenceVerify) {
                    if configuration.flags.contains(.discourageUpgradeableNops) {
                        throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                    }
                    break
                }
                try executeCheckSequence(opcode)
            case Opcode.nop1.rawValue,
                 Opcode.nop9.rawValue,
                 Opcode.nop10.rawValue:
                if configuration.flags.contains(.discourageUpgradeableNops) {
                    throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                }
            case Opcode.substring.rawValue, Opcode.left.rawValue, Opcode.right.rawValue:
                if configuration.era == .chronicle {
                    try executeChronicleSlice(opcode)
                    break
                }
                if configuration.flags.contains(.discourageUpgradeableNops) {
                    throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                }
            case Opcode.reserved.rawValue,
                 Opcode.reserved1.rawValue,
                 Opcode.reserved2.rawValue,
                 0xba...0xff:
                throw ScriptExecutionError.consensus(.reservedOpcode(opcode))
            default:
                throw ScriptExecutionError.unsupportedOpcode(opcode)
            }

            try enforceStackBudgets()
            if returnedAtTopLevel { break }
        }

        if !returnedAtTopLevel, !conditions.isEmpty {
            throw ScriptExecutionError.consensus(.unbalancedConditional)
        }
        if !returnedAtTopLevel {
            altStack.removeAll()
        }
    }

    mutating func replaceMainStack(with items: [[UInt8]]) throws {
        mainStack.removeAll()
        for item in items { mainStack.push(item) }
        try enforceStackBudgets()
    }

    private var isExecuting: Bool {
        !conditions.contains { $0 != .active }
    }

    private mutating func executeConditional(
        _ opcode: Opcode,
        mayEvaluateCondition: Bool
    ) throws {
        switch opcode.rawValue {
        case Opcode.if.rawValue, Opcode.notIf.rawValue:
            let outerExecuting = isExecuting
            let state: ConditionalState
            if outerExecuting, mayEvaluateCondition {
                let encoded = try mainStack.pop()
                if configuration.flags.contains(.minimalIf),
                   encoded != [] && encoded != [1] {
                    throw ScriptExecutionError.consensus(.minimalIf)
                }
                let value = scriptBoolean(encoded)
                let selected = opcode == Opcode.if ? value : !value
                state = selected ? .active : .inactive
            } else if outerExecuting {
                state = .inactive
            } else {
                state = .skipped
            }
            try appendConditionalState(state)
        case Opcode.else.rawValue:
            guard let state = conditions.last, let seen = elseSeen.last else {
                throw ScriptExecutionError.consensus(.unbalancedConditional)
            }
            if configuration.era != .legacy, seen {
                throw ScriptExecutionError.consensus(.multipleElse)
            }
            elseSeen[elseSeen.count - 1] = true
            switch state {
            case .active: conditions[conditions.count - 1] = .inactive
            case .inactive: conditions[conditions.count - 1] = .active
            case .skipped: break
            }
        case Opcode.endIf.rawValue:
            guard !conditions.isEmpty else {
                throw ScriptExecutionError.consensus(.unbalancedConditional)
            }
            conditions.removeLast()
            elseSeen.removeLast()
        case Opcode.verIf.rawValue, Opcode.verNotIf.rawValue:
            guard configuration.era == .chronicle else {
                // Genesis made these branch-sensitive before Chronicle gave
                // them transaction-version matching semantics.
                guard !isExecuting || !mayEvaluateCondition else {
                    throw ScriptExecutionError.consensus(.reservedOpcode(opcode))
                }
                return
            }

            let state: ConditionalState
            let hasInactiveParent = conditions.contains { condition in
                if case .inactive = condition { return true }
                return false
            }
            if !mayEvaluateCondition || hasInactiveParent {
                state = .inactive
            } else if case .skipped? = conditions.last {
                state = .skipped
            } else {
                guard mainStack.count > 0 else {
                    throw ScriptExecutionError.consensus(.unbalancedConditional)
                }
                let candidate = try mainStack.pop()
                let matches = context.map {
                    candidate == transactionVersionBytes($0.transaction.version)
                } ?? false
                let selected = opcode == .verIf ? matches : !matches
                state = selected ? .active : .inactive
            }
            try appendConditionalState(state)
        default:
            preconditionFailure("non-conditional opcode")
        }
    }

    private mutating func duplicateTop(_ count: Int) throws {
        try mainStack.require(count)
        let values = try (0..<count).reversed().map { try mainStack.peek($0) }
        for value in values { mainStack.push(value) }
    }

    private mutating func appendConditionalState(_ state: ConditionalState) throws {
        let newDepth = conditions.count + 1
        guard newDepth <= configuration.resourceLimits.maximumConditionalDepth else {
            throw ScriptExecutionError.resourceBudgetExceeded(.conditionalDepth(
                actual: newDepth,
                maximum: configuration.resourceLimits.maximumConditionalDepth
            ))
        }
        conditions.append(state)
        elseSeen.append(false)
    }

    private func transactionVersionBytes(_ version: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: version),
            UInt8(truncatingIfNeeded: version >> 8),
            UInt8(truncatingIfNeeded: version >> 16),
            UInt8(truncatingIfNeeded: version >> 24),
        ]
    }

    private mutating func popStackDepth() throws -> Int {
        let value = try popNativeNumber()
        guard value >= 0, value <= Int64(Int.max) else {
            throw ScriptExecutionError.consensus(.invalidStackIndex(Int(value)))
        }
        return Int(value)
    }

    private mutating func popNativeNumber() throws -> Int64 {
        try popScriptNumber().int64Clamped()
    }

    private mutating func popScriptNumber() throws -> ScriptNumber {
        let encoded = try mainStack.pop()
        try checkNumberSize(encoded.count)
        do {
            return try ScriptNumber(
                encoded: encoded,
                maximumByteCount: min(
                    consensusLimits.maximumScriptNumberByteCount,
                    configuration.resourceLimits.maximumScriptNumberByteCount
                ),
                requireMinimal: configuration.flags.contains(.minimalData)
            )
        } catch ScriptNumberError.nonMinimalEncoding {
            throw ScriptExecutionError.consensus(.nonMinimalNumber)
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
    }

    private func checkNumberSize(_ count: Int) throws {
        if count > consensusLimits.maximumScriptNumberByteCount {
            throw ScriptExecutionError.consensus(.numberTooLarge(
                actual: count,
                maximum: consensusLimits.maximumScriptNumberByteCount
            ))
        }
        if count > configuration.resourceLimits.maximumScriptNumberByteCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.scriptNumberByteCount(
                actual: count,
                maximum: configuration.resourceLimits.maximumScriptNumberByteCount
            ))
        }
    }

    private func checkElementResultSize(_ count: Int) throws {
        if count > consensusLimits.maximumPushDataByteCount {
            throw ScriptExecutionError.consensus(.pushDataTooLarge(
                actual: count,
                maximum: consensusLimits.maximumPushDataByteCount
            ))
        }
        if count > configuration.resourceLimits.maximumPushDataByteCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.pushDataByteCount(
                actual: count,
                maximum: configuration.resourceLimits.maximumPushDataByteCount
            ))
        }
    }

    private mutating func pushNumber(_ value: Int64) throws {
        let encoded: [UInt8]
        do {
            encoded = try ScriptNumber(value).serialized(
                maximumByteCount: consensusLimits.maximumScriptNumberByteCount
            )
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
        mainStack.push(encoded)
    }

    private mutating func pushScriptNumber(_ value: BigSigned) throws {
        let maximum = min(
            consensusLimits.maximumPushDataByteCount,
            configuration.resourceLimits.maximumPushDataByteCount
        )
        let encoded: [UInt8]
        do {
            encoded = try ScriptNumber(value: value).serialized(maximumByteCount: maximum)
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
        try checkElementResultSize(encoded.count)
        mainStack.push(encoded)
    }

    private func performBigNumberOperation<Result>(
        _ operation: (BigNumOperationBudget) throws -> Result
    ) throws -> Result {
        let resultLimit = min(
            consensusLimits.maximumPushDataByteCount,
            configuration.resourceLimits.maximumPushDataByteCount
        )
        let shiftLimit = resultLimit.multipliedReportingOverflow(by: 8)
        let maximumShift = shiftLimit.overflow ? Int.max : shiftLimit.partialValue
        do {
            let budget = try BigNumOperationBudget(
                maximumOperandByteCount: min(
                    consensusLimits.maximumScriptNumberByteCount,
                    configuration.resourceLimits.maximumScriptNumberByteCount
                ),
                maximumResultByteCount: resultLimit,
                maximumShiftBitCount: maximumShift
            )
            return try operation(budget)
        } catch BigNumError.divisionByZero {
            throw ScriptExecutionError.consensus(.divisionByZero)
        } catch BigNumError.invalidShift(let shift) {
            throw ScriptExecutionError.consensus(.invalidShiftAmount(Int64(shift)))
        } catch let error as BigNumError {
            switch error {
            case .operationBudgetExceeded(let actual, let maximum),
                 .inputTooLarge(let actual, let maximum):
                throw ScriptExecutionError.resourceBudgetExceeded(.scriptNumberByteCount(
                    actual: actual,
                    maximum: maximum
                ))
            case .resultTooLarge(let actual, let maximum):
                if consensusLimits.maximumPushDataByteCount <= configuration.resourceLimits.maximumPushDataByteCount {
                    throw ScriptExecutionError.consensus(.pushDataTooLarge(
                        actual: actual,
                        maximum: maximum
                    ))
                }
                throw ScriptExecutionError.resourceBudgetExceeded(
                    .pushDataByteCount(actual: actual, maximum: maximum)
                )
            default:
                throw ScriptExecutionError.scriptNumber(.numberTooLarge(
                    actual: Int.max,
                    maximum: resultLimit
                ))
            }
        }
    }

    private func performBigNumberDivision(
        dividend: BigSigned,
        divisor: BigSigned
    ) throws -> (quotient: BigSigned, remainder: BigSigned) {
        try performBigNumberOperation { budget in
            try dividend.quotientAndRemainder(
                dividingBy: divisor,
                budget: budget
            )
        }
    }

    private func shiftBytes(_ bytes: [UInt8], by shift: Int64, right: Bool) -> [UInt8] {
        guard shift > 0, !bytes.isEmpty else { return bytes }
        let totalBits = Int64(bytes.count) * 8
        guard shift < totalBits else { return Array(repeating: 0, count: bytes.count) }
        let byteShift = Int(shift / 8)
        let bitShift = Int(shift % 8)
        var result = Array(repeating: UInt8(0), count: bytes.count)
        for index in bytes.indices {
            if right {
                let destination = index + byteShift
                if destination < bytes.count {
                    result[destination] |= bytes[index] >> bitShift
                }
                if bitShift > 0, destination + 1 < bytes.count {
                    result[destination + 1] |= bytes[index] << (8 - bitShift)
                }
            } else {
                guard index >= byteShift else { continue }
                let destination = index - byteShift
                result[destination] |= bytes[index] << bitShift
                if bitShift > 0, destination > 0 {
                    result[destination - 1] |= bytes[index] >> (8 - bitShift)
                }
            }
        }
        return result
    }

    private mutating func executeChronicleSlice(_ opcode: Opcode) throws {
        let length = try popNativeNumber()
        if opcode == .substring {
            let offset = try popNativeNumber()
            let data = try mainStack.pop()
            guard offset >= 0, length >= 0,
                  offset < Int64(data.count),
                  length <= Int64(data.count) - offset
            else {
                throw ScriptExecutionError.consensus(.invalidSplitPosition(
                    position: offset,
                    byteCount: data.count
                ))
            }
            mainStack.push(Array(data[Int(offset)..<(Int(offset + length))]))
            return
        }
        let data = try mainStack.pop()
        guard length >= 0, length <= Int64(data.count) else {
            throw ScriptExecutionError.consensus(.invalidSplitPosition(
                position: length,
                byteCount: data.count
            ))
        }
        let count = Int(length)
        mainStack.push(opcode == .left
            ? Array(data.prefix(count))
            : Array(data.suffix(count)))
    }

    private mutating func executeCheckSignature(
        opcode: Opcode,
        script: Script,
        codeSeparatorOffset: Int
    ) throws -> Bool {
        guard let context else {
            throw ScriptExecutionError.missingExecutionContext(opcode: opcode)
        }
        guard configuration.flags.contains(.enableForkID) else {
            throw ScriptExecutionError.unsupportedOpcode(opcode)
        }
        try mainStack.require(2)
        let publicKeyBytes = try mainStack.pop()
        let signatureWithHashType = try mainStack.pop()
        guard let rawHashType = signatureWithHashType.last else {
            return false
        }

        let hashType: ForkIDSignatureHashType
        do {
            hashType = try ForkIDSignatureHashType(rawValue: rawHashType)
        } catch {
            if configuration.flags.contains(.strictEncoding) {
                throw ScriptExecutionError.consensus(.invalidSignatureHashType(rawHashType))
            }
            return try signatureFailure(signatureWithHashType)
        }

        let signature: ECDSASignature
        do {
            signature = try ECDSASignature(
                derBytes: Array(signatureWithHashType.dropLast())
            )
        } catch {
            if configuration.flags.contains(.derSignatures)
                || configuration.flags.contains(.strictEncoding)
                || configuration.flags.contains(.lowS) {
                throw ScriptExecutionError.consensus(.invalidSignatureEncoding)
            }
            return try signatureFailure(signatureWithHashType)
        }

        let publicKey: PublicKey
        do {
            publicKey = try PublicKey(publicKeyBytes)
        } catch {
            if configuration.flags.contains(.strictEncoding) {
                throw ScriptExecutionError.consensus(.invalidPublicKeyEncoding)
            }
            return try signatureFailure(signatureWithHashType)
        }

        var transaction = context.transaction
        transaction.inputs[context.inputIndex].sourceOutput = context.spentOutput
        let scriptCode: Script
        do {
            scriptCode = try Script(
                bytes: Array(script.bytes[codeSeparatorOffset...]),
                maximumByteCount: configuration.resourceLimits.maximumScriptByteCount
            )
        } catch {
            throw ScriptExecutionError.resourceBudgetExceeded(.scriptByteCount(
                actual: script.byteCount - codeSeparatorOffset,
                maximum: configuration.resourceLimits.maximumScriptByteCount
            ))
        }
        let digest: Hash256
        do {
            digest = try transaction.forkIDSignatureHash(
                inputIndex: context.inputIndex,
                hashType: hashType,
                scriptCode: scriptCode,
                limits: context.transactionLimits
            )
        } catch let error as TransactionError {
            throw ScriptExecutionError.transaction(error)
        }
        let valid = publicKey.verify(signature, digest: digest)
        if !valid { return try signatureFailure(signatureWithHashType) }
        return true
    }

    private func executeCheckLockTime(_ opcode: Opcode) throws {
        guard let context else {
            throw ScriptExecutionError.missingExecutionContext(opcode: opcode)
        }
        let required = try peekNativeNumber(maximumByteCount: 5)
        guard required >= 0 else {
            throw ScriptExecutionError.consensus(.unsatisfiedLockTime)
        }
        let transactionLockTime = Int64(context.transaction.lockTime)
        let threshold: Int64 = 500_000_000
        guard (transactionLockTime < threshold) == (required < threshold),
              required <= transactionLockTime,
              context.transaction.inputs[context.inputIndex].sequence
                != TransactionInput.finalSequence else {
            throw ScriptExecutionError.consensus(.unsatisfiedLockTime)
        }
    }

    private func executeCheckSequence(_ opcode: Opcode) throws {
        guard let context else {
            throw ScriptExecutionError.missingExecutionContext(opcode: opcode)
        }
        let required = try peekNativeNumber(maximumByteCount: 5)
        guard required >= 0 else {
            throw ScriptExecutionError.consensus(.unsatisfiedSequence)
        }
        let requiredSequence = UInt64(required)
        let disableFlag: UInt64 = 1 << 31
        if requiredSequence & disableFlag != 0 { return }

        let transactionSequence = UInt64(
            context.transaction.inputs[context.inputIndex].sequence
        )
        let typeFlag: UInt64 = 1 << 22
        let valueMask: UInt64 = 0x0000ffff
        let compareMask = typeFlag | valueMask
        guard context.transaction.version >= 2,
              transactionSequence & disableFlag == 0,
              requiredSequence & typeFlag == transactionSequence & typeFlag,
              requiredSequence & compareMask <= transactionSequence & compareMask else {
            throw ScriptExecutionError.consensus(.unsatisfiedSequence)
        }
    }

    private func peekNativeNumber(maximumByteCount: Int) throws -> Int64 {
        let encoded = try mainStack.peek()
        // CLTV and CSV deliberately accept a five-byte script number even in
        // legacy execution, where ordinary arithmetic remains limited to four
        // bytes. The caller supplies the opcode-specific consensus bound.
        let consensusMaximum = maximumByteCount
        if encoded.count > consensusMaximum {
            throw ScriptExecutionError.consensus(.numberTooLarge(
                actual: encoded.count,
                maximum: consensusMaximum
            ))
        }
        if encoded.count > configuration.resourceLimits.maximumScriptNumberByteCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.scriptNumberByteCount(
                actual: encoded.count,
                maximum: configuration.resourceLimits.maximumScriptNumberByteCount
            ))
        }
        do {
            return try ScriptNumber(
                encoded: encoded,
                maximumByteCount: consensusMaximum,
                requireMinimal: configuration.flags.contains(.minimalData)
            ).int64Clamped()
        } catch ScriptNumberError.nonMinimalEncoding {
            throw ScriptExecutionError.consensus(.nonMinimalNumber)
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
    }

    private func signatureFailure(_ nonemptySignature: [UInt8]) throws -> Bool {
        if configuration.flags.contains(.nullFail), !nonemptySignature.isEmpty {
            throw ScriptExecutionError.consensus(.nullFail)
        }
        return false
    }

    private mutating func countOperation() throws {
        operationsInCurrentScript += 1
        operationCount += 1
        if operationsInCurrentScript > consensusLimits.maximumOperationCountPerScript {
            throw ScriptExecutionError.consensus(.tooManyOperations(
                actual: operationsInCurrentScript,
                maximum: consensusLimits.maximumOperationCountPerScript
            ))
        }
        if operationsInCurrentScript > configuration.resourceLimits.maximumOperationCountPerScript {
            throw ScriptExecutionError.resourceBudgetExceeded(.operationCount(
                actual: operationsInCurrentScript,
                maximum: configuration.resourceLimits.maximumOperationCountPerScript
            ))
        }
    }

    private func checkScriptSize(_ byteCount: Int) throws {
        if byteCount > consensusLimits.maximumScriptByteCount {
            throw ScriptExecutionError.consensus(.scriptTooLarge(
                actual: byteCount,
                maximum: consensusLimits.maximumScriptByteCount
            ))
        }
        if byteCount > configuration.resourceLimits.maximumScriptByteCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.scriptByteCount(
                actual: byteCount,
                maximum: configuration.resourceLimits.maximumScriptByteCount
            ))
        }
    }

    private func enforceStackBudgets() throws {
        let itemCount = mainStack.count + altStack.count
        if itemCount > consensusLimits.maximumStackItemCount {
            throw ScriptExecutionError.consensus(.tooManyStackItems(
                actual: itemCount,
                maximum: consensusLimits.maximumStackItemCount
            ))
        }
        if itemCount > configuration.resourceLimits.maximumStackItemCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.stackItemCount(
                actual: itemCount,
                maximum: configuration.resourceLimits.maximumStackItemCount
            ))
        }
        let memory = mainStack.memoryByteCount + altStack.memoryByteCount
        if memory > configuration.resourceLimits.maximumStackMemoryByteCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.stackMemoryByteCount(
                actual: memory,
                maximum: configuration.resourceLimits.maximumStackMemoryByteCount
            ))
        }
    }

    private func isMinimalPush(opcode: Opcode, data: [UInt8]) -> Bool {
        switch data.count {
        case 0: opcode == .zero
        case 1 where (1...16).contains(data[0]):
            opcode.rawValue == Opcode.one.rawValue + data[0] - 1
        case 1 where data[0] == 0x81: opcode == .oneNegate
        case 1...75: opcode.rawValue == UInt8(data.count)
        case 76...255: opcode == .pushData1
        case 256...65_535: opcode == .pushData2
        default: opcode == .pushData4
        }
    }

    private func isConditional(_ opcode: Opcode) -> Bool {
        (Opcode.if.rawValue...Opcode.endIf.rawValue).contains(opcode.rawValue)
            && opcode != .verify
    }

    private func isAlwaysIllegalBeforeGenesis(_ opcode: Opcode) -> Bool {
        opcode == .verIf || opcode == .verNotIf
    }

    private func isLegacyDisabled(_ opcode: Opcode) -> Bool {
        switch opcode.rawValue {
        case Opcode.twoMul.rawValue, Opcode.twoDiv.rawValue:
            true
        default:
            false
        }
    }
}
