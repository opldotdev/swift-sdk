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
    /// SV Node `EnforceNonMalleability` for this spend.
    private let enforcesNonMalleability: Bool
    /// MINIMALDATA after the Chronicle malleability relaxation.
    private let requiresMinimalData: Bool
    private(set) var mainStack: ScriptStack
    private var altStack: ScriptStack
    private let debugState: ScriptDebugState?
    private var conditions: [ConditionalState] = []
    private var elseSeen: [Bool] = []
    private(set) var operationCount = 0
    private var operationsInCurrentScript = 0
    private(set) var didEarlyReturn = false

    init(
        configuration: ScriptExecutionConfiguration,
        context: ScriptExecutionContext?,
        debugSession: ScriptDebugSession? = nil
    ) {
        self.configuration = configuration
        self.context = context
        consensusLimits = .forEra(configuration.era)
        let enforcesNonMalleability = configuration.enforcesNonMalleability(
            transactionVersion: context?.transaction.version
        )
        self.enforcesNonMalleability = enforcesNonMalleability
        requiresMinimalData = configuration.flags.contains(.minimalData)
            && enforcesNonMalleability
        let debugState = debugSession.map(ScriptDebugState.init(session:))
        self.debugState = debugState
        mainStack = ScriptStack(debugState: debugState, debugStack: .main)
        altStack = ScriptStack(debugState: debugState, debugStack: .alternate)
    }

    mutating func execute(_ script: Script, phase: ScriptPhase) throws {
        try checkScriptSize(script.byteCount)
        // SV Node evaluates every script with a fresh alternate stack, so
        // nothing left there by an early-returning unlocking script reaches
        // the locking script.
        if altStack.count > 0 {
            altStack.removeAll()
        }
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
            try debugState?.beginStep(
                phase: phase,
                opcode: opcode,
                offset: offset,
                operationCount: operationCount
            )
            var didCompleteStep = false
            defer {
                if didCompleteStep {
                    debugState?.completeStep(operationCount: operationCount)
                }
            }
            if opcode.rawValue > Opcode.sixteen.rawValue {
                try countOperation()
            }

            let executing = isExecuting
                && (!returningWithinConditional || opcode == .return)
            if isDisabledBeforeChronicle(opcode), configuration.era != .afterChronicle,
               configuration.era == .beforeGenesis || executing {
                throw ScriptExecutionError.consensus(.disabledOpcode(opcode))
            }
            if isAlwaysIllegalBeforeGenesis(opcode), configuration.era == .beforeGenesis {
                throw ScriptExecutionError.consensus(.reservedOpcode(opcode))
            }

            if isConditional(opcode) {
                try executeConditional(
                    opcode,
                    mayEvaluateCondition: !returningWithinConditional
                )
                try enforceStackBudgets()
                didCompleteStep = true
                continue
            }
            guard executing else {
                didCompleteStep = true
                continue
            }

            if let data = instruction.data {
                if requiresMinimalData,
                   !isMinimalPush(opcode: opcode, data: data) {
                    throw ScriptExecutionError.consensus(.nonMinimalPush)
                }
                mainStack.push(data)
                try enforceStackBudgets()
                didCompleteStep = true
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
                didCompleteStep = true
                continue
            }

            switch opcode.rawValue {
            case Opcode.nop.rawValue:
                break
            case Opcode.ver.rawValue:
                guard configuration.era == .afterChronicle else {
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
                guard configuration.era != .beforeGenesis else {
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
                    phase: phase,
                    codeSeparatorOffset: lastCodeSeparatorOffset
                )
                if opcode == .checkSig {
                    mainStack.push(scriptBooleanBytes(valid))
                } else if !valid {
                    throw ScriptExecutionError.consensus(.checkSignatureVerifyFailed)
                }
            case Opcode.checkMultiSig.rawValue, Opcode.checkMultiSigVerify.rawValue:
                let valid = try executeCheckMultiSignature(
                    opcode: opcode,
                    script: script,
                    phase: phase,
                    codeSeparatorOffset: lastCodeSeparatorOffset
                )
                if opcode == .checkMultiSig {
                    mainStack.push(scriptBooleanBytes(valid))
                } else if !valid {
                    throw ScriptExecutionError.consensus(.checkMultiSignatureVerifyFailed)
                }
            case Opcode.leftShiftNumber.rawValue, Opcode.rightShiftNumber.rawValue:
                if configuration.era == .afterChronicle {
                    try executeNumericShift(opcode)
                    break
                }
                if configuration.flags.contains(.discourageUpgradeableNops) {
                    throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                }
            case Opcode.checkLockTimeVerify.rawValue:
                if configuration.era != .beforeGenesis
                    || !configuration.flags.contains(.checkLockTimeVerify) {
                    if configuration.flags.contains(.discourageUpgradeableNops) {
                        throw ScriptExecutionError.consensus(.discouragedUpgradeableNop(opcode))
                    }
                    break
                }
                try executeCheckLockTime(opcode)
            case Opcode.checkSequenceVerify.rawValue:
                if configuration.era != .beforeGenesis
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
                if configuration.era == .afterChronicle {
                    try executeAfterChronicleSlice(opcode)
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
            didCompleteStep = true
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

    mutating func debugEvent(_ kind: ScriptDebugEventKind, failure: ScriptDebugFailure? = nil) throws {
        try debugState?.execution(kind, failure: failure)
    }

    mutating func debugEventBestEffort(_ kind: ScriptDebugEventKind, failure: ScriptDebugFailure? = nil) {
        debugState?.executionBestEffort(kind, failure: failure)
    }

    mutating func debugTransition(to phase: ScriptPhase) throws {
        try debugState?.transition(to: phase, operationCount: operationCount)
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
                if configuration.flags.contains(.minimalIf), enforcesNonMalleability,
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
            if configuration.era != .beforeGenesis, seen {
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
            guard configuration.era == .afterChronicle else {
                // After Genesis these are branch-sensitive; after Chronicle they
                // receive transaction-version matching semantics.
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
                requireMinimal: requiresMinimalData
            )
        } catch ScriptNumberError.nonMinimalEncoding {
            throw ScriptExecutionError.consensus(.nonMinimalNumber)
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
    }

    /// Reads a CHECKMULTISIG key or signature count. SV Node parses both with
    /// `CScriptNum::MAXIMUM_ELEMENT_SIZE` (four bytes) in every era.
    private mutating func popCountNumber() throws -> Int64 {
        let encoded = try mainStack.pop()
        let maximum = ScriptNumber.beforeGenesisMaximumByteCount
        guard encoded.count <= maximum else {
            throw ScriptExecutionError.consensus(.numberTooLarge(
                actual: encoded.count,
                maximum: maximum
            ))
        }
        do {
            return try ScriptNumber(
                encoded: encoded,
                maximumByteCount: maximum,
                requireMinimal: requiresMinimalData
            ).int64Clamped()
        } catch ScriptNumberError.nonMinimalEncoding {
            throw ScriptExecutionError.consensus(.nonMinimalNumber)
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
    }

    /// Reads an OP_SUBSTR, OP_LEFT or OP_RIGHT operand the way SV Node v1.2.3
    /// does (`CScriptNum` without big-integer mode, `deserialize<int64_t>`
    /// and `getint()`): the era length limit, the minimal-encoding check, a
    /// nine-byte ceiling, the signed 64-bit range, then saturation to Int32.
    private mutating func popSpliceOperand() throws -> Int64 {
        let encoded = try mainStack.pop()
        try checkNumberSize(encoded.count)
        if requiresMinimalData, !ScriptNumber.isMinimallyEncoded(encoded) {
            throw ScriptExecutionError.consensus(.nonMinimalNumber)
        }
        guard let last = encoded.last else { return 0 }
        guard encoded.count <= 9 else {
            throw ScriptExecutionError.consensus(.scriptNumberOverflow)
        }
        let isNegative = last & 0x80 != 0
        var magnitude: UInt64 = 0
        if encoded.count == 9 {
            // The ninth byte may only carry the sign.
            guard last & 0x7f == 0 else {
                throw ScriptExecutionError.consensus(.scriptNumberOverflow)
            }
            for (index, byte) in encoded.prefix(8).enumerated() {
                magnitude |= UInt64(byte) << (8 * index)
            }
        } else {
            for (index, byte) in encoded.enumerated() {
                let digit = index == encoded.count - 1 ? byte & 0x7f : byte
                magnitude |= UInt64(digit) << (8 * index)
            }
        }
        let value: Int64
        if magnitude <= UInt64(Int64.max) {
            value = isNegative ? -Int64(magnitude) : Int64(magnitude)
        } else if isNegative, magnitude == UInt64(Int64.max) + 1 {
            value = .min
        } else {
            throw ScriptExecutionError.consensus(.scriptNumberOverflow)
        }
        return min(max(value, Int64(Int32.min)), Int64(Int32.max))
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
        // After Genesis the node's big-number operators reject a result
        // longer than the number limit (script_num.cpp:166, 196, 216). Only
        // ADD, SUB, MUL and the one-operand forms built on them can grow a
        // value; every other result is no longer than an operand that was
        // already checked. Before Genesis the node computes in int64 with no
        // result check, so a result can be up to eight bytes (OP_MUL).
        if configuration.era != .beforeGenesis {
            try checkNumberSize(encoded.count)
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

    /// OP_LSHIFTNUM and OP_RSHIFTNUM as SV Node v1.2.3 evaluates them with
    /// big Script numbers (`CScriptNum::operator<<=` and `operator>>=`).
    private mutating func executeNumericShift(_ opcode: Opcode) throws {
        let shift = try popScriptNumber()
        guard !shift.isNegative else {
            throw ScriptExecutionError.consensus(.invalidShiftAmount(shift.int64Clamped()))
        }
        let value = try popScriptNumber()
        let shiftCount = shift.int64Clamped()

        if opcode == .rightShiftNumber {
            // `bsv::bint::operator>>=` rejects a count above INT_MAX.
            guard shiftCount <= Int64(Int32.max) else {
                throw ScriptExecutionError.consensus(.invalidShiftAmount(shiftCount))
            }
            // OpenSSL BN_rshift shifts the magnitude and keeps the sign, so a
            // negative value rounds toward zero: -3 >> 1 is -1, -1 >> 1 is 0.
            let magnitude = value.value.magnitude
            guard shiftCount < Int64(magnitude.bitWidth) else {
                mainStack.push([])
                return
            }
            let shifted = try performBigNumberOperation { budget in
                try magnitude.shiftedRight(by: Int(shiftCount), budget: budget)
            }
            try pushScriptNumber(BigSigned(sign: value.value.sign, magnitude: shifted))
            return
        }

        // The node rejects the shift when the operand's minimal size plus the
        // whole bytes shifted exceeds the era number limit, whatever the
        // value, and again when the shifted result is too large.
        let bitWidth = value.value.magnitude.bitWidth
        let currentSize = bitWidth == 0 ? 0 : bitWidth / 8 + 1
        let projectedSize = Int64(currentSize) + shiftCount / 8
        try checkNumberSize(Int(clamping: projectedSize))
        let shifted = try performBigNumberOperation { budget in
            try value.value.shiftedLeft(by: Int(shiftCount), budget: budget)
        }
        let shiftedWidth = shifted.magnitude.bitWidth
        try checkNumberSize(shiftedWidth == 0 ? 0 : shiftedWidth / 8 + 1)
        try pushScriptNumber(shifted)
    }

    private mutating func executeAfterChronicleSlice(_ opcode: Opcode) throws {
        let length = try popSpliceOperand()
        if opcode == .substring {
            let offset = try popSpliceOperand()
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
        phase: ScriptPhase,
        codeSeparatorOffset: Int
    ) throws -> Bool {
        guard let context else {
            throw ScriptExecutionError.missingExecutionContext(opcode: opcode)
        }
        try mainStack.require(2)
        let publicKeyBytes = try mainStack.pop()
        let signatureWithHashType = try mainStack.pop()

        // SV Node checks the signature encoding (an empty signature passes)
        // and then the public-key encoding before it checks the signature.
        let signature = try checkSignatureEncoding(signatureWithHashType)
        try checkPublicKeyEncoding(publicKeyBytes)
        guard let rawHashType = signatureWithHashType.last,
              let signature,
              let publicKey = try? PublicKey(publicKeyBytes)
        else {
            return try signatureFailure(signatureWithHashType)
        }

        let transaction = signingTransaction(context)
        let scriptCode = signatureScriptCode(
            script: script,
            phase: phase,
            codeSeparatorOffset: codeSeparatorOffset,
            signatures: [signatureWithHashType]
        )
        let digest = try signatureDigest(
            transaction: transaction,
            context: context,
            rawHashType: rawHashType,
            scriptCode: scriptCode
        )
        guard signature.verifiesInScript(publicKey: publicKey, digest: digest) else {
            return try signatureFailure(signatureWithHashType)
        }
        return true
    }

    private struct MultiSignatureInfo {
        let bytes: [UInt8]
        var parsed: ECDSASignature?
        var didParse = false
    }

    private mutating func executeCheckMultiSignature(
        opcode: Opcode,
        script: Script,
        phase: ScriptPhase,
        codeSeparatorOffset: Int
    ) throws -> Bool {
        guard let context else {
            throw ScriptExecutionError.missingExecutionContext(opcode: opcode)
        }

        let rawPublicKeyCount = try popCountNumber()
        let maximumPublicKeys = configuration.era == .beforeGenesis ? 20 : Int64(Int32.max)
        guard rawPublicKeyCount >= 0, rawPublicKeyCount <= maximumPublicKeys else {
            throw ScriptExecutionError.consensus(.invalidPublicKeyCount(rawPublicKeyCount))
        }
        let publicKeyCount = Int(rawPublicKeyCount)
        try countOperations(publicKeyCount)
        try mainStack.require(publicKeyCount)
        var publicKeys: [[UInt8]] = []
        publicKeys.reserveCapacity(publicKeyCount)
        for _ in 0..<publicKeyCount { publicKeys.append(try mainStack.pop()) }

        let rawSignatureCount = try popCountNumber()
        guard rawSignatureCount >= 0, rawSignatureCount <= rawPublicKeyCount else {
            throw ScriptExecutionError.consensus(.invalidSignatureCount(rawSignatureCount))
        }
        let signatureCount = Int(rawSignatureCount)
        try mainStack.require(signatureCount + 1)
        var signatures: [MultiSignatureInfo] = []
        signatures.reserveCapacity(signatureCount)
        for _ in 0..<signatureCount {
            signatures.append(MultiSignatureInfo(bytes: try mainStack.pop()))
        }
        let dummy = try mainStack.pop()
        if configuration.flags.contains(.strictMultiSignatureDummy), enforcesNonMalleability,
           !dummy.isEmpty {
            throw ScriptExecutionError.consensus(.nullDummy)
        }

        let scriptCode = signatureScriptCode(
            script: script,
            phase: phase,
            codeSeparatorOffset: codeSeparatorOffset,
            signatures: signatures.map(\.bytes)
        )
        let transaction = signingTransaction(context)

        var remainingSignatures = signatureCount
        // The early-impossibility check counts the key selected in the current
        // iteration as still available, matching Bitcoin's historical loop.
        var remainingPublicKeys = publicKeyCount + 1
        var signatureIndex = 0
        var publicKeyIndex = 0
        var success = true
        var cachedDigests: [UInt8: Hash256] = [:]

        while remainingSignatures > 0 {
            remainingPublicKeys -= 1
            if remainingSignatures > remainingPublicKeys {
                success = false
                break
            }

            let rawSignature = signatures[signatureIndex].bytes
            let publicKeyBytes = publicKeys[publicKeyIndex]
            publicKeyIndex += 1

            // The node checks both encodings on every comparison, including
            // for an empty signature.
            if !signatures[signatureIndex].didParse {
                signatures[signatureIndex].parsed = try checkSignatureEncoding(rawSignature)
                signatures[signatureIndex].didParse = true
            }
            try checkPublicKeyEncoding(publicKeyBytes)
            guard let rawHashType = rawSignature.last,
                  let signature = signatures[signatureIndex].parsed,
                  let publicKey = try? PublicKey(publicKeyBytes)
            else { continue }

            let digest: Hash256
            if let cached = cachedDigests[rawHashType] {
                digest = cached
            } else {
                digest = try signatureDigest(
                    transaction: transaction,
                    context: context,
                    rawHashType: rawHashType,
                    scriptCode: scriptCode
                )
                cachedDigests[rawHashType] = digest
            }
            if signature.verifiesInScript(publicKey: publicKey, digest: digest) {
                signatureIndex += 1
                remainingSignatures -= 1
            }
        }

        if !success, configuration.flags.contains(.nullFail), enforcesNonMalleability,
           signatures.contains(where: { !$0.bytes.isEmpty }) {
            throw ScriptExecutionError.consensus(.nullFail)
        }
        return success
    }

    /// SV Node `CheckSignatureEncoding`: DER, then low S, then the hash type.
    /// Returns the parsed signature, or `nil` for an empty signature or one
    /// whose scalars cannot be used, so that the check fails without an error.
    ///
    /// The DER rule is the node's structural `IsValidSignatureEncoding`. It
    /// does not check the scalar range, so a structurally valid signature
    /// with `r` or `s` zero or at least the curve order passes it. The node's
    /// low-S rule then reads the signature with its lax parser
    /// (`CPubKey::CheckLowS`), which keeps `(r, s)` unless a value is longer
    /// than 32 bytes or not below the curve order, and only then reads the
    /// zero signature. So `r = 0` with a high `s` still fails LOW_S, while an
    /// overflowing signature counts as low S. Neither verifies.
    private func checkSignatureEncoding(_ signatureWithHashType: [UInt8]) throws -> ECDSASignature? {
        guard let rawHashType = signatureWithHashType.last else { return nil }
        let requiresStrictDER = configuration.flags.contains(.strictEncoding)
            || configuration.flags.contains(.derSignatures)
            || configuration.flags.contains(.lowS)
        if requiresStrictDER, !Self.isValidSignatureEncoding(signatureWithHashType) {
            throw ScriptExecutionError.consensus(.invalidSignatureEncoding)
        }
        let signature = try? ECDSASignature(
            scriptBytes: Array(signatureWithHashType.dropLast()),
            strict: requiresStrictDER
        )
        if configuration.flags.contains(.lowS), enforcesNonMalleability {
            let isLowS = signature?.isLowS
                ?? Self.laxParseIsLowS(Array(signatureWithHashType.dropLast()))
            if !isLowS {
                throw ScriptExecutionError.consensus(.invalidSignatureEncoding)
            }
        }
        try checkHashTypeEncoding(rawHashType)
        return signature
    }

    /// SV Node `CPubKey::CheckLowS` over a structurally valid DER signature
    /// (without its hash type) that the strict parser rejected because a
    /// scalar is zero or out of range (pubkey.cpp:32-175, 353-363).
    ///
    /// The lax parser strips leading zeros. When either value is longer than
    /// 32 bytes or not below the curve order, it reads the zero signature,
    /// which is low S. Otherwise it keeps the values, so the real `s` is
    /// compared with half the curve order.
    static func laxParseIsLowS(_ der: [UInt8]) -> Bool {
        guard der.count >= 8 else { return true }
        let lengthR = Int(der[3])
        guard 6 + lengthR < der.count else { return true }
        let r = Array(der[4..<(4 + lengthR)])
        let lengthS = Int(der[5 + lengthR])
        guard 6 + lengthR + lengthS <= der.count else { return true }
        let s = Array(der[(6 + lengthR)..<(6 + lengthR + lengthS)])
        guard let r32 = paddedScalar(r), let s32 = paddedScalar(s),
              r32.lexicographicallyPrecedes(curveOrder),
              s32.lexicographicallyPrecedes(curveOrder)
        else { return true }
        return !halfCurveOrder.lexicographicallyPrecedes(s32)
    }

    /// A big-endian integer as 32 bytes, or `nil` when it needs more.
    private static func paddedScalar(_ bytes: [UInt8]) -> [UInt8]? {
        let magnitude = bytes.drop { $0 == 0 }
        guard magnitude.count <= 32 else { return nil }
        return Array(repeating: 0, count: 32 - magnitude.count) + magnitude
    }

    private static let curveOrder: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    private static let halfCurveOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ]

    /// SV Node `IsValidSignatureEncoding` (interpreter.cpp:177-245): the
    /// structural DER rules over a signature followed by its hash-type byte.
    static func isValidSignatureEncoding(_ signature: [UInt8]) -> Bool {
        let size = signature.count
        guard (9...73).contains(size),
              signature[0] == 0x30,
              Int(signature[1]) == size - 3
        else { return false }
        let lengthR = Int(signature[3])
        guard 5 + lengthR < size else { return false }
        let lengthS = Int(signature[5 + lengthR])
        guard lengthR + lengthS + 7 == size,
              signature[2] == 0x02,
              lengthR != 0,
              signature[4] & 0x80 == 0,
              !(lengthR > 1 && signature[4] == 0x00 && signature[5] & 0x80 == 0),
              signature[lengthR + 4] == 0x02,
              lengthS != 0,
              signature[lengthR + 6] & 0x80 == 0,
              !(lengthS > 1 && signature[lengthR + 6] == 0x00 && signature[lengthR + 7] & 0x80 == 0)
        else { return false }
        return true
    }

    /// SV Node `CheckSignatureEncoding` hash-type rules under STRICTENC.
    private func checkHashTypeEncoding(_ rawHashType: UInt8) throws {
        guard configuration.flags.contains(.strictEncoding) else { return }
        let hasForkID = rawHashType & Self.forkIDBit != 0
        let hasChronicle = rawHashType & Self.chronicleBit != 0
        if configuration.flags.contains(.bip143SignatureHash), !hasForkID {
            throw ScriptExecutionError.consensus(.invalidSignatureHashType(rawHashType))
        }
        let baseType = rawHashType & ~(Self.chronicleBit | Self.forkIDBit | Self.anyoneCanPayBit)
        guard (1...3).contains(baseType) else {
            throw ScriptExecutionError.consensus(.invalidSignatureHashType(rawHashType))
        }
        let forkIDEnabled = configuration.flags.contains(.enableForkID)
        if !forkIDEnabled, hasForkID {
            throw ScriptExecutionError.consensus(.illegalForkID(rawHashType))
        }
        if !configuration.flags.contains(.chronicle), hasChronicle {
            throw ScriptExecutionError.consensus(.illegalChronicle(rawHashType))
        }
        if forkIDEnabled, !hasForkID {
            throw ScriptExecutionError.consensus(.illegalForkID(rawHashType))
        }
    }

    private func checkPublicKeyEncoding(_ bytes: [UInt8]) throws {
        guard configuration.flags.contains(.strictEncoding) else { return }
        let compressed = bytes.count == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03)
        let uncompressed = bytes.count == 65 && bytes[0] == 0x04
        guard compressed || uncompressed else {
            throw ScriptExecutionError.consensus(.invalidPublicKeyEncoding)
        }
    }

    private static let chronicleBit: UInt8 = 0x20
    private static let forkIDBit: UInt8 = ForkIDSignatureHashType.forkIDMask
    private static let anyoneCanPayBit: UInt8 = ForkIDSignatureHashType.anyoneCanPayMask

    private func signingTransaction(_ context: ScriptExecutionContext) -> Transaction {
        var transaction = context.transaction
        transaction.inputs[context.inputIndex].sourceOutput = context.spentOutput
        return transaction
    }

    /// SV Node `SignatureHash`: the BIP143 digest only when ForkID is enabled
    /// and the hash type has FORKID without CHRONICLE; otherwise the original
    /// transaction digest (OTDA) over the node's script-code walk.
    private func signatureDigest(
        transaction: Transaction,
        context: ScriptExecutionContext,
        rawHashType: UInt8,
        scriptCode: [UInt8]
    ) throws -> Hash256 {
        let usesBIP143 = configuration.flags.contains(.enableForkID)
            && rawHashType & Self.forkIDBit != 0
            && rawHashType & Self.chronicleBit == 0
        do {
            if usesBIP143 {
                return try transaction.forkIDSignatureHash(
                    inputIndex: context.inputIndex,
                    rawHashType: rawHashType,
                    scriptCodeBytes: scriptCode,
                    limits: context.transactionLimits
                )
            }
            let original = Self.originalDigestScriptCode(scriptCode)
            return try transaction.legacySignatureHash(
                inputIndex: context.inputIndex,
                rawHashType: rawHashType,
                scriptCodeBytes: original.bytes,
                encodedScriptCodeLength: original.encodedLength,
                limits: context.transactionLimits
            )
        } catch let error as TransactionError {
            throw ScriptExecutionError.transaction(error)
        }
    }

    /// The script code a signature commits to, before digest-specific
    /// serialization: the current script from the last OP_CODESEPARATOR,
    /// followed under Chronicle rules by the locking script when the check
    /// runs in the unlocking script, with each signature removed by
    /// `FindAndDelete` unless ForkID is enabled and that signature uses it
    /// (SV Node `CleanupScriptCode`).
    private func signatureScriptCode(
        script: Script,
        phase: ScriptPhase,
        codeSeparatorOffset: Int,
        signatures: [[UInt8]]
    ) -> [UInt8] {
        var bytes = Array(script.bytes[codeSeparatorOffset...])
        if phase == .unlocking, configuration.flags.contains(.chronicle), let context {
            bytes += context.spentOutput.lockingScript.bytes
        }
        let forkIDEnabled = configuration.flags.contains(.enableForkID)
        for signature in signatures {
            let hasForkID = (signature.last ?? 0) & Self.forkIDBit != 0
            guard !forkIDEnabled || !hasForkID else { continue }
            bytes = Self.findAndDelete(bytes, pattern: Self.pushEncoding(signature))
        }
        return bytes
    }

    /// `CScript(vchSig)`: the data push SV Node builds for `FindAndDelete`.
    static func pushEncoding(_ data: [UInt8]) -> [UInt8] {
        let count = data.count
        var result: [UInt8]
        if count < Int(Opcode.pushData1.rawValue) {
            result = [UInt8(count)]
        } else if count <= 0xff {
            result = [Opcode.pushData1.rawValue, UInt8(count)]
        } else if count <= 0xffff {
            result = [Opcode.pushData2.rawValue,
                      UInt8(truncatingIfNeeded: count),
                      UInt8(truncatingIfNeeded: count >> 8)]
        } else {
            result = [Opcode.pushData4.rawValue,
                      UInt8(truncatingIfNeeded: count),
                      UInt8(truncatingIfNeeded: count >> 8),
                      UInt8(truncatingIfNeeded: count >> 16),
                      UInt8(truncatingIfNeeded: count >> 24)]
        }
        result += data
        return result
    }

    /// SV Node `CScript::GetOp2` over raw bytes. Returns the opcode, or `nil`
    /// at the end or on a truncated push; on a truncated push `position` is
    /// left where the node leaves it (after the opcode and any complete
    /// length field).
    private static func nodeNextOpcode(_ bytes: [UInt8], _ position: inout Int) -> UInt8? {
        guard position < bytes.count else { return nil }
        let opcode = bytes[position]
        position += 1
        guard opcode <= Opcode.pushData4.rawValue else { return opcode }
        var size = 0
        switch opcode {
        case Opcode.pushData1.rawValue:
            guard bytes.count - position >= 1 else { return nil }
            size = Int(bytes[position])
            position += 1
        case Opcode.pushData2.rawValue:
            guard bytes.count - position >= 2 else { return nil }
            size = Int(bytes[position]) | Int(bytes[position + 1]) << 8
            position += 2
        case Opcode.pushData4.rawValue:
            guard bytes.count - position >= 4 else { return nil }
            size = Int(bytes[position])
                | Int(bytes[position + 1]) << 8
                | Int(bytes[position + 2]) << 16
                | Int(bytes[position + 3]) << 24
            position += 4
        default:
            size = Int(opcode)
        }
        guard bytes.count - position >= size else { return nil }
        position += size
        return opcode
    }

    /// SV Node `CScript::FindAndDelete`: removes every occurrence of
    /// `pattern` that starts at an instruction boundary. A truncated final
    /// instruction ends the walk and its bytes are kept.
    static func findAndDelete(_ bytes: [UInt8], pattern: [UInt8]) -> [UInt8] {
        guard !pattern.isEmpty else { return bytes }
        var result: [UInt8] = []
        var found = 0
        var position = 0
        var kept = 0
        repeat {
            result += bytes[kept..<position]
            while bytes.count - position >= pattern.count,
                  bytes[position..<(position + pattern.count)].elementsEqual(pattern) {
                position += pattern.count
                found += 1
            }
            kept = position
        } while nodeNextOpcode(bytes, &position) != nil
        guard found > 0 else { return bytes }
        result += bytes[kept...]
        return result
    }

    /// SV Node `CTransactionSignatureSerializer::SerializeScriptCode`: drops
    /// every OP_CODESEPARATOR found by the instruction walk, stops at a
    /// truncated push after writing what the walk consumed, and declares the
    /// script size minus the separators found as the CompactSize length.
    static func originalDigestScriptCode(
        _ bytes: [UInt8]
    ) -> (bytes: [UInt8], encodedLength: Int) {
        var position = 0
        var separators = 0
        while let opcode = nodeNextOpcode(bytes, &position) {
            if opcode == Opcode.codeSeparator.rawValue { separators += 1 }
        }

        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        position = 0
        var segmentStart = 0
        while let opcode = nodeNextOpcode(bytes, &position) {
            if opcode == Opcode.codeSeparator.rawValue {
                result += bytes[segmentStart..<(position - 1)]
                segmentStart = position
            }
        }
        if segmentStart != bytes.count {
            result += bytes[segmentStart..<position]
        }
        return (result, bytes.count - separators)
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
        // before-Genesis execution, where ordinary arithmetic remains limited to four
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
                requireMinimal: requiresMinimalData
            ).int64Clamped()
        } catch ScriptNumberError.nonMinimalEncoding {
            throw ScriptExecutionError.consensus(.nonMinimalNumber)
        } catch let error as ScriptNumberError {
            throw ScriptExecutionError.scriptNumber(error)
        }
    }

    /// NULLFAIL applies to the whole signature element, hash-type byte included.
    private func signatureFailure(_ signatureWithHashType: [UInt8]) throws -> Bool {
        if configuration.flags.contains(.nullFail), enforcesNonMalleability,
           !signatureWithHashType.isEmpty {
            throw ScriptExecutionError.consensus(.nullFail)
        }
        return false
    }

    private mutating func countOperation() throws {
        try countOperations(1)
    }

    private mutating func countOperations(_ additional: Int) throws {
        let (scriptTotal, scriptOverflow) = operationsInCurrentScript
            .addingReportingOverflow(additional)
        let (overallTotal, overallOverflow) = operationCount.addingReportingOverflow(additional)
        operationsInCurrentScript = scriptOverflow ? Int.max : scriptTotal
        operationCount = overallOverflow ? Int.max : overallTotal
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

    private func isDisabledBeforeChronicle(_ opcode: Opcode) -> Bool {
        switch opcode.rawValue {
        case Opcode.twoMul.rawValue, Opcode.twoDiv.rawValue:
            true
        default:
            false
        }
    }
}
