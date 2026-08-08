import BSVScript

/// Executes Bitcoin Script pairs under an explicit consensus era and resource policy.
public enum ScriptInterpreter {
    public static func execute(
        unlockingScript: Script,
        lockingScript: Script,
        configuration: ScriptExecutionConfiguration,
        context: ScriptExecutionContext? = nil
    ) throws -> ScriptExecutionResult {
        if let context {
            guard context.inputIndex >= 0,
                  context.inputIndex < context.transaction.inputs.count
            else {
                throw ScriptExecutionError.invalidContext(.inputIndexOutOfBounds(
                    index: context.inputIndex,
                    inputCount: context.transaction.inputs.count
                ))
            }
            guard context.transaction.inputs[context.inputIndex].unlockingScript == unlockingScript else {
                throw ScriptExecutionError.invalidContext(.unlockingScriptMismatch)
            }
            guard context.spentOutput.lockingScript == lockingScript else {
                throw ScriptExecutionError.invalidContext(.lockingScriptMismatch)
            }
        }

        let evaluatesPayToScriptHash = configuration.era == .beforeGenesis
            && configuration.flags.contains(.payToScriptHash)
            && lockingScript.isPayToScriptHash
        if configuration.flags.contains(.signaturePushOnly) || evaluatesPayToScriptHash {
            let isPushOnly = try isPushOnly(
                unlockingScript,
                configuration: configuration
            )
            guard isPushOnly else {
                throw ScriptExecutionError.consensus(.signatureScriptNotPushOnly)
            }
        }

        var machine = ScriptMachine(configuration: configuration, context: context)
        try machine.execute(unlockingScript, phase: .unlocking)
        let unlockingStack = machine.mainStack.items
        try machine.execute(lockingScript, phase: .locking)

        if evaluatesPayToScriptHash {
            guard let lockingResult = machine.mainStack.items.last else {
                throw ScriptExecutionError.consensus(.emptyFinalStack)
            }
            guard scriptBoolean(lockingResult) else {
                throw ScriptExecutionError.consensus(.evaluatedFalse)
            }
            guard let redeemBytes = unlockingStack.last else {
                throw ScriptExecutionError.consensus(.emptyFinalStack)
            }
            let redeemScript: Script
            do {
                redeemScript = try Script(
                    bytes: redeemBytes,
                    maximumByteCount: configuration.resourceLimits.maximumScriptByteCount
                )
            } catch {
                throw ScriptExecutionError.resourceBudgetExceeded(.scriptByteCount(
                    actual: redeemBytes.count,
                    maximum: configuration.resourceLimits.maximumScriptByteCount
                ))
            }
            try machine.replaceMainStack(with: Array(unlockingStack.dropLast()))
            try machine.execute(redeemScript, phase: .redeem)
        }

        let finalStack = machine.mainStack.items
        guard let top = finalStack.last else {
            throw ScriptExecutionError.consensus(.emptyFinalStack)
        }
        if configuration.flags.contains(.cleanStack), finalStack.count != 1 {
            throw ScriptExecutionError.consensus(.cleanStackViolation(
                actualItemCount: finalStack.count
            ))
        }
        guard scriptBoolean(top) else {
            throw ScriptExecutionError.consensus(.evaluatedFalse)
        }

        return ScriptExecutionResult(
            stack: finalStack,
            operationCount: machine.operationCount,
            didEarlyReturn: machine.didEarlyReturn
        )
    }

    private static func isPushOnly(
        _ script: Script,
        configuration: ScriptExecutionConfiguration
    ) throws -> Bool {
        let consensus = ScriptConsensusLimits.forEra(configuration.era)
        var offset = 0
        while offset < script.byteCount {
            let instruction = try ScriptInstructionDecoder.next(
                bytes: script.bytes,
                offset: &offset,
                phase: .unlocking,
                maximumConsensusPushByteCount: consensus.maximumPushDataByteCount,
                maximumResourcePushByteCount: configuration.resourceLimits.maximumPushDataByteCount
            )
            if instruction.opcode.rawValue > Opcode.sixteen.rawValue {
                return false
            }
        }
        return true
    }
}
