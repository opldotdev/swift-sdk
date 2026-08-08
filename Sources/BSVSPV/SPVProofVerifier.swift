import BSVCore
import BSVInterpreter
import BSVTransaction

/// Transport-independent SPV proof checks backed by caller-owned chain state.
public enum SPVProofVerifier {
    /// Verifies one transaction inclusion proof against a trusted chain tracker.
    public static func verify(
        _ merklePath: MerklePath,
        transactionID: TransactionID,
        using chainTracker: any ChainTracker
    ) async throws -> Bool {
        try await merklePath.verify(
            transactionID: transactionID,
            using: chainTracker
        )
    }

    /// Verifies BEEF dependency closure and all supplied Merkle roots.
    ///
    /// This proof-stage API does not execute Bitcoin scripts. Full BRC-67
    /// validation composes this result with interpreter, fee, and lock checks.
    public static func verify(
        _ beef: BEEF,
        using chainTracker: any ChainTracker,
        allowTransactionIDOnly: Bool,
        limits: TransactionLimits
    ) async throws -> Bool {
        try await beef.verify(
            using: chainTracker,
            allowTransactionIDOnly: allowTransactionIDOnly,
            limits: limits
        )
    }

    /// Performs complete BRC-67 validation for one root transaction in a BEEF graph.
    ///
    /// The envelope must prove every reachable source transaction either through
    /// a trusted Merkle root or through a complete chain of raw transactions.
    /// Transactions below a trusted Merkle anchor are not re-executed. Every
    /// unproven transaction has its source outputs resolved, value conservation
    /// checked, and input scripts evaluated. When supplied, `feeModel` applies to
    /// the root transaction only, matching the Go SDK's fee-policy boundary.
    ///
    /// Lock-time and sequence commitments are evaluated by the interpreter when
    /// the corresponding Script opcodes are present. Network-specific transaction
    /// finality policy remains caller-owned because BRC-67 does not define the
    /// height/time context required to evaluate it independently.
    public static func verify(
        _ beef: BEEF,
        rootTransactionID: TransactionID,
        using chainTracker: any ChainTracker,
        feeModel: (any TransactionFeeModel)? = nil,
        scriptConfiguration: ScriptExecutionConfiguration,
        allowTransactionIDOnly: Bool = false,
        limits: BEEFLimits
    ) async throws -> Bool {
        guard try await beef.verify(
            using: chainTracker,
            allowTransactionIDOnly: allowTransactionIDOnly,
            limits: limits.transactionLimits
        ) else {
            return false
        }

        let entries = try beef.indexedEntries(limits: limits.transactionLimits)
        guard let rootEntry = entries[rootTransactionID] else {
            throw SPVValidationError.rootTransactionMissing(rootTransactionID)
        }
        guard rootEntry.transaction != nil else {
            throw SPVValidationError.rootTransactionIDOnly(rootTransactionID)
        }

        let provenTransactionIDs = try Set(beef.transactions.compactMap { entry in
            let transactionID = try entry.transactionID(limits: limits.transactionLimits)
            return beef.isProven(transactionID, entry: entry) ? transactionID : nil
        })

        var contextualTransactions: [TransactionID: Transaction] = [:]
        var valueValidatedTransactionIDs: Set<TransactionID> = []
        if let feeModel {
            let root = try contextualTransaction(
                rootTransactionID,
                entries: entries
            )
            contextualTransactions[rootTransactionID] = root
            let paid = try transactionFee(root, transactionID: rootTransactionID)
            valueValidatedTransactionIDs.insert(rootTransactionID)
            let required = try feeModel.fee(
                for: root,
                limits: limits.transactionLimits
            )
            guard paid >= required else {
                throw SPVValidationError.feeTooLow(paid: paid, required: required)
            }
        }

        var pending = [rootTransactionID]
        var visited: Set<TransactionID> = []
        while let transactionID = pending.popLast() {
            guard visited.insert(transactionID).inserted else { continue }
            guard !provenTransactionIDs.contains(transactionID) else { continue }
            guard let entry = entries[transactionID] else {
                throw SPVValidationError.rootTransactionMissing(transactionID)
            }
            guard entry.transaction != nil else {
                throw SPVValidationError.rootTransactionIDOnly(transactionID)
            }

            let transaction: Transaction
            if let contextual = contextualTransactions[transactionID] {
                transaction = contextual
            } else {
                transaction = try contextualTransaction(transactionID, entries: entries)
                contextualTransactions[transactionID] = transaction
            }
            if valueValidatedTransactionIDs.insert(transactionID).inserted {
                _ = try transactionFee(transaction, transactionID: transactionID)
            }

            for inputIndex in transaction.inputs.indices {
                let input = transaction.inputs[inputIndex]
                guard let sourceOutput = input.sourceOutput else {
                    // contextualTransaction establishes this invariant.
                    throw SPVValidationError.missingSourceTransaction(
                        transactionID: transactionID,
                        inputIndex: inputIndex,
                        sourceTransactionID: input.previousOutput.transactionID
                    )
                }
                do {
                    _ = try ScriptInterpreter.execute(
                        unlockingScript: input.unlockingScript,
                        lockingScript: sourceOutput.lockingScript,
                        configuration: scriptConfiguration,
                        context: ScriptExecutionContext(
                            transaction: transaction,
                            inputIndex: inputIndex,
                            spentOutput: sourceOutput,
                            transactionLimits: limits.transactionLimits
                        )
                    )
                } catch let error as ScriptExecutionError {
                    throw SPVValidationError.scriptVerificationFailed(
                        transactionID: transactionID,
                        inputIndex: inputIndex,
                        cause: error
                    )
                }
                pending.append(input.previousOutput.transactionID)
            }
        }
        return true
    }

    private static func contextualTransaction(
        _ transactionID: TransactionID,
        entries: [TransactionID: BEEFTransaction]
    ) throws -> Transaction {
        guard let entry = entries[transactionID] else {
            throw SPVValidationError.rootTransactionMissing(transactionID)
        }
        guard var transaction = entry.transaction else {
            throw SPVValidationError.rootTransactionIDOnly(transactionID)
        }

        for inputIndex in transaction.inputs.indices {
            let outpoint = transaction.inputs[inputIndex].previousOutput
            guard let sourceEntry = entries[outpoint.transactionID],
                  let sourceTransaction = sourceEntry.transaction
            else {
                throw SPVValidationError.missingSourceTransaction(
                    transactionID: transactionID,
                    inputIndex: inputIndex,
                    sourceTransactionID: outpoint.transactionID
                )
            }
            let outputIndex = Int(outpoint.outputIndex)
            guard sourceTransaction.outputs.indices.contains(outputIndex) else {
                throw SPVValidationError.sourceOutputIndexOutOfBounds(
                    transactionID: transactionID,
                    inputIndex: inputIndex,
                    sourceTransactionID: outpoint.transactionID,
                    outputIndex: outpoint.outputIndex,
                    outputCount: sourceTransaction.outputs.count
                )
            }
            transaction.inputs[inputIndex].sourceOutput = sourceTransaction.outputs[outputIndex]
            if transaction.inputs[inputIndex].estimatedUnlockingScriptByteCount == nil {
                // Fee validation measures the received wire transaction. An
                // empty unlocking script is valid for scripts such as OP_TRUE,
                // so construction-time projection must explicitly be zero.
                transaction.inputs[inputIndex].estimatedUnlockingScriptByteCount =
                    transaction.inputs[inputIndex].unlockingScript.byteCount
            }
        }
        return transaction
    }

    private static func transactionFee(
        _ transaction: Transaction,
        transactionID: TransactionID
    ) throws -> UInt64 {
        var inputTotal: UInt64 = 0
        for input in transaction.inputs {
            guard let sourceOutput = input.sourceOutput else { continue }
            let (next, overflow) = inputTotal.addingReportingOverflow(sourceOutput.satoshis)
            guard !overflow else {
                throw SPVValidationError.satoshiTotalOverflow(transactionID: transactionID)
            }
            inputTotal = next
        }

        let outputTotal: UInt64
        do {
            outputTotal = try transaction.totalOutputSatoshis()
        } catch {
            throw SPVValidationError.satoshiTotalOverflow(transactionID: transactionID)
        }
        guard outputTotal <= inputTotal else {
            throw SPVValidationError.outputsExceedInputs(
                transactionID: transactionID,
                inputs: inputTotal,
                outputs: outputTotal
            )
        }
        guard outputTotal < inputTotal else {
            throw SPVValidationError.nonPositiveFee(
                transactionID: transactionID,
                satoshis: inputTotal
            )
        }
        return inputTotal - outputTotal
    }
}
