import BSVScript

public enum TransactionInscriptionError: Error, Equatable, Sendable {
    case outputsMustBeEmpty
    case invalidInputIndex(Int)
    case missingSourceOutput(inputIndex: Int)
    case emptySourceOutput(inputIndex: Int)
    case satoshiIndexOutOfRange(index: UInt64, sourceSatoshis: UInt64)
    case precedingSatoshiCountOverflow
}

public struct SpecificOrdinalOutputIndices: Hashable, Sendable {
    public let precedingSatoshisOutputIndex: Int
    public let inscriptionOutputIndex: Int

    public init(precedingSatoshisOutputIndex: Int, inscriptionOutputIndex: Int) {
        self.precedingSatoshisOutputIndex = precedingSatoshisOutputIndex
        self.inscriptionOutputIndex = inscriptionOutputIndex
    }
}

public extension Transaction {
    /// Atomically appends one 1-satoshi BRC-307 inscription output.
    @discardableResult
    mutating func inscribe(
        _ arguments: InscriptionArgs,
        inscriptionLimits: InscriptionLimits,
        transactionLimits: TransactionLimits
    ) throws -> Int {
        let script = try arguments.brc307LockingScript(limits: inscriptionLimits)
        var candidate = self
        let index = candidate.outputs.count
        candidate.outputs.append(TransactionOutput(satoshis: 1, lockingScript: script))
        _ = try candidate.serializedByteCount(limits: transactionLimits)
        self = candidate
        return index
    }

    /// Atomically places all preceding satoshis before a selected ordinal, then inscribes it.
    ///
    /// Every input through `inputIndex` must carry explicit `sourceOutput` metadata.
    /// Existing outputs are rejected because they would change ordinal assignment.
    /// Two outputs are always created for Go compatibility; when the selected
    /// ordinal is first in the input stream, the preceding output has zero satoshis.
    /// Unlike pinned Go v1.3.3, `inputIndex == inputs.count` and a satoshi index
    /// outside the selected source output are rejected before any output mutation.
    @discardableResult
    mutating func inscribeSpecificOrdinal(
        _ arguments: InscriptionArgs,
        inputIndex: Int,
        satoshiIndex: UInt64,
        precedingSatoshisLockingScript: Script,
        inscriptionLimits: InscriptionLimits,
        transactionLimits: TransactionLimits
    ) throws -> SpecificOrdinalOutputIndices {
        guard outputs.isEmpty else { throw TransactionInscriptionError.outputsMustBeEmpty }
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionInscriptionError.invalidInputIndex(inputIndex)
        }
        guard precedingSatoshisLockingScript.byteCount <= inscriptionLimits.maximumScriptByteCount else {
            throw InscriptionError.scriptTooLarge(
                actual: precedingSatoshisLockingScript.byteCount,
                maximum: inscriptionLimits.maximumScriptByteCount
            )
        }
        do {
            _ = try precedingSatoshisLockingScript.operations(
                maximumPushDataByteCount: inscriptionLimits.maximumScriptByteCount
            )
        } catch {
            throw InscriptionError.malformedLockingScript
        }

        var preceding: UInt64 = 0
        for index in 0...inputIndex {
            guard let sourceOutput = inputs[index].sourceOutput else {
                throw TransactionInscriptionError.missingSourceOutput(inputIndex: index)
            }
            guard sourceOutput.satoshis != 0 else {
                throw TransactionInscriptionError.emptySourceOutput(inputIndex: index)
            }
            if index == inputIndex {
                guard satoshiIndex < sourceOutput.satoshis else {
                    throw TransactionInscriptionError.satoshiIndexOutOfRange(
                        index: satoshiIndex,
                        sourceSatoshis: sourceOutput.satoshis
                    )
                }
            } else {
                let (next, overflow) = preceding.addingReportingOverflow(sourceOutput.satoshis)
                guard !overflow else { throw TransactionInscriptionError.precedingSatoshiCountOverflow }
                preceding = next
            }
        }
        let (precedingAmount, overflow) = preceding.addingReportingOverflow(satoshiIndex)
        guard !overflow else { throw TransactionInscriptionError.precedingSatoshiCountOverflow }

        let inscriptionScript = try arguments.brc307LockingScript(limits: inscriptionLimits)
        var candidate = self
        candidate.outputs.append(TransactionOutput(
            satoshis: precedingAmount,
            lockingScript: precedingSatoshisLockingScript
        ))
        candidate.outputs.append(TransactionOutput(satoshis: 1, lockingScript: inscriptionScript))
        _ = try candidate.serializedByteCount(limits: transactionLimits)
        self = candidate
        return SpecificOrdinalOutputIndices(
            precedingSatoshisOutputIndex: 0,
            inscriptionOutputIndex: 1
        )
    }
}
