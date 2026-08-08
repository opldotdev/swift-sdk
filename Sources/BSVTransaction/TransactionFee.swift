/// A deterministic transaction fee policy.
public protocol TransactionFeeModel: Sendable {
    /// Returns the required fee for the transaction's actual or projected size.
    func fee(for transaction: Transaction, limits: TransactionLimits) throws -> UInt64
}

/// A size-based fee policy using 1,000 bytes per kilobyte.
public struct SatoshisPerKilobyteFeeModel: TransactionFeeModel, Hashable, Sendable {
    public let satoshisPerKilobyte: UInt64

    public init(satoshisPerKilobyte: UInt64) {
        self.satoshisPerKilobyte = satoshisPerKilobyte
    }

    public func fee(for transaction: Transaction, limits: TransactionLimits) throws -> UInt64 {
        let scriptByteCounts = try transaction.inputs.enumerated().map { inputIndex, input in
            if input.unlockingScript.byteCount > 0 {
                return input.unlockingScript.byteCount
            }
            guard let estimate = input.estimatedUnlockingScriptByteCount else {
                throw TransactionError.missingUnlockingScriptEstimate(inputIndex: inputIndex)
            }
            guard estimate >= 0 else {
                throw TransactionError.invalidUnlockingScriptEstimate(
                    inputIndex: inputIndex,
                    byteCount: estimate
                )
            }
            let estimate64 = UInt64(estimate)
            guard estimate64 <= limits.maximumScriptByteCount else {
                throw TransactionError.unlockingScriptEstimateExceedsLimit(
                    inputIndex: inputIndex,
                    actual: estimate64,
                    maximum: limits.maximumScriptByteCount
                )
            }
            return estimate
        }
        let byteCount = try transaction.serializedByteCount(
            unlockingScriptByteCounts: scriptByteCounts,
            limits: limits
        )
        return try Self.roundedUpFee(
            byteCount: UInt64(byteCount),
            satoshisPerKilobyte: satoshisPerKilobyte
        )
    }

    package static func roundedUpFee(
        byteCount: UInt64,
        satoshisPerKilobyte rate: UInt64
    ) throws -> UInt64 {
        let wholeKilobytes = byteCount / 1_000
        let remainingBytes = byteCount % 1_000

        let (wholeFee, wholeOverflow) = wholeKilobytes.multipliedReportingOverflow(by: rate)
        guard !wholeOverflow else { throw TransactionError.feeCalculationOverflow }

        // Decompose the remainder calculation so neither intermediate needs
        // to evaluate remainingBytes * rate at UInt64.max.
        let rateKilobytes = rate / 1_000
        let rateRemainder = rate % 1_000
        let partialWhole = remainingBytes * rateKilobytes
        let partialNumerator = remainingBytes * rateRemainder
        let partialRounded = partialNumerator == 0
            ? 0
            : (partialNumerator - 1) / 1_000 + 1
        let (partialFee, partialOverflow) = partialWhole.addingReportingOverflow(partialRounded)
        guard !partialOverflow else { throw TransactionError.feeCalculationOverflow }
        let (fee, overflow) = wholeFee.addingReportingOverflow(partialFee)
        guard !overflow else { throw TransactionError.feeCalculationOverflow }
        return fee
    }
}

public extension Transaction {
    /// The fee already paid by the current input and output amounts.
    func fee() throws -> UInt64 {
        let inputs = try totalInputSatoshis()
        let outputs = try totalOutputSatoshis()
        guard outputs <= inputs else {
            throw TransactionError.outputSatoshisExceedInputs(inputs: inputs, outputs: outputs)
        }
        return inputs - outputs
    }

    /// Assigns equal-valued change outputs after reserving the model's fee.
    ///
    /// If the remainder cannot give every change output at least one satoshi,
    /// all change outputs are removed and the remainder becomes additional
    /// miner fee. Division remainders likewise become additional fee. The
    /// mutation is atomic: any failure leaves the receiver unchanged.
    mutating func applyFee(
        using model: any TransactionFeeModel,
        limits: TransactionLimits
    ) throws {
        let requiredFee = try model.fee(for: self, limits: limits)
        let inputSatoshis = try totalInputSatoshis()

        var fixedOutputSatoshis: UInt64 = 0
        let changeOutputCount = outputs.lazy.filter(\.isChange).count
        for output in outputs where !output.isChange {
            let (next, overflow) = fixedOutputSatoshis.addingReportingOverflow(output.satoshis)
            guard !overflow else { throw TransactionError.satoshiTotalOverflow }
            fixedOutputSatoshis = next
        }
        let (requiredSatoshis, overflow) = fixedOutputSatoshis.addingReportingOverflow(requiredFee)
        guard !overflow else { throw TransactionError.feeCalculationOverflow }
        guard inputSatoshis >= requiredSatoshis else {
            throw TransactionError.insufficientInputSatoshis(
                inputs: inputSatoshis,
                outputs: fixedOutputSatoshis,
                fee: requiredFee
            )
        }

        guard changeOutputCount > 0 else { return }
        let change = inputSatoshis - requiredSatoshis
        var candidate = self
        if change < UInt64(changeOutputCount) {
            candidate.outputs.removeAll(where: \.isChange)
        } else {
            let satoshisPerChangeOutput = change / UInt64(changeOutputCount)
            for index in candidate.outputs.indices where candidate.outputs[index].isChange {
                candidate.outputs[index].satoshis = satoshisPerChangeOutput
            }
        }
        _ = try candidate.serializedByteCount(limits: limits)
        self = candidate
    }
}
