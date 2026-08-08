import BSVCore
import BSVScript

public extension Transaction {
    mutating func addInput(_ input: TransactionInput) {
        inputs.append(input)
    }

    /// Adds a hydrated input suitable for fee calculation and signing.
    @discardableResult
    mutating func addInput(
        spending unspentOutput: UnspentTransactionOutput,
        sequence: UInt32 = TransactionInput.finalSequence,
        estimatedUnlockingScriptByteCount: Int? = nil
    ) throws -> Int {
        let emptyScript = try Script(bytes: [], maximumByteCount: 0)
        inputs.append(TransactionInput(
            previousOutput: unspentOutput.outpoint,
            unlockingScript: emptyScript,
            sequence: sequence,
            sourceOutput: unspentOutput.output,
            estimatedUnlockingScriptByteCount: estimatedUnlockingScriptByteCount
        ))
        return inputs.index(before: inputs.endIndex)
    }

    /// Adds a compressed-key P2PKH input with its safe maximum pre-signing size.
    @discardableResult
    mutating func addPayToPublicKeyHashInput(
        spending unspentOutput: UnspentTransactionOutput,
        sequence: UInt32 = TransactionInput.finalSequence
    ) throws -> Int {
        try addInput(
            spending: unspentOutput,
            sequence: sequence,
            estimatedUnlockingScriptByteCount:
                TransactionInput.payToPublicKeyHashUnlockingScriptByteCount
        )
    }

    mutating func addOutput(_ output: TransactionOutput) {
        outputs.append(output)
    }

    @discardableResult
    mutating func addOutput(
        satoshis: UInt64,
        lockingScript: Script,
        isChange: Bool = false
    ) -> Int {
        outputs.append(TransactionOutput(
            satoshis: satoshis,
            lockingScript: lockingScript,
            isChange: isChange
        ))
        return outputs.index(before: outputs.endIndex)
    }

    /// Adds a standard P2PKH output from an exact 20-byte public-key hash.
    @discardableResult
    mutating func addPayToPublicKeyHashOutput(
        satoshis: UInt64,
        publicKeyHash: Hash160,
        isChange: Bool = false,
        maximumScriptByteCount: Int = 25
    ) throws -> Int {
        let lockingScript = try Script.payToPublicKeyHash(
            publicKeyHash,
            maximumByteCount: maximumScriptByteCount
        )
        return addOutput(
            satoshis: satoshis,
            lockingScript: lockingScript,
            isChange: isChange
        )
    }
}
