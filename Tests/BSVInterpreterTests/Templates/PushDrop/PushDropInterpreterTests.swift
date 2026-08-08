import BSVCore
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@Suite("PushDrop interpreter spends")
struct PushDropInterpreterTests {
    @Test("lock-after and explicit compatibility spends execute; signed mutation fails", arguments: [
        PushDropLockPosition.after,
        PushDropLockPosition.beforeCompatibility,
    ])
    func spends(lockPosition: PushDropLockPosition) throws {
        let key = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let lockingScript = try PushDrop.lockingScript(
            fields: [[0xaa], [0xbb], [0xcc]],
            publicKey: key.publicKey,
            lockPosition: lockPosition
        )
        let spentOutput = TransactionOutput(satoshis: 10_000, lockingScript: lockingScript)
        let empty = try Script(bytes: [], maximumByteCount: 0)
        var transaction = Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(wireBytes: [UInt8](repeating: 0x33, count: 32)),
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sourceOutput: spentOutput
            )],
            outputs: [TransactionOutput(satoshis: 9_900, lockingScript: empty)]
        )
        try transaction.signPushDropInput(
            at: 0,
            with: key,
            lockPosition: lockPosition,
            limits: transactionLimits
        )
        #expect(try execute(transaction, spentOutput: spentOutput).stack == [[1]])

        var changed = transaction
        changed.outputs[0].satoshis -= 1
        #expect(throws: ScriptExecutionError.self) {
            try execute(changed, spentOutput: spentOutput)
        }
    }

    @Test("a wrong private key cannot install an unlocking script")
    func wrongKey() throws {
        let owner = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let wrong = try PrivateKey([UInt8](repeating: 0, count: 31) + [2])
        let lockingScript = try PushDrop.lockingScript(fields: [[1]], publicKey: owner.publicKey)
        let empty = try Script(bytes: [], maximumByteCount: 0)
        var transaction = Transaction(inputs: [TransactionInput(
            previousOutput: try Outpoint(
                transactionID: TransactionID(wireBytes: [UInt8](repeating: 0x44, count: 32)),
                outputIndex: 0
            ),
            unlockingScript: empty,
            sourceOutput: TransactionOutput(satoshis: 1, lockingScript: lockingScript)
        )])
        #expect(throws: PushDropError.privateKeyDoesNotMatchPublicKey(inputIndex: 0)) {
            try transaction.signPushDropInput(at: 0, with: wrong, limits: transactionLimits)
        }
        #expect(transaction.inputs[0].unlockingScript.isEmpty)
    }

    private let transactionLimits = try! TransactionLimits(
        maximumTransactionByteCount: 10_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 10_000
    )

    private func execute(
        _ transaction: Transaction,
        spentOutput: TransactionOutput
    ) throws -> ScriptExecutionResult {
        let configuration = try ScriptExecutionConfiguration(
            era: .afterGenesis,
            flags: [.enableForkID, .derSignatures, .lowS, .nullFail],
            resourceLimits: .standard
        )
        return try ScriptInterpreter.execute(
            unlockingScript: transaction.inputs[0].unlockingScript,
            lockingScript: spentOutput.lockingScript,
            configuration: configuration,
            context: ScriptExecutionContext(
                transaction: transaction,
                inputIndex: 0,
                spentOutput: spentOutput,
                transactionLimits: transactionLimits
            )
        )
    }
}
