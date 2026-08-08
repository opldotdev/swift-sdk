import BSVCore
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import Testing

@Suite("Wallet-backed PushDrop interpreter spends")
struct WalletPushDropInterpreterTests {
    @Test("cross-party wallet spends execute for both layouts and all ForkID flags")
    func realWalletSpends() async throws {
        let aliceKey = try privateKey(42)
        let bobKey = try privateKey(69)
        let alice = ProtoWallet(rootKey: aliceKey)
        let bob = ProtoWallet(rootKey: bobKey)
        let protocolID = try WalletProtocolID(
            securityLevel: .silent,
            name: "pushdrop interpreter"
        )
        let keyID = try WalletKeyID("cross-party spend")
        let hashTypes = try [UInt8(0x41), 0x42, 0x43, 0xc1, 0xc2, 0xc3].map {
            try ForkIDSignatureHashType(rawValue: $0)
        }

        for lockPosition in [
            PushDropLockPosition.after,
            .beforeCompatibility,
        ] {
            let lockingScript = try await PushDrop.lockingScript(
                fields: [[0], [1], [0x81], [UInt8](repeating: 0x4c, count: 76)],
                using: alice,
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .publicKey(bobKey.publicKey),
                forSelf: false,
                lockPosition: lockPosition
            )
            let spentOutput = TransactionOutput(
                satoshis: 10_000,
                lockingScript: lockingScript
            )

            for hashType in hashTypes {
                var transaction = try unsignedTransaction(spentOutput: spentOutput)
                try await transaction.signPushDropInput(
                    at: 0,
                    using: bob,
                    protocolID: protocolID,
                    keyID: keyID,
                    counterparty: .publicKey(aliceKey.publicKey),
                    lockPosition: lockPosition,
                    hashType: hashType,
                    limits: transactionLimits
                )

                #expect(try execute(transaction, spentOutput: spentOutput).stack == [[1]])
            }
        }
    }

    private let transactionLimits = try! TransactionLimits(
        maximumTransactionByteCount: 100_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 100_000
    )

    private func privateKey(_ value: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [value])
    }

    private func unsignedTransaction(
        spentOutput: TransactionOutput
    ) throws -> Transaction {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        return Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(
                        wireBytes: [UInt8](repeating: 0x44, count: 32)
                    ),
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sequence: 0xffff_fffe,
                sourceOutput: spentOutput
            )],
            outputs: [TransactionOutput(satoshis: 9_000, lockingScript: empty)]
        )
    }

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
