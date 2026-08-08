import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import Testing

@Suite("Wallet action ABI redaction")
struct WalletActionABIRedactionTests {
    @Test("create-action diagnostics redact scripts, BEEF, references, and nested values")
    func createActionFamilies() throws {
        let fixture = try ActionABIRedactionFixture()
        let inputUnlocking = WalletInputUnlocking.script(fixture.secretBytes)
        let input = try WalletCreateActionInput(
            outpoint: fixture.outpoint,
            inputDescription: fixture.secretText,
            unlockingScript: fixture.secretBytes
        )
        let output = try WalletCreateActionOutput(
            lockingScript: fixture.secretBytes,
            satoshis: 1,
            outputDescription: fixture.secretText,
            customInstructions: fixture.secretText,
            tags: [fixture.secretText]
        )
        let request = try WalletCreateActionRequest(
            description: fixture.secretText,
            inputBEEF: fixture.beef,
            inputs: [input],
            outputs: [output],
            labels: [fixture.secretText]
        )
        let signable = WalletSignableTransaction(
            transaction: fixture.atomicBEEF,
            reference: try WalletBase64Data(fixture.secretBytes)
        )
        let result = try WalletCreateActionResult(signableTransaction: signable)

        assertRedacted("WalletInputUnlocking", inputUnlocking, fixture: fixture)
        assertRedacted("WalletCreateActionInput", input, fixture: fixture)
        assertRedacted("WalletCreateActionOutput", output, fixture: fixture)
        assertRedacted("WalletCreateActionRequest", request, fixture: fixture)
        assertRedacted("WalletSignableTransaction", signable, fixture: fixture)
        assertRedacted("WalletCreateActionResult", result, fixture: fixture)
    }

    @Test("sign- and abort-action diagnostics redact scripts, references, and transaction material")
    func signAndAbortActionFamilies() throws {
        let fixture = try ActionABIRedactionFixture()
        let spend = try WalletSignActionSpend(unlockingScript: fixture.secretBytes)
        let request = try WalletSignActionRequest(
            reference: WalletBase64Data(fixture.secretBytes),
            spends: [7: spend]
        )
        let result = try WalletSignActionResult(
            transactionID: fixture.transactionID,
            transaction: fixture.atomicBEEF
        )
        let abort = WalletAbortActionRequest(reference: try WalletBase64Data(fixture.secretBytes))

        assertRedacted("WalletSignActionSpend", spend, fixture: fixture)
        assertRedacted("WalletSignActionRequest", request, fixture: fixture)
        assertRedacted("WalletSignActionResult", result, fixture: fixture)
        assertRedacted("WalletAbortActionRequest", abort, fixture: fixture)
    }

    @Test("listed action and output diagnostics redact every nested script")
    func listedActionFamilies() throws {
        let fixture = try ActionABIRedactionFixture()
        let input = try WalletActionInput(
            sourceOutpoint: fixture.outpoint,
            sourceSatoshis: 2,
            sourceLockingScript: fixture.secretBytes,
            unlockingScript: fixture.secretBytes,
            inputDescription: fixture.secretText,
            sequenceNumber: 3
        )
        let actionOutput = try WalletActionOutput(
            satoshis: 1,
            lockingScript: fixture.secretBytes,
            spendable: true,
            customInstructions: fixture.secretText,
            tags: [fixture.secretText],
            outputIndex: 0,
            outputDescription: fixture.secretText,
            basket: fixture.secretText
        )
        let action = try WalletAction(
            transactionID: fixture.transactionID,
            satoshis: -1,
            status: .completed,
            isOutgoing: true,
            description: fixture.secretText,
            labels: [fixture.secretText],
            version: 1,
            lockTime: 0,
            inputs: [input],
            outputs: [actionOutput]
        )
        let actionResult = try WalletListActionsResult(totalActions: 1, actions: [action])
        let output = try WalletOutput(
            satoshis: 1,
            lockingScript: fixture.secretBytes,
            spendable: true,
            customInstructions: fixture.secretText,
            tags: [fixture.secretText],
            outpoint: fixture.outpoint,
            labels: [fixture.secretText]
        )
        let outputResult = try WalletListOutputsResult(
            totalOutputs: 1,
            beef: fixture.beef,
            outputs: [output]
        )

        assertRedacted("WalletActionInput", input, fixture: fixture)
        assertRedacted("WalletActionOutput", actionOutput, fixture: fixture)
        assertRedacted("WalletAction", action, fixture: fixture)
        assertRedacted("WalletListActionsResult", actionResult, fixture: fixture)
        assertRedacted("WalletOutput", output, fixture: fixture)
        assertRedacted("WalletListOutputsResult", outputResult, fixture: fixture)
    }

    @Test("internalize diagnostics redact transaction and derivation material")
    func internalizeActionFamilies() throws {
        let fixture = try ActionABIRedactionFixture()
        let payment = try WalletPaymentRemittance(
            derivationPrefix: WalletBase64Data(fixture.secretBytes),
            derivationSuffix: WalletBase64Data(fixture.secretBytes.reversed()),
            senderIdentityKey: walletTestPrivateKey(42).publicKey
        )
        let remittance = WalletInternalizeRemittance.walletPayment(payment)
        let output = WalletInternalizeOutput(outputIndex: 0, remittance: remittance)
        let request = try WalletInternalizeActionRequest(
            transaction: fixture.atomicBEEF,
            description: fixture.secretText,
            labels: [fixture.secretText],
            outputs: [output]
        )

        assertRedacted("WalletPaymentRemittance", payment, fixture: fixture)
        assertRedacted("WalletInternalizeRemittance", remittance, fixture: fixture)
        assertRedacted("WalletInternalizeOutput", output, fixture: fixture)
        assertRedacted("WalletInternalizeActionRequest", request, fixture: fixture)
    }

    private func assertRedacted(
        _ typeName: String,
        _ value: Any,
        fixture: ActionABIRedactionFixture
    ) {
        let described = String(describing: value)
        let reflected = String(reflecting: value)
        var dumped = ""
        dump(value, to: &dumped)

        #expect(described.contains("<redacted"), "\(typeName) has no redacted description label")
        #expect(reflected.contains("<redacted"), "\(typeName) has no redacted reflection label")
        #expect(dumped.contains("<redacted"), "\(typeName) has no redacted dump label")
        #expect(
            Array(Mirror(reflecting: value).children).isEmpty,
            "\(typeName) exposes children through Mirror"
        )
        for forbidden in fixture.forbiddenDiagnosticValues {
            #expect(!described.contains(forbidden), "\(typeName) description exposes protected data")
            #expect(!reflected.contains(forbidden), "\(typeName) reflection exposes protected data")
            #expect(!dumped.contains(forbidden), "\(typeName) dump exposes protected data")
        }
    }
}

private struct ActionABIRedactionFixture {
    let secretText = "action-abi-secret-sentinel"
    let secretBytes = Array("action-abi-secret-sentinel".utf8)
    let transactionID: TransactionID
    let outpoint: Outpoint
    let beef: BEEF
    let atomicBEEF: AtomicBEEF

    init() throws {
        let limits = try BEEFLimits(
            maximumByteCount: 10_000,
            maximumMerklePathCount: 10,
            maximumTransactionCount: 10,
            transactionLimits: try TransactionLimits(
                maximumTransactionByteCount: 10_000,
                maximumInputCount: 10,
                maximumOutputCount: 10,
                maximumScriptByteCount: 1_000
            ),
            merklePathLimits: try MerklePathLimits(
                maximumByteCount: 10_000,
                maximumLeavesPerLevel: 10,
                maximumTotalLeaves: 10
            )
        )
        let transactionID = try TransactionID(wireBytes: Array(repeating: 0xA7, count: 32))
        let beef = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [.transactionID(transactionID)],
            limits: limits
        )
        self.transactionID = transactionID
        self.outpoint = Outpoint(transactionID: transactionID, outputIndex: 7)
        self.beef = beef
        self.atomicBEEF = try AtomicBEEF(
            subjectTransactionID: transactionID,
            beef: beef,
            limits: limits
        )
    }

    var forbiddenDiagnosticValues: [String] {
        [
            secretText,
            secretBytes.description,
            String(describing: transactionID),
            String(reflecting: transactionID),
        ]
    }
}
