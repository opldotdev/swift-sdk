import BSVCore
import BSVCrypto
import BSVInterpreter
import BSVSPV
import BSVScript
import BSVTransaction
import Testing

@Suite("SPV proof verifier")
struct SPVProofVerifierTests {
    @Test("the public façade verifies a transaction inclusion proof")
    func merklePath() async throws {
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 1_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 100
        )
        let transaction = Transaction(
            version: 1,
            inputs: [],
            outputs: [],
            lockTime: 0
        )
        let transactionID = try transaction.transactionID(limits: limits)
        let root = try Hash256(transactionID.wireBytes)
        let path = try MerklePath(
            blockHeight: 100,
            levels: [[.hash(offset: 0, hash: root, isTransactionID: true)]]
        )
        let tracker = FixedChainTracker(root: root, blockHeight: 100)

        #expect(try await SPVProofVerifier.verify(
            path,
            transactionID: transactionID,
            using: tracker
        ))
    }

    @Test("complete BRC-67 validation resolves ancestry, fees, and scripts")
    func completeValidation() async throws {
        let fixture = try FullSPVFixture()

        #expect(try await SPVProofVerifier.verify(
            fixture.beef,
            rootTransactionID: fixture.childID,
            using: fixture.tracker,
            feeModel: SatoshisPerKilobyteFeeModel(satoshisPerKilobyte: 1),
            scriptConfiguration: fixture.scriptConfiguration,
            limits: fixture.beefLimits
        ))
    }

    @Test("untrusted roots return false before transaction execution")
    func rejectedRoot() async throws {
        let fixture = try FullSPVFixture()
        let tracker = FixedChainTracker(
            root: BSVHashing.sha256d([0xff]),
            blockHeight: fixture.path.blockHeight
        )

        #expect(!(try await SPVProofVerifier.verify(
            fixture.beef,
            rootTransactionID: fixture.childID,
            using: tracker,
            scriptConfiguration: fixture.scriptConfiguration,
            limits: fixture.beefLimits
        )))
    }

    @Test("root fee policy and value conservation are checked")
    func fees() async throws {
        let fixture = try FullSPVFixture()

        await #expect(throws: SPVValidationError.feeTooLow(paid: 1, required: 1_000)) {
            try await SPVProofVerifier.verify(
                fixture.beef,
                rootTransactionID: fixture.childID,
                using: fixture.tracker,
                feeModel: FixedFeeModel(fee: 1_000),
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }

        let inflationaryChild = Transaction(
            version: 1,
            inputs: [try fixture.input(outputIndex: 0)],
            outputs: [TransactionOutput(
                satoshis: 11,
                lockingScript: fixture.trueScript
            )],
            lockTime: 0
        )
        let inflationaryID = try inflationaryChild.transactionID(
            limits: fixture.transactionLimits
        )
        let inflationaryBEEF = try BEEF(
            merklePaths: [fixture.path],
            transactions: [
                .rawWithMerklePath(
                    transaction: fixture.parent,
                    merklePathIndex: 0
                ),
                .raw(inflationaryChild),
            ],
            limits: fixture.beefLimits
        )
        await #expect(throws: SPVValidationError.outputsExceedInputs(
            transactionID: inflationaryID,
            inputs: 10,
            outputs: 11
        )) {
            try await SPVProofVerifier.verify(
                inflationaryBEEF,
                rootTransactionID: inflationaryID,
                using: fixture.tracker,
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }

        let zeroFeeChild = Transaction(
            version: 1,
            inputs: [try fixture.input(outputIndex: 0)],
            outputs: [TransactionOutput(
                satoshis: 10,
                lockingScript: fixture.trueScript
            )],
            lockTime: 0
        )
        let zeroFeeID = try zeroFeeChild.transactionID(limits: fixture.transactionLimits)
        let zeroFeeBEEF = try BEEF(
            merklePaths: [fixture.path],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(zeroFeeChild),
            ],
            limits: fixture.beefLimits
        )
        await #expect(throws: SPVValidationError.nonPositiveFee(
            transactionID: zeroFeeID,
            satoshis: 10
        )) {
            try await SPVProofVerifier.verify(
                zeroFeeBEEF,
                rootTransactionID: zeroFeeID,
                using: fixture.tracker,
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }
    }

    @Test("source indexes and script failures are typed")
    func failures() async throws {
        let fixture = try FullSPVFixture()
        let badIndexChild = Transaction(
            version: 1,
            inputs: [try fixture.input(outputIndex: 1)],
            outputs: [TransactionOutput(satoshis: 9, lockingScript: fixture.trueScript)],
            lockTime: 0
        )
        let badIndexID = try badIndexChild.transactionID(limits: fixture.transactionLimits)
        let badIndexBEEF = try BEEF(
            merklePaths: [fixture.path],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(badIndexChild),
            ],
            limits: fixture.beefLimits
        )
        await #expect(throws: SPVValidationError.sourceOutputIndexOutOfBounds(
            transactionID: badIndexID,
            inputIndex: 0,
            sourceTransactionID: fixture.parentID,
            outputIndex: 1,
            outputCount: 1
        )) {
            try await SPVProofVerifier.verify(
                badIndexBEEF,
                rootTransactionID: badIndexID,
                using: fixture.tracker,
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }

        let falseScript = try Script(bytes: [Opcode.zero.rawValue], maximumByteCount: 1)
        let falseParent = Transaction(
            version: 1,
            inputs: [],
            outputs: [TransactionOutput(satoshis: 10, lockingScript: falseScript)],
            lockTime: 0
        )
        let falseParentID = try falseParent.transactionID(limits: fixture.transactionLimits)
        let falsePath = try MerklePath(
            blockHeight: 43,
            levels: [[.hash(
                offset: 0,
                hash: try Hash256(falseParentID.wireBytes),
                isTransactionID: true
            )]]
        )
        let falseChild = Transaction(
            version: 1,
            inputs: [TransactionInput(
                previousOutput: Outpoint(transactionID: falseParentID, outputIndex: 0),
                unlockingScript: try Script(bytes: [], maximumByteCount: 0)
            )],
            outputs: [TransactionOutput(satoshis: 9, lockingScript: fixture.trueScript)],
            lockTime: 0
        )
        let falseChildID = try falseChild.transactionID(limits: fixture.transactionLimits)
        let falseBEEF = try BEEF(
            merklePaths: [falsePath],
            transactions: [
                .rawWithMerklePath(transaction: falseParent, merklePathIndex: 0),
                .raw(falseChild),
            ],
            limits: fixture.beefLimits
        )
        let falseTracker = FixedChainTracker(
            root: try falsePath.root(for: falseParentID),
            blockHeight: 43
        )
        await #expect(throws: SPVValidationError.scriptVerificationFailed(
            transactionID: falseChildID,
            inputIndex: 0,
            cause: .consensus(.evaluatedFalse)
        )) {
            try await SPVProofVerifier.verify(
                falseBEEF,
                rootTransactionID: falseChildID,
                using: falseTracker,
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }

        let missingID = TransactionID(
            exactDigestBytesGuaranteed: BSVHashing.sha256d([0x42]).bytes
        )
        await #expect(throws: SPVValidationError.rootTransactionMissing(missingID)) {
            try await SPVProofVerifier.verify(
                fixture.beef,
                rootTransactionID: missingID,
                using: fixture.tracker,
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }
    }

    @Test("satoshi overflow and transaction-ID-only roots are typed")
    func hostileValueShapes() async throws {
        let fixture = try FullSPVFixture()
        let overflowParent = Transaction(
            version: 1,
            inputs: [],
            outputs: [
                TransactionOutput(satoshis: .max, lockingScript: fixture.trueScript),
                TransactionOutput(satoshis: .max, lockingScript: fixture.trueScript),
            ],
            lockTime: 0
        )
        let overflowParentID = try overflowParent.transactionID(
            limits: fixture.transactionLimits
        )
        let overflowPath = try MerklePath(
            blockHeight: 44,
            levels: [[.hash(
                offset: 0,
                hash: try Hash256(overflowParentID.wireBytes),
                isTransactionID: true
            )]]
        )
        let emptyScript = try Script(bytes: [], maximumByteCount: 0)
        let overflowChild = Transaction(
            version: 1,
            inputs: [0, 1].map { outputIndex in
                TransactionInput(
                    previousOutput: Outpoint(
                        transactionID: overflowParentID,
                        outputIndex: UInt32(outputIndex)
                    ),
                    unlockingScript: emptyScript
                )
            },
            outputs: [TransactionOutput(satoshis: 1, lockingScript: fixture.trueScript)],
            lockTime: 0
        )
        let overflowChildID = try overflowChild.transactionID(
            limits: fixture.transactionLimits
        )
        let overflowBEEF = try BEEF(
            merklePaths: [overflowPath],
            transactions: [
                .rawWithMerklePath(transaction: overflowParent, merklePathIndex: 0),
                .raw(overflowChild),
            ],
            limits: fixture.beefLimits
        )
        let overflowTracker = FixedChainTracker(
            root: try overflowPath.root(for: overflowParentID),
            blockHeight: 44
        )
        await #expect(throws: SPVValidationError.satoshiTotalOverflow(
            transactionID: overflowChildID
        )) {
            try await SPVProofVerifier.verify(
                overflowBEEF,
                rootTransactionID: overflowChildID,
                using: overflowTracker,
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            )
        }

        let placeholderID = TransactionID(
            exactDigestBytesGuaranteed: BSVHashing.sha256d([0x99]).bytes
        )
        let placeholderBEEF = try BEEF(
            merklePaths: [],
            transactions: [.transactionID(placeholderID)],
            limits: fixture.beefLimits
        )
        await #expect(throws: SPVValidationError.rootTransactionIDOnly(placeholderID)) {
            try await SPVProofVerifier.verify(
                placeholderBEEF,
                rootTransactionID: placeholderID,
                using: fixture.tracker,
                scriptConfiguration: fixture.scriptConfiguration,
                allowTransactionIDOnly: true,
                limits: fixture.beefLimits
            )
        }
    }
}

private struct FullSPVFixture {
    let transactionLimits: TransactionLimits
    let beefLimits: BEEFLimits
    let trueScript: Script
    let parent: Transaction
    let parentID: TransactionID
    let child: Transaction
    let childID: TransactionID
    let path: MerklePath
    let beef: BEEF
    let tracker: FixedChainTracker
    let scriptConfiguration: ScriptExecutionConfiguration

    init() throws {
        transactionLimits = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        beefLimits = try BEEFLimits(
            maximumByteCount: 100_000,
            maximumMerklePathCount: 10,
            maximumTransactionCount: 10,
            transactionLimits: transactionLimits,
            merklePathLimits: MerklePathLimits(
                maximumByteCount: 10_000,
                maximumLeavesPerLevel: 100,
                maximumTotalLeaves: 1_000
            )
        )
        trueScript = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        parent = Transaction(
            version: 1,
            inputs: [],
            outputs: [TransactionOutput(satoshis: 10, lockingScript: trueScript)],
            lockTime: 0
        )
        parentID = try parent.transactionID(limits: transactionLimits)
        child = Transaction(
            version: 1,
            inputs: [TransactionInput(
                previousOutput: Outpoint(transactionID: parentID, outputIndex: 0),
                unlockingScript: try Script(bytes: [], maximumByteCount: 0)
            )],
            outputs: [TransactionOutput(satoshis: 9, lockingScript: trueScript)],
            lockTime: 0
        )
        childID = try child.transactionID(limits: transactionLimits)
        path = try MerklePath(
            blockHeight: 42,
            levels: [[.hash(
                offset: 0,
                hash: try Hash256(parentID.wireBytes),
                isTransactionID: true
            )]]
        )
        beef = try BEEF(
            merklePaths: [path],
            transactions: [
                .rawWithMerklePath(transaction: parent, merklePathIndex: 0),
                .raw(child),
            ],
            limits: beefLimits
        )
        tracker = FixedChainTracker(
            root: try path.root(for: parentID),
            blockHeight: path.blockHeight
        )
        scriptConfiguration = try ScriptExecutionConfiguration(
            era: .genesis,
            flags: [.enableForkID],
            resourceLimits: .standard
        )
    }

    func input(outputIndex: UInt32) throws -> TransactionInput {
        TransactionInput(
            previousOutput: Outpoint(transactionID: parentID, outputIndex: outputIndex),
            unlockingScript: try Script(bytes: [], maximumByteCount: 0)
        )
    }
}

private struct FixedFeeModel: TransactionFeeModel {
    let fee: UInt64

    func fee(for transaction: Transaction, limits: TransactionLimits) throws -> UInt64 {
        fee
    }
}

private struct FixedChainTracker: ChainTracker {
    let root: Hash256
    let blockHeight: UInt32

    func isValidRoot(
        _ candidate: Hash256,
        atBlockHeight candidateHeight: UInt32
    ) async throws -> Bool {
        candidate == root && candidateHeight == blockHeight
    }

    func currentHeight() async throws -> UInt32 {
        blockHeight
    }
}
