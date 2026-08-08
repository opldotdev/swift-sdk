import BSVCore
import BSVCrypto
import BSVInterpreter
import BSVSPV
import BSVScript
import BSVTransaction
import Testing

@Suite("SPV proof conformance", .serialized)
struct SPVProofConformanceTests {
    @Test("complete BRC-67 verification matches the pinned Go SDK")
    func completeVerification() async throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("SPV Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let fixture = try completeSPVConformanceFixture()
            let root = try fixture.path.root(for: fixture.parentID)
            let rootDisplay = TransactionID(
                exactDigestBytesGuaranteed: root.bytes
            ).displayHex

            #expect(try await SPVProofVerifier.verify(
                fixture.beef,
                rootTransactionID: fixture.childID,
                using: ConformanceChainTracker(
                    root: root,
                    blockHeight: fixture.path.blockHeight
                ),
                feeModel: SatoshisPerKilobyteFeeModel(satoshisPerKilobyte: 1),
                scriptConfiguration: fixture.scriptConfiguration,
                limits: fixture.beefLimits
            ))

            let response = try client.request(
                id: "spv-complete-brc67",
                operation: "spv.verify",
                arguments: [
                    "bytes": .string(try fixture.beef.hex(limits: fixture.beefLimits)),
                    "satoshisPerKilobyte": .string("1"),
                    "validRoots": .array([.object([
                        "blockHeight": .string(String(fixture.path.blockHeight)),
                        "root": .string(rootDisplay),
                    ])]),
                ]
            )
            #expect(response.ok)
            #expect(response.result == .object(["valid": .bool(true)]))

            let inflationary = try completeSPVConformanceFixture(outputSatoshis: 11)
            let inflationaryRoot = try inflationary.path.root(for: inflationary.parentID)
            let inflationaryRootDisplay = TransactionID(
                exactDigestBytesGuaranteed: inflationaryRoot.bytes
            ).displayHex
            await #expect(throws: SPVValidationError.outputsExceedInputs(
                transactionID: inflationary.childID,
                inputs: 10,
                outputs: 11
            )) {
                try await SPVProofVerifier.verify(
                    inflationary.beef,
                    rootTransactionID: inflationary.childID,
                    using: ConformanceChainTracker(
                        root: inflationaryRoot,
                        blockHeight: inflationary.path.blockHeight
                    ),
                    scriptConfiguration: inflationary.scriptConfiguration,
                    limits: inflationary.beefLimits
                )
            }
            let goInflationary = try client.request(
                id: "spv-go-unused-input-total-artifact",
                operation: "spv.verify",
                arguments: [
                    "bytes": .string(try inflationary.beef.hex(
                        limits: inflationary.beefLimits
                    )),
                    "validRoots": .array([.object([
                        "blockHeight": .string(String(inflationary.path.blockHeight)),
                        "root": .string(inflationaryRootDisplay),
                    ])]),
                ]
            )
            #expect(goInflationary.result == .object(["valid": .bool(true)]))
        }
    }

    @Test("pinned Go agrees on accepted and rejected BEEF chain roots")
    func beefVerification() async throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("SPV Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let fixture = try spvConformanceFixture()
            let root = try fixture.path.root(for: fixture.transactionID)
            let beef = try BEEF(
                merklePaths: [fixture.path],
                transactions: [.rawWithMerklePath(
                    transaction: fixture.transaction,
                    merklePathIndex: 0
                )],
                limits: fixture.beefLimits
            )
            let encoded = try beef.hex(limits: fixture.beefLimits)
            let rootDisplay = TransactionID(exactDigestBytesGuaranteed: root.bytes).displayHex

            let acceptingTracker = ConformanceChainTracker(
                root: root,
                blockHeight: fixture.path.blockHeight
            )
            #expect(try await beef.verify(
                using: acceptingTracker,
                allowTransactionIDOnly: false,
                limits: fixture.transactionLimits
            ))
            let accepted = try client.request(
                id: "spv-beef-valid-root",
                operation: "transaction.beef.verify",
                arguments: [
                    "allowTransactionIDOnly": .bool(false),
                    "bytes": .string(encoded),
                    "validRoots": .array([.object([
                        "blockHeight": .string(String(fixture.path.blockHeight)),
                        "root": .string(rootDisplay),
                    ])]),
                ]
            )
            #expect(accepted.result == .object(["valid": .bool(true)]))

            let rejectingTracker = ConformanceChainTracker(
                root: BSVHashing.sha256d([0xff]),
                blockHeight: fixture.path.blockHeight
            )
            #expect(!(try await beef.verify(
                using: rejectingTracker,
                allowTransactionIDOnly: false,
                limits: fixture.transactionLimits
            )))
            let rejected = try client.request(
                id: "spv-beef-invalid-root",
                operation: "transaction.beef.verify",
                arguments: [
                    "allowTransactionIDOnly": .bool(false),
                    "bytes": .string(encoded),
                    "validRoots": .array([]),
                ]
            )
            #expect(rejected.result == .object(["valid": .bool(false)]))

            let second = Transaction(
                version: 2,
                inputs: [],
                outputs: [TransactionOutput(
                    satoshis: 2,
                    lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
                )],
                lockTime: 1
            )
            let secondID = try second.transactionID(limits: fixture.transactionLimits)
            let conflictingPath = try spvConflictingPath(
                first: fixture.transactionID,
                second: secondID,
                blockHeight: 43
            )
            let conflicting = try BEEF(
                merklePaths: [conflictingPath],
                transactions: [.raw(fixture.transaction), .raw(second)],
                limits: fixture.beefLimits
            )
            let firstRoot = try conflictingPath.root(for: fixture.transactionID)
            let firstRootDisplay = TransactionID(
                exactDigestBytesGuaranteed: firstRoot.bytes
            ).displayHex
            let conflictTracker = ConformanceChainTracker(
                root: firstRoot,
                blockHeight: 43
            )
            await #expect(throws: BEEFError.conflictingMerkleRoot(blockHeight: 43)) {
                try await conflicting.verify(
                    using: conflictTracker,
                    allowTransactionIDOnly: false,
                    limits: fixture.transactionLimits
                )
            }
            let goConflict = try client.request(
                id: "spv-beef-conflicting-combined-path",
                operation: "transaction.beef.verify",
                arguments: [
                    "allowTransactionIDOnly": .bool(false),
                    "bytes": .string(try conflicting.hex(limits: fixture.beefLimits)),
                    "validRoots": .array([.object([
                        "blockHeight": .string("43"),
                        "root": .string(firstRootDisplay),
                    ])]),
                ]
            )
            #expect(goConflict.result == .object(["valid": .bool(false)]))
        }
    }
}

private struct CompleteSPVConformanceFixture {
    let beefLimits: BEEFLimits
    let beef: BEEF
    let parentID: TransactionID
    let childID: TransactionID
    let path: MerklePath
    let scriptConfiguration: ScriptExecutionConfiguration
}

private func completeSPVConformanceFixture(
    outputSatoshis: UInt64 = 9
) throws -> CompleteSPVConformanceFixture {
    let transactionLimits = try TransactionLimits(
        maximumTransactionByteCount: 10_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 1_000
    )
    let beefLimits = try BEEFLimits(
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
    let trueScript = try Script(
        bytes: [Opcode.drop.rawValue, Opcode.one.rawValue],
        maximumByteCount: 2
    )
    let parent = Transaction(
        version: 1,
        inputs: [],
        outputs: [TransactionOutput(satoshis: 10, lockingScript: trueScript)],
        lockTime: 0
    )
    let parentID = try parent.transactionID(limits: transactionLimits)
    let child = Transaction(
        version: 1,
        inputs: [TransactionInput(
            previousOutput: Outpoint(transactionID: parentID, outputIndex: 0),
            unlockingScript: try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        )],
        outputs: [TransactionOutput(
            satoshis: outputSatoshis,
            lockingScript: trueScript
        )],
        lockTime: 0
    )
    let childID = try child.transactionID(limits: transactionLimits)
    let path = try MerklePath(
        blockHeight: 42,
        levels: [[.hash(
            offset: 0,
            hash: try Hash256(parentID.wireBytes),
            isTransactionID: true
        )]]
    )
    let beef = try BEEF(
        version: .v1,
        merklePaths: [path],
        transactions: [
            .rawWithMerklePath(transaction: parent, merklePathIndex: 0),
            .raw(child),
        ],
        limits: beefLimits
    )
    return CompleteSPVConformanceFixture(
        beefLimits: beefLimits,
        beef: beef,
        parentID: parentID,
        childID: childID,
        path: path,
        scriptConfiguration: try ScriptExecutionConfiguration(
            era: .genesis,
            flags: [.enableForkID],
            resourceLimits: .standard
        )
    )
}

private struct SPVConformanceFixture {
    let transactionLimits: TransactionLimits
    let beefLimits: BEEFLimits
    let transaction: Transaction
    let transactionID: TransactionID
    let path: MerklePath
}

private func spvConformanceFixture() throws -> SPVConformanceFixture {
    let transactionLimits = try TransactionLimits(
        maximumTransactionByteCount: 10_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 1_000
    )
    let merkleLimits = try MerklePathLimits(
        maximumByteCount: 10_000,
        maximumLeavesPerLevel: 100,
        maximumTotalLeaves: 1_000
    )
    let beefLimits = try BEEFLimits(
        maximumByteCount: 100_000,
        maximumMerklePathCount: 10,
        maximumTransactionCount: 100,
        transactionLimits: transactionLimits,
        merklePathLimits: merkleLimits
    )
    let transaction = Transaction(
        version: 1,
        inputs: [],
        outputs: [TransactionOutput(
            satoshis: 1,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )],
        lockTime: 0
    )
    let transactionID = try transaction.transactionID(limits: transactionLimits)
    let path = try MerklePath(
        blockHeight: 42,
        levels: [[.hash(
            offset: 0,
            hash: try Hash256(transactionID.wireBytes),
            isTransactionID: true
        )]]
    )
    return SPVConformanceFixture(
        transactionLimits: transactionLimits,
        beefLimits: beefLimits,
        transaction: transaction,
        transactionID: transactionID,
        path: path
    )
}

private struct ConformanceChainTracker: ChainTracker {
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

private func spvConflictingPath(
    first: TransactionID,
    second: TransactionID,
    blockHeight: UInt32
) throws -> MerklePath {
    let firstHash = try Hash256(first.wireBytes)
    let secondHash = try Hash256(second.wireBytes)
    let firstSibling = BSVHashing.sha256d([0xa1])
    let secondSibling = BSVHashing.sha256d([0xb2])
    return try MerklePath(
        blockHeight: blockHeight,
        levels: [
            [
                .hash(offset: 0, hash: firstHash, isTransactionID: true),
                .hash(offset: 1, hash: firstSibling, isTransactionID: false),
                .hash(offset: 2, hash: secondHash, isTransactionID: true),
                .hash(offset: 3, hash: secondSibling, isTransactionID: false),
            ],
            [
                .hash(
                    offset: 0,
                    hash: MerkleTree.parent(firstHash, firstSibling),
                    isTransactionID: false
                ),
                .hash(
                    offset: 1,
                    hash: BSVHashing.sha256d([0xff]),
                    isTransactionID: false
                ),
            ],
        ]
    )
}
