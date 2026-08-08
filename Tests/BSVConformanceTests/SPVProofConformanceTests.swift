import BSVCore
import BSVCrypto
import BSVScript
import BSVTransaction
import Testing

@Suite("SPV proof conformance", .serialized)
struct SPVProofConformanceTests {
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
