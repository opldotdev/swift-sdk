import BSVCore
import BSVCrypto
import BSVScript
import BSVTransaction
import Testing

@Suite("Transaction proof verification")
struct ChainTrackerVerificationTests {
    @Test("Merkle paths submit the exact computed root and height")
    func merklePathVerification() async throws {
        let fixture = try proofFixture()
        let tracker = RecordingChainTracker(acceptedRoots: [
            fixture.path.blockHeight: try fixture.path.root(for: fixture.parentID),
        ])

        #expect(try await fixture.path.verify(
            transactionID: fixture.parentID,
            using: tracker
        ))
        #expect(await tracker.requests() == [RootRequest(
            root: try fixture.path.root(for: fixture.parentID),
            blockHeight: fixture.path.blockHeight
        )])
    }

    @Test("BEEF verifies every root in ascending height order")
    func beefVerification() async throws {
        let fixture = try proofFixture()
        let secondID = TransactionID(exactDigestBytesGuaranteed: BSVHashing.sha256d([0x22]).bytes)
        let secondPath = try MerklePath(
            blockHeight: 9,
            levels: [[.hash(
                offset: 0,
                hash: try Hash256(secondID.wireBytes),
                isTransactionID: false
            )]]
        )
        let beef = try BEEF(
            merklePaths: [secondPath, fixture.path],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 1),
                .raw(fixture.child),
            ],
            limits: fixture.beefLimits
        )
        let parentRoot = try fixture.path.root(for: fixture.parentID)
        let secondRoot = try secondPath.root()
        let tracker = RecordingChainTracker(acceptedRoots: [7: parentRoot, 9: secondRoot])

        #expect(try await beef.verify(
            using: tracker,
            allowTransactionIDOnly: false,
            limits: fixture.transactionLimits
        ))
        #expect(await tracker.requests() == [
            RootRequest(root: parentRoot, blockHeight: 7),
            RootRequest(root: secondRoot, blockHeight: 9),
        ])
    }

    @Test("invalid graphs do not consult trusted chain state")
    func invalidGraphShortCircuits() async throws {
        let fixture = try proofFixture()
        let incomplete = try BEEF(
            merklePaths: [],
            transactions: [.raw(fixture.child)],
            limits: fixture.beefLimits
        )
        let tracker = RecordingChainTracker(acceptedRoots: [:])

        #expect(!(try await incomplete.verify(
            using: tracker,
            allowTransactionIDOnly: false,
            limits: fixture.transactionLimits
        )))
        #expect(await tracker.requests().isEmpty)
    }

    @Test("every combined-path leaf must compute the same trusted root")
    func conflictingCombinedPath() async throws {
        let fixture = try proofFixture()
        let second = Transaction(
            version: 2,
            inputs: [],
            outputs: [TransactionOutput(
                satoshis: 11,
                lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
            )],
            lockTime: 1
        )
        let secondID = try second.transactionID(limits: fixture.transactionLimits)
        let forgedPath = try conflictingPath(
            first: fixture.parentID,
            second: secondID,
            blockHeight: 12
        )
        let beef = try BEEF(
            merklePaths: [forgedPath],
            transactions: [.raw(fixture.parent), .raw(second)],
            limits: fixture.beefLimits
        )
        let acceptedFirstRoot = try forgedPath.root(for: fixture.parentID)
        let tracker = RecordingChainTracker(acceptedRoots: [12: acceptedFirstRoot])

        await #expect(throws: BEEFError.conflictingMerkleRoot(blockHeight: 12)) {
            try await beef.verify(
                using: tracker,
                allowTransactionIDOnly: false,
                limits: fixture.transactionLimits
            )
        }
        #expect(await tracker.requests().isEmpty)
    }

    @Test("tracker rejection returns false and tracker failures propagate")
    func trackerOutcomes() async throws {
        let fixture = try proofFixture()
        let beef = try BEEF(
            merklePaths: [fixture.path],
            transactions: [.rawWithMerklePath(
                transaction: fixture.parent,
                merklePathIndex: 0
            )],
            limits: fixture.beefLimits
        )
        let rejecting = RecordingChainTracker(acceptedRoots: [:])
        #expect(!(try await beef.verify(
            using: rejecting,
            allowTransactionIDOnly: false,
            limits: fixture.transactionLimits
        )))

        let failing = RecordingChainTracker(
            acceptedRoots: [:],
            failingHeight: fixture.path.blockHeight
        )
        await #expect(throws: RecordingChainTracker.Failure.unavailable) {
            try await beef.verify(
                using: failing,
                allowTransactionIDOnly: false,
                limits: fixture.transactionLimits
            )
        }
    }

    @Test("transaction-ID-only trust remains explicit and requires no root lookup")
    func transactionIDOnlyPolicy() async throws {
        let fixture = try proofFixture()
        let beef = try BEEF(
            merklePaths: [],
            transactions: [.transactionID(fixture.parentID)],
            limits: fixture.beefLimits
        )
        let tracker = RecordingChainTracker(acceptedRoots: [:])

        #expect(!(try await beef.verify(
            using: tracker,
            allowTransactionIDOnly: false,
            limits: fixture.transactionLimits
        )))
        #expect(try await beef.verify(
            using: tracker,
            allowTransactionIDOnly: true,
            limits: fixture.transactionLimits
        ))
        #expect(await tracker.requests().isEmpty)
    }

    @Test("chain-tracker values satisfy Sendable")
    func sendableSurface() throws {
        let fixture = try proofFixture()
        acceptSendable(RecordingChainTracker(acceptedRoots: [
            7: try fixture.path.root(for: fixture.parentID),
        ]))
    }
}

private struct ProofFixture {
    let transactionLimits: TransactionLimits
    let beefLimits: BEEFLimits
    let parent: Transaction
    let child: Transaction
    let parentID: TransactionID
    let path: MerklePath
}

private func proofFixture() throws -> ProofFixture {
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
    let parent = Transaction(
        version: 1,
        inputs: [],
        outputs: [TransactionOutput(
            satoshis: 10,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )],
        lockTime: 0
    )
    let parentID = try parent.transactionID(limits: transactionLimits)
    let child = Transaction(
        version: 1,
        inputs: [TransactionInput(
            previousOutput: Outpoint(transactionID: parentID, outputIndex: 0),
            unlockingScript: try Script(bytes: [], maximumByteCount: 0),
            sequence: .max
        )],
        outputs: [TransactionOutput(
            satoshis: 9,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )],
        lockTime: 0
    )
    let path = try MerklePath(
        blockHeight: 7,
        levels: [[.hash(
            offset: 0,
            hash: try Hash256(parentID.wireBytes),
            isTransactionID: true
        )]]
    )
    return ProofFixture(
        transactionLimits: transactionLimits,
        beefLimits: beefLimits,
        parent: parent,
        child: child,
        parentID: parentID,
        path: path
    )
}

private struct RootRequest: Equatable, Sendable {
    let root: Hash256
    let blockHeight: UInt32
}

private func conflictingPath(
    first: TransactionID,
    second: TransactionID,
    blockHeight: UInt32
) throws -> MerklePath {
    let firstHash = try Hash256(first.wireBytes)
    let secondHash = try Hash256(second.wireBytes)
    let firstSibling = BSVHashing.sha256d([0xa1])
    let secondSibling = BSVHashing.sha256d([0xb2])
    let honestFirstParent = MerkleTree.parent(firstHash, firstSibling)
    let forgedSecondParent = BSVHashing.sha256d([0xff])
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
                .hash(offset: 0, hash: honestFirstParent, isTransactionID: false),
                .hash(offset: 1, hash: forgedSecondParent, isTransactionID: false),
            ],
        ]
    )
}

private actor RecordingChainTracker: ChainTracker {
    enum Failure: Error, Equatable {
        case unavailable
    }

    private let acceptedRoots: [UInt32: Hash256]
    private let failingHeight: UInt32?
    private var recordedRequests: [RootRequest] = []

    init(acceptedRoots: [UInt32: Hash256], failingHeight: UInt32? = nil) {
        self.acceptedRoots = acceptedRoots
        self.failingHeight = failingHeight
    }

    func isValidRoot(
        _ root: Hash256,
        atBlockHeight blockHeight: UInt32
    ) throws -> Bool {
        recordedRequests.append(RootRequest(root: root, blockHeight: blockHeight))
        if failingHeight == blockHeight {
            throw Failure.unavailable
        }
        return acceptedRoots[blockHeight] == root
    }

    func currentHeight() -> UInt32 {
        acceptedRoots.keys.max() ?? 0
    }

    func requests() -> [RootRequest] {
        recordedRequests
    }
}

private func acceptSendable<T: Sendable>(_: T) {}
