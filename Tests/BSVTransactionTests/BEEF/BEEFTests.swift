import BSVCore
import BSVCrypto
import BSVScript
import BSVTransaction
import Testing

@Suite("BEEF transaction envelopes")
struct BEEFTests {
    @Test("BRC-62 v1 and BRC-96 v2 have exact distinct field order")
    func versionsRoundTrip() throws {
        let fixture = try beefFixture()
        let v1 = try BEEF(
            version: .v1,
            merklePaths: [fixture.parentPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        let v2 = try BEEF(
            version: .v2,
            merklePaths: [fixture.parentPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )

        let path = try fixture.parentPath.serialized(limits: fixture.limits.merklePathLimits)
        let parent = try fixture.parent.serialized(limits: fixture.limits.transactionLimits)
        let child = try fixture.child.serialized(limits: fixture.limits.transactionLimits)
        let expectedV1 = [0x01, 0x00, 0xbe, 0xef, 0x01] + path
            + [0x02] + parent + [0x01, 0x00] + child + [0x00]
        let expectedV2 = [0x02, 0x00, 0xbe, 0xef, 0x01] + path
            + [0x02, 0x01, 0x00] + parent + [0x00] + child

        #expect(try v1.serialized(limits: fixture.limits) == expectedV1)
        #expect(try v2.serialized(limits: fixture.limits) == expectedV2)
        #expect(try BEEF(bytes: expectedV1, limits: fixture.limits) == v1)
        #expect(try BEEF(bytes: expectedV2, limits: fixture.limits) == v2)
        #expect(try BEEF(hex: Hex.encode(expectedV2).uppercased(), limits: fixture.limits) == v2)
    }

    @Test("BRC-96 txid-only records are exact and policy-controlled anchors")
    func transactionIDOnly() throws {
        let fixture = try beefFixture()
        let envelope = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [
                .transactionID(fixture.parentID),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        let bytes = try envelope.serialized(limits: fixture.limits)
        #expect(Array(bytes.prefix(7)) == [0x02, 0x00, 0xbe, 0xef, 0, 2, 2])
        #expect(Array(bytes[7..<39]) == fixture.parentID.wireBytes)
        #expect(try BEEF(bytes: bytes, limits: fixture.limits) == envelope)

        let trusted = try envelope.validation(
            allowTransactionIDOnly: true,
            limits: fixture.limits.transactionLimits
        )
        #expect(trusted.isValid)
        #expect(trusted.validTransactionIDs == [fixture.parentID, fixture.childID])
        #expect(trusted.transactionIDOnly == [fixture.parentID])

        let untrusted = try envelope.validation(
            allowTransactionIDOnly: false,
            limits: fixture.limits.transactionLimits
        )
        #expect(!untrusted.isValid)
        #expect(untrusted.invalidTransactionIDs == [fixture.parentID, fixture.childID])

        #expect(throws: BEEFError.transactionIDOnlyRequiresVersion2(transaction: 0)) {
            try BEEF(
                version: .v1,
                merklePaths: [],
                transactions: [.transactionID(fixture.parentID)],
                limits: fixture.limits
            )
        }
    }

    @Test("proofs and dependency closure validate without executing scripts")
    func dependencyValidation() throws {
        let fixture = try beefFixture()
        let envelope = try BEEF(
            merklePaths: [fixture.parentPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        let result = try envelope.validation(
            allowTransactionIDOnly: false,
            limits: fixture.limits.transactionLimits
        )
        #expect(result.isValid)
        #expect(result.validTransactionIDs == [fixture.parentID, fixture.childID])
        #expect(try envelope.transaction(
            for: fixture.childID,
            limits: fixture.limits.transactionLimits
        ) == fixture.child)
        #expect(envelope.merklePath(for: fixture.parentID) == fixture.parentPath)
        #expect(try envelope.merkleRootsByBlockHeight() == [7: fixture.parentHash])

        let missing = try BEEF(
            merklePaths: [],
            transactions: [.raw(fixture.child)],
            limits: fixture.limits
        )
        let missingResult = try missing.validation(
            allowTransactionIDOnly: false,
            limits: fixture.limits.transactionLimits
        )
        #expect(!missingResult.isValid)
        #expect(missingResult.invalidTransactionIDs == [fixture.childID])
        #expect(missingResult.missingInputTransactionIDs == [fixture.parentID])

        let conflictingPath = try MerklePath(
            blockHeight: 7,
            levels: [[.hash(
                offset: 0,
                hash: BSVHashing.sha256d([0xff]),
                isTransactionID: true
            )]]
        )
        let conflicting = try BEEF(
            merklePaths: [fixture.parentPath, conflictingPath],
            transactions: [],
            limits: fixture.limits
        )
        #expect(throws: BEEFError.conflictingMerkleRoot(blockHeight: 7)) {
            try conflicting.merkleRootsByBlockHeight()
        }
    }

    @Test("graph order, identity, and proof references are structural invariants")
    func structuralValidation() throws {
        let fixture = try beefFixture()
        #expect(throws: BEEFError.parentAfterChild(
            parent: fixture.parentID,
            child: fixture.childID
        )) {
            try BEEF(
                merklePaths: [fixture.parentPath],
                transactions: [
                    .raw(fixture.child),
                    .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                ],
                limits: fixture.limits
            )
        }
        #expect(throws: BEEFError.duplicateTransactionID(fixture.parentID)) {
            try BEEF(
                merklePaths: [],
                transactions: [.raw(fixture.parent), .raw(fixture.parent)],
                limits: fixture.limits
            )
        }
        #expect(throws: BEEFError.merklePathIndexOutOfRange(
            transaction: 0,
            index: 1,
            count: 1
        )) {
            try BEEF(
                merklePaths: [fixture.parentPath],
                transactions: [.rawWithMerklePath(
                    transaction: fixture.parent,
                    merklePathIndex: 1
                )],
                limits: fixture.limits
            )
        }
        #expect(throws: BEEFError.merklePathDoesNotProveTransaction(
            transaction: 0,
            index: 0
        )) {
            try BEEF(
                merklePaths: [fixture.parentPath],
                transactions: [.rawWithMerklePath(
                    transaction: fixture.child,
                    merklePathIndex: 0
                )],
                limits: fixture.limits
            )
        }
    }

    @Test("Atomic BEEF round trips one complete minimal ancestry graph")
    func atomicRoundTrip() throws {
        let fixture = try beefFixture()
        let envelope = try BEEF(
            merklePaths: [fixture.parentPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        let atomic = try AtomicBEEF(
            subjectTransactionID: fixture.childID,
            beef: envelope,
            limits: fixture.limits
        )
        let bytes = try atomic.serialized(limits: fixture.limits)
        #expect(Array(bytes.prefix(4)) == [1, 1, 1, 1])
        #expect(Array(bytes[4..<36]) == fixture.childID.wireBytes)
        #expect(try AtomicBEEF(bytes: bytes, limits: fixture.limits) == atomic)
        #expect(try AtomicBEEF(
            bytes: try Hex.decode(
                atomic.hex(limits: fixture.limits),
                maximumDecodedByteCount: fixture.limits.maximumByteCount
            ),
            limits: fixture.limits
        ) == atomic)
    }

    @Test("Atomic BEEF rejects missing, incomplete, and unrelated data")
    func atomicityFailures() throws {
        let fixture = try beefFixture()
        let parentOnly = try BEEF(
            merklePaths: [fixture.parentPath],
            transactions: [.rawWithMerklePath(
                transaction: fixture.parent,
                merklePathIndex: 0
            )],
            limits: fixture.limits
        )
        #expect(throws: BEEFError.missingSubjectTransaction(fixture.childID)) {
            try AtomicBEEF(
                subjectTransactionID: fixture.childID,
                beef: parentOnly,
                limits: fixture.limits
            )
        }

        let incomplete = try BEEF(
            merklePaths: [],
            transactions: [.raw(fixture.child)],
            limits: fixture.limits
        )
        #expect(throws: BEEFError.missingAncestor(
            transaction: fixture.childID,
            ancestor: fixture.parentID
        )) {
            try AtomicBEEF(
                subjectTransactionID: fixture.childID,
                beef: incomplete,
                limits: fixture.limits
            )
        }

        let unrelated = try BEEF(
            merklePaths: [fixture.parentPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
                .transactionID(fixture.unrelatedID),
            ],
            limits: fixture.limits
        )
        #expect(throws: BEEFError.unrelatedTransaction(fixture.unrelatedID)) {
            try AtomicBEEF(
                subjectTransactionID: fixture.childID,
                beef: unrelated,
                limits: fixture.limits
            )
        }

        let unrelatedPath = try MerklePath(
            blockHeight: 8,
            levels: [[.hash(
                offset: 0,
                hash: BSVHashing.sha256d([0xee]),
                isTransactionID: true
            )]]
        )
        let extraProof = try BEEF(
            merklePaths: [fixture.parentPath, unrelatedPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        #expect(throws: BEEFError.unrelatedMerklePath(index: 1)) {
            try AtomicBEEF(
                subjectTransactionID: fixture.childID,
                beef: extraProof,
                limits: fixture.limits
            )
        }
    }

    @Test("Atomic BEEF accepts a combined BUMP with additional same-block leaves")
    func atomicCombinedMerklePath() throws {
        let fixture = try beefFixture()
        let other = BSVHashing.sha256d([0xbb])
        let combined = try MerklePath(
            blockHeight: 7,
            levels: [[
                .hash(offset: 0, hash: fixture.parentHash, isTransactionID: true),
                .hash(offset: 1, hash: other, isTransactionID: true),
            ]]
        )
        let envelope = try BEEF(
            merklePaths: [combined],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )

        #expect(try AtomicBEEF(
            subjectTransactionID: fixture.childID,
            beef: envelope,
            limits: fixture.limits
        ).beef == envelope)
    }

    @Test("an unproven zero-input transaction is not an implicit validation anchor")
    func unprovenZeroInput() throws {
        let fixture = try beefFixture()
        let envelope = try BEEF(
            merklePaths: [],
            transactions: [.raw(fixture.parent)],
            limits: fixture.limits
        )
        let result = try envelope.validation(
            allowTransactionIDOnly: true,
            limits: fixture.limits.transactionLimits
        )

        #expect(!result.isValid)
        #expect(result.invalidTransactionIDs == [fixture.parentID])
    }

    @Test("every truncation, trailing byte, format, version, and limit fails safely")
    func malformedAndLimits() throws {
        let fixture = try beefFixture()
        let envelope = try BEEF(
            merklePaths: [fixture.parentPath],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        let bytes = try envelope.serialized(limits: fixture.limits)
        for count in 0..<bytes.count {
            #expect(throws: BEEFError.self) {
                try BEEF(bytes: Array(bytes.prefix(count)), limits: fixture.limits)
            }
        }
        #expect(throws: BEEFError.self) {
            try BEEF(bytes: bytes + [0], limits: fixture.limits)
        }

        var invalidVersion = bytes
        invalidVersion[0] = 3
        #expect(throws: BEEFError.invalidVersion(4_022_206_467)) {
            try BEEF(bytes: invalidVersion, limits: fixture.limits)
        }

        let txidOnly = try BEEF(
            merklePaths: [],
            transactions: [.transactionID(fixture.parentID)],
            limits: fixture.limits
        ).serialized(limits: fixture.limits)
        var invalidFormat = txidOnly
        invalidFormat[6] = 3
        #expect(throws: BEEFError.invalidTransactionFormat(transaction: 0, format: 3)) {
            try BEEF(bytes: invalidFormat, limits: fixture.limits)
        }

        let noncanonicalPathCount = Array(bytes.prefix(4)) + [0xfd, 1, 0] + Array(bytes.dropFirst(5))
        #expect(throws: BEEFError.self) {
            try BEEF(bytes: noncanonicalPathCount, limits: fixture.limits)
        }
        #expect(try BEEF(
            bytes: noncanonicalPathCount,
            limits: fixture.limits,
            compactSizeCanonicality: .permissive
        ) == envelope)

        let tooSmall = try BEEFLimits(
            maximumByteCount: bytes.count - 1,
            maximumMerklePathCount: 10,
            maximumTransactionCount: 10,
            transactionLimits: fixture.limits.transactionLimits,
            merklePathLimits: fixture.limits.merklePathLimits
        )
        #expect(throws: BEEFError.envelopeTooLarge(
            actual: bytes.count,
            maximum: bytes.count - 1
        )) {
            try BEEF(bytes: bytes, limits: tooSmall)
        }

        let atomic = try AtomicBEEF(
            subjectTransactionID: fixture.childID,
            beef: envelope,
            limits: fixture.limits
        ).serialized(limits: fixture.limits)
        for count in 0..<36 {
            #expect(throws: BEEFError.self) {
                try AtomicBEEF(bytes: Array(atomic.prefix(count)), limits: fixture.limits)
            }
        }
        var invalidAtomicPrefix = atomic
        invalidAtomicPrefix[0] = 2
        #expect(throws: BEEFError.invalidAtomicPrefix(0x0101_0102)) {
            try AtomicBEEF(bytes: invalidAtomicPrefix, limits: fixture.limits)
        }
    }

    @Test("public values are Sendable")
    func sendableValues() throws {
        let fixture = try beefFixture()
        let envelope = try BEEF(
            merklePaths: [fixture.parentPath],
            transactions: [.rawWithMerklePath(
                transaction: fixture.parent,
                merklePathIndex: 0
            )],
            limits: fixture.limits
        )
        let atomic = try AtomicBEEF(
            subjectTransactionID: fixture.parentID,
            beef: envelope,
            limits: fixture.limits
        )
        requireSendable(envelope)
        requireSendable(atomic)
        requireSendable(BEEFTransaction.raw(fixture.parent))
    }
}

private struct BEEFFixture {
    let limits: BEEFLimits
    let parent: Transaction
    let child: Transaction
    let parentID: TransactionID
    let childID: TransactionID
    let unrelatedID: TransactionID
    let parentHash: Hash256
    let parentPath: MerklePath
}

private func beefFixture() throws -> BEEFFixture {
    let transactionLimits = try TransactionLimits(
        maximumTransactionByteCount: 100_000,
        maximumInputCount: 100,
        maximumOutputCount: 100,
        maximumScriptByteCount: 10_000
    )
    let merkleLimits = try MerklePathLimits(
        maximumByteCount: 100_000,
        maximumLeavesPerLevel: 100,
        maximumTotalLeaves: 1_000
    )
    let limits = try BEEFLimits(
        maximumByteCount: 1_000_000,
        maximumMerklePathCount: 100,
        maximumTransactionCount: 1_000,
        transactionLimits: transactionLimits,
        merklePathLimits: merkleLimits
    )
    let parent = Transaction(
        version: 1,
        inputs: [],
        outputs: [TransactionOutput(
            satoshis: 50,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )],
        lockTime: 0
    )
    let parentID = try parent.transactionID(limits: transactionLimits)
    let parentHash = try Hash256(parentID.wireBytes)
    let parentPath = try MerklePath(
        blockHeight: 7,
        levels: [[.hash(offset: 0, hash: parentHash, isTransactionID: true)]]
    )
    let child = Transaction(
        version: 2,
        inputs: [TransactionInput(
            previousOutput: Outpoint(transactionID: parentID, outputIndex: 0),
            unlockingScript: try Script(bytes: [], maximumByteCount: 0),
            sequence: 1
        )],
        outputs: [TransactionOutput(
            satoshis: 40,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )],
        lockTime: 3
    )
    return BEEFFixture(
        limits: limits,
        parent: parent,
        child: child,
        parentID: parentID,
        childID: try child.transactionID(limits: transactionLimits),
        unrelatedID: TransactionID(
            exactDigestBytesGuaranteed: BSVHashing.sha256d([0xaa]).bytes
        ),
        parentHash: parentHash,
        parentPath: parentPath
    )
}

private func requireSendable<T: Sendable>(_ value: T) {
    _ = value
}
