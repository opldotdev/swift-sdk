import BSVCore
import BSVScript
import BSVTransaction
import Foundation
import Testing

/// BEEF bytes produced by the TypeScript SDK (`@bsv/sdk` 4.1.0, `Beef.toBinary()`).
///
/// `Beef.sortTxs()` emits transactions with missing inputs first, then
/// transactions that do not chain to a proof, then txid-only records, then
/// proven transactions and their dependents. A child that is not fully proven
/// therefore lands before its own parents. The TypeScript reader accepts that
/// order; these vectors pin it so the Swift reader stays compatible.
enum ForeignBEEFVectors {
    /// C spends proven P and an input whose parent is absent. Wire order: C, P.
    static let missingInput = [
        "0200beef01fe00350c0001020002b6b78c136a6fd3e17704045c487c1dc1805ac2b300ae47bd8c26d271d2aed8c80100",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc02000100000002b6b78c136a6fd3e177",
        "04045c487c1dc1805ac2b300ae47bd8c26d271d2aed8c8000000000151ffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000151ffffffff01a00f0000000000001976a9141111111111111111",
        "11111111111111111111111188ac0000000001000100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaa000000000151ffffffff0188130000000000001976a91411111111111111111111111111111111",
        "1111111188ac00000000",
    ].joined()

    /// D spends an absent parent; C spends P and D. Wire order: D, C, P.
    static let notValid = [
        "0200beef01fe00350c0001020002b6b78c136a6fd3e17704045c487c1dc1805ac2b300ae47bd8c26d271d2aed8c80100",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc03000100000001eeeeeeeeeeeeeeeeee",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000151ffffffff01b80b0000000000001976a9141111",
        "11111111111111111111111111111111111188ac00000000000100000002b6b78c136a6fd3e17704045c487c1dc1805a",
        "c2b300ae47bd8c26d271d2aed8c8000000000151ffffffff6c8a1e75eb69485fd81f40af6db3587233020623f1bff09c",
        "5424c3e79c96203f000000000151ffffffff01581b0000000000001976a9141111111111111111111111111111111111",
        "11111188ac0000000001000100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "000000000151ffffffff0188130000000000001976a914111111111111111111111111111111111111111188ac000000",
        "00",
    ].joined()

    /// C spends txid-only T and an absent parent. Wire order: C, T.
    static let transactionIDOnlyParent = [
        "0200beef0002000100000002777777777777777777777777777777777777777777777777777777777777777700000000",
        "0151ffffffffeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000151ffffffff",
        "01d0070000000000001976a914111111111111111111111111111111111111111188ac00000000027777777777777777",
        "777777777777777777777777777777777777777777777777",
    ].joined()
}

@Suite("BEEF from TypeScript writers")
struct ForeignBEEFOrderTests {
    @Test("strict parse rejects the order the TypeScript writer emits")
    func strictParseRejectsChildFirst() throws {
        for hex in [
            ForeignBEEFVectors.missingInput,
            ForeignBEEFVectors.notValid,
            ForeignBEEFVectors.transactionIDOnlyParent,
        ] {
            #expect {
                try BEEF(hex: hex, limits: foreignLimits())
            } throws: { error in
                guard case BEEFError.parentAfterChild = error else { return false }
                return true
            }
            #expect {
                try BEEF(hex: hex, limits: foreignLimits(), transactionOrder: .parentsFirst)
            } throws: { error in
                guard case BEEFError.parentAfterChild = error else { return false }
                return true
            }
        }
    }

    @Test("any-order parse returns the same records parents-first")
    func anyOrderReordersParentsFirst() throws {
        let limits = try foreignLimits()
        for hex in [
            ForeignBEEFVectors.missingInput,
            ForeignBEEFVectors.notValid,
            ForeignBEEFVectors.transactionIDOnlyParent,
        ] {
            let bytes = try Hex.decode(hex, maximumDecodedByteCount: limits.maximumByteCount)
            let beef = try BEEF(bytes: bytes, limits: limits, transactionOrder: .any)
            let wireIDs = try wireTransactionIDs(bytes, limits: limits)
            let orderedIDs = try beef.transactions.map {
                try $0.transactionID(limits: limits.transactionLimits)
            }
            #expect(Set(orderedIDs) == Set(wireIDs))
            #expect(orderedIDs.count == wireIDs.count)
            #expect(orderedIDs != wireIDs)
            try expectParentsFirst(beef, limits: limits)
            // The reordered envelope is one this SDK can write and read strictly.
            let rewritten = try beef.serialized(limits: limits)
            #expect(try BEEF(bytes: rewritten, limits: limits) == beef)
            #expect(try BEEF(hex: hex, limits: limits, transactionOrder: .any) == beef)
        }
    }

    @Test("the proven parent moves ahead of its unproven child")
    func provenParentFirst() throws {
        let limits = try foreignLimits()
        let beef = try BEEF(
            hex: ForeignBEEFVectors.missingInput,
            limits: limits,
            transactionOrder: .any
        )
        #expect(beef.transactions.count == 2)
        #expect(beef.transactions[0].merklePathIndex == 0)
        #expect(beef.transactions[1].merklePathIndex == nil)

        let notValid = try BEEF(
            hex: ForeignBEEFVectors.notValid,
            limits: limits,
            transactionOrder: .any
        )
        // Wire order D, C, P becomes D, P, C: D keeps its place, P moves ahead of C.
        #expect(notValid.transactions.map(\.merklePathIndex) == [nil, 0, nil])
    }

    @Test("records already parents-first keep their order")
    func orderedInputUnchanged() throws {
        let fixture = try orderFixture()
        let strict = try BEEF(
            merklePaths: [fixture.path],
            transactions: [
                .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                .transactionID(fixture.unrelatedID),
                .raw(fixture.child),
            ],
            limits: fixture.limits
        )
        let bytes = try strict.serialized(limits: fixture.limits)
        let reordered = try BEEF(bytes: bytes, limits: fixture.limits, transactionOrder: .any)
        #expect(reordered == strict)
        #expect(try reordered.serialized(limits: fixture.limits) == bytes)
    }

    @Test("any-order parse keeps every other structural check")
    func anyOrderStillValidates() throws {
        let fixture = try orderFixture()
        let parent = try fixture.parent.serialized(limits: fixture.limits.transactionLimits)
        var duplicate: [UInt8] = [0x02, 0x00, 0xbe, 0xef, 0x00, 0x02]
        duplicate += [0x00] + parent + [0x00] + parent
        #expect(throws: BEEFError.duplicateTransactionID(fixture.parentID)) {
            try BEEF(bytes: duplicate, limits: fixture.limits, transactionOrder: .any)
        }
    }

    @Test("child-first Atomic BEEF is reordered with the subject last")
    func atomicChildFirst() throws {
        let fixture = try orderFixture()
        let path = try fixture.path.serialized(limits: fixture.limits.merklePathLimits)
        let parent = try fixture.parent.serialized(limits: fixture.limits.transactionLimits)
        let child = try fixture.child.serialized(limits: fixture.limits.transactionLimits)
        var nested: [UInt8] = [0x02, 0x00, 0xbe, 0xef, 0x01] + path + [0x02]
        nested += [0x00] + child + [0x01, 0x00] + parent
        let atomic: [UInt8] = [0x01, 0x01, 0x01, 0x01] + fixture.childID.wireBytes + nested

        #expect(throws: BEEFError.parentAfterChild(
            parent: fixture.parentID,
            child: fixture.childID
        )) {
            try AtomicBEEF(bytes: atomic, limits: fixture.limits)
        }
        let envelope = try AtomicBEEF(
            bytes: atomic,
            limits: fixture.limits,
            transactionOrder: .any
        )
        #expect(envelope.subjectTransactionID == fixture.childID)
        #expect(try envelope.beef.transactions.last?.transactionID(
            limits: fixture.limits.transactionLimits
        ) == fixture.childID)
        #expect(try envelope.beef.transactions.first?.transactionID(
            limits: fixture.limits.transactionLimits
        ) == fixture.parentID)
    }

    @Test("an incomplete Atomic BEEF still reports the missing ancestor")
    func atomicIncompleteKeepsError() throws {
        let limits = try foreignLimits()
        let nested = try Hex.decode(ForeignBEEFVectors.missingInput, maximumDecodedByteCount: limits.maximumByteCount)
        let reordered = try BEEF(bytes: nested, limits: limits, transactionOrder: .any)
        let subject = try #require(reordered.transactions.last).transactionID(
            limits: limits.transactionLimits
        )
        let atomic: [UInt8] = [0x01, 0x01, 0x01, 0x01] + subject.wireBytes + nested
        #expect {
            try AtomicBEEF(bytes: atomic, limits: limits, transactionOrder: .any)
        } throws: { error in
            guard case BEEFError.missingAncestor(let transaction, _) = error else { return false }
            return transaction == subject
        }
    }

    @Test("BEEF errors read as plain sentences")
    func plainDescriptions() throws {
        let fixture = try orderFixture()
        let error: Error = BEEFError.parentAfterChild(
            parent: fixture.parentID,
            child: fixture.childID
        )
        #expect(
            error.localizedDescription
                == "The wallet's transaction data came back incomplete or out of order. Try again."
        )
        let missing: Error = BEEFError.missingAncestor(
            transaction: fixture.childID,
            ancestor: fixture.parentID
        )
        #expect(missing.localizedDescription == error.localizedDescription)
        let unreadable: Error = BEEFError.invalidVersion(7)
        #expect(
            unreadable.localizedDescription
                == "The wallet received transaction data it could not read."
        )
        #expect(!error.localizedDescription.contains("BEEFError"))
    }
}

private func wireTransactionIDs(_ bytes: [UInt8], limits: BEEFLimits) throws -> [TransactionID] {
    // Reads record IDs in wire order without the graph-order check.
    var cursor = ByteCursor(bytes)
    _ = try cursor.readUInt32LE()
    let pathCount = try cursor.readCompactSize(canonicality: .required).value
    for _ in 0..<pathCount {
        _ = try MerklePath(consuming: &cursor, limits: limits.merklePathLimits)
    }
    let count = try cursor.readCompactSize(canonicality: .required).value
    var ids: [TransactionID] = []
    for _ in 0..<count {
        let format = try cursor.read(count: 1)[0]
        switch format {
        case 2:
            ids.append(try TransactionID(wireBytes: cursor.read(count: 32)))
        default:
            if format == 1 { _ = try cursor.readCompactSize(canonicality: .required) }
            let transaction = try Transaction(consuming: &cursor, limits: limits.transactionLimits)
            ids.append(try transaction.transactionID(limits: limits.transactionLimits))
        }
    }
    return ids
}

private func expectParentsFirst(_ beef: BEEF, limits: BEEFLimits) throws {
    var seen: Set<TransactionID> = []
    let present = try Set(beef.transactions.map {
        try $0.transactionID(limits: limits.transactionLimits)
    })
    for entry in beef.transactions {
        for input in entry.transaction?.inputs ?? [] {
            let parent = input.previousOutput.transactionID
            if present.contains(parent) { #expect(seen.contains(parent)) }
        }
        seen.insert(try entry.transactionID(limits: limits.transactionLimits))
    }
}

private struct OrderFixture {
    let limits: BEEFLimits
    let parent: Transaction
    let child: Transaction
    let parentID: TransactionID
    let childID: TransactionID
    let unrelatedID: TransactionID
    let path: MerklePath
}

private func orderFixture() throws -> OrderFixture {
    let limits = try foreignLimits()
    let script = try Script(bytes: [0x51], maximumByteCount: 1)
    let parent = Transaction(
        version: 1,
        inputs: [],
        outputs: [TransactionOutput(satoshis: 50, lockingScript: script)],
        lockTime: 0
    )
    let parentID = try parent.transactionID(limits: limits.transactionLimits)
    let path = try MerklePath(
        blockHeight: 7,
        levels: [[.hash(offset: 0, hash: try Hash256(parentID.wireBytes), isTransactionID: true)]]
    )
    let child = Transaction(
        version: 2,
        inputs: [TransactionInput(
            previousOutput: Outpoint(transactionID: parentID, outputIndex: 0),
            unlockingScript: try Script(bytes: [], maximumByteCount: 0),
            sequence: 1
        )],
        outputs: [TransactionOutput(satoshis: 40, lockingScript: script)],
        lockTime: 3
    )
    return OrderFixture(
        limits: limits,
        parent: parent,
        child: child,
        parentID: parentID,
        childID: try child.transactionID(limits: limits.transactionLimits),
        unrelatedID: TransactionID(exactDigestBytesGuaranteed: [UInt8](repeating: 0x5a, count: 32)),
        path: path
    )
}

func foreignLimits() throws -> BEEFLimits {
    try BEEFLimits(
        maximumByteCount: 1_000_000,
        maximumMerklePathCount: 100,
        maximumTransactionCount: 1_000,
        transactionLimits: TransactionLimits(
            maximumTransactionByteCount: 100_000,
            maximumInputCount: 100,
            maximumOutputCount: 100,
            maximumScriptByteCount: 10_000
        ),
        merklePathLimits: MerklePathLimits(
            maximumByteCount: 100_000,
            maximumLeavesPerLevel: 100,
            maximumTotalLeaves: 1_000
        )
    )
}
