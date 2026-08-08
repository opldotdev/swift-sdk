import BSVCore
import BSVCrypto
import BSVScript
import BSVTransaction
import Testing

@Suite("BRC-62, BRC-95, and BRC-96 BEEF conformance", .serialized)
struct BEEFConformanceTests {
    @Test("pinned Go SDK agrees on BEEF v1, v2, Atomic framing, and validation")
    func goOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BEEF Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let fixture = try conformanceBEEFFixture()
            let v1 = try BEEF(
                version: .v1,
                merklePaths: [fixture.path],
                transactions: [
                    .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                    .raw(fixture.child),
                ],
                limits: fixture.limits
            )
            let v2 = try BEEF(
                version: .v2,
                merklePaths: [fixture.path],
                transactions: [
                    .rawWithMerklePath(transaction: fixture.parent, merklePathIndex: 0),
                    .raw(fixture.child),
                ],
                limits: fixture.limits
            )
            let atomic = try AtomicBEEF(
                subjectTransactionID: fixture.childID,
                beef: v2,
                limits: fixture.limits
            )

            try assertGoDecode(
                client: client,
                id: "beef-v1-decode",
                bytes: v1.serialized(limits: fixture.limits),
                version: BEEFVersion.v1.rawValue,
                subject: "",
                fixture: fixture
            )
            try assertGoDecode(
                client: client,
                id: "beef-v2-decode",
                bytes: v2.serialized(limits: fixture.limits),
                version: BEEFVersion.v2.rawValue,
                subject: "",
                fixture: fixture
            )
            try assertGoDecode(
                client: client,
                id: "atomic-beef-decode",
                bytes: atomic.serialized(limits: fixture.limits),
                version: BEEFVersion.v2.rawValue,
                subject: fixture.childID.displayHex,
                fixture: fixture
            )

            for (id, bytes, expected, isAtomic) in [
                (
                    "beef-v2-go-reencode",
                    try v2.serialized(limits: fixture.limits),
                    v2,
                    false
                ),
                (
                    "atomic-beef-go-reencode",
                    try atomic.serialized(limits: fixture.limits),
                    v2,
                    true
                ),
            ] {
                let response = try client.request(
                    id: id,
                    operation: "transaction.beef.reencode",
                    arguments: ["bytes": .string(Hex.encode(bytes))]
                )
                guard case .object(let result) = response.result,
                      case .string(let encoded)? = result["bytes"] else {
                    Issue.record("Go BEEF re-encode returned an unexpected result")
                    continue
                }
                let emitted = try Hex.decode(
                    encoded,
                    maximumDecodedByteCount: fixture.limits.maximumByteCount
                )
                if isAtomic {
                    let parsed = try AtomicBEEF(bytes: emitted, limits: fixture.limits)
                    #expect(parsed.subjectTransactionID == fixture.childID)
                    #expect(parsed.beef == expected)
                } else {
                    #expect(try BEEF(bytes: emitted, limits: fixture.limits) == expected)
                }
            }

            for (id, envelope) in [("beef-v1-valid", v1), ("beef-v2-valid", v2)] {
                let response = try client.request(
                    id: id,
                    operation: "transaction.beef.validate",
                    arguments: [
                        "allowTransactionIDOnly": .bool(false),
                        "bytes": .string(try envelope.hex(limits: fixture.limits)),
                    ]
                )
                #expect(response.result == .object(["valid": .bool(true)]))
            }

            let transactionIDOnly = try BEEF(
                version: .v2,
                merklePaths: [],
                transactions: [.transactionID(fixture.parentID)],
                limits: fixture.limits
            )
            let strict = try client.request(
                id: "beef-txid-only-strict",
                operation: "transaction.beef.validate",
                arguments: [
                    "allowTransactionIDOnly": .bool(false),
                    "bytes": .string(try transactionIDOnly.hex(limits: fixture.limits)),
                ]
            )
            let trusted = try client.request(
                id: "beef-txid-only-trusted",
                operation: "transaction.beef.validate",
                arguments: [
                    "allowTransactionIDOnly": .bool(true),
                    "bytes": .string(try transactionIDOnly.hex(limits: fixture.limits)),
                ]
            )
            #expect(strict.result == .object(["valid": .bool(false)]))
            #expect(trusted.result == .object(["valid": .bool(true)]))

            let transactionIDOnlyParent = try BEEF(
                version: .v2,
                merklePaths: [],
                transactions: [
                    .transactionID(fixture.parentID),
                    .raw(fixture.child),
                ],
                limits: fixture.limits
            )
            #expect(try transactionIDOnlyParent.validation(
                allowTransactionIDOnly: true,
                limits: fixture.limits.transactionLimits
            ).isValid)
            let pinnedGoDivergence = try client.request(
                id: "beef-txid-only-child-go-artifact",
                operation: "transaction.beef.validate",
                arguments: [
                    "allowTransactionIDOnly": .bool(true),
                    "bytes": .string(try transactionIDOnlyParent.hex(limits: fixture.limits)),
                ]
            )
            // BRC-96 explicitly makes a txid-only parent an implicit anchor.
            // Pinned Go v1.3.3 only propagates validity when that txid is also
            // BUMP-marked, so this false result is a recorded Go artifact.
            #expect(pinnedGoDivergence.result == .object(["valid": .bool(false)]))
        }
    }

    @Test("graph transforms match intended Go semantics and record merge artifacts")
    func graphTransformDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BEEF graph Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let fixture = try conformanceBEEFFixture()
            let proofless = try BEEF(
                merklePaths: [],
                transactions: [.raw(fixture.parent)],
                limits: fixture.limits
            )
            let proof = try BEEF(
                merklePaths: [fixture.path],
                transactions: [.transactionID(fixture.parentID)],
                limits: fixture.limits
            )
            let merged = try proofless.merging(proof, limits: fixture.limits)
            #expect(merged.transactions == [.rawWithMerklePath(
                transaction: fixture.parent,
                merklePathIndex: 0
            )])

            let goMerge = try client.request(
                id: "beef-graph-merge-stale-format-artifact",
                operation: "transaction.beef.merge",
                arguments: [
                    "left": .string(try proofless.hex(limits: fixture.limits)),
                    "right": .string(try proof.hex(limits: fixture.limits)),
                ]
            )
            #expect(goMerge.result == .object([
                "bumps": .string("1"),
                "transactions": .array([.object([
                    "format": .string("0"),
                    "transactionID": .string(fixture.parentID.displayHex),
                ])]),
                "version": .string(String(BEEFVersion.v2.rawValue)),
            ]))

            let projected = try proofless.transactionIDOnly(limits: fixture.limits)
            let goProjection = try client.request(
                id: "beef-graph-txid-only",
                operation: "transaction.beef.txidonly",
                arguments: [
                    "bytes": .string(try proofless.hex(limits: fixture.limits)),
                ]
            )
            #expect(projected.transactions == [.transactionID(fixture.parentID)])
            #expect(goProjection.result == .object([
                "bumps": .string("0"),
                "transactions": .array([.object([
                    "format": .string("2"),
                    "transactionID": .string(fixture.parentID.displayHex),
                ])]),
                "version": .string(String(BEEFVersion.v2.rawValue)),
            ]))

            let trimmed = try projected.trimmingKnownTransactionIDs(
                [fixture.parentID],
                limits: fixture.limits
            )
            let goTrim = try client.request(
                id: "beef-graph-trim-known",
                operation: "transaction.beef.trim",
                arguments: [
                    "bytes": .string(try projected.hex(limits: fixture.limits)),
                    "knownTransactionIDs": .array([
                        .string(fixture.parentID.displayHex),
                    ]),
                ]
            )
            #expect(trimmed.transactions.isEmpty)
            #expect(goTrim.result == .object([
                "bumps": .string("0"),
                "transactions": .array([]),
                "version": .string(String(BEEFVersion.v2.rawValue)),
            ]))
        }
    }
}

private struct ConformanceBEEFFixture {
    let limits: BEEFLimits
    let parent: Transaction
    let child: Transaction
    let parentID: TransactionID
    let childID: TransactionID
    let path: MerklePath
}

private func conformanceBEEFFixture() throws -> ConformanceBEEFFixture {
    let transactionLimits = try TransactionLimits(
        maximumTransactionByteCount: 100_000,
        maximumInputCount: 100,
        maximumOutputCount: 100,
        maximumScriptByteCount: 10_000
    )
    let merklePathLimits = try MerklePathLimits(
        maximumByteCount: 100_000,
        maximumLeavesPerLevel: 100,
        maximumTotalLeaves: 1_000
    )
    let limits = try BEEFLimits(
        maximumByteCount: 1_000_000,
        maximumMerklePathCount: 100,
        maximumTransactionCount: 1_000,
        transactionLimits: transactionLimits,
        merklePathLimits: merklePathLimits
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
    let path = try MerklePath(
        blockHeight: 7,
        levels: [[.hash(
            offset: 0,
            hash: try Hash256(parentID.wireBytes),
            isTransactionID: true
        )]]
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
    return ConformanceBEEFFixture(
        limits: limits,
        parent: parent,
        child: child,
        parentID: parentID,
        childID: try child.transactionID(limits: transactionLimits),
        path: path
    )
}

private func assertGoDecode(
    client: GoOracleClient,
    id: String,
    bytes: [UInt8],
    version: UInt32,
    subject: String,
    fixture: ConformanceBEEFFixture
) throws {
    let response = try client.request(
        id: id,
        operation: "transaction.beef.decode",
        arguments: ["bytes": .string(Hex.encode(bytes))]
    )
    #expect(response.result == .object([
        "atomicSubject": .string(subject),
        "bumps": .string("1"),
        "newestTxid": .string(fixture.childID.displayHex),
        "transactions": .string("2"),
        "version": .string(String(version)),
    ]))
}
