import BSVCore
import BSVCrypto
import BSVTransaction
import Testing

@Suite("BRC-74 Merkle path conformance", .serialized)
struct MerklePathConformanceTests {
    @Test("pinned Go SDK agrees on canonical binary and independently authored roots")
    func goOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Merkle-path Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let limits = try MerklePathLimits(
                maximumByteCount: 10_000,
                maximumLeavesPerLevel: 100,
                maximumTotalLeaves: 1_000
            )
            let a = BSVHashing.sha256d([0x10])
            let b = BSVHashing.sha256d([0x11])
            let c = BSVHashing.sha256d([0x12])
            let d = BSVHashing.sha256d([0x13])
            let path = try MerklePath(
                blockHeight: 42,
                levels: [
                    [
                        .hash(offset: 0, hash: a, isTransactionID: true),
                        .hash(offset: 1, hash: b, isTransactionID: false),
                    ],
                    [.hash(
                        offset: 1,
                        hash: MerkleTree.parent(c, d),
                        isTransactionID: false
                    )],
                ]
            )
            let bytes = try path.serialized(limits: limits)
            let encoded = Hex.encode(bytes)
            let txid = try TransactionID(wireBytes: a.bytes)
            let root = try path.root(for: txid)
            let rootDisplay = try TransactionID(wireBytes: root.bytes).displayHex

            let decoded = try client.request(
                id: "merklepath-decode",
                operation: "transaction.merklepath.decode",
                arguments: ["bytes": .string(encoded)]
            )
            #expect(decoded.result == .object([
                "blockHeight": .string("42"),
                "bytes": .string(encoded),
                "treeHeight": .string("2"),
            ]))

            let computed = try client.request(
                id: "merklepath-root",
                operation: "transaction.merklepath.root",
                arguments: [
                    "bytes": .string(encoded),
                    "txid": .string(txid.displayHex),
                ]
            )
            #expect(computed.result == .object(["root": .string(rootDisplay)]))

            // Pinned Go explicitly derives an effective height from the
            // largest level-zero offset for single-level compound paths.
            let compound = try MerklePath(
                blockHeight: 42,
                levels: [[
                    .hash(offset: 0, hash: a, isTransactionID: false),
                    .hash(offset: 1, hash: b, isTransactionID: false),
                    .hash(offset: 2, hash: c, isTransactionID: true),
                    .hash(offset: 3, hash: d, isTransactionID: false),
                ]]
            )
            let compoundBytes = try compound.hex(limits: limits)
            let compoundTransactionID = try TransactionID(wireBytes: c.bytes)
            let compoundRoot = try TransactionID(
                wireBytes: compound.root(for: compoundTransactionID).bytes
            ).displayHex
            let computedCompound = try client.request(
                id: "merklepath-compound-root",
                operation: "transaction.merklepath.root",
                arguments: [
                    "bytes": .string(compoundBytes),
                    "txid": .string(compoundTransactionID.displayHex),
                ]
            )
            #expect(computedCompound.result == .object(["root": .string(compoundRoot)]))

            let pathC = try MerklePath(
                blockHeight: 42,
                levels: [
                    [
                        .hash(offset: 2, hash: c, isTransactionID: true),
                        .hash(offset: 3, hash: d, isTransactionID: false),
                    ],
                    [.hash(
                        offset: 0,
                        hash: MerkleTree.parent(a, b),
                        isTransactionID: false
                    )],
                ]
            )
            let pathCHex = try pathC.hex(limits: limits)
            let expectedCombined = try path.merging(pathC).hex(limits: limits)
            let combined = try client.request(
                id: "merklepath-combine",
                operation: "transaction.merklepath.combine",
                arguments: [
                    "left": .string(encoded),
                    "right": .string(pathCHex),
                ]
            )
            #expect(combined.result == .object(["bytes": .string(expectedCombined)]))
        }
    }
}
