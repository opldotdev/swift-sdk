import BSVCore
import BSVCrypto
import BSVTransaction
import Testing

/// Interop with @bsv/sdk 4.1.1 `src/transaction/MerklePath.ts`.
@Suite("BRC-74 Merkle paths interoperate with @bsv/sdk")
struct MerklePathTypeScriptCompatibilityTests {
    @Test("a single-level path pairs the last odd node with itself at every height")
    func singleLevelOddNode() throws {
        // MerklePath.ts:34, :380, :430, :671. A one-level path lists the block's
        // transactions, so the right-most node with no neighbour is duplicated.
        let h0 = BSVHashing.sha256d([0x10])
        let h1 = BSVHashing.sha256d([0x11])
        let h2 = BSVHashing.sha256d([0x12])
        let path = try MerklePath(blockHeight: 1, levels: [[
            .hash(offset: 0, hash: h0, isTransactionID: true),
            .hash(offset: 1, hash: h1, isTransactionID: false),
            .hash(offset: 2, hash: h2, isTransactionID: true),
        ]])
        let expected = MerkleTree.parent(
            MerkleTree.parent(h0, h1),
            MerkleTree.parent(h2, h2)
        )
        #expect(try path.root(for: transactionID(h0)) == expected)
        #expect(try path.root(for: transactionID(h2)) == expected)

        let limits = try merkleLimits()
        let reparsed = try MerklePath(hex: try path.hex(limits: limits), limits: limits)
        #expect(try reparsed.root(for: transactionID(h2)) == expected)
    }

    @Test("every transaction of block 125632 proves the header root from level zero alone")
    func block125632() throws {
        // MerklePath.test.ts:439 (BLOCK_125632 at :172). Eleven transactions:
        // level 2 has three nodes, so its last node is duplicated implicitly.
        let hashes = try block125632Transactions.map { try TransactionID(displayHex: $0) }
        let root = try TransactionID(displayHex: block125632Root).wireBytes
        let leaves = try hashes.enumerated().map { offset, id in
            MerklePathElement.hash(
                offset: UInt64(offset),
                hash: try Hash256(id.wireBytes),
                isTransactionID: true
            )
        }

        let implicit = try MerklePath(blockHeight: 125_632, levels: [leaves])
        let explicit = try MerklePath(
            blockHeight: 125_632,
            levels: [leaves + [.duplicate(offset: 11)]]
        )
        for id in hashes {
            #expect(try implicit.root(for: id).bytes == root)
            #expect(try explicit.root(for: id).bytes == root)
        }
    }

    @Test("implicit duplication never replaces a missing left sibling or an upper level")
    func implicitDuplicationIsBounded() throws {
        let a = BSVHashing.sha256d([0x20])
        let c = BSVHashing.sha256d([0x22])
        let d = BSVHashing.sha256d([0x23])

        // MerklePath.test.ts:358: a lone leaf is a proof only at offset 0.
        let loneRight = try MerklePath(blockHeight: 1, levels: [[
            .hash(offset: 1, hash: a, isTransactionID: true),
        ]])
        #expect(throws: MerklePathError.missingSibling(level: 0, offset: 0)) {
            try loneRight.root(for: transactionID(a))
        }

        // MerklePath.test.ts:623: empty upper levels do not imply duplicates.
        let twoLevels = try MerklePath(blockHeight: 1, levels: [
            [
                .hash(offset: 0, hash: a, isTransactionID: false),
                .hash(offset: 1, hash: a, isTransactionID: false),
                .hash(offset: 2, hash: c, isTransactionID: true),
            ],
            [],
        ])
        #expect(throws: MerklePathError.missingSibling(level: 0, offset: 3)) {
            try twoLevels.root(for: transactionID(c))
        }

        // Offsets 0 and 1 are missing: the right-most pair has no left
        // neighbour to stand in for.
        let missingLeft = try MerklePath(blockHeight: 1, levels: [[
            .hash(offset: 2, hash: c, isTransactionID: true),
            .hash(offset: 3, hash: d, isTransactionID: false),
        ]])
        #expect(throws: MerklePathError.missingSibling(level: 1, offset: 0)) {
            try missingLeft.root(for: transactionID(c))
        }
    }

    @Test("@bsv/sdk valid BUMP vectors parse and every level-zero hash agrees on the root")
    func typeScriptValidVectors() throws {
        let limits = try merkleLimits()
        for hex in typeScriptValidBUMPs {
            let path = try MerklePath(hex: hex, limits: limits)
            _ = try path.consistentRoot()
            #expect(try path.hex(limits: limits) == hex)
        }
    }

    @Test("@bsv/sdk invalid BUMP vectors are rejected")
    func typeScriptInvalidVectors() throws {
        let limits = try merkleLimits()
        for vector in typeScriptInvalidBUMPs {
            // @bsv/sdk checks roots in its constructor; Swift checks them when
            // a path is merged, put in a BEEF, or used for a root.
            #expect(throws: MerklePathError.self, "\(vector.error)") {
                let path = try MerklePath(hex: vector.hex, limits: limits)
                _ = try path.consistentRoot()
            }
        }

        // bump.invalid.vectors.ts entry 1: an upper-level node no level-zero
        // hash needs ("Invalid offset: 12, at height: 1").
        #expect(throws: MerklePathError.illegalOffset(level: 1, offset: 12)) {
            try MerklePath(hex: typeScriptInvalidBUMPs[0].hex, limits: limits)
        }
    }

    @Test("upper-level nodes must be siblings of a level-zero hash's ancestors")
    func legalOffsets() throws {
        // MerklePath.ts:218-244 (legalOffsetsOnly).
        let a = BSVHashing.sha256d([0x30])
        let b = BSVHashing.sha256d([0x31])
        let ab = MerkleTree.parent(a, b)
        let cd = MerkleTree.parent(BSVHashing.sha256d([0x32]), BSVHashing.sha256d([0x33]))

        #expect(throws: MerklePathError.illegalOffset(level: 1, offset: 0)) {
            try MerklePath(blockHeight: 1, levels: [
                [
                    .hash(offset: 0, hash: a, isTransactionID: true),
                    .hash(offset: 1, hash: b, isTransactionID: false),
                ],
                [
                    .hash(offset: 0, hash: ab, isTransactionID: false),
                    .hash(offset: 1, hash: cd, isTransactionID: false),
                ],
            ])
        }
        // A duplicate marker at level zero does not make its ancestors' siblings legal.
        #expect(throws: MerklePathError.illegalOffset(level: 1, offset: 3)) {
            try MerklePath(blockHeight: 1, levels: [
                [
                    .hash(offset: 0, hash: a, isTransactionID: true),
                    .hash(offset: 1, hash: b, isTransactionID: false),
                    .duplicate(offset: 5),
                ],
                [
                    .hash(offset: 1, hash: cd, isTransactionID: false),
                    .hash(offset: 3, hash: ab, isTransactionID: false),
                ],
            ])
        }
    }

    @Test("BUMP flags are a bitmask: bit 0 duplicates, otherwise bit 1 marks a txid")
    func flagBitmask() throws {
        // MerklePath.ts:142-148. @bsv/sdk writes flags 3 for a duplicate leaf
        // that also carries a txid marker (MerklePath.ts:296-301).
        let a = BSVHashing.sha256d([0x40])
        let limits = try merkleLimits()
        func bump(secondFlags: UInt8, firstFlags: UInt8 = 2) -> [UInt8] {
            [100, 1, 2, 0, firstFlags] + a.bytes + [1, secondFlags]
        }

        let duplicate = try MerklePath(blockHeight: 100, levels: [[
            .hash(offset: 0, hash: a, isTransactionID: true),
            .duplicate(offset: 1),
        ]])
        #expect(try MerklePath(bytes: bump(secondFlags: 3), limits: limits) == duplicate)
        #expect(try MerklePath(bytes: bump(secondFlags: 0xff), limits: limits) == duplicate)

        let unmarked = try MerklePath(bytes: bump(secondFlags: 1, firstFlags: 4), limits: limits)
        #expect(unmarked.levels[0][0] == .hash(offset: 0, hash: a, isTransactionID: false))
        let marked = try MerklePath(bytes: bump(secondFlags: 1, firstFlags: 6), limits: limits)
        #expect(marked == duplicate)
        #expect(try marked.serialized(limits: limits) == bump(secondFlags: 1))
    }

    @Test("a coinbase proof verifies only 100 blocks deep")
    func coinbaseMaturity() async throws {
        // MerklePath.ts:510-519; MerklePath.test.ts:417 and :428.
        let coinbase = BSVHashing.sha256d([0x50])
        let sibling = BSVHashing.sha256d([0x51])
        let path = try MerklePath(blockHeight: 800_000, levels: [[
            .hash(offset: 0, hash: coinbase, isTransactionID: true),
            .hash(offset: 1, hash: sibling, isTransactionID: true),
        ]])
        let root = MerkleTree.parent(coinbase, sibling)

        let shallow = HeightChainTracker(root: root, blockHeight: 800_000, currentHeight: 800_099)
        #expect(!(try await path.verify(transactionID: transactionID(coinbase), using: shallow)))
        #expect(await shallow.rootRequests() == 0)

        let deep = HeightChainTracker(root: root, blockHeight: 800_000, currentHeight: 800_100)
        #expect(try await path.verify(transactionID: transactionID(coinbase), using: deep))

        // Only offset zero is a coinbase.
        #expect(try await path.verify(transactionID: transactionID(sibling), using: shallow))

        let maximumHeight = try MerklePath(blockHeight: .max, levels: path.levels)
        let top = HeightChainTracker(root: root, blockHeight: .max, currentHeight: .max)
        #expect(!(try await maximumHeight.verify(transactionID: transactionID(coinbase), using: top)))
    }
}

private actor HeightChainTracker: ChainTracker {
    let root: Hash256
    let blockHeight: UInt32
    let height: UInt32
    private var requests = 0

    init(root: Hash256, blockHeight: UInt32, currentHeight: UInt32) {
        self.root = root
        self.blockHeight = blockHeight
        height = currentHeight
    }

    func isValidRoot(_ candidate: Hash256, atBlockHeight candidateHeight: UInt32) -> Bool {
        requests += 1
        return candidate == root && candidateHeight == blockHeight
    }

    func currentHeight() -> UInt32 { height }

    func rootRequests() -> Int { requests }
}

private func transactionID(_ hash: Hash256) -> TransactionID {
    TransactionID(exactDigestBytesGuaranteed: hash.bytes)
}

private func merkleLimits() throws -> MerklePathLimits {
    try MerklePathLimits(
        maximumByteCount: 100_000,
        maximumLeavesPerLevel: 1_000,
        maximumTotalLeaves: 10_000
    )
}

private let block125632Root = "205b2e27c58601fc1a8de04c83b6b0c46f89c16b2161c93441b7e9269cf6bc4a"
private let block125632Transactions = [
    "17cba98da71fe75862aac894392f2ff604356db386767fec364877a5a9ff200c",
    "14ce64bd223ec9bb42662b74fdcf94f96a209a1aee72b7ba7639db503150ec2e",
    "90a2de85351cfadd2326b9b0098e9c453af09b2980835f57a1429bbb44beb872",
    "a31f2ddfea7ddd4581dca3007ee99e58ea6baa97a8ac3b32bb4610baac9f7206",
    "c36eeed6fbc0259d30804f59f804dfcda35a54461157d6ac9c094f0ea378f35c",
    "17752483868c52a98407a0e226d73b42e214e0fad548541619d858e1fd4a9549",
    "3b8c4460412cfc55be0d50308ba704a859bd6f83bfed01b0828c9b067cd69246",
    "a3f1b9d4b3ef3b061af352fdc2d02048417030fef9282c36da689cd899437cdb",
    "66e2b022da877621ef197e02c3ef7d3f820d33a86ead2e72bf966432ea6776f1",
    "e988b5d7a2cec8e0759ade2e151737d1cdfdde68accff42938583ad12eb98b99",
    "5e7a8a8ec3f912ac1c4e90279c04263f170ed055c0411c8d490b846f01e6a99e",
]
