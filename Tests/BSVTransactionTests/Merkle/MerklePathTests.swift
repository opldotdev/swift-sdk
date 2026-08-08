import BSVCore
import BSVCrypto
import BSVTransaction
import Testing

@Suite("BRC-74 Merkle paths")
struct MerklePathTests {
    @Test("canonical binary round trips and sorts offsets")
    func binaryRoundTrip() throws {
        let fixture = try fourLeafFixture()
        let unsorted = try MerklePath(
            blockHeight: 100,
            levels: [
                [
                    .hash(offset: 1, hash: fixture.b, isTransactionID: false),
                    .hash(offset: 0, hash: fixture.a, isTransactionID: true),
                ],
                [.hash(offset: 1, hash: fixture.cd, isTransactionID: false)],
            ]
        )
        let limits = try testMerkleLimits()
        let bytes = try unsorted.serialized(limits: limits)
        let hex = try unsorted.hex(limits: limits)

        #expect(unsorted.levels[0].map(\.offset) == [0, 1])
        #expect(Array(bytes.prefix(4)) == [100, 2, 2, 0])
        #expect(try unsorted.serializedByteCount(limits: limits) == bytes.count)
        #expect(try MerklePath(bytes: bytes, limits: limits) == unsorted)
        #expect(try MerklePath(hex: hex.uppercased(), limits: limits) == unsorted)
    }

    @Test("bounded JSON round trips with explicit display hash order")
    func jsonRoundTrip() throws {
        let fixture = try fourLeafFixture()
        let limits = try testMerkleLimits()
        let json = try fixture.pathA.jsonBytes(limits: limits)
        let text = String(decoding: json, as: UTF8.self)

        #expect(text.contains("\"blockHeight\":100"))
        #expect(text.contains("\"hash\":\"\(fixture.aID.displayHex)\""))
        #expect(text.contains("\"txid\":true"))
        #expect(try MerklePath(jsonBytes: json, limits: limits) == fixture.pathA)

        let unknown = Array(
            "{\"blockHeight\":1,\"path\":[[{\"offset\":0,\"duplicate\":true,\"extra\":1}]]}"
                .utf8
        )
        #expect(throws: MerklePathError.invalidJSON) {
            try MerklePath(jsonBytes: unknown, limits: limits)
        }
        let falseMarker = Array(
            "{\"blockHeight\":1,\"path\":[[{\"offset\":0,\"hash\":\"\(fixture.aID.displayHex)\",\"txid\":false}]]}"
                .utf8
        )
        #expect(throws: MerklePathError.invalidJSON) {
            try MerklePath(jsonBytes: falseMarker, limits: limits)
        }
        let ambiguous = Array(
            "{\"blockHeight\":1,\"path\":[[{\"offset\":1,\"hash\":\"\(fixture.aID.displayHex)\",\"duplicate\":true}]]}"
                .utf8
        )
        #expect(throws: MerklePathError.invalidJSON) {
            try MerklePath(jsonBytes: ambiguous, limits: limits)
        }
    }

    @Test("root computation supports explicit siblings, derived parents, and duplicates")
    func roots() throws {
        let fixture = try fourLeafFixture()
        let expected = MerkleTree.parent(fixture.ab, fixture.cd)

        #expect(try fixture.pathA.root(for: fixture.aID) == expected)

        let compound = try MerklePath(
            blockHeight: 100,
            levels: [
                [
                    .hash(offset: 0, hash: fixture.a, isTransactionID: false),
                    .hash(offset: 1, hash: fixture.b, isTransactionID: false),
                    .hash(offset: 2, hash: fixture.c, isTransactionID: true),
                    .duplicate(offset: 3),
                ],
                [],
            ]
        )
        let duplicateRoot = MerkleTree.parent(
            fixture.ab,
            MerkleTree.parent(fixture.c, fixture.c)
        )
        #expect(try compound.root(for: fixture.cID) == duplicateRoot)

        let singleton = try MerklePath(
            blockHeight: 1,
            levels: [[.hash(offset: 0, hash: fixture.a, isTransactionID: true)]]
        )
        #expect(try singleton.root(for: fixture.aID) == fixture.a)

        let incompleteRightOnly = try MerklePath(
            blockHeight: 1,
            levels: [[.hash(offset: 1, hash: fixture.a, isTransactionID: true)]]
        )
        #expect(throws: MerklePathError.missingSibling(level: 0, offset: 0)) {
            try incompleteRightOnly.root(for: fixture.aID)
        }

        let markedTarget = try MerklePath(
            blockHeight: 1,
            levels: [
                [
                    .hash(offset: 0, hash: fixture.a, isTransactionID: false),
                    .hash(offset: 2, hash: fixture.c, isTransactionID: true),
                    .hash(offset: 3, hash: fixture.d, isTransactionID: false),
                ],
                [.hash(offset: 0, hash: fixture.ab, isTransactionID: false)],
            ]
        )
        #expect(
            try markedTarget.root()
                == MerkleTree.parent(fixture.ab, MerkleTree.parent(fixture.c, fixture.d))
        )
    }

    @Test("merging unions proofs, preserves targets, and removes derivable parents")
    func merging() throws {
        let fixture = try fourLeafFixture()
        let pathC = try MerklePath(
            blockHeight: 100,
            levels: [
                [
                    .hash(offset: 2, hash: fixture.c, isTransactionID: true),
                    .hash(offset: 3, hash: fixture.d, isTransactionID: false),
                ],
                [.hash(offset: 0, hash: fixture.ab, isTransactionID: false)],
            ]
        )

        let merged = try fixture.pathA.merging(pathC)
        #expect(merged.levels[0].map(\.offset) == [0, 1, 2, 3])
        #expect(merged.levels[1].isEmpty)
        #expect(merged.levels[0][0].isTransactionID)
        #expect(merged.levels[0][2].isTransactionID)
        #expect(try merged.root(for: fixture.aID) == fixture.root)
        #expect(try merged.root(for: fixture.cID) == fixture.root)

        let wrongHeight = try MerklePath(
            blockHeight: 101,
            levels: pathC.levels
        )
        #expect(throws: MerklePathError.blockHeightMismatch(expected: 100, actual: 101)) {
            try fixture.pathA.merging(wrongHeight)
        }

        let duplicateProof = try MerklePath(
            blockHeight: 100,
            levels: [[
                .hash(offset: 0, hash: fixture.a, isTransactionID: true),
                .duplicate(offset: 1),
            ]]
        )
        let explicitEqualProof = try MerklePath(
            blockHeight: 100,
            levels: [[
                .hash(offset: 0, hash: fixture.a, isTransactionID: true),
                .hash(offset: 1, hash: fixture.a, isTransactionID: false),
            ]]
        )
        #expect(throws: MerklePathError.conflictingElement(level: 0, offset: 1)) {
            try duplicateProof.merging(explicitEqualProof)
        }
    }

    @Test("structural invariants reject ambiguous states")
    func structuralValidation() throws {
        let fixture = try fourLeafFixture()
        #expect(throws: MerklePathError.invalidTreeHeight(0)) {
            try MerklePath(blockHeight: 0, levels: [])
        }
        #expect(throws: MerklePathError.missingLevelZeroHash) {
            try MerklePath(blockHeight: 0, levels: [[.duplicate(offset: 1)]])
        }
        #expect(throws: MerklePathError.duplicateLeafOffset(level: 0, offset: 0)) {
            try MerklePath(blockHeight: 0, levels: [[
                .hash(offset: 0, hash: fixture.a, isTransactionID: false),
                .hash(offset: 0, hash: fixture.b, isTransactionID: false),
            ]])
        }
        #expect(throws: MerklePathError.duplicateMarkerRequiresOddOffset(level: 0, offset: 2)) {
            try MerklePath(blockHeight: 0, levels: [[
                .hash(offset: 0, hash: fixture.a, isTransactionID: false),
                .duplicate(offset: 2),
            ]])
        }
        #expect(throws: MerklePathError.transactionIDMarkerOutsideLevelZero(level: 1, offset: 1)) {
            try MerklePath(blockHeight: 0, levels: [
                [.hash(offset: 0, hash: fixture.a, isTransactionID: false)],
                [.hash(offset: 1, hash: fixture.b, isTransactionID: true)],
            ])
        }
        #expect(throws: MerklePathError.offsetOutOfRange(level: 1, offset: 2, treeHeight: 2)) {
            try MerklePath(blockHeight: 0, levels: [
                [.hash(offset: 0, hash: fixture.a, isTransactionID: false)],
                [.hash(offset: 2, hash: fixture.b, isTransactionID: false)],
            ])
        }
    }

    @Test("every truncation, trailing data, and invalid flag is rejected")
    func malformedBinary() throws {
        let fixture = try fourLeafFixture()
        let limits = try testMerkleLimits()
        let bytes = try fixture.pathA.serialized(limits: limits)
        for count in 0..<bytes.count {
            #expect(throws: MerklePathError.self) {
                try MerklePath(bytes: Array(bytes.prefix(count)), limits: limits)
            }
        }
        #expect(throws: MerklePathError.self) {
            try MerklePath(bytes: bytes + [0], limits: limits)
        }

        var badFlags = bytes
        let firstFlagsIndex = 4
        badFlags[firstFlagsIndex] = 3
        #expect(throws: MerklePathError.invalidFlags(level: 0, leaf: 0, flags: 3)) {
            try MerklePath(bytes: badFlags, limits: limits)
        }

        let oversizedHeight = CompactSize.encode(UInt64(UInt32.max) + 1) + [1]
        #expect(throws: MerklePathError.blockHeightOutOfRange(
            UInt64(UInt32.max) + 1
        )) {
            try MerklePath(bytes: oversizedHeight, limits: limits)
        }
        #expect(throws: MerklePathError.invalidTreeHeight(0)) {
            try MerklePath(bytes: [0, 0], limits: limits)
        }
        #expect(throws: MerklePathError.invalidTreeHeight(65)) {
            try MerklePath(bytes: [0, 65], limits: limits)
        }
    }

    @Test("CompactSize policy and resource limits are explicit")
    func policiesAndLimits() throws {
        let fixture = try fourLeafFixture()
        let limits = try testMerkleLimits()
        let canonical = try fixture.pathA.serialized(limits: limits)
        #expect(throws: MerklePathError.invalidMaximumByteCount(-1)) {
            try MerklePathLimits(
                maximumByteCount: -1,
                maximumLeavesPerLevel: 1,
                maximumTotalLeaves: 1
            )
        }
        #expect(throws: MerklePathError.invalidMaximumLeavesPerLevel(.max)) {
            try MerklePathLimits(
                maximumByteCount: 1,
                maximumLeavesPerLevel: .max,
                maximumTotalLeaves: 1
            )
        }
        #expect(throws: MerklePathError.invalidMaximumTotalLeaves(.max)) {
            try MerklePathLimits(
                maximumByteCount: 1,
                maximumLeavesPerLevel: 1,
                maximumTotalLeaves: .max
            )
        }
        let noncanonicalHeight = [UInt8](arrayLiteral: 0xfd, 100, 0) + canonical.dropFirst()
        #expect(throws: MerklePathError.self) {
            try MerklePath(bytes: Array(noncanonicalHeight), limits: limits)
        }
        #expect(
            try MerklePath(
                bytes: Array(noncanonicalHeight),
                limits: limits,
                compactSizeCanonicality: .permissive
            ) == fixture.pathA
        )

        let tinyHexLimit = try MerklePathLimits(
            maximumByteCount: 1,
            maximumLeavesPerLevel: 1,
            maximumTotalLeaves: 1
        )
        #expect(throws: MerklePathError.invalidHex(
            .decodedSizeLimitExceeded(maximum: 1)
        )) {
            try MerklePath(
                hex: String(repeating: "00", count: 1_000_000),
                limits: tinyHexLimit
            )
        }

        let byteLimited = try MerklePathLimits(
            maximumByteCount: canonical.count - 1,
            maximumLeavesPerLevel: 10,
            maximumTotalLeaves: 10
        )
        #expect(throws: MerklePathError.pathTooLarge(
            actual: canonical.count,
            maximum: canonical.count - 1
        )) {
            try MerklePath(bytes: canonical, limits: byteLimited)
        }

        let leafLimited = try MerklePathLimits(
            maximumByteCount: canonical.count,
            maximumLeavesPerLevel: 1,
            maximumTotalLeaves: 10
        )
        #expect(throws: MerklePathError.leafCountExceedsLimit(
            level: 0,
            actual: 2,
            maximum: 1
        )) {
            try MerklePath(bytes: canonical, limits: leafLimited)
        }

        let totalLimited = try MerklePathLimits(
            maximumByteCount: canonical.count,
            maximumLeavesPerLevel: 2,
            maximumTotalLeaves: 2
        )
        #expect(throws: MerklePathError.totalLeafCountExceedsLimit(actual: 3, maximum: 2)) {
            try MerklePath(bytes: canonical, limits: totalLimited)
        }
    }

    @Test("missing targets, siblings, and mismatched roots are typed")
    func proofFailures() throws {
        let fixture = try fourLeafFixture()
        let absent = try TransactionID(wireBytes: [UInt8](repeating: 0xff, count: 32))
        #expect(throws: MerklePathError.transactionNotInPath(absent)) {
            try fixture.pathA.root(for: absent)
        }

        let incomplete = try MerklePath(
            blockHeight: 100,
            levels: [
                [.hash(offset: 0, hash: fixture.a, isTransactionID: true)],
                [],
            ]
        )
        #expect(throws: MerklePathError.missingSibling(level: 0, offset: 1)) {
            try incomplete.root(for: fixture.aID)
        }

        let wrongRootPath = try MerklePath(
            blockHeight: 100,
            levels: [
                [
                    .hash(offset: 0, hash: fixture.a, isTransactionID: true),
                    .hash(offset: 1, hash: fixture.c, isTransactionID: false),
                ],
                [.hash(offset: 1, hash: fixture.cd, isTransactionID: false)],
            ]
        )
        #expect(throws: MerklePathError.rootMismatch) {
            try fixture.pathA.merging(wrongRootPath)
        }
    }
}

private struct FourLeafFixture {
    let a: Hash256
    let b: Hash256
    let c: Hash256
    let d: Hash256
    let ab: Hash256
    let cd: Hash256
    let root: Hash256
    let aID: TransactionID
    let cID: TransactionID
    let pathA: MerklePath
}

private func fourLeafFixture() throws -> FourLeafFixture {
    let a = BSVHashing.sha256d([0x00])
    let b = BSVHashing.sha256d([0x01])
    let c = BSVHashing.sha256d([0x02])
    let d = BSVHashing.sha256d([0x03])
    let ab = MerkleTree.parent(a, b)
    let cd = MerkleTree.parent(c, d)
    let aID = try TransactionID(wireBytes: a.bytes)
    let cID = try TransactionID(wireBytes: c.bytes)
    let path = try MerklePath(
        blockHeight: 100,
        levels: [
            [
                .hash(offset: 0, hash: a, isTransactionID: true),
                .hash(offset: 1, hash: b, isTransactionID: false),
            ],
            [.hash(offset: 1, hash: cd, isTransactionID: false)],
        ]
    )
    return FourLeafFixture(
        a: a,
        b: b,
        c: c,
        d: d,
        ab: ab,
        cd: cd,
        root: MerkleTree.parent(ab, cd),
        aID: aID,
        cID: cID,
        pathA: path
    )
}

private func testMerkleLimits() throws -> MerklePathLimits {
    try MerklePathLimits(
        maximumByteCount: 10_000,
        maximumLeavesPerLevel: 100,
        maximumTotalLeaves: 1_000
    )
}
