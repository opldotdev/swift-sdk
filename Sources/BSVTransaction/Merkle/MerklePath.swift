import BSVCore
import BSVCrypto

/// One node encoded in a BRC-74 Merkle path.
///
/// The two cases make the format's mutually exclusive hash and duplicate
/// representations unambiguous. Transaction-ID markers are valid only at
/// level zero.
public enum MerklePathElement: Hashable, Sendable {
    case hash(offset: UInt64, hash: Hash256, isTransactionID: Bool)
    case duplicate(offset: UInt64)

    public var offset: UInt64 {
        switch self {
        case .hash(let offset, _, _), .duplicate(let offset): offset
        }
    }

    public var hash: Hash256? {
        guard case .hash(_, let hash, _) = self else { return nil }
        return hash
    }

    public var isTransactionID: Bool {
        guard case .hash(_, _, let isTransactionID) = self else { return false }
        return isTransactionID
    }

    public var isDuplicate: Bool {
        guard case .duplicate = self else { return false }
        return true
    }
}

/// Bitcoin Merkle-tree hashing over hashes in wire/internal byte order.
public enum MerkleTree {
    /// Returns `SHA256d(left || right)` without display-order reversal.
    public static func parent(_ left: Hash256, _ right: Hash256) -> Hash256 {
        BSVHashing.sha256d(left.bytes + right.bytes)
    }
}

/// A canonical value-semantic BRC-74 BSV Unified Merkle Path (BUMP).
public struct MerklePath: Hashable, Sendable {
    public static let maximumTreeHeight = 64

    public let blockHeight: UInt32
    public let levels: [[MerklePathElement]]

    public var treeHeight: Int { levels.count }

    /// Creates a structurally valid path and sorts every level by offset.
    public init(blockHeight: UInt32, levels: [[MerklePathElement]]) throws {
        guard (1...Self.maximumTreeHeight).contains(levels.count) else {
            throw MerklePathError.invalidTreeHeight(levels.count)
        }

        let sortedLevels = levels.map { level in
            level.sorted { $0.offset < $1.offset }
        }
        guard sortedLevels[0].contains(where: { $0.hash != nil }) else {
            throw MerklePathError.missingLevelZeroHash
        }

        let maximumLevelZeroOffset = sortedLevels[0].map(\.offset).max() ?? 0
        let offsetHeight = maximumLevelZeroOffset == 0
            ? 1
            : UInt64.bitWidth - maximumLevelZeroOffset.leadingZeroBitCount
        let effectiveHeight = max(sortedLevels.count, offsetHeight)

        for (levelIndex, level) in sortedLevels.enumerated() {
            var previousOffset: UInt64?
            let remainingHeight = effectiveHeight - levelIndex
            for element in level {
                if previousOffset == element.offset {
                    throw MerklePathError.duplicateLeafOffset(
                        level: levelIndex,
                        offset: element.offset
                    )
                }
                previousOffset = element.offset

                if element.isDuplicate && element.offset.isMultiple(of: 2) {
                    throw MerklePathError.duplicateMarkerRequiresOddOffset(
                        level: levelIndex,
                        offset: element.offset
                    )
                }
                if levelIndex != 0 && element.isTransactionID {
                    throw MerklePathError.transactionIDMarkerOutsideLevelZero(
                        level: levelIndex,
                        offset: element.offset
                    )
                }
                if remainingHeight < UInt64.bitWidth,
                   element.offset >= (UInt64(1) << remainingHeight)
                {
                    throw MerklePathError.offsetOutOfRange(
                        level: levelIndex,
                        offset: element.offset,
                        treeHeight: effectiveHeight
                    )
                }
            }
        }

        self.blockHeight = blockHeight
        self.levels = sortedLevels
    }

    /// Parses exactly one bounded binary BRC-74 path.
    public init(
        bytes: [UInt8],
        limits: MerklePathLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        guard bytes.count <= limits.maximumByteCount else {
            throw MerklePathError.pathTooLarge(
                actual: bytes.count,
                maximum: limits.maximumByteCount
            )
        }

        var cursor = ByteCursor(bytes)
        try self.init(
            consuming: &cursor,
            limits: limits,
            compactSizeCanonicality: compactSizeCanonicality
        )
        do {
            try cursor.requireFinished()
        } catch let error as BinaryDecodingError {
            throw MerklePathError.malformed(
                field: .trailingBytes,
                offset: cursor.position,
                cause: error
            )
        }
    }

    /// Consumes one BRC-74 path from an enclosing package format.
    package init(
        consuming cursor: inout ByteCursor,
        limits: MerklePathLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        let startPosition = cursor.position
        let heightValue = try Self.read(.blockHeight, from: &cursor) {
            try $0.readCompactSize(canonicality: compactSizeCanonicality).value
        }
        guard heightValue <= UInt64(UInt32.max) else {
            throw MerklePathError.blockHeightOutOfRange(heightValue)
        }
        let treeHeight = Int(try Self.read(.treeHeight, from: &cursor) {
            try $0.read(count: 1)[0]
        })
        guard (1...Self.maximumTreeHeight).contains(treeHeight) else {
            throw MerklePathError.invalidTreeHeight(treeHeight)
        }

        var parsedLevels: [[MerklePathElement]] = []
        parsedLevels.reserveCapacity(treeHeight)
        var totalLeaves: UInt64 = 0

        for levelIndex in 0..<treeHeight {
            let leafCount = try Self.read(.leafCount(level: levelIndex), from: &cursor) {
                try $0.readCompactSize(canonicality: compactSizeCanonicality).value
            }
            guard leafCount <= limits.maximumLeavesPerLevel else {
                throw MerklePathError.leafCountExceedsLimit(
                    level: levelIndex,
                    actual: leafCount,
                    maximum: limits.maximumLeavesPerLevel
                )
            }
            let (nextTotal, overflow) = totalLeaves.addingReportingOverflow(leafCount)
            guard !overflow, nextTotal <= limits.maximumTotalLeaves else {
                throw MerklePathError.totalLeafCountExceedsLimit(
                    actual: overflow ? .max : nextTotal,
                    maximum: limits.maximumTotalLeaves
                )
            }
            guard leafCount <= UInt64(Int.max) else {
                throw MerklePathError.countNotRepresentable(leafCount)
            }
            totalLeaves = nextTotal

            var level: [MerklePathElement] = []
            level.reserveCapacity(min(Int(leafCount), cursor.remaining / 2))
            for leafIndex in 0..<Int(leafCount) {
                let offset = try Self.read(
                    .offset(level: levelIndex, leaf: leafIndex),
                    from: &cursor
                ) {
                    try $0.readCompactSize(canonicality: compactSizeCanonicality).value
                }
                let flags = try Self.read(
                    .flags(level: levelIndex, leaf: leafIndex),
                    from: &cursor
                ) {
                    try $0.read(count: 1)[0]
                }
                switch flags {
                case 0, 2:
                    let hashBytes = try Self.read(
                        .hash(level: levelIndex, leaf: leafIndex),
                        from: &cursor
                    ) {
                        try $0.read(count: 32)
                    }
                    level.append(.hash(
                        offset: offset,
                        hash: try Hash256(hashBytes),
                        isTransactionID: flags == 2
                    ))
                case 1:
                    level.append(.duplicate(offset: offset))
                default:
                    throw MerklePathError.invalidFlags(
                        level: levelIndex,
                        leaf: leafIndex,
                        flags: flags
                    )
                }
            }
            parsedLevels.append(level)
        }

        let byteCount = cursor.position - startPosition
        guard byteCount <= limits.maximumByteCount else {
            throw MerklePathError.pathTooLarge(
                actual: byteCount,
                maximum: limits.maximumByteCount
            )
        }

        try self.init(blockHeight: UInt32(heightValue), levels: parsedLevels)
    }

    /// Parses lowercase or uppercase BRC-74 hexadecimal within the byte limit.
    public init(
        hex: String,
        limits: MerklePathLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        do {
            if limits.maximumByteCount <= (Int.max - 1) / 2 {
                let maximumHexByteCount = limits.maximumByteCount * 2
                guard hex.utf8.prefix(maximumHexByteCount + 1).count <= maximumHexByteCount else {
                    throw TextEncodingError.decodedSizeLimitExceeded(
                        maximum: limits.maximumByteCount
                    )
                }
            }
            try self.init(
                bytes: Hex.decode(
                    hex,
                    maximumDecodedByteCount: limits.maximumByteCount
                ),
                limits: limits,
                compactSizeCanonicality: compactSizeCanonicality
            )
        } catch let error as TextEncodingError {
            throw MerklePathError.invalidHex(error)
        }
    }

    /// Serializes the path using canonical CompactSize values and sorted offsets.
    public func serialized(limits: MerklePathLimits) throws -> [UInt8] {
        let byteCount = try serializedByteCount(limits: limits)
        var writer = ByteWriter(capacity: byteCount)
        writer.writeCompactSize(UInt64(blockHeight))
        writer.write([UInt8(treeHeight)])
        for level in levels {
            writer.writeCompactSize(UInt64(level.count))
            for element in level {
                writer.writeCompactSize(element.offset)
                switch element {
                case .hash(_, let hash, let isTransactionID):
                    writer.write([isTransactionID ? 2 : 0])
                    writer.write(hash.bytes)
                case .duplicate:
                    writer.write([1])
                }
            }
        }
        return writer.bytes
    }

    /// Emits the canonical binary BRC-74 representation as lowercase hexadecimal.
    public func hex(limits: MerklePathLimits) throws -> String {
        Hex.encode(try serialized(limits: limits))
    }

    /// Returns the exact canonical binary size after enforcing resource limits.
    public func serializedByteCount(limits: MerklePathLimits) throws -> Int {
        var totalLeaves: UInt64 = 0
        var byteCount = CompactSize.encodedLength(of: UInt64(blockHeight)) + 1
        for (levelIndex, level) in levels.enumerated() {
            let count = UInt64(level.count)
            guard count <= limits.maximumLeavesPerLevel else {
                throw MerklePathError.leafCountExceedsLimit(
                    level: levelIndex,
                    actual: count,
                    maximum: limits.maximumLeavesPerLevel
                )
            }
            let (nextTotal, overflow) = totalLeaves.addingReportingOverflow(count)
            guard !overflow, nextTotal <= limits.maximumTotalLeaves else {
                throw MerklePathError.totalLeafCountExceedsLimit(
                    actual: overflow ? .max : nextTotal,
                    maximum: limits.maximumTotalLeaves
                )
            }
            totalLeaves = nextTotal
            try Self.add(CompactSize.encodedLength(of: count), to: &byteCount)
            for element in level {
                try Self.add(CompactSize.encodedLength(of: element.offset), to: &byteCount)
                try Self.add(element.isDuplicate ? 1 : 33, to: &byteCount)
            }
        }
        guard byteCount <= limits.maximumByteCount else {
            throw MerklePathError.pathTooLarge(
                actual: byteCount,
                maximum: limits.maximumByteCount
            )
        }
        return byteCount
    }

    /// Computes the root for a transaction explicitly included at level zero.
    public func root(for transactionID: TransactionID) throws -> Hash256 {
        let target = try Hash256(transactionID.wireBytes)
        guard let targetElement = levels[0].first(where: { $0.hash == target }) else {
            throw MerklePathError.transactionNotInPath(transactionID)
        }
        if levels.count == 1, levels[0].count == 1, targetElement.offset == 0 {
            return target
        }

        var index = MerklePathIndex(levels: levels)
        var workingHash = target
        let targetOffset = targetElement.offset
        let maximumOffset = levels[0].map(\.offset).max() ?? 0
        let offsetHeight = maximumOffset == 0
            ? 1
            : UInt64.bitWidth - maximumOffset.leadingZeroBitCount
        let effectiveHeight = max(levels.count, offsetHeight)

        for level in 0..<effectiveHeight {
            let siblingOffset = (targetOffset >> level) ^ 1
            if index.element(level: level, offset: siblingOffset)?.isDuplicate == true {
                workingHash = MerkleTree.parent(workingHash, workingHash)
                continue
            }
            guard let siblingHash = index.hash(level: level, offset: siblingOffset) else {
                throw MerklePathError.missingSibling(
                    level: level,
                    offset: siblingOffset
                )
            }
            workingHash = siblingOffset.isMultiple(of: 2)
                ? MerkleTree.parent(siblingHash, workingHash)
                : MerkleTree.parent(workingHash, siblingHash)
        }
        return workingHash
    }

    /// Computes a root using the first marked transaction ID, falling back to
    /// the first hash only for imported paths without relevance markers.
    public func root() throws -> Hash256 {
        let markedHash = levels[0].first(where: \.isTransactionID)?.hash
        guard let hash = markedHash ?? levels[0].compactMap(\.hash).first else {
            throw MerklePathError.missingLevelZeroHash
        }
        return try root(for: TransactionID(wireBytes: hash.bytes))
    }

    /// Returns a canonical union after proving both paths anchor to the same block root.
    public func merging(_ other: MerklePath) throws -> MerklePath {
        guard blockHeight == other.blockHeight else {
            throw MerklePathError.blockHeightMismatch(
                expected: blockHeight,
                actual: other.blockHeight
            )
        }
        guard try root() == other.root() else {
            throw MerklePathError.rootMismatch
        }

        let levelCount = max(levels.count, other.levels.count)
        var combined = Array(repeating: [UInt64: MerklePathElement](), count: levelCount)
        for source in [levels, other.levels] {
            for (levelIndex, level) in source.enumerated() {
                for element in level {
                    if let existing = combined[levelIndex][element.offset] {
                        combined[levelIndex][element.offset] = try Self.merge(
                            existing,
                            element,
                            level: levelIndex
                        )
                    } else {
                        combined[levelIndex][element.offset] = element
                    }
                }
            }
        }

        var compacted = Array(repeating: [MerklePathElement](), count: levelCount)
        for levelIndex in stride(from: levelCount - 1, through: 0, by: -1) {
            for element in combined[levelIndex].values {
                if levelIndex > 0 {
                    let leftOffset = element.offset &* 2
                    let hasLeft = combined[levelIndex - 1][leftOffset] != nil
                    let hasRight = combined[levelIndex - 1][leftOffset &+ 1] != nil
                    if hasLeft && hasRight { continue }
                }
                compacted[levelIndex].append(element)
            }
        }
        return try MerklePath(blockHeight: blockHeight, levels: compacted)
    }

    private static func merge(
        _ left: MerklePathElement,
        _ right: MerklePathElement,
        level: Int
    ) throws -> MerklePathElement {
        switch (left, right) {
        case (.duplicate(let leftOffset), .duplicate):
            return .duplicate(offset: leftOffset)
        case (
            .hash(let offset, let leftHash, let leftIsTransactionID),
            .hash(_, let rightHash, let rightIsTransactionID)
        ) where leftHash == rightHash:
            return .hash(
                offset: offset,
                hash: leftHash,
                isTransactionID: leftIsTransactionID || rightIsTransactionID
            )
        default:
            throw MerklePathError.conflictingElement(level: level, offset: left.offset)
        }
    }

    private static func read<T>(
        _ field: MerklePathField,
        from cursor: inout ByteCursor,
        _ operation: (inout ByteCursor) throws -> T
    ) throws -> T {
        let offset = cursor.position
        do {
            return try operation(&cursor)
        } catch let error as BinaryDecodingError {
            throw MerklePathError.malformed(field: field, offset: offset, cause: error)
        }
    }

    private static func add(_ value: Int, to total: inout Int) throws {
        let (sum, overflow) = total.addingReportingOverflow(value)
        guard !overflow else { throw MerklePathError.serializedSizeOverflow }
        total = sum
    }
}

private struct MerklePathNode: Hashable {
    let level: Int
    let offset: UInt64
}

private struct MerklePathIndex {
    let levels: [[UInt64: MerklePathElement]]
    var derived: [MerklePathNode: Hash256] = [:]

    init(levels: [[MerklePathElement]]) {
        self.levels = levels.map { level in
            Dictionary(uniqueKeysWithValues: level.map { ($0.offset, $0) })
        }
    }

    func element(level: Int, offset: UInt64) -> MerklePathElement? {
        guard level < levels.count else { return nil }
        return levels[level][offset]
    }

    mutating func hash(level: Int, offset: UInt64) -> Hash256? {
        if let element = element(level: level, offset: offset) {
            return element.hash
        }
        let node = MerklePathNode(level: level, offset: offset)
        if let cached = derived[node] { return cached }
        guard level > 0 else { return nil }

        let leftOffset = offset &* 2
        guard let left = hash(level: level - 1, offset: leftOffset) else {
            return nil
        }
        let rightOffset = leftOffset &+ 1
        let parent: Hash256
        if element(level: level - 1, offset: rightOffset)?.isDuplicate == true {
            parent = MerkleTree.parent(left, left)
        } else {
            guard let right = hash(level: level - 1, offset: rightOffset) else {
                return nil
            }
            parent = MerkleTree.parent(left, right)
        }
        derived[node] = parent
        return parent
    }
}
