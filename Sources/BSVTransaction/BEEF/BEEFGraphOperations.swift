import BSVCore

extension BEEF {
    /// Returns the bounded union of two envelopes without mutating either input.
    ///
    /// BRC-96 is selected whenever either operand requires its superset format.
    /// Transactions are emitted in stable parent-before-child order, complete
    /// records replace transaction-ID-only placeholders, and merged BUMPs attach
    /// proofs to every raw transaction they contain.
    public func merging(_ other: BEEF, limits: BEEFLimits) throws -> BEEF {
        var paths: [MerklePath] = []
        var pathIndexByKey: [BEEFPathKey: Int] = [:]
        let leftPathMap = try Self.mergePaths(
            merklePaths,
            into: &paths,
            indexes: &pathIndexByKey
        )
        let rightPathMap = try Self.mergePaths(
            other.merklePaths,
            into: &paths,
            indexes: &pathIndexByKey
        )

        var entries: [TransactionID: BEEFTransaction] = [:]
        var firstSeen: [TransactionID] = []
        try Self.absorb(
            transactions,
            pathMap: leftPathMap,
            limits: limits.transactionLimits,
            entries: &entries,
            firstSeen: &firstSeen
        )
        try Self.absorb(
            other.transactions,
            pathMap: rightPathMap,
            limits: limits.transactionLimits,
            entries: &entries,
            firstSeen: &firstSeen
        )

        for transactionID in firstSeen {
            guard case .raw(let transaction)? = entries[transactionID],
                  let pathIndex = paths.firstIndex(where: {
                      Self.path($0, contains: transactionID)
                  })
            else { continue }
            entries[transactionID] = .rawWithMerklePath(
                transaction: transaction,
                merklePathIndex: pathIndex
            )
        }

        let ordered = try Self.topologicallyOrdered(
            entries: entries,
            firstSeen: firstSeen
        )
        let result = try BEEF(
            version: version == .v2 || other.version == .v2 ? .v2 : .v1,
            merklePaths: paths,
            transactions: ordered,
            limits: limits
        )
        _ = try result.serialized(limits: limits)
        return result
    }

    /// Projects every record to BRC-96 transaction-ID-only form.
    ///
    /// The result always uses v2 because v1 has no transaction-ID-only wire
    /// representation. Merkle paths are preserved for trusted-root checking.
    public func transactionIDOnly(limits: BEEFLimits) throws -> BEEF {
        let projected = try transactions.map {
            BEEFTransaction.transactionID(
                try $0.transactionID(limits: limits.transactionLimits)
            )
        }
        let result = try BEEF(
            version: .v2,
            merklePaths: merklePaths,
            transactions: projected,
            limits: limits
        )
        _ = try result.serialized(limits: limits)
        return result
    }

    /// Removes transaction-ID-only records already known by the receiver.
    ///
    /// Complete raw transactions are never removed. BUMPs that no longer prove
    /// or are referenced by a retained record are discarded and proof indexes
    /// are remapped atomically.
    public func trimmingKnownTransactionIDs(
        _ knownTransactionIDs: Set<TransactionID>,
        limits: BEEFLimits
    ) throws -> BEEF {
        let retained = transactions.filter { entry in
            guard case .transactionID(let transactionID) = entry else { return true }
            return !knownTransactionIDs.contains(transactionID)
        }
        let retainedIDs = try Set(retained.map {
            try $0.transactionID(limits: limits.transactionLimits)
        })
        var usedPathIndexes = Set<Int>()
        for entry in retained {
            if let pathIndex = entry.merklePathIndex {
                usedPathIndexes.insert(pathIndex)
            }
        }
        for (pathIndex, path) in merklePaths.enumerated()
            where retainedIDs.contains(where: { Self.path(path, contains: $0) })
        {
            usedPathIndexes.insert(pathIndex)
        }

        var pathMap: [Int: Int] = [:]
        var retainedPaths: [MerklePath] = []
        for (oldIndex, path) in merklePaths.enumerated() where usedPathIndexes.contains(oldIndex) {
            pathMap[oldIndex] = retainedPaths.count
            retainedPaths.append(path)
        }
        let remapped = retained.map { entry -> BEEFTransaction in
            guard case .rawWithMerklePath(let transaction, let oldIndex) = entry,
                  let newIndex = pathMap[oldIndex]
            else { return entry }
            return .rawWithMerklePath(
                transaction: transaction,
                merklePathIndex: newIndex
            )
        }
        let result = try BEEF(
            version: version,
            merklePaths: retainedPaths,
            transactions: remapped,
            limits: limits
        )
        _ = try result.serialized(limits: limits)
        return result
    }

    private static func mergePaths(
        _ incoming: [MerklePath],
        into merged: inout [MerklePath],
        indexes: inout [BEEFPathKey: Int]
    ) throws -> [Int: Int] {
        var mapping: [Int: Int] = [:]
        for (oldIndex, path) in incoming.enumerated() {
            let key = BEEFPathKey(
                blockHeight: path.blockHeight,
                root: try path.consistentRoot()
            )
            if let existingIndex = indexes[key] {
                merged[existingIndex] = try merged[existingIndex].merging(path)
                mapping[oldIndex] = existingIndex
            } else {
                let newIndex = merged.count
                merged.append(path)
                indexes[key] = newIndex
                mapping[oldIndex] = newIndex
            }
        }
        return mapping
    }

    private static func absorb(
        _ incoming: [BEEFTransaction],
        pathMap: [Int: Int],
        limits: TransactionLimits,
        entries: inout [TransactionID: BEEFTransaction],
        firstSeen: inout [TransactionID]
    ) throws {
        for entry in incoming {
            let remapped = Self.remap(entry, using: pathMap)
            let transactionID = try remapped.transactionID(limits: limits)
            if let existing = entries[transactionID] {
                entries[transactionID] = try Self.preferred(
                    existing,
                    over: remapped,
                    transactionID: transactionID
                )
            } else {
                entries[transactionID] = remapped
                firstSeen.append(transactionID)
            }
        }
    }

    private static func remap(
        _ entry: BEEFTransaction,
        using pathMap: [Int: Int]
    ) -> BEEFTransaction {
        guard case .rawWithMerklePath(let transaction, let oldIndex) = entry,
              let newIndex = pathMap[oldIndex]
        else { return entry }
        return .rawWithMerklePath(
            transaction: transaction,
            merklePathIndex: newIndex
        )
    }

    private static func preferred(
        _ existing: BEEFTransaction,
        over incoming: BEEFTransaction,
        transactionID: TransactionID
    ) throws -> BEEFTransaction {
        switch (existing.transaction, incoming.transaction) {
        case (nil, nil):
            return existing
        case (nil, .some):
            return incoming
        case (.some, nil):
            return existing
        case (.some(let left), .some(let right)):
            guard left == right else {
                throw BEEFError.conflictingTransactionData(transactionID)
            }
            if existing.merklePathIndex != nil { return existing }
            return incoming.merklePathIndex != nil ? incoming : existing
        }
    }

    private static func topologicallyOrdered(
        entries: [TransactionID: BEEFTransaction],
        firstSeen: [TransactionID]
    ) throws -> [BEEFTransaction] {
        let rank = Dictionary(uniqueKeysWithValues: firstSeen.enumerated().map { ($1, $0) })
        var indegree: [TransactionID: Int] = [:]
        var children: [TransactionID: [TransactionID]] = [:]
        for transactionID in firstSeen {
            guard let transaction = entries[transactionID]?.transaction else {
                indegree[transactionID] = 0
                continue
            }
            let parents = Set(transaction.inputs.map(\.previousOutput.transactionID))
                .intersection(entries.keys)
            indegree[transactionID] = parents.count
            for parent in parents {
                children[parent, default: []].append(transactionID)
            }
        }
        for parent in children.keys {
            children[parent]?.sort { rank[$0, default: .max] < rank[$1, default: .max] }
        }

        var ready = BEEFReadyHeap(rank: rank)
        for transactionID in firstSeen where indegree[transactionID] == 0 {
            ready.insert(transactionID)
        }
        var ordered: [BEEFTransaction] = []
        ordered.reserveCapacity(entries.count)
        while let transactionID = ready.removeFirst() {
            guard let entry = entries[transactionID] else { continue }
            ordered.append(entry)
            for child in children[transactionID, default: []] {
                let next = (indegree[child] ?? 0) - 1
                indegree[child] = next
                if next == 0 { ready.insert(child) }
            }
        }
        guard ordered.count == entries.count else {
            let cyclic = firstSeen.first(where: { (indegree[$0] ?? 0) > 0 })
                ?? firstSeen[0]
            throw BEEFError.cyclicDependency(cyclic)
        }
        return ordered
    }
}

private struct BEEFPathKey: Hashable {
    let blockHeight: UInt32
    let root: Hash256
}

private struct BEEFReadyHeap {
    private var values: [TransactionID] = []
    private let rank: [TransactionID: Int]

    init(rank: [TransactionID: Int]) {
        self.rank = rank
    }

    mutating func insert(_ value: TransactionID) {
        values.append(value)
        var index = values.count - 1
        while index > 0 {
            let parent = (index - 1) / 2
            guard isEarlier(values[index], than: values[parent]) else { break }
            values.swapAt(index, parent)
            index = parent
        }
    }

    mutating func removeFirst() -> TransactionID? {
        guard !values.isEmpty else { return nil }
        if values.count == 1 { return values.removeLast() }
        let first = values[0]
        values[0] = values.removeLast()
        var index = 0
        while true {
            let left = index * 2 + 1
            guard left < values.count else { break }
            let right = left + 1
            let child = right < values.count && isEarlier(values[right], than: values[left])
                ? right
                : left
            guard isEarlier(values[child], than: values[index]) else { break }
            values.swapAt(index, child)
            index = child
        }
        return first
    }

    private func isEarlier(_ left: TransactionID, than right: TransactionID) -> Bool {
        rank[left, default: .max] < rank[right, default: .max]
    }
}
