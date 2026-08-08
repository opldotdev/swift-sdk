import BSVCore

/// An ordered, value-semantic BRC-62/BRC-96 BEEF envelope.
public struct BEEF: Hashable, Sendable {
    public let version: BEEFVersion
    public let merklePaths: [MerklePath]
    public let transactions: [BEEFTransaction]

    public init(
        version: BEEFVersion = .v2,
        merklePaths: [MerklePath],
        transactions: [BEEFTransaction],
        limits: BEEFLimits
    ) throws {
        guard UInt64(merklePaths.count) <= limits.maximumMerklePathCount else {
            throw BEEFError.merklePathCountExceedsLimit(
                actual: UInt64(merklePaths.count),
                maximum: limits.maximumMerklePathCount
            )
        }
        guard UInt64(transactions.count) <= limits.maximumTransactionCount else {
            throw BEEFError.transactionCountExceedsLimit(
                actual: UInt64(transactions.count),
                maximum: limits.maximumTransactionCount
            )
        }

        var positions: [TransactionID: Int] = [:]
        positions.reserveCapacity(transactions.count)
        for (index, entry) in transactions.enumerated() {
            if version == .v1, entry.format == .transactionIDOnly {
                throw BEEFError.transactionIDOnlyRequiresVersion2(transaction: index)
            }
            let transactionID = try entry.transactionID(limits: limits.transactionLimits)
            guard positions.updateValue(index, forKey: transactionID) == nil else {
                throw BEEFError.duplicateTransactionID(transactionID)
            }
            if let pathIndex = entry.merklePathIndex {
                guard pathIndex >= 0, pathIndex < merklePaths.count else {
                    throw BEEFError.merklePathIndexOutOfRange(
                        transaction: index,
                        index: pathIndex < 0 ? .max : UInt64(pathIndex),
                        count: merklePaths.count
                    )
                }
                guard Self.path(merklePaths[pathIndex], contains: transactionID) else {
                    throw BEEFError.merklePathDoesNotProveTransaction(
                        transaction: index,
                        index: pathIndex
                    )
                }
            }
        }

        for (childIndex, entry) in transactions.enumerated() {
            guard let transaction = entry.transaction else { continue }
            let childID = try entry.transactionID(limits: limits.transactionLimits)
            for input in transaction.inputs {
                let parentID = input.previousOutput.transactionID
                if let parentIndex = positions[parentID], parentIndex >= childIndex {
                    throw BEEFError.parentAfterChild(parent: parentID, child: childID)
                }
            }
        }

        self.version = version
        self.merklePaths = merklePaths
        self.transactions = transactions
    }

    /// Parses exactly one bounded standard BEEF envelope.
    public init(
        bytes: [UInt8],
        limits: BEEFLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        guard bytes.count <= limits.maximumByteCount else {
            throw BEEFError.envelopeTooLarge(
                actual: bytes.count,
                maximum: limits.maximumByteCount
            )
        }
        var cursor = ByteCursor(bytes)
        let versionValue = try Self.read(.version, from: &cursor) {
            try $0.readUInt32LE()
        }
        guard let version = BEEFVersion(rawValue: versionValue) else {
            throw BEEFError.invalidVersion(versionValue)
        }

        let pathCount = try Self.read(.merklePathCount, from: &cursor) {
            try $0.readCompactSize(canonicality: compactSizeCanonicality).value
        }
        guard pathCount <= limits.maximumMerklePathCount else {
            throw BEEFError.merklePathCountExceedsLimit(
                actual: pathCount,
                maximum: limits.maximumMerklePathCount
            )
        }
        guard pathCount <= UInt64(Int.max) else {
            throw BEEFError.countNotRepresentable(pathCount)
        }
        var paths: [MerklePath] = []
        paths.reserveCapacity(min(Int(pathCount), cursor.remaining / 5))
        for index in 0..<Int(pathCount) {
            do {
                paths.append(try MerklePath(
                    consuming: &cursor,
                    limits: limits.merklePathLimits,
                    compactSizeCanonicality: compactSizeCanonicality
                ))
            } catch let error as MerklePathError {
                throw BEEFError.invalidMerklePath(index: index, cause: error)
            }
        }

        let transactionCount = try Self.read(.transactionCount, from: &cursor) {
            try $0.readCompactSize(canonicality: compactSizeCanonicality).value
        }
        guard transactionCount <= limits.maximumTransactionCount else {
            throw BEEFError.transactionCountExceedsLimit(
                actual: transactionCount,
                maximum: limits.maximumTransactionCount
            )
        }
        guard transactionCount <= UInt64(Int.max) else {
            throw BEEFError.countNotRepresentable(transactionCount)
        }

        var entries: [BEEFTransaction] = []
        entries.reserveCapacity(min(Int(transactionCount), cursor.remaining / 11))
        for index in 0..<Int(transactionCount) {
            switch version {
            case .v1:
                let transaction = try Self.readTransaction(
                    index: index,
                    cursor: &cursor,
                    limits: limits,
                    canonicality: compactSizeCanonicality
                )
                let hasPath = try Self.read(.transactionFormat(index: index), from: &cursor) {
                    try $0.read(count: 1)[0]
                }
                switch hasPath {
                case 0:
                    entries.append(.raw(transaction))
                case 1:
                    let pathIndex = try Self.readPathIndex(
                        transaction: index,
                        cursor: &cursor,
                        pathCount: paths.count,
                        canonicality: compactSizeCanonicality
                    )
                    entries.append(.rawWithMerklePath(
                        transaction: transaction,
                        merklePathIndex: pathIndex
                    ))
                default:
                    throw BEEFError.invalidTransactionFormat(
                        transaction: index,
                        format: hasPath
                    )
                }
            case .v2:
                let formatValue = try Self.read(
                    .transactionFormat(index: index),
                    from: &cursor
                ) {
                    try $0.read(count: 1)[0]
                }
                guard let format = BEEFTransactionFormat(rawValue: formatValue) else {
                    throw BEEFError.invalidTransactionFormat(
                        transaction: index,
                        format: formatValue
                    )
                }
                switch format {
                case .rawTransaction:
                    entries.append(.raw(try Self.readTransaction(
                        index: index,
                        cursor: &cursor,
                        limits: limits,
                        canonicality: compactSizeCanonicality
                    )))
                case .rawTransactionWithMerklePath:
                    let pathIndex = try Self.readPathIndex(
                        transaction: index,
                        cursor: &cursor,
                        pathCount: paths.count,
                        canonicality: compactSizeCanonicality
                    )
                    entries.append(.rawWithMerklePath(
                        transaction: try Self.readTransaction(
                            index: index,
                            cursor: &cursor,
                            limits: limits,
                            canonicality: compactSizeCanonicality
                        ),
                        merklePathIndex: pathIndex
                    ))
                case .transactionIDOnly:
                    let transactionIDBytes = try Self.read(
                        .transactionID(index: index),
                        from: &cursor
                    ) {
                        try $0.read(count: 32)
                    }
                    entries.append(.transactionID(
                        try TransactionID(wireBytes: transactionIDBytes)
                    ))
                }
            }
        }

        do {
            try cursor.requireFinished()
        } catch let error as BinaryDecodingError {
            throw BEEFError.malformed(
                field: .trailingBytes,
                offset: cursor.position,
                cause: error
            )
        }
        try self.init(
            version: version,
            merklePaths: paths,
            transactions: entries,
            limits: limits
        )
    }

    /// Parses lowercase or uppercase hexadecimal within the envelope byte limit.
    public init(
        hex: String,
        limits: BEEFLimits,
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
                bytes: Hex.decode(hex, maximumDecodedByteCount: limits.maximumByteCount),
                limits: limits,
                compactSizeCanonicality: compactSizeCanonicality
            )
        } catch let error as TextEncodingError {
            throw BEEFError.invalidHex(error)
        }
    }

    /// Emits canonical CompactSize values while preserving required graph order.
    public func serialized(limits: BEEFLimits) throws -> [UInt8] {
        _ = try BEEF(
            version: version,
            merklePaths: merklePaths,
            transactions: transactions,
            limits: limits
        )

        let pathBytes = try merklePaths.enumerated().map { index, path in
            do {
                return try path.serialized(limits: limits.merklePathLimits)
            } catch let error as MerklePathError {
                throw BEEFError.invalidMerklePath(index: index, cause: error)
            }
        }
        let transactionBytes = try transactions.enumerated().map { index, entry in
            try Self.serialize(
                entry,
                index: index,
                version: version,
                limits: limits
            )
        }

        var byteCount = 4
        try Self.add(CompactSize.encodedLength(of: UInt64(pathBytes.count)), to: &byteCount)
        for bytes in pathBytes { try Self.add(bytes.count, to: &byteCount) }
        try Self.add(
            CompactSize.encodedLength(of: UInt64(transactionBytes.count)),
            to: &byteCount
        )
        for bytes in transactionBytes { try Self.add(bytes.count, to: &byteCount) }
        guard byteCount <= limits.maximumByteCount else {
            throw BEEFError.envelopeTooLarge(
                actual: byteCount,
                maximum: limits.maximumByteCount
            )
        }

        var writer = ByteWriter(capacity: byteCount)
        writer.writeUInt32LE(version.rawValue)
        writer.writeCompactSize(UInt64(pathBytes.count))
        for bytes in pathBytes { writer.write(bytes) }
        writer.writeCompactSize(UInt64(transactionBytes.count))
        for bytes in transactionBytes { writer.write(bytes) }
        return writer.bytes
    }

    public func hex(limits: BEEFLimits) throws -> String {
        Hex.encode(try serialized(limits: limits))
    }

    public func entry(
        for transactionID: TransactionID,
        limits: TransactionLimits
    ) throws -> BEEFTransaction? {
        for entry in transactions where try entry.transactionID(limits: limits) == transactionID {
            return entry
        }
        return nil
    }

    public func transaction(
        for transactionID: TransactionID,
        limits: TransactionLimits
    ) throws -> Transaction? {
        try entry(for: transactionID, limits: limits)?.transaction
    }

    public func merklePath(for transactionID: TransactionID) -> MerklePath? {
        merklePaths.first(where: { Self.path($0, contains: transactionID) })
    }

    package func indexedEntries(
        limits: TransactionLimits
    ) throws -> [TransactionID: BEEFTransaction] {
        try Dictionary(uniqueKeysWithValues: transactions.map {
            (try $0.transactionID(limits: limits), $0)
        })
    }

    package func isProven(
        _ transactionID: TransactionID,
        entry: BEEFTransaction
    ) -> Bool {
        if let index = entry.merklePathIndex,
           index >= 0,
           index < merklePaths.count,
           Self.path(merklePaths[index], contains: transactionID)
        {
            return true
        }
        return merklePaths.contains(where: { Self.path($0, contains: transactionID) })
    }

    package static func path(_ path: MerklePath, contains transactionID: TransactionID) -> Bool {
        guard let hash = try? Hash256(transactionID.wireBytes) else { return false }
        return path.levels[0].contains(where: { $0.hash == hash })
    }

    package static func markedTransactionIDs(in path: MerklePath) -> [TransactionID] {
        path.levels[0].compactMap { element in
            guard element.isTransactionID, let hash = element.hash else { return nil }
            return TransactionID(exactDigestBytesGuaranteed: hash.bytes)
        }
    }

    private static func readTransaction(
        index: Int,
        cursor: inout ByteCursor,
        limits: BEEFLimits,
        canonicality: CompactSizeCanonicality
    ) throws -> Transaction {
        do {
            return try Transaction(
                consuming: &cursor,
                limits: limits.transactionLimits,
                compactSizeCanonicality: canonicality
            )
        } catch let error as TransactionError {
            throw BEEFError.invalidTransaction(index: index, cause: error)
        }
    }

    private static func readPathIndex(
        transaction: Int,
        cursor: inout ByteCursor,
        pathCount: Int,
        canonicality: CompactSizeCanonicality
    ) throws -> Int {
        let value = try read(.merklePathIndex(transaction: transaction), from: &cursor) {
            try $0.readCompactSize(canonicality: canonicality).value
        }
        guard value < UInt64(pathCount) else {
            throw BEEFError.merklePathIndexOutOfRange(
                transaction: transaction,
                index: value,
                count: pathCount
            )
        }
        return Int(value)
    }

    private static func serialize(
        _ entry: BEEFTransaction,
        index: Int,
        version: BEEFVersion,
        limits: BEEFLimits
    ) throws -> [UInt8] {
        let rawBytes: [UInt8]
        switch entry {
        case .raw(let transaction), .rawWithMerklePath(let transaction, _):
            do {
                rawBytes = try transaction.serialized(limits: limits.transactionLimits)
            } catch let error as TransactionError {
                throw BEEFError.invalidTransaction(index: index, cause: error)
            }
        case .transactionID:
            rawBytes = []
        }

        var writer = ByteWriter()
        switch (version, entry) {
        case (.v1, .raw):
            writer.write(rawBytes)
            writer.write([0])
        case (.v1, .rawWithMerklePath(_, let pathIndex)):
            writer.write(rawBytes)
            writer.write([1])
            writer.writeCompactSize(UInt64(pathIndex))
        case (.v1, .transactionID):
            throw BEEFError.transactionIDOnlyRequiresVersion2(transaction: index)
        case (.v2, .raw):
            writer.write([BEEFTransactionFormat.rawTransaction.rawValue])
            writer.write(rawBytes)
        case (.v2, .rawWithMerklePath(_, let pathIndex)):
            writer.write([BEEFTransactionFormat.rawTransactionWithMerklePath.rawValue])
            writer.writeCompactSize(UInt64(pathIndex))
            writer.write(rawBytes)
        case (.v2, .transactionID(let transactionID)):
            writer.write([BEEFTransactionFormat.transactionIDOnly.rawValue])
            writer.write(transactionID.wireBytes)
        }
        return writer.bytes
    }

    private static func read<T>(
        _ field: BEEFField,
        from cursor: inout ByteCursor,
        _ operation: (inout ByteCursor) throws -> T
    ) throws -> T {
        let offset = cursor.position
        do {
            return try operation(&cursor)
        } catch let error as BinaryDecodingError {
            throw BEEFError.malformed(field: field, offset: offset, cause: error)
        }
    }

    private static func add(_ value: Int, to total: inout Int) throws {
        let (sum, overflow) = total.addingReportingOverflow(value)
        guard !overflow else { throw BEEFError.serializedSizeOverflow }
        total = sum
    }
}
