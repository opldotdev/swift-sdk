import BSVCore

/// A BRC-95 envelope containing one subject transaction and exactly its proof graph.
public struct AtomicBEEF: Hashable, Sendable {
    public static let prefix: UInt32 = 0x0101_0101

    public let subjectTransactionID: TransactionID
    public let beef: BEEF

    public init(
        subjectTransactionID: TransactionID,
        beef: BEEF,
        limits: BEEFLimits
    ) throws {
        try Self.validate(
            subjectTransactionID: subjectTransactionID,
            beef: beef,
            limits: limits
        )
        self.subjectTransactionID = subjectTransactionID
        self.beef = beef
    }

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
        let prefixOffset = cursor.position
        let prefix: UInt32
        do {
            prefix = try cursor.readUInt32LE()
        } catch let error as BinaryDecodingError {
            throw BEEFError.malformed(
                field: .atomicPrefix,
                offset: prefixOffset,
                cause: error
            )
        }
        guard prefix == Self.prefix else {
            throw BEEFError.invalidAtomicPrefix(prefix)
        }
        let subjectOffset = cursor.position
        let subjectBytes: [UInt8]
        do {
            subjectBytes = try cursor.read(count: 32)
        } catch let error as BinaryDecodingError {
            throw BEEFError.malformed(
                field: .atomicSubjectTransactionID,
                offset: subjectOffset,
                cause: error
            )
        }
        let subject = try TransactionID(wireBytes: subjectBytes)
        let nestedBytes: [UInt8]
        do {
            nestedBytes = try cursor.read(count: cursor.remaining)
        } catch let error as BinaryDecodingError {
            throw BEEFError.malformed(
                field: .version,
                offset: cursor.position,
                cause: error
            )
        }
        let nestedLimit = max(0, limits.maximumByteCount - 36)
        let nestedLimits = try BEEFLimits(
            maximumByteCount: nestedLimit,
            maximumMerklePathCount: limits.maximumMerklePathCount,
            maximumTransactionCount: limits.maximumTransactionCount,
            transactionLimits: limits.transactionLimits,
            merklePathLimits: limits.merklePathLimits
        )
        let beef = try BEEF(
            bytes: nestedBytes,
            limits: nestedLimits,
            compactSizeCanonicality: compactSizeCanonicality
        )
        try self.init(subjectTransactionID: subject, beef: beef, limits: limits)
    }

    public func serialized(limits: BEEFLimits) throws -> [UInt8] {
        try Self.validate(
            subjectTransactionID: subjectTransactionID,
            beef: beef,
            limits: limits
        )
        let nestedLimit = max(0, limits.maximumByteCount - 36)
        let nestedLimits = try BEEFLimits(
            maximumByteCount: nestedLimit,
            maximumMerklePathCount: limits.maximumMerklePathCount,
            maximumTransactionCount: limits.maximumTransactionCount,
            transactionLimits: limits.transactionLimits,
            merklePathLimits: limits.merklePathLimits
        )
        let nested = try beef.serialized(limits: nestedLimits)
        let byteCount = 36 + nested.count
        guard byteCount <= limits.maximumByteCount else {
            throw BEEFError.envelopeTooLarge(
                actual: byteCount,
                maximum: limits.maximumByteCount
            )
        }
        var writer = ByteWriter(capacity: byteCount)
        writer.writeUInt32LE(Self.prefix)
        writer.write(subjectTransactionID.wireBytes)
        writer.write(nested)
        return writer.bytes
    }

    public func hex(limits: BEEFLimits) throws -> String {
        Hex.encode(try serialized(limits: limits))
    }

    private static func validate(
        subjectTransactionID: TransactionID,
        beef: BEEF,
        limits: BEEFLimits
    ) throws {
        let entries = try beef.indexedEntries(limits: limits.transactionLimits)
        guard entries[subjectTransactionID] != nil else {
            throw BEEFError.missingSubjectTransaction(subjectTransactionID)
        }

        var relevant: Set<TransactionID> = []
        func visit(_ transactionID: TransactionID) throws {
            if relevant.contains(transactionID) { return }
            guard let entry = entries[transactionID] else {
                throw BEEFError.missingAncestor(
                    transaction: subjectTransactionID,
                    ancestor: transactionID
                )
            }
            relevant.insert(transactionID)
            if entry.format != .transactionIDOnly,
               !beef.isProven(transactionID, entry: entry),
               let transaction = entry.transaction
            {
                for input in transaction.inputs {
                    let parentID = input.previousOutput.transactionID
                    guard entries[parentID] != nil else {
                        throw BEEFError.missingAncestor(
                            transaction: transactionID,
                            ancestor: parentID
                        )
                    }
                    try visit(parentID)
                }
            }
        }
        try visit(subjectTransactionID)

        for transactionID in entries.keys where !relevant.contains(transactionID) {
            throw BEEFError.unrelatedTransaction(transactionID)
        }
        for (index, path) in beef.merklePaths.enumerated() {
            // A combined BUMP may legitimately contain additional marked
            // leaves from the same block. It is relevant when it proves at
            // least one transaction in the subject's ancestry, regardless of
            // whether that particular leaf carries the optional txid marker.
            guard relevant.contains(where: { BEEF.path(path, contains: $0) }) else {
                throw BEEFError.unrelatedMerklePath(index: index)
            }
        }
    }
}
