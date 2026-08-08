import BSVCore

/// A BEEF field being consumed when decoding failed.
public enum BEEFField: Equatable, Sendable {
    case atomicPrefix
    case atomicSubjectTransactionID
    case version
    case merklePathCount
    case merklePath(index: Int)
    case transactionCount
    case transactionFormat(index: Int)
    case merklePathIndex(transaction: Int)
    case transaction(index: Int)
    case transactionID(index: Int)
    case trailingBytes
}

/// Typed BEEF representation, graph, resource, and atomicity failures.
public enum BEEFError: Error, Equatable, Sendable {
    case invalidMaximumByteCount(Int)
    case invalidMaximumMerklePathCount(UInt64)
    case invalidMaximumTransactionCount(UInt64)
    case envelopeTooLarge(actual: Int, maximum: Int)
    case merklePathCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case transactionCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case countNotRepresentable(UInt64)
    case invalidVersion(UInt32)
    case invalidAtomicPrefix(UInt32)
    case invalidTransactionFormat(transaction: Int, format: UInt8)
    case transactionIDOnlyRequiresVersion2(transaction: Int)
    case merklePathIndexOutOfRange(transaction: Int, index: UInt64, count: Int)
    case merklePathDoesNotProveTransaction(transaction: Int, index: Int)
    case duplicateTransactionID(TransactionID)
    case parentAfterChild(parent: TransactionID, child: TransactionID)
    case missingSubjectTransaction(TransactionID)
    case missingAncestor(transaction: TransactionID, ancestor: TransactionID)
    case unrelatedTransaction(TransactionID)
    case unrelatedMerklePath(index: Int)
    case conflictingMerkleRoot(blockHeight: UInt32)
    case malformed(field: BEEFField, offset: Int, cause: BinaryDecodingError)
    case invalidTransaction(index: Int, cause: TransactionError)
    case invalidMerklePath(index: Int, cause: MerklePathError)
    case invalidHex(TextEncodingError)
    case serializedSizeOverflow
}
