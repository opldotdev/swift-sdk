import BSVCore

/// One ordered transaction record in a BEEF envelope.
public enum BEEFTransaction: Hashable, Sendable {
    case raw(Transaction)
    case rawWithMerklePath(transaction: Transaction, merklePathIndex: Int)
    case transactionID(TransactionID)

    public var format: BEEFTransactionFormat {
        switch self {
        case .raw: .rawTransaction
        case .rawWithMerklePath: .rawTransactionWithMerklePath
        case .transactionID: .transactionIDOnly
        }
    }

    public var transaction: Transaction? {
        switch self {
        case .raw(let transaction), .rawWithMerklePath(let transaction, _): transaction
        case .transactionID: nil
        }
    }

    public var merklePathIndex: Int? {
        guard case .rawWithMerklePath(_, let index) = self else { return nil }
        return index
    }

    public func transactionID(limits: TransactionLimits) throws -> TransactionID {
        switch self {
        case .raw(let transaction), .rawWithMerklePath(let transaction, _):
            try transaction.transactionID(limits: limits)
        case .transactionID(let transactionID):
            transactionID
        }
    }
}
