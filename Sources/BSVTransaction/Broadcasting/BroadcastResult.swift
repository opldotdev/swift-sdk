import BSVCore

/// The result of submitting a transaction to a broadcaster.
public struct BroadcastResult: Hashable, Sendable {
    public let transactionID: TransactionID
    public let message: String?

    public init(transactionID: TransactionID, message: String? = nil) {
        self.transactionID = transactionID
        self.message = message
    }
}
