/// A transport-neutral service that submits transactions to the Bitcoin network.
///
/// A thrown cancellation or transport error does not prove that submission
/// failed: the remote provider may already have accepted the transaction.
/// Callers should reconcile uncertain outcomes by transaction ID rather than
/// automatically retrying a non-idempotent submission.
public protocol Broadcaster: Sendable {
    func broadcast(
        _ transaction: Transaction,
        limits: TransactionLimits
    ) async throws -> BroadcastResult
}

public extension Transaction {
    /// Submits this transaction through `broadcaster` using the caller's limits.
    func broadcast(
        using broadcaster: any Broadcaster,
        limits: TransactionLimits
    ) async throws -> BroadcastResult {
        try await broadcaster.broadcast(self, limits: limits)
    }
}
