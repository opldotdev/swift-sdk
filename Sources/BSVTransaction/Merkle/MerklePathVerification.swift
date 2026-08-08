import BSVCore

extension MerklePath {
    /// Verifies this path's computed root against a trusted chain tracker.
    public func verify(
        transactionID: TransactionID,
        using chainTracker: any ChainTracker
    ) async throws -> Bool {
        let computedRoot = try root(for: transactionID)
        return try await chainTracker.isValidRoot(
            computedRoot,
            atBlockHeight: blockHeight
        )
    }
}
