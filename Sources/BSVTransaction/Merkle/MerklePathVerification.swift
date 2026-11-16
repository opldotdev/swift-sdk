import BSVCore

extension MerklePath {
    /// Blocks a coinbase must be buried under before its outputs can be spent.
    static let coinbaseMaturity: UInt64 = 100

    /// Verifies this path's computed root against a trusted chain tracker.
    ///
    /// A transaction at offset zero is its block's coinbase. Matching
    /// @bsv/sdk `MerklePath.verify`, its proof verifies only once the
    /// tracker's current height is at least `blockHeight + 100`; before then
    /// this returns `false` without asking the tracker about the root.
    public func verify(
        transactionID: TransactionID,
        using chainTracker: any ChainTracker
    ) async throws -> Bool {
        let computedRoot = try root(for: transactionID)
        let target = try Hash256(transactionID.wireBytes)
        if levels[0].first(where: { $0.hash == target })?.offset == 0 {
            let currentHeight = try await chainTracker.currentHeight()
            guard UInt64(blockHeight) + Self.coinbaseMaturity <= UInt64(currentHeight) else {
                return false
            }
        }
        return try await chainTracker.isValidRoot(
            computedRoot,
            atBlockHeight: blockHeight
        )
    }
}
