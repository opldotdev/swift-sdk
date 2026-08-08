import BSVCore

extension BEEF {
    /// Verifies dependency closure and every supplied BUMP against trusted chain state.
    ///
    /// Script execution is deliberately outside this transaction-layer operation.
    /// Invalid dependency graphs return `false`; malformed or conflicting proofs
    /// and chain-tracker failures are thrown.
    public func verify(
        using chainTracker: any ChainTracker,
        allowTransactionIDOnly: Bool,
        limits: TransactionLimits
    ) async throws -> Bool {
        let validation = try validation(
            allowTransactionIDOnly: allowTransactionIDOnly,
            limits: limits
        )
        guard validation.isValid else { return false }

        let rootsByHeight = try merkleRootsByBlockHeight()

        for blockHeight in rootsByHeight.keys.sorted() {
            guard let root = rootsByHeight[blockHeight] else { continue }
            guard try await chainTracker.isValidRoot(
                root,
                atBlockHeight: blockHeight
            ) else {
                return false
            }
        }
        return true
    }
}
