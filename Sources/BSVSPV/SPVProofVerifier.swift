import BSVCore
import BSVTransaction

/// Transport-independent SPV proof checks backed by caller-owned chain state.
public enum SPVProofVerifier {
    /// Verifies one transaction inclusion proof against a trusted chain tracker.
    public static func verify(
        _ merklePath: MerklePath,
        transactionID: TransactionID,
        using chainTracker: any ChainTracker
    ) async throws -> Bool {
        try await merklePath.verify(
            transactionID: transactionID,
            using: chainTracker
        )
    }

    /// Verifies BEEF dependency closure and all supplied Merkle roots.
    ///
    /// This proof-stage API does not execute Bitcoin scripts. Full BRC-67
    /// validation composes this result with interpreter, fee, and lock checks.
    public static func verify(
        _ beef: BEEF,
        using chainTracker: any ChainTracker,
        allowTransactionIDOnly: Bool,
        limits: TransactionLimits
    ) async throws -> Bool {
        try await beef.verify(
            using: chainTracker,
            allowTransactionIDOnly: allowTransactionIDOnly,
            limits: limits
        )
    }
}
