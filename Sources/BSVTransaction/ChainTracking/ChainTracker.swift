import BSVCore

/// Supplies trusted chain state without coupling transactions to a transport.
public protocol ChainTracker: Sendable {
    /// Returns whether `root` is the accepted Merkle root at `blockHeight`.
    func isValidRoot(_ root: Hash256, atBlockHeight blockHeight: UInt32) async throws -> Bool

    /// Returns the tracker's current best-chain height.
    ///
    /// This must be the real chain tip. `MerklePath.verify` and the full
    /// `SPVProofVerifier.verify(_:rootTransactionID:...)` use it for coinbase
    /// maturity: a proof at offset zero verifies only when this height is at
    /// least 100 above the proof's block. A placeholder height makes every
    /// coinbase proof fail (too low) or lets immature ones pass (too high).
    func currentHeight() async throws -> UInt32
}
