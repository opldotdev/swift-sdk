import BSVCore

/// Supplies trusted chain state without coupling transactions to a transport.
public protocol ChainTracker: Sendable {
    /// Returns whether `root` is the accepted Merkle root at `blockHeight`.
    func isValidRoot(_ root: Hash256, atBlockHeight blockHeight: UInt32) async throws -> Bool

    /// Returns the tracker's current best-chain height.
    func currentHeight() async throws -> UInt32
}
