/// Standard BEEF wire versions.
public enum BEEFVersion: UInt32, CaseIterable, Hashable, Sendable {
    /// BRC-62: raw transaction followed by a BUMP-presence byte.
    case v1 = 4_022_206_465

    /// BRC-96: transaction data format precedes raw transaction or txid data.
    case v2 = 4_022_206_466
}

/// The three BRC-96 transaction representations.
public enum BEEFTransactionFormat: UInt8, CaseIterable, Hashable, Sendable {
    case rawTransaction = 0
    case rawTransactionWithMerklePath = 1
    case transactionIDOnly = 2
}
