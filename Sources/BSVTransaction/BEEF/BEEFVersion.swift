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

/// How a BEEF reader treats the order of transaction records on the wire.
///
/// This SDK always writes parents before children. `Beef.toBinary()` in
/// `@bsv/sdk` does not when a transaction is not fully proven: `sortTxs()`
/// emits transactions with missing inputs first, then transactions that do not
/// chain to a proof, then txid-only records, then proven transactions and their
/// dependents. `Beef.fromBinary()` accepts any order and sorts before use.
public enum BEEFTransactionOrder: Hashable, Sendable {
    /// Parents must precede children. A child listed before one of its parents
    /// throws ``BEEFError/parentAfterChild(parent:child:)``.
    case parentsFirst

    /// Records may arrive in any order. They are reordered parents-first with a
    /// stable topological sort: records already in a valid order keep their
    /// order, and otherwise each record keeps its wire position relative to the
    /// records it does not depend on. Use this for BEEF written by another
    /// implementation, such as wallet storage or an overlay. Every other check
    /// still applies, and a dependency cycle throws
    /// ``BEEFError/cyclicDependency(_:)``.
    case any
}
