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
/// `@bsv/sdk` does not: `sortTxs()` emits transactions with missing inputs
/// first, then transactions that do not chain to a proof, then txid-only
/// records, then every proven transaction in the order it was merged, then the
/// transactions that depend on them. So a child that is not fully proven is
/// written ahead of its parents, and a proven child is written ahead of its
/// proven parent whenever the child was merged first, as happens when a graph
/// is assembled from one proof per output. The second is a complete, valid
/// graph. `Beef.fromBinary()` accepts any order and sorts before use.
public enum BEEFTransactionOrder: Hashable, Sendable {
    /// Parents must precede children. A child listed before one of its parents
    /// throws ``BEEFError/parentAfterChild(parent:child:)``.
    case parentsFirst

    /// Records may arrive in any order. They are reordered parents-first by a
    /// stable topological sort: at each step the next record is the
    /// earliest-listed one whose parents in the envelope are all placed.
    /// Records already parents-first keep their order. A record listed early
    /// waits for its parents and then comes straight after the last of them,
    /// ahead of later records it does not depend on: wire `[U, A, P, B]`, where
    /// `U` spends `P`, becomes `[A, P, U, B]`.
    ///
    /// Use this for BEEF written by another implementation, such as wallet
    /// storage, a peer or an overlay. Every other check still applies, and a
    /// dependency cycle throws ``BEEFError/cyclicDependency(_:)``.
    ///
    /// Transaction indexes in errors depend on when the error is found. One
    /// found while decoding a record, such as
    /// ``BEEFError/invalidTransaction(index:cause:)``, counts wire positions.
    /// One found by the graph checks after the reorder, such as
    /// ``BEEFError/merklePathDoesNotProveTransaction(transaction:index:)``,
    /// counts positions in the reordered list. Transaction IDs in errors are
    /// unaffected.
    case any
}
