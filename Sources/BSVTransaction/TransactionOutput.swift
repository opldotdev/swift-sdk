import BSVScript

/// One satoshi amount and its locking script.
public struct TransactionOutput: Hashable, Sendable {
    public var satoshis: UInt64
    public var lockingScript: Script

    /// Marks an output whose value should be assigned by a fee calculation.
    ///
    /// This construction marker is not serialized and does not participate in
    /// equality or hashing.
    public var isChange: Bool

    public init(satoshis: UInt64, lockingScript: Script, isChange: Bool = false) {
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.isChange = isChange
    }

    public static func == (lhs: TransactionOutput, rhs: TransactionOutput) -> Bool {
        lhs.satoshis == rhs.satoshis && lhs.lockingScript == rhs.lockingScript
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(satoshis)
        hasher.combine(lockingScript)
    }
}
