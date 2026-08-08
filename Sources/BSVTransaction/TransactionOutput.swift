import BSVScript

/// One satoshi amount and its locking script.
public struct TransactionOutput: Hashable, Sendable {
    public var satoshis: UInt64
    public var lockingScript: Script

    public init(satoshis: UInt64, lockingScript: Script) {
        self.satoshis = satoshis
        self.lockingScript = lockingScript
    }
}
