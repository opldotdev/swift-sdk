import BSVCore
import BSVScript

/// The outpoint and output data required to construct and sign a spend.
public struct UnspentTransactionOutput: Hashable, Sendable {
    public let transactionID: TransactionID
    public let outputIndex: UInt32
    public let satoshis: UInt64
    public let lockingScript: Script

    public init(
        transactionID: TransactionID,
        outputIndex: UInt32,
        satoshis: UInt64,
        lockingScript: Script
    ) {
        self.transactionID = transactionID
        self.outputIndex = outputIndex
        self.satoshis = satoshis
        self.lockingScript = lockingScript
    }

    public var outpoint: Outpoint {
        Outpoint(transactionID: transactionID, outputIndex: outputIndex)
    }

    public var output: TransactionOutput {
        TransactionOutput(satoshis: satoshis, lockingScript: lockingScript)
    }
}
