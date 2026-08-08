import BSVScript

/// One transaction input and its optional source-output signing metadata.
public struct TransactionInput: Hashable, Sendable {
    public static let finalSequence: UInt32 = .max

    public var previousOutput: Outpoint
    public var unlockingScript: Script
    public var sequence: UInt32

    /// The spent output when known. This metadata is not part of transaction
    /// wire bytes, equality, or hashing.
    public var sourceOutput: TransactionOutput?

    public init(
        previousOutput: Outpoint,
        unlockingScript: Script,
        sequence: UInt32 = TransactionInput.finalSequence,
        sourceOutput: TransactionOutput? = nil
    ) {
        self.previousOutput = previousOutput
        self.unlockingScript = unlockingScript
        self.sequence = sequence
        self.sourceOutput = sourceOutput
    }

    public static func == (lhs: TransactionInput, rhs: TransactionInput) -> Bool {
        lhs.previousOutput == rhs.previousOutput
            && lhs.unlockingScript == rhs.unlockingScript
            && lhs.sequence == rhs.sequence
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(previousOutput)
        hasher.combine(unlockingScript)
        hasher.combine(sequence)
    }
}
