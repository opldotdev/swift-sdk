import BSVScript

/// One transaction input and its optional source-output signing metadata.
public struct TransactionInput: Hashable, Sendable {
    public static let finalSequence: UInt32 = .max

    /// Maximum projected size of a compressed-key P2PKH unlocking script.
    ///
    /// libsecp256k1 produces low-S signatures, but R can require a DER sign
    /// padding byte. A 71-byte DER signature, hash-type byte, and compressed
    /// public-key push occupy at most 107 bytes in total.
    public static let payToPublicKeyHashUnlockingScriptByteCount = 107

    /// Maximum size of a canonical PushDrop unlocking script.
    ///
    /// A 71-byte DER signature, the hash-type byte, and the push operation use
    /// at most 73 bytes.
    public static let pushDropUnlockingScriptByteCount = 73

    public var previousOutput: Outpoint
    public var unlockingScript: Script
    public var sequence: UInt32

    /// The spent output when known. This metadata is not part of transaction
    /// wire bytes, equality, or hashing.
    public var sourceOutput: TransactionOutput?

    /// The projected unlocking-script size used before an input is signed.
    ///
    /// Fee models ignore this value once `unlockingScript` is nonempty. Like
    /// `sourceOutput`, it is construction metadata and does not participate in
    /// wire serialization, equality, or hashing.
    public var estimatedUnlockingScriptByteCount: Int?

    public init(
        previousOutput: Outpoint,
        unlockingScript: Script,
        sequence: UInt32 = TransactionInput.finalSequence,
        sourceOutput: TransactionOutput? = nil,
        estimatedUnlockingScriptByteCount: Int? = nil
    ) {
        self.previousOutput = previousOutput
        self.unlockingScript = unlockingScript
        self.sequence = sequence
        self.sourceOutput = sourceOutput
        self.estimatedUnlockingScriptByteCount = estimatedUnlockingScriptByteCount
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
