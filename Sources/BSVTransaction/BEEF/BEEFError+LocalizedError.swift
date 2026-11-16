import Foundation

/// Plain sentences a wallet can show when BEEF cannot be read or built.
///
/// The cases stay typed for callers that branch on them. These descriptions
/// replace Foundation's fallback, which names the enum and its case number
/// (for example "BSVTransaction.BEEFError error 15").
extension BEEFError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .parentAfterChild, .cyclicDependency, .missingSubjectTransaction,
            .missingAncestor, .unrelatedTransaction, .unrelatedMerklePath:
            "The wallet's transaction data came back incomplete or out of order. Try again."
        case .merklePathDoesNotProveTransaction, .conflictingMerkleRoot:
            "The wallet's transaction data has a proof that does not match its transactions."
        case .envelopeTooLarge, .merklePathCountExceedsLimit, .transactionCountExceedsLimit,
            .countNotRepresentable, .serializedSizeOverflow:
            "The transaction data is larger than the wallet can handle."
        case .invalidMaximumByteCount, .invalidMaximumMerklePathCount,
            .invalidMaximumTransactionCount:
            "The wallet's transaction size limits are not valid."
        case .invalidVersion, .invalidAtomicPrefix, .invalidTransactionFormat,
            .transactionIDOnlyRequiresVersion2, .merklePathIndexOutOfRange,
            .duplicateTransactionID, .conflictingTransactionData, .malformed,
            .invalidTransaction, .invalidMerklePath, .invalidHex:
            "The wallet received transaction data it could not read."
        }
    }
}
