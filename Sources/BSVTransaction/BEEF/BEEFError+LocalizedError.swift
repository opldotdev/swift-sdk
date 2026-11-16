import BSVCore
import Foundation

/// Plain sentences a wallet can show when BEEF cannot be read or built.
///
/// The cases stay typed for callers that branch on them, and `String(reflecting:)` still names
/// the case and its transaction IDs for a log. These descriptions replace Foundation's fallback,
/// which names the enum and its case number (for example "BSVTransaction.BEEFError error 15").
///
/// They say what is wrong with the data and not where it came from, because the same bytes can
/// come from wallet storage, a peer, or an overlay. None of them suggests trying again: each
/// describes the bytes as they are, and reading the same bytes again gives the same answer.
extension BEEFError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingSubjectTransaction, .missingAncestor:
            "The transaction data is incomplete: a transaction it depends on is missing."
        case .parentAfterChild:
            "The transaction data lists a transaction before a transaction it spends."
        case .cyclicDependency:
            "The transaction data has transactions that spend each other in a loop."
        case .unrelatedTransaction, .unrelatedMerklePath:
            "The transaction data includes records unrelated to the transaction it proves."
        case .duplicateTransactionID, .conflictingTransactionData:
            "The transaction data lists the same transaction more than once."
        case .merklePathDoesNotProveTransaction, .conflictingMerkleRoot:
            "The transaction data has a proof that does not match its transactions."
        case .envelopeTooLarge, .merklePathCountExceedsLimit, .transactionCountExceedsLimit,
            .countNotRepresentable, .serializedSizeOverflow:
            "The transaction data is larger than the wallet can handle."
        case .invalidMaximumByteCount, .invalidMaximumMerklePathCount,
            .invalidMaximumTransactionCount:
            "The transaction data size limits are not valid."
        case .invalidVersion, .invalidAtomicPrefix, .invalidTransactionFormat,
            .transactionIDOnlyRequiresVersion2, .merklePathIndexOutOfRange, .malformed,
            .invalidTransaction, .invalidMerklePath, .invalidHex:
            "The transaction data could not be read."
        }
    }
}

/// The case with its values, for logs. Transaction IDs print as display hex, the form block
/// explorers and `@bsv/sdk` use, rather than as their raw byte storage.
extension BEEFError: CustomDebugStringConvertible {
    public var debugDescription: String {
        let mirror = Mirror(reflecting: self)
        guard let payload = mirror.children.first, let name = payload.label else {
            return "BEEFError"
        }
        let values = Mirror(reflecting: payload.value).children
        let fields: [String]
        if values.isEmpty || payload.value is TransactionID {
            fields = [Self.logValue(payload.value)]
        } else {
            fields = values.map { child in
                let value = Self.logValue(child.value)
                guard let label = child.label, !label.hasPrefix(".") else { return value }
                return "\(label): \(value)"
            }
        }
        return "BEEFError.\(name)(\(fields.joined(separator: ", ")))"
    }

    private static func logValue(_ value: Any) -> String {
        if let transactionID = value as? TransactionID { return transactionID.displayHex }
        return String(reflecting: value)
    }
}
