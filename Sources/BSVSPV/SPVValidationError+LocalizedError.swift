import BSVCore
import Foundation

/// Plain sentences a wallet can show when a received transaction fails verification.
///
/// They describe the transaction as it is; checking it again gives the same answer.
extension SPVValidationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .rootTransactionMissing:
            "The transaction data does not include the transaction it is meant to prove."
        case .rootTransactionIDOnly:
            "The transaction data names the transaction but does not include it."
        case .missingSourceTransaction(_, let inputIndex, _):
            "The transaction data is missing the transaction that input \(inputIndex) spends."
        case .sourceOutputIndexOutOfBounds(_, let inputIndex, _, let outputIndex, _):
            "Input \(inputIndex) spends output \(outputIndex), which does not exist."
        case .satoshiTotalOverflow:
            "The transaction amounts are too large to add up."
        case .outputsExceedInputs(_, let inputs, let outputs):
            "The transaction sends \(outputs) satoshis, but its inputs hold only \(inputs)."
        case .nonPositiveFee:
            "The transaction pays no fee."
        case .feeTooLow(let paid, let required):
            "The transaction fee is too low: it pays \(paid) satoshis and needs \(required)."
        case .scriptVerificationFailed(_, let inputIndex, _):
            "Input \(inputIndex) of the transaction is not validly signed."
        }
    }
}

/// The case with its values, for logs. Transaction IDs print as display hex, the form block
/// explorers use, rather than as their raw byte storage.
extension SPVValidationError: CustomDebugStringConvertible {
    public var debugDescription: String {
        let mirror = Mirror(reflecting: self)
        guard let payload = mirror.children.first, let name = payload.label else {
            return "SPVValidationError"
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
        return "SPVValidationError.\(name)(\(fields.joined(separator: ", ")))"
    }

    private static func logValue(_ value: Any) -> String {
        if let transactionID = value as? TransactionID { return transactionID.displayHex }
        return String(reflecting: value)
    }
}
