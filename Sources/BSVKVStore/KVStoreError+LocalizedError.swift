import BSVWallet
import Foundation

/// Plain sentences a wallet can show when a key-value entry is refused.
/// `String(reflecting:)` still gives the case with its sizes and cause for a log.
extension KVStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidLimits, .sizeOverflow:
            "The key-value store is not set up correctly."
        case .emptyContext:
            "The key-value store name must not be empty."
        case .emptyKey:
            "The key must not be empty."
        case .emptyValue:
            "The value must not be empty."
        case .locatorByteCountExceedsLimit(let kind, _, _):
            kind == "context" ? "The key-value store name is too long." : "The key is too long."
        case .valueByteCountExceedsLimit:
            "The value is larger than the key-value store accepts."
        case .invalidTokenFieldCount, .invalidLockingScript:
            "The stored entry is not in the expected format."
        case .invalidSignatureEncoding, .invalidSignature:
            "The stored entry is not signed correctly."
        case .lockingKeyMismatch:
            "The stored entry does not belong to this wallet."
        case .invalidWalletLocator(.protocolNameTooShort(_, let minimum)):
            "The key-value store name must be at least \(minimum) characters long."
        case .invalidWalletLocator(.protocolNameTooLong(_, let maximum)):
            "The key-value store name must be at most \(maximum) characters long."
        case .invalidWalletLocator(.keyIDTooShort), .invalidWalletLocator(.keyIDTooLong):
            "The key is not a length the wallet accepts."
        case .invalidWalletLocator:
            "The key-value store name may use only letters, digits and single spaces, "
                + "and must not start with \"admin\"."
        }
    }
}
