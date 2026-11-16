import Foundation

/// Plain sentences a wallet can show when a file host's offer is refused.
/// `String(reflecting:)` still gives the exact rule that failed for a log.
extension UHRPAdvertisementError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidPushDrop, .unexpectedFieldCount, .payloadTooLarge:
            "The file host's offer is not in the expected format."
        case .invalidHostIdentityKey:
            "The file host's offer does not name a valid host key."
        case .invalidHash:
            "The file host's offer does not name a valid file hash."
        case .invalidURL:
            "The file host's offer does not give a safe HTTPS address."
        case .invalidExpiryTime:
            "The file host's offer has an invalid expiry time."
        case .invalidFileSize:
            "The file host's offer has an invalid file size."
        case .invalidSignatureEncoding, .invalidSignature:
            "The file host's offer is not signed correctly."
        case .lockingKeyNotLinkedToHost:
            "The file host's offer was not made by the host it names."
        }
    }
}
