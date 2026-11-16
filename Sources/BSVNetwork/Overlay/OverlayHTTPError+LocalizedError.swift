import Foundation

/// Plain sentences a wallet can show when an overlay call fails. `String(reflecting:)` still
/// gives the case with its status and the overlay's reason for a log.
extension OverlayHTTPError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            "The overlay connection is not set up correctly."
        case .invalidHost:
            "The overlay address is not a valid HTTPS address."
        case .invalidQuery:
            "The overlay question could not be sent: it is too large or not valid."
        case .malformedResponse:
            "The overlay sent an answer the wallet could not read."
        case .unsupportedContentType:
            "The overlay sent an answer in a format the wallet does not read."
        case .rejected(let statusCode, let message):
            NetworkServiceError.statusSentence(code: statusCode, message: message, service: "The overlay")
        case .resourceLimit:
            "The overlay answer is larger than the wallet accepts."
        case .transport:
            "The overlay could not be reached. Check your connection and try again."
        case .uncertainDelivery:
            "The transaction may have reached the overlay, but no answer came back. "
                + "Check its status before sending it again."
        }
    }
}
