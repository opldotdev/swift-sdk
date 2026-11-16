import Foundation

/// Plain sentences an app can show when an authenticated HTTP request or
/// response cannot be built or read.
///
/// The cases stay typed for callers that branch on them, and
/// `String(reflecting:)` still gives the case for a log.
extension BRC104Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidRequestID:
            "The response does not belong to this request."
        case .invalidMethod:
            "The request method is not one the server accepts."
        case .invalidPath:
            "The request address is not valid or is too long."
        case .invalidStatus:
            "The response status is not one an authenticated server may send."
        case .invalidHeader, .duplicateHeader:
            "The request or response has a header that is not valid."
        case .headerNotPermitted:
            "The request or response has a header that cannot be signed."
        case .resourceLimit:
            "The request or response is larger than the app can handle."
        case .malformedPayload, .trailingData:
            "The signed request or response could not be read."
        }
    }
}

/// Plain sentences for an authenticated HTTP message whose headers or framing
/// are not valid.
extension BRC104HTTPFramingError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidFrame:
            "The request or response is not one an authenticated server accepts."
        case .invalidAuthenticationHeader, .duplicateAuthenticationHeader,
            .unknownAuthenticationHeader:
            "The server's authentication headers are not valid."
        case .missingAuthenticationHeader:
            "The server's response is missing its authentication headers."
        case .certificateExchangeUnavailable:
            "The server asked for certificates in a way this app does not support."
        case .requestIDMismatch:
            "The response does not belong to this request."
        case .resourceLimit:
            "The request or response is larger than the app can handle."
        }
    }
}
