import Foundation

/// Plain sentences an app can show when an authenticated HTTP request or
/// response cannot be built or read. They hold whether the app is the client
/// or the server.
///
/// The cases stay typed for callers that branch on them, and
/// `String(reflecting:)` still gives the case for a log. When a framing error
/// stands for a more detailed one, the detail is written to `AuthLog`.
extension BRC104Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidRequestID:
            "The response does not belong to this request."
        case .invalidMethod:
            "The request method is not one that authenticated HTTP allows."
        case .invalidPath:
            "The request address is not valid or is too long."
        case .invalidStatus:
            "The response status is not one that authenticated HTTP allows."
        case .invalidHeader, .duplicateHeader:
            "The request or response has a header that is not valid."
        case .headerNotPermitted:
            "The request or response has a header that cannot be signed."
        case .resourceLimit:
            "The request or response is too large."
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
            "The request or response is not one that authenticated HTTP allows."
        case .invalidAuthenticationHeader, .duplicateAuthenticationHeader,
            .unknownAuthenticationHeader:
            "The authentication headers are not valid."
        case .missingAuthenticationHeader:
            "The request or response is missing authentication headers."
        case .certificateExchangeUnavailable:
            "Certificates cannot be sent with an HTTP request or response."
        case .requestIDMismatch:
            "The response does not belong to this request."
        case .resourceLimit:
            "The request or response is too large."
        }
    }
}
