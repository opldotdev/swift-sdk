/// A bounded, redacted failure produced by a network service.
public enum NetworkServiceError: Error, Equatable, Sendable {
    case invalidConfiguration
    case cancelled
    case timedOut
    case transport(code: Int?)
    case nonHTTPResponse
    case redirect(statusCode: Int)
    case responseBodyTooLarge(maximumByteCount: Int)
    case httpStatus(code: Int, message: String?)
    case malformedResponse
    case inconsistentResponse
}
