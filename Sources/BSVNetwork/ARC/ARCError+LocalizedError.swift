import Foundation

/// Plain sentences a wallet can show when ARC refuses a transaction or its answer is unclear.
/// `String(reflecting:)` still gives the case with ARC's full response for a log.
extension ARCError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .rejected(_, let response):
            Self.sentence("ARC rejected the transaction", response.shortReason)
        case .providerFailure(let httpStatusCode, let response):
            Self.sentence(
                "ARC did not accept the transaction (HTTP \(httpStatusCode))",
                response.shortReason
            )
        case .uncertainDelivery(_, let cause):
            "The transaction may have reached ARC, but \(cause.plainWords). "
                + "Check its status before sending it again."
        }
    }

    private static func sentence(_ lead: String, _ reason: String?) -> String {
        guard let reason else { return lead + "." }
        return reason.hasSuffix(".") ? "\(lead): \(reason)" : "\(lead): \(reason)."
    }
}

extension ARCUncertainDeliveryCause {
    /// What went wrong, to follow "The transaction may have reached ARC, but".
    var plainWords: String {
        switch self {
        case .cancelled:
            "the request was cancelled before ARC answered"
        case .timedOut:
            "ARC did not answer in time"
        case .transport:
            "the connection failed before ARC answered"
        case .redirect(let statusCode):
            "ARC tried to send the request elsewhere (HTTP \(statusCode))"
        case .responseBodyTooLarge:
            "ARC sent a larger answer than the wallet accepts"
        case .providerResponse(let httpStatusCode, _):
            "ARC answered with HTTP \(httpStatusCode) and no clear result"
        case .invalidResponse:
            "ARC's answer could not be read"
        }
    }
}

extension ARCResponse {
    /// ARC's own short reason: the status with `extraInfo` ("REJECTED arc error 461: ..."),
    /// else `detail` or `title`. One line, at most 120 characters.
    var shortReason: String? {
        let status = txStatus?.rawValue
        let extra = extraInfo.flatMap(oneLineProviderReason)
        if let extra {
            return oneLineProviderReason([status, extra].compactMap { $0 }.joined(separator: " "))
        }
        return detail.flatMap(oneLineProviderReason) ?? title.flatMap(oneLineProviderReason)
    }
}
