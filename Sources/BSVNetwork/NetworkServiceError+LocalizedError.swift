import Foundation

/// Plain sentences a wallet can show when a network call fails.
///
/// The error does not know which service it came from, so these say "the network service";
/// a caller that knows the service can put its name first. `String(reflecting:)` still gives
/// the case with its status and provider text for a log.
extension NetworkServiceError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            "The network service is not set up correctly."
        case .cancelled:
            "The network request was cancelled."
        case .timedOut:
            "The network service did not answer in time. Check your connection and try again."
        case .transport:
            "The network request could not be completed. Check your connection and try again."
        case .nonHTTPResponse:
            "The network service sent an answer that was not a web response."
        case .redirect(let statusCode):
            "The network service tried to send the request elsewhere (HTTP \(statusCode)), which the wallet does not follow."
        case .responseBodyTooLarge:
            "The network service sent a larger answer than the wallet accepts."
        case .httpStatus(let code, let message):
            Self.statusSentence(code: code, message: message)
        case .malformedResponse:
            "The network service sent an answer the wallet could not read."
        case .inconsistentResponse:
            "The network service sent an answer that does not match the request."
        }
    }

    /// "The network service refused the request (HTTP 400): reason." with a retry hint for
    /// 408, 429 and 5xx.
    static func statusSentence(code: Int, message: String?, service: String = "The network service") -> String {
        let retry = code == 408 || code == 429 || code >= 500
        var text = "\(service) \(retry ? "could not answer" : "refused the request") (HTTP \(code))"
        if let reason = message.flatMap(oneLineProviderReason) {
            text += ": \(reason)"
        }
        if !text.hasSuffix(".") { text += "." }
        if retry { text += " Try again in a minute." }
        return text
    }
}

/// The provider's short reason: a JSON `message`, `error`, `detail` or `title`, or else the
/// first line of plain text, trimmed to 120 characters. Nil for empty text, markup, or JSON
/// without one of those fields, so a body is never shown as a reason.
package func oneLineProviderReason(_ text: String) -> String? {
    let leading = text.trimmingCharacters(in: .whitespacesAndNewlines)
    if leading.hasPrefix("{") || leading.hasPrefix("[") {
        // A body that is not a JSON object has no field to read a reason from.
        guard let object = (try? JSONSerialization.jsonObject(with: Data(leading.utf8))) as? [String: Any] else {
            return nil
        }
        for key in ["message", "error", "detail", "title"] {
            if let value = object[key] as? String, let reason = oneLineProviderReason(value) {
                return reason
            }
        }
        return nil
    }
    let first = leading.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
    let trimmed = first.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty, !trimmed.hasPrefix("<") else { return nil }
    return trimmed.count > 120 ? String(trimmed.prefix(119)) + "…" : trimmed
}
