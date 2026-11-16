import BSVCore
import Foundation

/// The network log: `BSVLog` category `BSVNetwork`, written to `os.Logger` on
/// Apple platforms and to the caller's `BSVLog` handler on every platform.
///
/// A line names the call, the method, and the host and path. It never holds a query string,
/// a request header or a request body, because those can carry API keys and callback tokens.
/// Provider bodies go through `sanitizedProviderText` first, with the caller's secrets redacted.
package enum NetworkLog {
    package static let subsystem = BSVLog.subsystem
    package static let category = "BSVNetwork"

    package static func error(_ message: String) {
        BSVLog.error(category: category, message)
    }

    /// A response that arrived but could not be used: its status, the reason and the body.
    package static func failure(
        _ operation: String,
        request: HTTPRequest,
        statusCode: Int,
        body: Data,
        redacting secrets: [String] = [],
        reason: String? = nil
    ) {
        error(line(
            operation,
            request: request,
            statusCode: statusCode,
            body: body,
            redacting: secrets,
            reason: reason
        ))
    }

    /// A request that got no usable response: the underlying error and its type.
    package static func failure(
        _ operation: String,
        request: HTTPRequest,
        underlying: any Error
    ) {
        error(
            "\(operation): \(request.method.rawValue) \(location(request.url)) failed: "
                + "\(type(of: underlying)): \(String(reflecting: underlying))"
        )
    }

    package static func line(
        _ operation: String,
        request: HTTPRequest,
        statusCode: Int,
        body: Data,
        redacting secrets: [String] = [],
        reason: String? = nil
    ) -> String {
        let text = sanitizedProviderText(
            body,
            redacting: secrets,
            maximumUTF8ByteCount: 2_000
        ) ?? "(empty)"
        let why = reason.map { " (\($0))" } ?? ""
        return "\(operation): \(request.method.rawValue) \(location(request.url)) -> HTTP \(statusCode)\(why); "
            + "\(body.count) bytes: \(text)"
    }

    /// Host and path only; the query string is dropped.
    package static func location(_ url: URL) -> String {
        (url.host ?? "") + url.path
    }
}
