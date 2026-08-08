import Foundation

package enum HTTPMethod: String, Sendable {
    case get = "GET"
    case post = "POST"
}

package struct HTTPRequest: Sendable {
    package let method: HTTPMethod
    package let url: URL
    package let headers: [String: String]
    package let body: Data?

    package init(
        method: HTTPMethod,
        url: URL,
        headers: [String: String] = [:],
        body: Data? = nil
    ) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

package struct HTTPResponse: Sendable {
    package let statusCode: Int
    package let headers: [String: String]
    package let body: Data

    package init(
        statusCode: Int,
        headers: [String: String] = [:],
        body: Data
    ) {
        self.statusCode = statusCode
        self.headers = headers
        self.body = body
    }

    package func headerValue(for name: String) -> String? {
        headers.first { key, _ in
            key.compare(name, options: .caseInsensitive) == .orderedSame
        }?.value
    }
}

package protocol HTTPTransport: Sendable {
    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse
}
