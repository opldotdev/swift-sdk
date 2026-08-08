import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import BSVNetwork
import Testing

@Suite("Bounded URLSession HTTP transport", .serialized)
struct URLSessionHTTPTransportTests {
    @Test("accepts a response exactly at the body limit")
    func exactBodyLimit() async throws {
        MockURLProtocol.configure(.response(
            status: 200,
            headers: ["Content-Length": "8"],
            chunks: [Data("1234".utf8), Data("5678".utf8)]
        ))
        let response = try await transport().send(request, maximumResponseBodyByteCount: 8)
        #expect(response.statusCode == 200)
        #expect(response.body == Data("12345678".utf8))
    }

    @Test("rejects declared body overflow before receiving the body")
    func declaredBodyOverflow() async throws {
        MockURLProtocol.configure(.response(
            status: 200,
            headers: ["Content-Length": "9"],
            chunks: [Data("123456789".utf8)]
        ))
        await #expect(throws: NetworkServiceError.responseBodyTooLarge(
            maximumByteCount: 8
        )) {
            try await transport().send(request, maximumResponseBodyByteCount: 8)
        }
        await expectProtocolStopWhenObservable()
    }

    @Test("rejects chunked body overflow as soon as limit plus one arrives")
    func chunkedBodyOverflow() async throws {
        MockURLProtocol.configure(.response(
            status: 200,
            headers: [:],
            chunks: [Data("12345678".utf8), Data("9".utf8), Data(repeating: 0x61, count: 64)]
        ))
        await #expect(throws: NetworkServiceError.responseBodyTooLarge(
            maximumByteCount: 8
        )) {
            try await transport().send(request, maximumResponseBodyByteCount: 8)
        }
        await expectProtocolStopWhenObservable()
    }

    @Test("rejects redirects without following the target")
    func redirect() async throws {
#if os(Linux)
        // swift-corelibs-foundation traps if a custom URLProtocol invokes the
        // redirect callback directly. A delivered 3xx response exercises the
        // transport's equivalent fail-closed response path without entering
        // that unsupported test-harness path.
        MockURLProtocol.configure(.response(
            status: 307,
            headers: ["Location": "https://redirect.invalid/target"],
            chunks: []
        ))
#else
        MockURLProtocol.configure(.redirect(status: 307))
#endif
        await #expect(throws: NetworkServiceError.redirect(statusCode: 307)) {
            try await transport().send(request, maximumResponseBodyByteCount: 8)
        }
        #expect(MockURLProtocol.requestCount == 1)
    }

    @Test("normalizes non-HTTP responses")
    func nonHTTPResponse() async throws {
        MockURLProtocol.configure(.nonHTTP)
        await #expect(throws: NetworkServiceError.nonHTTPResponse) {
            try await transport().send(request, maximumResponseBodyByteCount: 8)
        }
    }

    @Test("normalizes timeout and transport error codes", arguments: [
        URLError.Code.timedOut, URLError.Code.networkConnectionLost,
    ])
    func normalizedErrors(_ code: URLError.Code) async throws {
        MockURLProtocol.configure(.failure(code))
        do {
            _ = try await transport().send(request, maximumResponseBodyByteCount: 8)
            Issue.record("Expected a normalized URL error")
        } catch let error as NetworkServiceError {
            if code == .timedOut {
                #expect(error == .timedOut)
            } else {
                #expect(error == .transport(code: code.rawValue))
            }
        }
    }

    @Test("cancelling the caller immediately cancels URL loading")
    func cancellation() async throws {
        MockURLProtocol.configure(.stall)
        let operation = Task {
            try await transport().send(request, maximumResponseBodyByteCount: 8)
        }
        while MockURLProtocol.requestCount == 0 {
            await Task.yield()
        }
        operation.cancel()
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: NetworkServiceError.cancelled) {
            try await operation.value
        }
        #expect(start.duration(to: clock.now) < .seconds(1))
        await expectProtocolStopWhenObservable()
    }

    private var request: HTTPRequest {
        HTTPRequest(method: .get, url: URL(string: "https://mock.invalid/resource")!)
    }

    private func transport() -> URLSessionHTTPTransport {
        URLSessionHTTPTransport(
            requestTimeout: .seconds(1),
            resourceTimeout: .seconds(2)
        ) {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.protocolClasses = [MockURLProtocol.self]
            return configuration
        }
    }

    private func waitForProtocolStop() async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(1))
        while !MockURLProtocol.wasStopped, clock.now < deadline {
            await Task.yield()
        }
        return MockURLProtocol.wasStopped
    }

    private func expectProtocolStopWhenObservable() async {
#if os(Linux)
        // FoundationNetworking does not promise to invoke stopLoading() on a
        // custom URLProtocol after response-disposition or task cancellation.
        // The typed failure and single request remain the portable contract.
        #expect(MockURLProtocol.requestCount == 1)
#else
        #expect(await waitForProtocolStop())
#endif
    }
}

private enum MockURLResponseSpecification: Sendable {
    case response(status: Int, headers: [String: String], chunks: [Data])
    case redirect(status: Int)
    case nonHTTP
    case failure(URLError.Code)
    case stall
}

private final class MockURLProtocol: URLProtocol {
    private static let lock = NSLock()
    // Access to these process-wide test fixtures is serialized by `lock` and by
    // the suite's serialized trait.
    nonisolated(unsafe) private static var specification: MockURLResponseSpecification = .stall
    nonisolated(unsafe) private static var requests = 0
    nonisolated(unsafe) private static var stopped = false

    static var requestCount: Int {
        lock.withLock { requests }
    }

    static var wasStopped: Bool {
        lock.withLock { stopped }
    }

    static func configure(_ specification: MockURLResponseSpecification) {
        lock.withLock {
            self.specification = specification
            requests = 0
            stopped = false
        }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let specification = Self.lock.withLock {
            Self.requests += 1
            return Self.specification
        }
        guard let client else { return }

        switch specification {
        case .response(let status, let headers, let chunks):
            guard let response = HTTPURLResponse(
                url: request.url!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: headers
            ) else {
                client.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
                return
            }
            client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            for chunk in chunks {
                client.urlProtocol(self, didLoad: chunk)
            }
            client.urlProtocolDidFinishLoading(self)
        case .redirect(let status):
            let target = URL(string: "https://redirect.invalid/target")!
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Location": target.absoluteString]
            )!
            client.urlProtocol(
                self,
                wasRedirectedTo: URLRequest(url: target),
                redirectResponse: response
            )
        case .nonHTTP:
            client.urlProtocol(
                self,
                didReceive: URLResponse(
                    url: request.url!,
                    mimeType: nil,
                    expectedContentLength: 0,
                    textEncodingName: nil
                ),
                cacheStoragePolicy: .notAllowed
            )
            client.urlProtocolDidFinishLoading(self)
        case .failure(let code):
            client.urlProtocol(self, didFailWithError: URLError(code))
        case .stall:
            break
        }
    }

    override func stopLoading() {
        Self.lock.withLock {
            Self.stopped = true
        }
    }
}
