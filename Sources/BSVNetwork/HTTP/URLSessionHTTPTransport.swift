import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

package struct URLSessionHTTPTransport: HTTPTransport, Sendable {
    private let requestTimeout: TimeInterval
    private let resourceTimeout: TimeInterval
    private let configurationProvider: @Sendable () -> URLSessionConfiguration

    package init(requestTimeout: Duration, resourceTimeout: Duration) {
        self.requestTimeout = requestTimeout.networkTimeInterval
        self.resourceTimeout = resourceTimeout.networkTimeInterval
        self.configurationProvider = { URLSessionConfiguration.ephemeral }
    }

    package init(
        requestTimeout: Duration,
        resourceTimeout: Duration,
        configurationProvider: @escaping @Sendable () -> URLSessionConfiguration
    ) {
        self.requestTimeout = requestTimeout.networkTimeInterval
        self.resourceTimeout = resourceTimeout.networkTimeInterval
        self.configurationProvider = configurationProvider
    }

    package func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        guard maximumResponseBodyByteCount >= 0 else {
            throw NetworkServiceError.invalidConfiguration
        }

        let operation = URLSessionRequestOperation(
            requestTimeout: requestTimeout,
            resourceTimeout: resourceTimeout,
            maximumResponseBodyByteCount: maximumResponseBodyByteCount,
            configuration: configurationProvider()
        )
        return try await withTaskCancellationHandler {
            try await operation.execute(request)
        } onCancel: {
            operation.cancel()
        }
    }
}

// URLSession calls its delegate concurrently. Request lifecycle state is
// protected by `lock`; `configuration` is prepared before the session starts
// and is never mutated after delegate callbacks can begin.
private final class URLSessionRequestOperation: NSObject, @unchecked Sendable {
    private let lock = NSLock()
    private let requestTimeout: TimeInterval
    private let resourceTimeout: TimeInterval
    private let maximumResponseBodyByteCount: Int
    private let configuration: URLSessionConfiguration

    private var continuation: CheckedContinuation<HTTPResponse, any Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var responseStatusCode: Int?
    private var responseHeaders: [String: String] = [:]
    private var responseBody = Data()
    private var pendingError: NetworkServiceError?
    private var cancellationRequested = false

    init(
        requestTimeout: TimeInterval,
        resourceTimeout: TimeInterval,
        maximumResponseBodyByteCount: Int,
        configuration: URLSessionConfiguration
    ) {
        self.requestTimeout = requestTimeout
        self.resourceTimeout = resourceTimeout
        self.maximumResponseBodyByteCount = maximumResponseBodyByteCount
        self.configuration = configuration
    }

    func execute(_ request: HTTPRequest) async throws -> HTTPResponse {
        try await withCheckedThrowingContinuation { continuation in
            start(request, continuation: continuation)
        }
    }

    func cancel() {
        let taskToCancel = lock.withLock {
            cancellationRequested = true
            return task
        }
        taskToCancel?.cancel()
    }

    private func start(
        _ request: HTTPRequest,
        continuation: CheckedContinuation<HTTPResponse, any Error>
    ) {
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = resourceTimeout
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData

        let session = URLSession(
            configuration: configuration,
            delegate: self,
            delegateQueue: nil
        )
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        urlRequest.timeoutInterval = requestTimeout
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        urlRequest.httpBody = request.body
        let task = session.dataTask(with: urlRequest)

        let shouldStart = lock.withLock {
            guard self.continuation == nil else {
                return false
            }
            self.continuation = continuation
            self.session = session
            self.task = task
            return !cancellationRequested
        }

        if shouldStart {
            task.resume()
        } else {
            task.cancel()
            finish(.failure(NetworkServiceError.cancelled))
        }
    }

    private func record(_ error: NetworkServiceError) {
        lock.withLock {
            if pendingError == nil {
                pendingError = error
            }
        }
    }

    private func finish(_ result: Result<HTTPResponse, any Error>) {
        let completion: (
            CheckedContinuation<HTTPResponse, any Error>,
            URLSession?
        )? = lock.withLock {
            guard let continuation else {
                return nil
            }
            self.continuation = nil
            self.task = nil
            let session = self.session
            self.session = nil
            return (continuation, session)
        }
        guard let completion else { return }
        completion.1?.finishTasksAndInvalidate()
        completion.0.resume(with: result)
    }

    private func normalizedError(_ error: (any Error)?) -> NetworkServiceError? {
        if let pending = lock.withLock({ pendingError }) {
            return pending
        }
        guard let error else { return nil }
        if error is CancellationError {
            return .cancelled
        }
        if let urlError = error as? URLError {
            switch urlError.code {
            case .cancelled:
                return .cancelled
            case .timedOut:
                return .timedOut
            default:
                return .transport(code: urlError.errorCode)
            }
        }
        return .transport(code: nil)
    }
}

extension URLSessionRequestOperation: URLSessionDataDelegate {
    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let httpResponse = response as? HTTPURLResponse else {
            record(.nonHTTPResponse)
            completionHandler(.cancel)
            return
        }
        guard !(300...399).contains(httpResponse.statusCode) else {
            record(.redirect(statusCode: httpResponse.statusCode))
            completionHandler(.cancel)
            return
        }

        let declaredLength = httpResponse.expectedContentLength
        if declaredLength > Int64(maximumResponseBodyByteCount) {
            record(.responseBodyTooLarge(
                maximumByteCount: maximumResponseBodyByteCount
            ))
            completionHandler(.cancel)
            return
        }

        let headers = httpResponse.allHeaderFields.reduce(into: [String: String]()) {
            result, entry in
            result[String(describing: entry.key)] = String(describing: entry.value)
        }
        lock.withLock {
            responseStatusCode = httpResponse.statusCode
            responseHeaders = headers
        }
        completionHandler(.allow)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive data: Data
    ) {
        let overflowed = lock.withLock {
            guard pendingError == nil else { return true }
            guard data.count <= maximumResponseBodyByteCount - responseBody.count else {
                pendingError = .responseBodyTooLarge(
                    maximumByteCount: maximumResponseBodyByteCount
                )
                return true
            }
            responseBody.append(data)
            return false
        }
        if overflowed {
            dataTask.cancel()
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        record(.redirect(statusCode: response.statusCode))
        completionHandler(nil)
        task.cancel()
        finish(.failure(NetworkServiceError.redirect(statusCode: response.statusCode)))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: (any Error)?
    ) {
        if let error = normalizedError(error) {
            finish(.failure(error))
            return
        }
        let response: HTTPResponse? = lock.withLock {
            guard let responseStatusCode else { return nil }
            return HTTPResponse(
                statusCode: responseStatusCode,
                headers: responseHeaders,
                body: responseBody
            )
        }
        guard let response else {
            finish(.failure(NetworkServiceError.nonHTTPResponse))
            return
        }
        finish(.success(response))
    }
}
