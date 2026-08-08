import BSVCore
import BSVTransaction
import Foundation

/// A bounded ARC transaction broadcaster and status client.
///
/// Submissions are never retried. After the POST begins, only a valid matching
/// success or explicit rejection gives a definite result. All other failures
/// return ``ARCError/uncertainDelivery(transactionID:cause:)`` because ARC may
/// already have accepted the transaction.
public struct ARCClient: Broadcaster, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable {
    public static let maximumResponseBodyByteCount = 64 * 1_024

    private let configuration: ARCConfiguration
    private let broadcastPolicy: NetworkRequestPolicy
    private let statusPolicy: NetworkRequestPolicy
    private let broadcastTransport: any HTTPTransport
    private let statusTransport: any HTTPTransport
    private let sleeper: any NetworkBackoffSleeper

    public init(
        configuration: ARCConfiguration,
        broadcastPolicy: NetworkRequestPolicy = .broadcast,
        statusPolicy: NetworkRequestPolicy = .chainLookup
    ) {
        self.configuration = configuration
        self.broadcastPolicy = broadcastPolicy
        self.statusPolicy = statusPolicy
        self.broadcastTransport = URLSessionHTTPTransport(
            requestTimeout: broadcastPolicy.requestTimeout,
            resourceTimeout: broadcastPolicy.resourceTimeout
        )
        self.statusTransport = URLSessionHTTPTransport(
            requestTimeout: statusPolicy.requestTimeout,
            resourceTimeout: statusPolicy.resourceTimeout
        )
        self.sleeper = TaskNetworkBackoffSleeper()
    }

    package init(
        configuration: ARCConfiguration,
        broadcastPolicy: NetworkRequestPolicy = .broadcast,
        statusPolicy: NetworkRequestPolicy = .chainLookup,
        broadcastTransport: any HTTPTransport,
        statusTransport: any HTTPTransport,
        sleeper: any NetworkBackoffSleeper = TaskNetworkBackoffSleeper()
    ) {
        self.configuration = configuration
        self.broadcastPolicy = broadcastPolicy
        self.statusPolicy = statusPolicy
        self.broadcastTransport = broadcastTransport
        self.statusTransport = statusTransport
        self.sleeper = sleeper
    }

    public var description: String { "<redacted ARC client>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    /// Submits a transaction and returns ARC's full validated response.
    ///
    /// Extended Format is used exactly when every input has a source output;
    /// this is vacuously true for a zero-input transaction. Any Extended
    /// Format serialization error is propagated without a raw fallback.
    public func submit(
        _ transaction: Transaction,
        limits: TransactionLimits
    ) async throws -> ARCResponse {
        let transactionID = try transaction.transactionID(limits: limits)
        let format: TransactionWireFormat = transaction.inputs.allSatisfy {
            $0.sourceOutput != nil
        } ? .extended : .raw
        let body = Data(try transaction.serialized(format: format, limits: limits))
        let request = try makeBroadcastRequest(body: body)

        do {
            try Task.checkCancellation()
        } catch {
            throw NetworkServiceError.cancelled
        }

        let response: HTTPResponse
        do {
            response = try await broadcastTransport.send(
                request,
                maximumResponseBodyByteCount: responseLimit(for: broadcastPolicy)
            )
        } catch is CancellationError {
            throw ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: .cancelled
            )
        } catch let error as NetworkServiceError {
            switch error {
            case .cancelled:
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .cancelled
                )
            case .timedOut:
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .timedOut
                )
            case .transport(let code):
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .transport(code: code)
                )
            case .redirect(let statusCode):
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .redirect(statusCode: statusCode)
                )
            case .responseBodyTooLarge(let maximumByteCount):
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .responseBodyTooLarge(maximumByteCount: maximumByteCount)
                )
            default:
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .invalidResponse
                )
            }
        } catch {
            throw ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: .transport(code: nil)
            )
        }

        do {
            return try validatedBroadcastResponse(
                response,
                expectedTransactionID: transactionID
            )
        } catch let error as ARCError {
            switch error {
            case .rejected:
                throw error
            case .providerFailure(let httpStatusCode, let response):
                throw ARCError.uncertainDelivery(
                    transactionID: transactionID,
                    cause: .providerResponse(
                        httpStatusCode: httpStatusCode,
                        status: response.status
                    )
                )
            case .uncertainDelivery:
                throw error
            }
        } catch let error as NetworkServiceError {
            let cause: ARCUncertainDeliveryCause
            if case .responseBodyTooLarge(let maximumByteCount) = error {
                cause = .responseBodyTooLarge(maximumByteCount: maximumByteCount)
            } else if case .httpStatus(let code, _) = error {
                cause = .providerResponse(httpStatusCode: code, status: nil)
            } else {
                cause = .invalidResponse
            }
            throw ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: cause
            )
        } catch {
            throw ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: .invalidResponse
            )
        }
    }

    public func broadcast(
        _ transaction: Transaction,
        limits: TransactionLimits
    ) async throws -> BroadcastResult {
        let response = try await submit(transaction, limits: limits)
        return BroadcastResult(
            transactionID: response.transactionID,
            message: response.title
        )
    }

    /// Fetches ARC status using the conventional display-order transaction ID.
    public func status(for transactionID: TransactionID) async throws -> ARCResponse {
        let request = try makeStatusRequest(transactionID: transactionID)
        let response = try await statusResponse(for: request)
        return try validatedStatusResponse(
            response,
            expectedTransactionID: transactionID
        )
    }

    private func validatedBroadcastResponse(
        _ response: HTTPResponse,
        expectedTransactionID: TransactionID
    ) throws -> ARCResponse {
        try requireBodyBound(response, policy: broadcastPolicy)
        let parsed = try? parseResponse(response.body)

        guard (200...299).contains(response.statusCode) else {
            if let parsed {
                try requireMatchingTransactionID(parsed, expected: expectedTransactionID)
                if isExplicitARCRejection(parsed) {
                    throw ARCError.rejected(
                        httpStatusCode: response.statusCode,
                        response: parsed
                    )
                }
                throw ARCError.providerFailure(
                    httpStatusCode: response.statusCode,
                    response: parsed
                )
            }
            throw NetworkServiceError.httpStatus(
                code: response.statusCode,
                message: sanitizedProviderText(
                    response.body,
                    redacting: responseRedactions
                )
            )
        }

        guard let parsed else {
            throw NetworkServiceError.malformedResponse
        }
        try requireMatchingTransactionID(parsed, expected: expectedTransactionID)
        if isExplicitARCRejection(parsed) {
            throw ARCError.rejected(
                httpStatusCode: response.statusCode,
                response: parsed
            )
        }
        guard parsed.status == 200,
              parsed.txStatus != nil,
              parsed.title != nil,
              parsed.timestamp != nil
        else {
            throw ARCError.providerFailure(
                httpStatusCode: response.statusCode,
                response: parsed
            )
        }
        return parsed
    }

    private func validatedStatusResponse(
        _ response: HTTPResponse,
        expectedTransactionID: TransactionID
    ) throws -> ARCResponse {
        try requireBodyBound(response, policy: statusPolicy)
        let parsed = try? parseResponse(response.body)

        guard (200...299).contains(response.statusCode) else {
            if let parsed {
                try requireMatchingTransactionID(parsed, expected: expectedTransactionID)
                throw ARCError.providerFailure(
                    httpStatusCode: response.statusCode,
                    response: parsed
                )
            }
            throw NetworkServiceError.httpStatus(
                code: response.statusCode,
                message: sanitizedProviderText(
                    response.body,
                    redacting: responseRedactions
                )
            )
        }

        guard let parsed else {
            throw NetworkServiceError.malformedResponse
        }
        try requireMatchingTransactionID(parsed, expected: expectedTransactionID)
        guard parsed.txStatus != nil, parsed.timestamp != nil else {
            throw NetworkServiceError.malformedResponse
        }
        return parsed
    }

    private func parseResponse(_ body: Data) throws -> ARCResponse {
        try ARCResponse(body: body, redacting: responseRedactions)
    }

    private var responseRedactions: [String] {
        [configuration.apiKey, configuration.callbackToken].compactMap { $0 }
    }

    private func requireMatchingTransactionID(
        _ response: ARCResponse,
        expected: TransactionID
    ) throws {
        guard response.transactionID == expected else {
            throw NetworkServiceError.inconsistentResponse
        }
    }

    private func requireBodyBound(
        _ response: HTTPResponse,
        policy: NetworkRequestPolicy
    ) throws {
        let maximum = responseLimit(for: policy)
        guard response.body.count <= maximum else {
            throw NetworkServiceError.responseBodyTooLarge(maximumByteCount: maximum)
        }
    }

    private func responseLimit(for policy: NetworkRequestPolicy) -> Int {
        min(policy.maximumResponseBodyByteCount, Self.maximumResponseBodyByteCount)
    }

    private func makeBroadcastRequest(body: Data) throws -> HTTPRequest {
        HTTPRequest(
            method: .post,
            url: try endpointURL(suffix: "/tx"),
            headers: broadcastHeaders(),
            body: body
        )
    }

    private func makeStatusRequest(transactionID: TransactionID) throws -> HTTPRequest {
        HTTPRequest(
            method: .get,
            url: try endpointURL(suffix: "/tx/" + transactionID.displayHex),
            headers: authorizationHeaders()
        )
    }

    private func endpointURL(suffix: String) throws -> URL {
        let text = configuration.baseURL.absoluteString + suffix
        guard text.utf8.count <= ARCConfiguration.maximumBaseURLUTF8ByteCount + 68,
              let url = URL(string: text)
        else {
            throw NetworkServiceError.invalidConfiguration
        }
        return url
    }

    private func authorizationHeaders() -> [String: String] {
        guard let apiKey = configuration.apiKey, !apiKey.isEmpty else { return [:] }
        return ["Authorization": "Bearer " + apiKey]
    }

    private func broadcastHeaders() -> [String: String] {
        var headers = authorizationHeaders()
        headers["Content-Type"] = "application/octet-stream"
        if let callbackURL = configuration.callbackURL {
            headers["X-CallbackUrl"] = callbackURL.absoluteString
        }
        if let callbackToken = configuration.callbackToken {
            headers["X-CallbackToken"] = callbackToken
        }
        if configuration.callbackBatch {
            headers["X-CallbackBatch"] = "true"
        }
        if configuration.fullStatusUpdates {
            headers["X-FullStatusUpdates"] = "true"
        }
        if let maximumTimeoutSeconds = configuration.maximumTimeoutSeconds {
            headers["X-MaxTimeout"] = String(maximumTimeoutSeconds)
        }
        if configuration.skipFeeValidation {
            headers["X-SkipFeeValidation"] = "true"
        }
        if configuration.skipScriptValidation {
            headers["X-SkipScriptValidation"] = "true"
        }
        if configuration.skipTransactionValidation {
            headers["X-SkipTxValidation"] = "true"
        }
        if configuration.cumulativeFeeValidation {
            headers["X-CumulativeFeeValidation"] = "true"
        }
        if let waitForStatus = configuration.waitForStatus, !waitForStatus.isEmpty {
            headers["X-WaitForStatus"] = waitForStatus
        }
        if let waitFor = configuration.waitFor, !waitFor.rawValue.isEmpty {
            headers["X-WaitFor"] = waitFor.rawValue
        }
        return headers
    }

    private func statusResponse(for request: HTTPRequest) async throws -> HTTPResponse {
        var nextBackoff = statusPolicy.initialBackoff
        var attempt = 1

        while true {
            do {
                try Task.checkCancellation()
                let response = try await statusTransport.send(
                    request,
                    maximumResponseBodyByteCount: responseLimit(for: statusPolicy)
                )
                try Task.checkCancellation()
                try requireBodyBound(response, policy: statusPolicy)
                if isARCTransientStatus(response.statusCode),
                   attempt < statusPolicy.maximumAttempts {
                    try await sleep(
                        retryDelay(response: response, fallback: nextBackoff)
                    )
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                return response
            } catch is CancellationError {
                throw NetworkServiceError.cancelled
            } catch let error as NetworkServiceError {
                if isARCTransient(error), attempt < statusPolicy.maximumAttempts {
                    try await sleep(nextBackoff)
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                throw error
            } catch {
                let normalized = NetworkServiceError.transport(code: nil)
                if attempt < statusPolicy.maximumAttempts {
                    try await sleep(nextBackoff)
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                throw normalized
            }
        }
    }

    private func sleep(_ duration: Duration) async throws {
        do {
            try await sleeper.sleep(for: duration)
        } catch is CancellationError {
            throw NetworkServiceError.cancelled
        } catch let error as NetworkServiceError {
            throw error
        } catch {
            throw NetworkServiceError.transport(code: nil)
        }
    }

    private func doubledBackoff(_ duration: Duration) -> Duration {
        guard duration > .zero else { return .zero }
        guard duration < statusPolicy.maximumBackoff / 2 else {
            return statusPolicy.maximumBackoff
        }
        return duration * 2
    }

    private func retryDelay(response: HTTPResponse, fallback: Duration) -> Duration {
        guard let value = response.headerValue(for: "Retry-After")?.trimmingCharacters(
            in: .whitespacesAndNewlines
        ),
        let seconds = Int64(value),
        seconds >= 0
        else {
            return fallback
        }
        return min(.seconds(seconds), statusPolicy.maximumBackoff)
    }
}

private func isARCTransient(_ error: NetworkServiceError) -> Bool {
    switch error {
    case .timedOut, .transport:
        return true
    default:
        return false
    }
}

private func isARCTransientStatus(_ statusCode: Int) -> Bool {
    [408, 429, 500, 502, 503, 504].contains(statusCode)
}

private func isExplicitARCRejection(_ response: ARCResponse) -> Bool {
    if response.txStatus == .rejected {
        return true
    }
    guard let status = response.status else { return false }
    return [
        460, 461, 462, 463, 464, 465, 467, 468, 469, 471, 472, 473,
    ].contains(status)
}
