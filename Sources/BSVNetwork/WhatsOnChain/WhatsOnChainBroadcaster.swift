import BSVCore
import BSVTransaction
import Foundation

/// A bounded, unauthenticated WhatsOnChain transaction broadcaster.
public struct WhatsOnChainBroadcaster: Broadcaster, Sendable {
    private let network: WhatsOnChainNetwork
    private let policy: NetworkRequestPolicy
    private let transport: any HTTPTransport

    public init(
        network: WhatsOnChainNetwork,
        policy: NetworkRequestPolicy = .broadcast
    ) {
        self.network = network
        self.policy = policy
        self.transport = URLSessionHTTPTransport(
            requestTimeout: policy.requestTimeout,
            resourceTimeout: policy.resourceTimeout
        )
    }

    package init(
        network: WhatsOnChainNetwork,
        policy: NetworkRequestPolicy = .broadcast,
        transport: any HTTPTransport
    ) {
        self.network = network
        self.policy = policy
        self.transport = transport
    }

    public func broadcast(
        _ transaction: Transaction,
        limits: TransactionLimits
    ) async throws -> BroadcastResult {
        let transactionHex = try transaction.hex(limits: limits)
        let localTransactionID = try transaction.transactionID(limits: limits)
        let body = try JSONEncoder().encode(BroadcastRequest(txhex: transactionHex))
        let request = try makeRequest(body: body)

        do {
            try Task.checkCancellation()
            let response = try await transport.send(
                request,
                maximumResponseBodyByteCount: policy.maximumResponseBodyByteCount
            )
            try Task.checkCancellation()
            guard response.body.count <= policy.maximumResponseBodyByteCount else {
                throw NetworkServiceError.responseBodyTooLarge(
                    maximumByteCount: policy.maximumResponseBodyByteCount
                )
            }
            guard response.statusCode == 200 else {
                throw NetworkServiceError.httpStatus(
                    code: response.statusCode,
                    message: sanitizedBroadcastErrorExcerpt(
                        response.body,
                        redacting: transactionHex
                    )
                )
            }
            let providerTransactionID = try parseCanonicalTransactionID(response.body)
            guard providerTransactionID == localTransactionID else {
                throw NetworkServiceError.inconsistentResponse
            }
            return BroadcastResult(transactionID: localTransactionID)
        } catch is CancellationError {
            throw NetworkServiceError.cancelled
        } catch let error as NetworkServiceError {
            throw error
        } catch {
            throw NetworkServiceError.transport(code: nil)
        }
    }

    private func makeRequest(body: Data) throws -> HTTPRequest {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "api.whatsonchain.com"
        components.path = "/v1/bsv/\(network.rawValue)/tx/raw"
        guard let url = components.url else {
            throw NetworkServiceError.invalidConfiguration
        }
        return HTTPRequest(
            method: .post,
            url: url,
            headers: ["Content-Type": "application/json"],
            body: body
        )
    }
}

private struct BroadcastRequest: Encodable {
    let txhex: String
}

private func parseCanonicalTransactionID(_ body: Data) throws -> TransactionID {
    guard let decoded = String(data: body, encoding: .utf8) else {
        throw NetworkServiceError.inconsistentResponse
    }
    let bytes = Array(decoded.utf8)
    var lowerBound = bytes.startIndex
    var upperBound = bytes.endIndex
    while lowerBound < upperBound, isASCIISurroundingWhitespace(bytes[lowerBound]) {
        lowerBound += 1
    }
    while upperBound > lowerBound, isASCIISurroundingWhitespace(bytes[upperBound - 1]) {
        upperBound -= 1
    }
    let candidate = bytes[lowerBound..<upperBound]
    guard candidate.count == 64,
          candidate.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    else {
        throw NetworkServiceError.inconsistentResponse
    }

    do {
        return try TransactionID(displayHex: String(decoding: candidate, as: UTF8.self))
    } catch {
        throw NetworkServiceError.inconsistentResponse
    }
}

private func isASCIISurroundingWhitespace(_ byte: UInt8) -> Bool {
    byte == 0x20 || (0x09...0x0d).contains(byte)
}

private func sanitizedBroadcastErrorExcerpt(
    _ body: Data,
    redacting transactionHex: String
) -> String? {
    let decoded = String(decoding: body, as: UTF8.self)
    var withoutControls = ""
    for scalar in decoded.unicodeScalars {
        guard scalar.properties.generalCategory != .control else { continue }
        withoutControls.unicodeScalars.append(scalar)
    }
    guard !withoutControls.isEmpty else { return nil }
    let withoutRequestField = withoutControls.replacingOccurrences(
        of: "txhex",
        with: "[redacted-field]",
        options: .caseInsensitive
    ).replacingOccurrences(
        of: transactionHex,
        with: "[redacted]",
        options: .caseInsensitive
    )
    return boundedErrorExcerpt(redactingLongHexRuns(withoutRequestField))
}

private func redactingLongHexRuns(_ text: String) -> String {
    var result = ""
    var hexRun = ""

    func appendHexRun() {
        result += hexRun.utf8.count >= 8 ? "[redacted]" : hexRun
        hexRun.removeAll(keepingCapacity: true)
    }

    for scalar in text.unicodeScalars {
        if isASCIIHex(scalar.value) {
            hexRun.unicodeScalars.append(scalar)
        } else {
            appendHexRun()
            result.unicodeScalars.append(scalar)
        }
    }
    appendHexRun()
    return result
}

private func isASCIIHex(_ value: UInt32) -> Bool {
    (48...57).contains(value)
        || (65...70).contains(value)
        || (97...102).contains(value)
}

private func boundedErrorExcerpt(_ text: String) -> String? {
    var result = ""
    var byteCount = 0
    for scalar in text.unicodeScalars {
        let scalarByteCount = scalar.utf8.count
        guard byteCount + scalarByteCount <= 1_024 else { break }
        result.unicodeScalars.append(scalar)
        byteCount += scalarByteCount
    }
    return result.isEmpty ? nil : result
}
