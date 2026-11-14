import BSVCore
import BSVTransaction
import Foundation

/// A bounded, unauthenticated WhatsOnChain transaction broadcaster.
///
/// Mirrors the TypeScript SDK's `WhatsOnChainBroadcaster` and wallet-toolbox's
/// `WhatsOnChain.postRawTx`: it posts `{"txhex": ...}` to `/tx/raw`, reads the
/// transaction ID that WhatsOnChain returns as a JSON string (a bare ID is also
/// accepted), and counts WhatsOnChain's "Transaction already in the mempool"
/// rejection as a success because the transaction is already on the network.
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
                let providerText = decodedProviderText(response.body)
                if providerText == alreadyInMempoolResponse {
                    return BroadcastResult(
                        transactionID: localTransactionID,
                        message: alreadyInMempoolMessage
                    )
                }
                let message: String?
                if let providerText {
                    message = sanitizedProviderText(
                        providerText,
                        redacting: [transactionHex],
                        redactingFieldNames: ["txhex"]
                    )
                } else {
                    message = sanitizedProviderText(
                        response.body,
                        redacting: [transactionHex],
                        redactingFieldNames: ["txhex"]
                    )
                }
                throw NetworkServiceError.httpStatus(
                    code: response.statusCode,
                    message: message
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
            headers: [
                "Content-Type": "application/json",
                "Accept": "text/plain",
            ],
            body: body
        )
    }
}

private struct BroadcastRequest: Encodable {
    let txhex: String
}

/// The error text WhatsOnChain returns when the transaction is already in its
/// mempool. wallet-toolbox's `WhatsOnChain.postRawTx` treats exactly this
/// response as a successful broadcast.
private let alreadyInMempoolResponse =
    "unexpected response code 500: Transaction already in the mempool"
private let alreadyInMempoolMessage = "Transaction already in the mempool"

/// Parses WhatsOnChain's success body, which is the transaction ID as a JSON
/// string (`"<txid>"`, served as `application/json`), or a bare ID.
private func parseCanonicalTransactionID(_ body: Data) throws -> TransactionID {
    guard let decoded = String(data: body, encoding: .utf8) else {
        throw NetworkServiceError.inconsistentResponse
    }
    var candidate = trimmingASCIISurroundingWhitespace(decoded)
    if candidate.hasPrefix("\"") {
        guard let unquoted = jsonStringValue(candidate) else {
            throw NetworkServiceError.inconsistentResponse
        }
        candidate = unquoted
    }
    let bytes = Array(candidate.utf8)
    guard bytes.count == 64,
          bytes.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    else {
        throw NetworkServiceError.inconsistentResponse
    }

    do {
        return try TransactionID(displayHex: candidate)
    } catch {
        throw NetworkServiceError.inconsistentResponse
    }
}

/// Returns the provider's text with surrounding ASCII whitespace removed and,
/// when the body is a JSON string, its decoded value. Returns `nil` for bodies
/// that are not UTF-8.
private func decodedProviderText(_ body: Data) -> String? {
    guard let decoded = String(data: body, encoding: .utf8) else {
        return nil
    }
    let trimmed = trimmingASCIISurroundingWhitespace(decoded)
    if trimmed.hasPrefix("\""), let unquoted = jsonStringValue(trimmed) {
        return unquoted
    }
    return trimmed
}

private func jsonStringValue(_ text: String) -> String? {
    do {
        return try JSONSerialization.jsonObject(
            with: Data(text.utf8),
            options: [.fragmentsAllowed]
        ) as? String
    } catch {
        return nil
    }
}

private func trimmingASCIISurroundingWhitespace(_ text: String) -> String {
    let bytes = Array(text.utf8)
    var lowerBound = bytes.startIndex
    var upperBound = bytes.endIndex
    while lowerBound < upperBound, isASCIISurroundingWhitespace(bytes[lowerBound]) {
        lowerBound += 1
    }
    while upperBound > lowerBound, isASCIISurroundingWhitespace(bytes[upperBound - 1]) {
        upperBound -= 1
    }
    return String(decoding: bytes[lowerBound..<upperBound], as: UTF8.self)
}

private func isASCIISurroundingWhitespace(_ byte: UInt8) -> Bool {
    byte == 0x20 || (0x09...0x0d).contains(byte)
}
