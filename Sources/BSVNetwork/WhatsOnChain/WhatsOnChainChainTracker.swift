import BSVCore
import BSVTransaction
import CoreFoundation
import Foundation

/// The WhatsOnChain network used for chain lookups.
public enum WhatsOnChainNetwork: String, CaseIterable, Sendable {
    case mainnet = "main"
    case testnet = "test"
}

package protocol NetworkBackoffSleeper: Sendable {
    func sleep(for duration: Duration) async throws
}

package struct TaskNetworkBackoffSleeper: NetworkBackoffSleeper, Sendable {
    package func sleep(for duration: Duration) async throws {
        try await Task.sleep(for: duration)
    }
}

/// A bounded, unauthenticated WhatsOnChain implementation of `ChainTracker`.
public struct WhatsOnChainChainTracker: ChainTracker, Sendable {
    private let network: WhatsOnChainNetwork
    private let policy: NetworkRequestPolicy
    private let transport: any HTTPTransport
    private let sleeper: any NetworkBackoffSleeper

    public init(
        network: WhatsOnChainNetwork,
        policy: NetworkRequestPolicy = .chainLookup
    ) {
        self.network = network
        self.policy = policy
        self.transport = URLSessionHTTPTransport(
            requestTimeout: policy.requestTimeout,
            resourceTimeout: policy.resourceTimeout
        )
        self.sleeper = TaskNetworkBackoffSleeper()
    }

    package init(
        network: WhatsOnChainNetwork,
        policy: NetworkRequestPolicy = .chainLookup,
        transport: any HTTPTransport,
        sleeper: any NetworkBackoffSleeper = TaskNetworkBackoffSleeper()
    ) {
        self.network = network
        self.policy = policy
        self.transport = transport
        self.sleeper = sleeper
    }

    public func isValidRoot(
        _ root: Hash256,
        atBlockHeight blockHeight: UInt32
    ) async throws -> Bool {
        let response = try await response(for: [
            "block", String(blockHeight), "header",
        ])
        if response.statusCode == 404 {
            return false
        }
        try requireSuccess(response)

        guard let object = tryJSONObject(response.body),
              let returnedHeight = strictUInt32(object["height"]),
              let rootText = object["merkleroot"] as? String,
              let displayBytes = parseHash256Hex(rootText)
        else {
            throw NetworkServiceError.malformedResponse
        }
        guard returnedHeight == blockHeight else {
            throw NetworkServiceError.inconsistentResponse
        }
        return root.bytes == displayBytes.reversed()
    }

    public func currentHeight() async throws -> UInt32 {
        let response = try await response(for: ["chain", "info"])
        try requireSuccess(response)
        guard let object = tryJSONObject(response.body),
              let blocks = strictUInt32(object["blocks"])
        else {
            throw NetworkServiceError.malformedResponse
        }
        return blocks
    }

    private func response(for pathComponents: [String]) async throws -> HTTPResponse {
        let request = try makeRequest(pathComponents: pathComponents)
        var nextBackoff = policy.initialBackoff
        var attempt = 1

        while true {
            do {
                try Task.checkCancellation()
                let response = try await transport.send(
                    request,
                    maximumResponseBodyByteCount: policy.maximumResponseBodyByteCount
                )
                try Task.checkCancellation()
                if isRetryableStatus(response.statusCode), attempt < policy.maximumAttempts {
                    let delay = retryDelay(response: response, fallback: nextBackoff)
                    try await sleep(delay)
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                return response
            } catch is CancellationError {
                throw NetworkServiceError.cancelled
            } catch let error as NetworkServiceError {
                if isRetryable(error), attempt < policy.maximumAttempts {
                    try await sleep(nextBackoff)
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                throw error
            } catch {
                throw NetworkServiceError.transport(code: nil)
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

    private func makeRequest(pathComponents: [String]) throws -> HTTPRequest {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "api.whatsonchain.com"
        components.path = (["v1", "bsv", network.rawValue] + pathComponents)
            .reduce(into: "") { path, component in
                path += "/" + component
            }
        guard let url = components.url else {
            throw NetworkServiceError.invalidConfiguration
        }
        return HTTPRequest(method: .get, url: url)
    }

    private func doubledBackoff(_ duration: Duration) -> Duration {
        guard duration > .zero else { return .zero }
        guard duration < policy.maximumBackoff / 2 else {
            return policy.maximumBackoff
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
        return min(.seconds(seconds), policy.maximumBackoff)
    }
}

private func isRetryable(_ error: NetworkServiceError) -> Bool {
    switch error {
    case .timedOut, .transport:
        return true
    default:
        return false
    }
}

private func isRetryableStatus(_ statusCode: Int) -> Bool {
    [408, 429, 500, 502, 503, 504].contains(statusCode)
}

private func requireSuccess(_ response: HTTPResponse) throws {
    guard (200...299).contains(response.statusCode) else {
        throw NetworkServiceError.httpStatus(
            code: response.statusCode,
            message: sanitizedErrorExcerpt(response.body)
        )
    }
}

private func tryJSONObject(_ data: Data) -> [String: Any]? {
    guard let value = try? JSONSerialization.jsonObject(with: data),
          let object = value as? [String: Any]
    else {
        return nil
    }
    return object
}

private func strictUInt32(_ value: Any?) -> UInt32? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID()
    else {
        return nil
    }
    let type = String(cString: number.objCType)
    guard ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(type) else {
        return nil
    }
    let signed = number.int64Value
    guard signed >= 0, UInt64(signed) <= UInt64(UInt32.max) else {
        return nil
    }
    return UInt32(signed)
}

private func parseHash256Hex(_ text: String) -> [UInt8]? {
    let utf8 = Array(text.utf8)
    guard utf8.count == 64 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(32)
    for offset in stride(from: 0, to: utf8.count, by: 2) {
        guard let high = hexNibble(utf8[offset]),
              let low = hexNibble(utf8[offset + 1])
        else {
            return nil
        }
        bytes.append((high << 4) | low)
    }
    return bytes
}

private func hexNibble(_ character: UInt8) -> UInt8? {
    switch character {
    case 48...57: return character - 48
    case 65...70: return character - 55
    case 97...102: return character - 87
    default: return nil
    }
}

private func sanitizedErrorExcerpt(_ body: Data) -> String? {
    let decoded = String(decoding: body, as: UTF8.self)
    var result = ""
    var byteCount = 0
    for scalar in decoded.unicodeScalars {
        guard scalar.properties.generalCategory != .control else { continue }
        let scalarByteCount = scalar.utf8.count
        guard byteCount + scalarByteCount <= 1_024 else { break }
        result.unicodeScalars.append(scalar)
        byteCount += scalarByteCount
    }
    return result.isEmpty ? nil : result
}
