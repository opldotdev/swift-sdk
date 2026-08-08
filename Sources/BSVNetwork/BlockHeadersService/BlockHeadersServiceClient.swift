import BSVCore
import BSVSPV
import BSVTransaction
import CoreFoundation
import Foundation

/// A bounded, authenticated block-headers-service client.
///
/// All operations use the injected transport. Only GET requests are issued and
/// only those idempotent lookups are retried. Webhook mutation is deliberately
/// not part of this client yet: it needs a separately reviewed no-retry API.
public struct BlockHeadersServiceClient: ChainTracker, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maximumHeaderCandidates = 64
    public static let maximumMerkleRootsPerPage = 1_000

    private let configuration: BlockHeadersServiceConfiguration
    private let policy: NetworkRequestPolicy
    private let transport: any HTTPTransport
    private let sleeper: any NetworkBackoffSleeper

    public init(
        configuration: BlockHeadersServiceConfiguration,
        policy: NetworkRequestPolicy = .chainLookup
    ) {
        self.configuration = configuration
        self.policy = policy
        self.transport = URLSessionHTTPTransport(
            requestTimeout: policy.requestTimeout,
            resourceTimeout: policy.resourceTimeout
        )
        self.sleeper = TaskNetworkBackoffSleeper()
    }

    package init(
        configuration: BlockHeadersServiceConfiguration,
        policy: NetworkRequestPolicy = .chainLookup,
        transport: any HTTPTransport,
        sleeper: any NetworkBackoffSleeper = TaskNetworkBackoffSleeper()
    ) {
        self.configuration = configuration
        self.policy = policy
        self.transport = transport
        self.sleeper = sleeper
    }

    public var description: String { "<redacted block headers service client>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    /// Returns the best-chain block header at `height`.
    ///
    /// Multiple candidates are resolved only when the service confirms a
    /// matching `LONGEST_CHAIN` state. A stale candidate is never silently
    /// returned as a trusted chain header.
    public func blockByHeight(_ height: UInt32) async throws -> BlockHeadersServiceHeader {
        let response = try await get(
            path: ["api", "v1", "chain", "header", "byHeight"],
            queryItems: [URLQueryItem(name: "height", value: String(height))]
        )
        try requireSuccess(response)
        let candidates = try parseHeaders(response.body)

        for candidate in candidates {
            guard candidate.height == height else {
                throw NetworkServiceError.inconsistentResponse
            }
            let blockState = try await state(for: candidate.hash)
            guard blockState.header.hash == candidate.hash else {
                throw NetworkServiceError.inconsistentResponse
            }
            guard blockState.height == height else {
                throw NetworkServiceError.inconsistentResponse
            }
            if blockState.isLongestChain {
                return candidate
            }
        }
        throw NetworkServiceError.inconsistentResponse
    }

    /// Returns the current state of `hash`.
    public func state(for hash: BlockHash) async throws -> BlockHeadersServiceState {
        let response = try await get(
            path: ["api", "v1", "chain", "header", "state", hash.displayHex]
        )
        try requireSuccess(response)
        let parsed = try parseState(response.body)
        guard parsed.header.hash == hash else {
            throw NetworkServiceError.inconsistentResponse
        }
        return parsed
    }

    /// Returns the service's explicitly longest-chain tip.
    public func chainTip() async throws -> BlockHeadersServiceState {
        let response = try await get(path: ["api", "v1", "chain", "tip", "longest"])
        try requireSuccess(response)
        let parsed = try parseState(response.body)
        guard parsed.isLongestChain,
              parsed.header.height == parsed.height
        else {
            throw NetworkServiceError.inconsistentResponse
        }
        return parsed
    }

    /// Returns the current best-chain height.
    public func currentHeight() async throws -> UInt32 {
        try await chainTip().height
    }

    /// Validates a Merkle root from the selected best-chain block header.
    ///
    /// This keeps `ChainTracker` validation on bounded, retry-safe GET
    /// lookups; it intentionally does not use the Go client's mutable POST
    /// verification endpoint.
    public func isValidRoot(
        _ root: Hash256,
        atBlockHeight blockHeight: UInt32
    ) async throws -> Bool {
        try await blockByHeight(blockHeight).header.merkleRoot == root
    }

    /// Fetches a bounded page of accepted Merkle roots.
    public func merkleRoots(
        batchSize: Int,
        lastEvaluatedKey: BlockHash? = nil
    ) async throws -> BlockHeadersServiceMerkleRootsPage {
        guard (1...Self.maximumMerkleRootsPerPage).contains(batchSize) else {
            throw NetworkServiceError.invalidConfiguration
        }
        var queryItems = [URLQueryItem(name: "batchSize", value: String(batchSize))]
        if let lastEvaluatedKey {
            queryItems.append(URLQueryItem(
                name: "lastEvaluatedKey",
                value: lastEvaluatedKey.displayHex
            ))
        }
        let response = try await get(
            path: ["api", "v1", "chain", "merkleroot"],
            queryItems: queryItems
        )
        try requireSuccess(response)
        return try parseMerkleRoots(response.body, maximumCount: batchSize)
    }

    private func get(
        path: [String],
        queryItems: [URLQueryItem] = []
    ) async throws -> HTTPResponse {
        let request = try makeRequest(path: path, queryItems: queryItems)
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
                try requireBodyBound(response)
                if isTransientStatus(response.statusCode), attempt < policy.maximumAttempts {
                    try await sleep(retryDelay(response: response, fallback: nextBackoff))
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                return response
            } catch is CancellationError {
                throw NetworkServiceError.cancelled
            } catch let error as NetworkServiceError {
                if isTransient(error), attempt < policy.maximumAttempts {
                    try await sleep(nextBackoff)
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                throw error
            } catch {
                let error = NetworkServiceError.transport(code: nil)
                if attempt < policy.maximumAttempts {
                    try await sleep(nextBackoff)
                    attempt += 1
                    nextBackoff = doubledBackoff(nextBackoff)
                    continue
                }
                throw error
            }
        }
    }

    private func makeRequest(
        path: [String],
        queryItems: [URLQueryItem]
    ) throws -> HTTPRequest {
        guard path.allSatisfy({ component in
            !component.isEmpty && component.unicodeScalars.allSatisfy { scalar in
                (48...57).contains(scalar.value)
                    || (65...90).contains(scalar.value)
                    || (97...122).contains(scalar.value)
                    || scalar.value == 45
            }
        }),
        var components = URLComponents(url: configuration.baseURL, resolvingAgainstBaseURL: false)
        else {
            throw NetworkServiceError.invalidConfiguration
        }
        components.path += "/" + path.joined(separator: "/")
        if !queryItems.isEmpty {
            components.queryItems = queryItems
        }
        guard let url = components.url else { throw NetworkServiceError.invalidConfiguration }
        return HTTPRequest(
            method: .get,
            url: url,
            headers: ["Authorization": "Bearer " + configuration.apiKey]
        )
    }

    private func requireBodyBound(_ response: HTTPResponse) throws {
        guard response.body.count <= policy.maximumResponseBodyByteCount else {
            throw NetworkServiceError.responseBodyTooLarge(
                maximumByteCount: policy.maximumResponseBodyByteCount
            )
        }
    }

    private func requireSuccess(_ response: HTTPResponse) throws {
        guard (200...299).contains(response.statusCode) else {
            throw NetworkServiceError.httpStatus(
                code: response.statusCode,
                message: sanitizedProviderText(
                    response.body,
                    redacting: [configuration.apiKey],
                    redactingFieldNames: ["authorization"]
                )
            )
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
        guard duration < policy.maximumBackoff / 2 else { return policy.maximumBackoff }
        return duration * 2
    }

    private func retryDelay(response: HTTPResponse, fallback: Duration) -> Duration {
        guard let value = response.headerValue(for: "Retry-After")?.trimmingCharacters(
            in: .whitespacesAndNewlines
        ),
        let seconds = Int64(value), seconds >= 0
        else {
            return fallback
        }
        return min(.seconds(seconds), policy.maximumBackoff)
    }

    private func parseHeaders(_ body: Data) throws -> [BlockHeadersServiceHeader] {
        guard let array = tryJSON(body) as? [Any],
              !array.isEmpty,
              array.count <= Self.maximumHeaderCandidates
        else {
            throw NetworkServiceError.malformedResponse
        }
        return try array.map { value in
            guard let object = value as? [String: Any] else {
                throw NetworkServiceError.malformedResponse
            }
            return try parseHeader(object)
        }
    }

    private func parseState(_ body: Data) throws -> BlockHeadersServiceState {
        guard let object = tryJSON(body) as? [String: Any],
              let headerObject = object["header"] as? [String: Any],
              let state = object["state"] as? String,
              let height = strictUInt32(object["height"])
        else {
            throw NetworkServiceError.malformedResponse
        }
        return try BlockHeadersServiceState(
            header: parseHeader(headerObject),
            state: state,
            height: height
        )
    }

    private func parseMerkleRoots(
        _ body: Data,
        maximumCount: Int
    ) throws -> BlockHeadersServiceMerkleRootsPage {
        guard let object = tryJSON(body) as? [String: Any],
              let content = object["content"] as? [Any],
              content.count <= maximumCount,
              content.count <= Self.maximumMerkleRootsPerPage
        else {
            throw NetworkServiceError.malformedResponse
        }
        let roots = try content.map { value -> BlockHeadersServiceMerkleRoot in
            guard let object = value as? [String: Any],
                  let rootText = object["merkleRoot"] as? String,
                  let root = parseDisplayHash256(rootText),
                  let height = strictUInt32(object["blockHeight"])
            else {
                throw NetworkServiceError.malformedResponse
            }
            return BlockHeadersServiceMerkleRoot(merkleRoot: root, blockHeight: height)
        }
        let key: BlockHash?
        if let page = object["page"] {
            guard let page = page as? [String: Any] else {
                throw NetworkServiceError.malformedResponse
            }
            if let rawKey = page["lastEvaluatedKey"], !(rawKey is NSNull) {
                guard let text = rawKey as? String, let parsed = parseBlockHash(text) else {
                    throw NetworkServiceError.malformedResponse
                }
                key = parsed
            } else {
                key = nil
            }
        } else {
            key = nil
        }
        return BlockHeadersServiceMerkleRootsPage(content: roots, lastEvaluatedKey: key)
    }

    private func parseHeader(_ object: [String: Any]) throws -> BlockHeadersServiceHeader {
        guard let height = strictUInt32(object["height"]),
              let hashText = object["hash"] as? String,
              let hash = parseBlockHash(hashText),
              let version = strictUInt32(object["version"]),
              let merkleRootText = object["merkleRoot"] as? String,
              let merkleRoot = parseDisplayHash256(merkleRootText),
              let timestamp = strictUInt32(object["creationTimestamp"]),
              let bits = strictUInt32(object["difficultyTarget"]),
              let nonce = strictUInt32(object["nonce"]),
              let previousText = object["prevBlockHash"] as? String,
              let previousBlockHash = parseBlockHash(previousText)
        else {
            throw NetworkServiceError.malformedResponse
        }
        return try BlockHeadersServiceHeader(
            height: height,
            hash: hash,
            header: BlockHeader(
                version: Int32(bitPattern: version),
                previousBlockHash: previousBlockHash,
                merkleRoot: merkleRoot,
                timestamp: timestamp,
                bits: bits,
                nonce: nonce
            )
        )
    }
}

private func isTransient(_ error: NetworkServiceError) -> Bool {
    switch error {
    case .timedOut, .transport: true
    default: false
    }
}

private func isTransientStatus(_ statusCode: Int) -> Bool {
    [408, 429, 500, 502, 503, 504].contains(statusCode)
}

private func tryJSON(_ body: Data) -> Any? {
    try? JSONSerialization.jsonObject(with: body)
}

private func strictUInt32(_ value: Any?) -> UInt32? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID()
    else {
        return nil
    }
    let type = String(cString: number.objCType)
    if ["C", "S", "I", "L", "Q"].contains(type) {
        return UInt32(exactly: number.uint64Value)
    }
    guard ["c", "s", "i", "l", "q"].contains(type) else { return nil }
    return UInt32(exactly: number.int64Value)
}

private func parseBlockHash(_ text: String) -> BlockHash? {
    guard isCanonicalDisplayHash(text), let hash = try? BlockHash(displayHex: text) else {
        return nil
    }
    return hash
}

private func parseDisplayHash256(_ text: String) -> Hash256? {
    guard isCanonicalDisplayHash(text), let bytes = try? Hex.decode(
        text,
        maximumDecodedByteCount: 32
    ), let hash = try? Hash256(bytes.reversed()) else {
        return nil
    }
    return hash
}

private func isCanonicalDisplayHash(_ text: String) -> Bool {
    guard text.utf8.count == 64 else { return false }
    return text.utf8.allSatisfy { byte in
        (48...57).contains(byte) || (97...102).contains(byte)
    }
}
