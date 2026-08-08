import BSVCore
import Foundation
@testable import BSVNetwork
import Testing

@Suite("WhatsOnChain chain tracker")
struct WhatsOnChainChainTrackerTests {
    @Test("builds exact GET URLs for both networks")
    func exactURLs() async throws {
        let mainTransport = ScriptedHTTPTransport([
            .success(headerResponse(height: 1, displayRoot: displayRoot)),
            .success(chainInfoResponse(blocks: 961_399)),
        ])
        let main = makeTracker(network: .mainnet, transport: mainTransport)
        _ = try await main.isValidRoot(wireRoot, atBlockHeight: 1)
        _ = try await main.currentHeight()

        let mainRequests = await mainTransport.recordedRequests()
        #expect(mainRequests.map(\.method) == [.get, .get])
        #expect(mainRequests.map(\.url.absoluteString) == [
            "https://api.whatsonchain.com/v1/bsv/main/block/1/header",
            "https://api.whatsonchain.com/v1/bsv/main/chain/info",
        ])

        let testTransport = ScriptedHTTPTransport([
            .success(headerResponse(height: 7, displayRoot: displayRoot)),
        ])
        let test = makeTracker(network: .testnet, transport: testTransport)
        _ = try await test.isValidRoot(wireRoot, atBlockHeight: 7)
        #expect(await testTransport.recordedRequests().first?.url.absoluteString ==
            "https://api.whatsonchain.com/v1/bsv/test/block/7/header")
    }

    @Test("reverses display-order roots into stored wire order")
    func displayWireOrder() async throws {
        let transport = ScriptedHTTPTransport([
            .success(headerResponse(height: 1, displayRoot: displayRoot)),
            .success(headerResponse(height: 1, displayRoot: displayRoot)),
        ])
        let tracker = makeTracker(transport: transport)

        #expect(try await tracker.isValidRoot(wireRoot, atBlockHeight: 1))
        #expect(!(try await tracker.isValidRoot(
            try Hash256(Array(wireRoot.bytes.dropLast()) + [0xff]),
            atBlockHeight: 1
        )))
        #expect(wireRoot.bytes.first == 0x98)
        #expect(wireRoot.bytes.last == 0x0e)
    }

    @Test("numeric zero and one are not confused with JSON booleans", arguments: [UInt32(0), 1])
    func zeroAndOneRemainNumbers(_ height: UInt32) async throws {
        let transport = ScriptedHTTPTransport([
            .success(headerResponse(height: height, displayRoot: displayRoot)),
            .success(chainInfoResponse(blocks: height)),
        ])
        let tracker = makeTracker(transport: transport)
        #expect(try await tracker.isValidRoot(wireRoot, atBlockHeight: height))
        #expect(try await tracker.currentHeight() == height)
    }

    @Test("header 404 means an unknown height")
    func headerNotFound() async throws {
        let tracker = makeTracker(transport: ScriptedHTTPTransport([
            .success(response(status: 404, body: "not found")),
        ]))
        #expect(!(try await tracker.isValidRoot(wireRoot, atBlockHeight: 44)))
    }

    @Test("rejects inconsistent and malformed headers", arguments: [
        "wrong-height", "missing-height", "malformed-json", "short-root",
        "long-root", "non-hex-root", "boolean-height", "floating-height",
    ])
    func malformedHeaders(_ kind: String) async throws {
        let providerResponse: HTTPResponse
        let expected: NetworkServiceError
        switch kind {
        case "wrong-height":
            providerResponse = headerResponse(height: 2, displayRoot: displayRoot)
            expected = .inconsistentResponse
        case "missing-height":
            providerResponse = response(status: 200, body: "{\"merkleroot\":\"\(displayRoot)\"}")
            expected = .malformedResponse
        case "malformed-json":
            providerResponse = response(status: 200, body: "{")
            expected = .malformedResponse
        case "short-root":
            providerResponse = headerResponse(height: 1, displayRoot: String(displayRoot.dropLast(2)))
            expected = .malformedResponse
        case "long-root":
            providerResponse = headerResponse(height: 1, displayRoot: displayRoot + "00")
            expected = .malformedResponse
        case "boolean-height":
            providerResponse = response(
                status: 200,
                body: "{\"height\":true,\"merkleroot\":\"\(displayRoot)\"}"
            )
            expected = .malformedResponse
        case "floating-height":
            providerResponse = response(
                status: 200,
                body: "{\"height\":1.0,\"merkleroot\":\"\(displayRoot)\"}"
            )
            expected = .malformedResponse
        default:
            providerResponse = headerResponse(height: 1, displayRoot: String(repeating: "z", count: 64))
            expected = .malformedResponse
        }
        let tracker = makeTracker(transport: ScriptedHTTPTransport([.success(providerResponse)]))
        await #expect(throws: expected) {
            try await tracker.isValidRoot(wireRoot, atBlockHeight: 1)
        }
    }

    @Test("accepts a valid current height")
    func currentHeight() async throws {
        let tracker = makeTracker(transport: ScriptedHTTPTransport([
            .success(chainInfoResponse(blocks: UInt32.max)),
        ]))
        #expect(try await tracker.currentHeight() == UInt32.max)
    }

    @Test("rejects malformed chain heights", arguments: [
        "{}", "{\"blocks\":-1}", "{\"blocks\":1.5}", "{\"blocks\":1.0}",
        "{\"blocks\":\"1\"}", "{\"blocks\":null}", "{\"blocks\":true}",
        "{\"blocks\":4294967296}",
    ])
    func malformedCurrentHeight(_ json: String) async throws {
        let tracker = makeTracker(transport: ScriptedHTTPTransport([
            .success(response(status: 200, body: json)),
        ]))
        await #expect(throws: NetworkServiceError.malformedResponse) {
            try await tracker.currentHeight()
        }
    }

    @Test("non-success statuses produce sanitized bounded errors")
    func sanitizedHTTPError() async throws {
        let unsafe = Data("A\u{202e}\u{200b}".utf8) + Data([0x00, 0x0a, 0xff])
            + Data(repeating: Character("x").asciiValue!, count: 2_000)
        let tracker = makeTracker(transport: ScriptedHTTPTransport([
            .success(HTTPResponse(statusCode: 418, body: unsafe)),
        ]))
        do {
            _ = try await tracker.currentHeight()
            Issue.record("Expected an HTTP status error")
        } catch let NetworkServiceError.httpStatus(code, message) {
            #expect(code == 418)
            let message = try #require(message)
            #expect(!message.contains("\0"))
            #expect(!message.contains("\n"))
            #expect(!message.unicodeScalars.contains("\u{202e}"))
            #expect(!message.unicodeScalars.contains("\u{200b}"))
            #expect(message.utf8.count <= 1_024)
            #expect(message.hasPrefix("A�"))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("chain-info 404 remains an HTTP error")
    func chainInfoNotFound() async throws {
        let tracker = makeTracker(transport: ScriptedHTTPTransport([
            .success(response(status: 404, body: "missing")),
        ]))
        await #expect(throws: NetworkServiceError.httpStatus(
            code: 404,
            message: "missing"
        )) {
            try await tracker.currentHeight()
        }
    }

    @Test("retries only retryable HTTP statuses", arguments: [408, 429, 500, 502, 503, 504])
    func retriesHTTPStatus(_ status: Int) async throws {
        let transport = ScriptedHTTPTransport([
            .success(response(status: status, body: "retry")),
            .success(chainInfoResponse(blocks: 9)),
        ])
        let sleeper = RecordingSleeper()
        let tracker = makeTracker(
            policy: try policy(maximumAttempts: 2),
            transport: transport,
            sleeper: sleeper
        )
        #expect(try await tracker.currentHeight() == 9)
        #expect(await transport.attemptCount() == 2)
        #expect(await sleeper.recordedDurations() == [.milliseconds(350)])
    }

    @Test("transport loss and timeout use capped exponential backoff")
    func transportRetries() async throws {
        let transport = ScriptedHTTPTransport([
            .failure(.transport(code: -1005)),
            .failure(.timedOut),
            .success(chainInfoResponse(blocks: 10)),
        ])
        let sleeper = RecordingSleeper()
        let tracker = makeTracker(transport: transport, sleeper: sleeper)
        #expect(try await tracker.currentHeight() == 10)
        #expect(await transport.attemptCount() == 3)
        #expect(await sleeper.recordedDurations() == [
            .milliseconds(350), .milliseconds(700),
        ])
    }

    @Test("Retry-After is parsed case-insensitively and bounded")
    func retryAfter() async throws {
        let transport = ScriptedHTTPTransport([
            .success(HTTPResponse(
                statusCode: 429,
                headers: ["retry-after": "999999"],
                body: Data()
            )),
            .success(chainInfoResponse(blocks: 11)),
        ])
        let sleeper = RecordingSleeper()
        let tracker = makeTracker(transport: transport, sleeper: sleeper)
        #expect(try await tracker.currentHeight() == 11)
        #expect(await sleeper.recordedDurations() == [.seconds(2)])
    }

    @Test("retry attempts are exactly bounded")
    func boundedAttempts() async throws {
        let transport = ScriptedHTTPTransport([
            .failure(.timedOut), .failure(.timedOut), .failure(.timedOut),
        ])
        let sleeper = RecordingSleeper()
        let tracker = makeTracker(transport: transport, sleeper: sleeper)
        await #expect(throws: NetworkServiceError.timedOut) {
            try await tracker.currentHeight()
        }
        #expect(await transport.attemptCount() == 3)
        #expect(await sleeper.recordedDurations().count == 2)
    }

    @Test("does not retry cancellation, deterministic failures, or ordinary HTTP errors")
    func noDeterministicRetry() async throws {
        for expected in [
            NetworkServiceError.cancelled,
            .malformedResponse,
            .inconsistentResponse,
            .redirect(statusCode: 302),
            .responseBodyTooLarge(maximumByteCount: 8),
        ] {
            let transport = ScriptedHTTPTransport([.failure(expected)])
            let sleeper = RecordingSleeper()
            let tracker = makeTracker(transport: transport, sleeper: sleeper)
            await #expect(throws: expected) { try await tracker.currentHeight() }
            #expect(await transport.attemptCount() == 1)
            #expect(await sleeper.recordedDurations().isEmpty)
        }

        let transport = ScriptedHTTPTransport([
            .success(response(status: 400, body: "bad")),
        ])
        let tracker = makeTracker(transport: transport)
        await #expect(throws: NetworkServiceError.httpStatus(code: 400, message: "bad")) {
            try await tracker.currentHeight()
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("task cancellation propagates promptly")
    func cancellation() async throws {
        let tracker = makeTracker(transport: CancellationAwareTransport())
        let task = Task { try await tracker.currentHeight() }
        await Task.yield()
        task.cancel()
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: NetworkServiceError.cancelled) { try await task.value }
        #expect(start.duration(to: clock.now) < .seconds(1))
    }

    @Test("policy validation and defaults are bounded")
    func policyValidation() throws {
        #expect(NetworkRequestPolicy.chainLookup.requestTimeout == .seconds(10))
        #expect(NetworkRequestPolicy.chainLookup.resourceTimeout == .seconds(30))
        #expect(NetworkRequestPolicy.chainLookup.maximumResponseBodyByteCount == 65_536)
        #expect(NetworkRequestPolicy.chainLookup.maximumAttempts == 3)
        #expect(NetworkRequestPolicy.chainLookup.initialBackoff == .milliseconds(350))
        #expect(NetworkRequestPolicy.chainLookup.maximumBackoff == .seconds(2))
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try policy(requestTimeout: .zero)
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try policy(maximumBody: 0)
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try policy(maximumAttempts: 0)
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try policy(initialBackoff: .seconds(3), maximumBackoff: .seconds(2))
        }
    }

    @Test("public values and tracker are Sendable")
    func sendableSurface() {
        acceptSendable(WhatsOnChainNetwork.mainnet)
        acceptSendable(NetworkRequestPolicy.chainLookup)
        acceptSendable(NetworkServiceError.cancelled)
        acceptSendable(WhatsOnChainChainTracker(network: .mainnet))
    }
}

private let displayRoot =
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"

private let wireRoot: Hash256 = {
    do {
        return try Hash256(try hexBytes(displayRoot).reversed())
    } catch {
        preconditionFailure("The static display root must be valid")
    }
}()

private func makeTracker(
    network: WhatsOnChainNetwork = .mainnet,
    policy: NetworkRequestPolicy = .chainLookup,
    transport: any HTTPTransport,
    sleeper: any NetworkBackoffSleeper = RecordingSleeper()
) -> WhatsOnChainChainTracker {
    WhatsOnChainChainTracker(
        network: network,
        policy: policy,
        transport: transport,
        sleeper: sleeper
    )
}

private func policy(
    requestTimeout: Duration = .seconds(1),
    maximumBody: Int = 1_024,
    maximumAttempts: Int = 3,
    initialBackoff: Duration = .milliseconds(350),
    maximumBackoff: Duration = .seconds(2)
) throws -> NetworkRequestPolicy {
    try NetworkRequestPolicy(
        requestTimeout: requestTimeout,
        resourceTimeout: .seconds(2),
        maximumResponseBodyByteCount: maximumBody,
        maximumAttempts: maximumAttempts,
        initialBackoff: initialBackoff,
        maximumBackoff: maximumBackoff
    )
}

private func response(status: Int, body: String) -> HTTPResponse {
    HTTPResponse(statusCode: status, body: Data(body.utf8))
}

private func headerResponse(height: UInt32, displayRoot: String) -> HTTPResponse {
    response(
        status: 200,
        body: "{\"height\":\(height),\"merkleroot\":\"\(displayRoot)\",\"ignored\":true}"
    )
}

private func chainInfoResponse(blocks: UInt32) -> HTTPResponse {
    response(status: 200, body: "{\"blocks\":\(blocks),\"ignored\":true}")
}

private func hexBytes(_ value: String) throws -> [UInt8] {
    var result: [UInt8] = []
    var index = value.startIndex
    while index < value.endIndex {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else {
            throw NetworkServiceError.malformedResponse
        }
        result.append(byte)
        index = next
    }
    return result
}

private actor ScriptedHTTPTransport: HTTPTransport {
    private var results: [Result<HTTPResponse, NetworkServiceError>]
    private var requests: [HTTPRequest] = []

    init(_ results: [Result<HTTPResponse, NetworkServiceError>]) {
        self.results = results
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        requests.append(request)
        guard !results.isEmpty else { throw NetworkServiceError.malformedResponse }
        return try results.removeFirst().get()
    }

    func recordedRequests() -> [HTTPRequest] { requests }
    func attemptCount() -> Int { requests.count }
}

private actor RecordingSleeper: NetworkBackoffSleeper {
    private var durations: [Duration] = []

    func sleep(for duration: Duration) async throws {
        durations.append(duration)
    }

    func recordedDurations() -> [Duration] { durations }
}

private struct CancellationAwareTransport: HTTPTransport {
    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        try await Task.sleep(for: .seconds(60))
        return HTTPResponse(statusCode: 200, body: Data())
    }
}

private func acceptSendable<T: Sendable>(_ value: T) {}
