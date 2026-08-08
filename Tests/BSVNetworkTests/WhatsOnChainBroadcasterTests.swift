import BSVCore
import BSVTransaction
import Foundation
@testable import BSVNetwork
import Testing

@Suite("WhatsOnChain broadcaster")
struct WhatsOnChainBroadcasterTests {
    @Test("builds exact POST request for both networks")
    func exactRequests() async throws {
        for (network, networkPath) in [
            (WhatsOnChainNetwork.mainnet, "main"),
            (.testnet, "test"),
        ] {
            let transaction = Transaction()
            let limits = try testLimits()
            let transactionID = try transaction.transactionID(limits: limits)
            let transport = ScriptedBroadcastTransport([
                .success(successResponse(transactionID.displayHex)),
            ])
            let broadcaster = makeBroadcaster(network: network, transport: transport)

            _ = try await broadcaster.broadcast(transaction, limits: limits)

            let request = try #require(await transport.recordedRequests().first)
            #expect(request.method == .post)
            #expect(request.url.absoluteString ==
                "https://api.whatsonchain.com/v1/bsv/\(networkPath)/tx/raw")
            #expect(request.headers == ["Content-Type": "application/json"])
            #expect(request.body == Data(
                "{\"txhex\":\"01000000000000000000\"}".utf8
            ))
            #expect(await transport.recordedMaximumBodyCounts() == [65_536])
        }
    }

    @Test("accepts a canonical matching display transaction ID with ASCII whitespace")
    func matchingSuccess() async throws {
        let transaction = Transaction(version: 2, lockTime: 9)
        let limits = try testLimits()
        let transactionID = try transaction.transactionID(limits: limits)
        let transport = ScriptedBroadcastTransport([
            .success(successResponse("\t\n \(transactionID.displayHex)\r\u{000B}\u{000C}")),
        ])
        let result = try await makeBroadcaster(transport: transport)
            .broadcast(transaction, limits: limits)

        #expect(result == BroadcastResult(transactionID: transactionID))
        #expect(result.message == nil)
        #expect(await transport.attemptCount() == 1)
    }

    @Test("rejects noncanonical or malformed HTTP 200 bodies", arguments: [
        "empty", "malformed", "short", "long", "uppercase", "quoted",
        "mismatched", "unicode-whitespace", "invalid-utf8",
    ])
    func rejectsInvalidSuccess(_ kind: String) async throws {
        let transaction = Transaction()
        let limits = try testLimits()
        let localID = try transaction.transactionID(limits: limits).displayHex
        let body: Data
        switch kind {
        case "empty":
            body = Data()
        case "malformed":
            body = Data(String(repeating: "g", count: 64).utf8)
        case "short":
            body = Data(localID.dropLast().utf8)
        case "long":
            body = Data((localID + "0").utf8)
        case "uppercase":
            body = Data(localID.uppercased().utf8)
        case "quoted":
            body = Data("\"\(localID)\"".utf8)
        case "mismatched":
            let replacement = localID.last == "0" ? "1" : "0"
            body = Data((localID.dropLast() + replacement).utf8)
        case "unicode-whitespace":
            body = Data("\u{00a0}\(localID)\u{00a0}".utf8)
        default:
            body = Data([0xff])
        }
        let transport = ScriptedBroadcastTransport([
            .success(HTTPResponse(statusCode: 200, body: body)),
        ])
        let broadcaster = makeBroadcaster(transport: transport)

        await #expect(throws: NetworkServiceError.inconsistentResponse) {
            try await broadcaster.broadcast(transaction, limits: limits)
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("every non-200 category maps to a bounded sanitized provider error", arguments: [
        199, 201, 204, 299, 300, 400, 404, 408, 429, 500, 503, 504,
    ])
    func nonSuccessStatus(_ status: Int) async throws {
        let unsafe = Data("A\u{202e}\u{200b}".utf8) + Data([0x00, 0x0a, 0xff])
            + Data(repeating: Character("x").asciiValue!, count: 2_000)
        let transport = ScriptedBroadcastTransport([
            .success(HTTPResponse(statusCode: status, body: unsafe)),
        ])
        let broadcaster = makeBroadcaster(
            policy: try broadcastPolicy(maximumAttempts: 4),
            transport: transport
        )

        do {
            _ = try await broadcaster.broadcast(Transaction(), limits: testLimits())
            Issue.record("Expected an HTTP status error")
        } catch let NetworkServiceError.httpStatus(code, message) {
            #expect(code == status)
            let message = try #require(message)
            #expect(message.hasPrefix("A�"))
            #expect(!message.contains("\0"))
            #expect(!message.contains("\n"))
            #expect(!message.unicodeScalars.contains("\u{202e}"))
            #expect(!message.unicodeScalars.contains("\u{200b}"))
            #expect(message.utf8.count <= 1_024)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("transaction limit failure occurs before transport")
    func preflightLimitFailure() async throws {
        let transport = ScriptedBroadcastTransport([])
        let broadcaster = makeBroadcaster(transport: transport)
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 9,
            maximumInputCount: 0,
            maximumOutputCount: 0,
            maximumScriptByteCount: 0
        )

        await #expect(throws: TransactionError.transactionTooLarge(actual: 10, maximum: 9)) {
            try await broadcaster.broadcast(Transaction(), limits: limits)
        }
        #expect(await transport.attemptCount() == 0)
    }

    @Test("POST failures are never retried", arguments: [
        NetworkServiceError.timedOut,
        .transport(code: -1_005),
        .httpStatus(code: 408, message: "retry"),
        .httpStatus(code: 429, message: "retry"),
        .httpStatus(code: 500, message: "retry"),
        .httpStatus(code: 503, message: "retry"),
        .httpStatus(code: 504, message: "retry"),
    ])
    func noRetry(_ failure: NetworkServiceError) async throws {
        let result: Result<HTTPResponse, NetworkServiceError>
        switch failure {
        case .httpStatus(let code, _):
            result = .success(response(status: code, body: "retry"))
        default:
            result = .failure(failure)
        }
        let transport = ScriptedBroadcastTransport([
            result,
            .success(successResponse(String(repeating: "0", count: 64))),
        ])
        let broadcaster = makeBroadcaster(
            policy: try broadcastPolicy(maximumAttempts: 8),
            transport: transport
        )

        await #expect(throws: failure) {
            try await broadcaster.broadcast(Transaction(), limits: testLimits())
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("cancellation propagates as cancelled without retry")
    func cancellation() async throws {
        let transport = CancellationBroadcastTransport()
        let broadcaster = makeBroadcaster(
            policy: try broadcastPolicy(maximumAttempts: 3),
            transport: transport
        )
        let operation = Task {
            try await broadcaster.broadcast(Transaction(), limits: testLimits())
        }
        while await transport.attemptCount() == 0 {
            await Task.yield()
        }
        operation.cancel()

        await #expect(throws: NetworkServiceError.cancelled) {
            try await operation.value
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("oversized injected provider responses remain bounded")
    func oversizedProviderBody() async throws {
        let transport = ScriptedBroadcastTransport([
            .success(HTTPResponse(
                statusCode: 200,
                body: Data(repeating: 0x61, count: 65_537)
            )),
        ])
        let broadcaster = makeBroadcaster(transport: transport)

        await #expect(throws: NetworkServiceError.responseBodyTooLarge(
            maximumByteCount: 65_536
        )) {
            try await broadcaster.broadcast(Transaction(), limits: testLimits())
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("errors and reflection redact raw transaction request data")
    func errorRedaction() async throws {
        let transaction = Transaction(version: 7, lockTime: 11)
        let limits = try testLimits()
        let transactionHex = try transaction.hex(limits: limits)
        let requestBody = "{\"txhex\":\"\(transactionHex)\"}"
        let transport = ScriptedBroadcastTransport([
            .success(response(status: 400, body: "rejected \(requestBody)")),
        ])
        let broadcaster = makeBroadcaster(transport: transport)

        do {
            _ = try await broadcaster.broadcast(transaction, limits: limits)
            Issue.record("Expected an HTTP status error")
        } catch {
            let description = String(describing: error)
            let reflection = String(reflecting: error)
            #expect(!description.contains(transactionHex))
            #expect(!reflection.contains(transactionHex))
            #expect(!description.contains(requestBody))
            #expect(!reflection.contains(requestBody))
            #expect(!description.localizedCaseInsensitiveContains("txhex"))
            #expect(!reflection.localizedCaseInsensitiveContains("txhex"))
        }
    }

    @Test("redacts a long echoed transaction before bounding provider text")
    func longTransactionErrorRedaction() async throws {
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 2_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        let transaction = try longTransaction(limits: limits)
        let transactionHex = try transaction.hex(limits: limits)
        #expect(transactionHex.utf8.count > 1_024)
        let providerBody = "provider echoed {\"txhex\":\"\(transactionHex)\"}"
        let transport = ScriptedBroadcastTransport([
            .success(response(status: 400, body: providerBody)),
        ])

        do {
            _ = try await makeBroadcaster(transport: transport)
                .broadcast(transaction, limits: limits)
            Issue.record("Expected an HTTP status error")
        } catch let NetworkServiceError.httpStatus(_, message) {
            let message = try #require(message)
            let reflection = String(reflecting: NetworkServiceError.httpStatus(
                code: 400,
                message: message
            ))
            #expect(message.utf8.count <= 1_024)
            #expect(!message.localizedCaseInsensitiveContains("txhex"))
            #expect(!message.contains(String(repeating: "51", count: 32)))
            #expect(!reflection.contains(String(repeating: "51", count: 32)))
            #expect(!message.contains(String(transactionHex.prefix(1_024))))
            #expect(!reflection.contains(String(transactionHex.prefix(1_024))))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("broadcast policy and public broadcaster are bounded and Sendable")
    func defaultsAndSendable() {
        #expect(NetworkRequestPolicy.broadcast.requestTimeout == .seconds(15))
        #expect(NetworkRequestPolicy.broadcast.resourceTimeout == .seconds(30))
        #expect(NetworkRequestPolicy.broadcast.maximumResponseBodyByteCount == 65_536)
        #expect(NetworkRequestPolicy.broadcast.maximumAttempts == 1)
        acceptSendable(NetworkRequestPolicy.broadcast)
        acceptSendable(WhatsOnChainBroadcaster(network: .mainnet))
    }
}

private func makeBroadcaster(
    network: WhatsOnChainNetwork = .mainnet,
    policy: NetworkRequestPolicy = .broadcast,
    transport: any HTTPTransport
) -> WhatsOnChainBroadcaster {
    WhatsOnChainBroadcaster(network: network, policy: policy, transport: transport)
}

private func testLimits() throws -> TransactionLimits {
    try TransactionLimits(
        maximumTransactionByteCount: 1_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 100
    )
}

private func longTransaction(limits: TransactionLimits) throws -> Transaction {
    let scriptByteCount = 600
    let rawHex = "01000000" // version
        + "00" // input count
        + "01" // output count
        + "0000000000000000" // satoshis
        + "fd5802" // 600-byte CompactSize
        + String(repeating: "51", count: scriptByteCount)
        + "00000000" // lock time
    return try Transaction(hex: rawHex, limits: limits)
}

private func broadcastPolicy(maximumAttempts: Int) throws -> NetworkRequestPolicy {
    try NetworkRequestPolicy(
        requestTimeout: .seconds(15),
        resourceTimeout: .seconds(30),
        maximumResponseBodyByteCount: 65_536,
        maximumAttempts: maximumAttempts,
        initialBackoff: .milliseconds(1),
        maximumBackoff: .milliseconds(2)
    )
}

private func successResponse(_ transactionID: String) -> HTTPResponse {
    response(status: 200, body: transactionID)
}

private func response(status: Int, body: String) -> HTTPResponse {
    HTTPResponse(statusCode: status, body: Data(body.utf8))
}

private actor ScriptedBroadcastTransport: HTTPTransport {
    private var results: [Result<HTTPResponse, NetworkServiceError>]
    private var requests: [HTTPRequest] = []
    private var maximumBodyCounts: [Int] = []

    init(_ results: [Result<HTTPResponse, NetworkServiceError>]) {
        self.results = results
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        requests.append(request)
        maximumBodyCounts.append(maximumResponseBodyByteCount)
        guard !results.isEmpty else {
            throw NetworkServiceError.malformedResponse
        }
        return try results.removeFirst().get()
    }

    func attemptCount() -> Int { requests.count }
    func recordedRequests() -> [HTTPRequest] { requests }
    func recordedMaximumBodyCounts() -> [Int] { maximumBodyCounts }
}

private actor CancellationBroadcastTransport: HTTPTransport {
    private var attempts = 0

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        attempts += 1
        try await Task.sleep(for: .seconds(60))
        throw NetworkServiceError.malformedResponse
    }

    func attemptCount() -> Int { attempts }
}

private func acceptSendable<T: Sendable>(_ value: T) {}
