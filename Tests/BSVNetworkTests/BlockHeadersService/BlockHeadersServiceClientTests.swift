import BSVCore
import BSVSPV
import Foundation
@testable import BSVNetwork
import Testing

@Suite("Block headers service client")
struct BlockHeadersServiceClientTests {
    @Test("uses the injected bounded transport with exact authenticated HTTPS URLs")
    func requestSurface() async throws {
        let header = fixtureHeader()
        let transport = ScriptedHeadersTransport([
            .success(headersResponse(height: 7, header: header)),
            .success(stateResponse(height: 7, header: header)),
            .success(stateResponse(height: 7, header: header)),
            .success(headersResponse(height: 7, header: header)),
            .success(stateResponse(height: 7, header: header)),
            .success(merkleRootsResponse(
                roots: [(height: 7, root: header.merkleRoot)],
                lastEvaluatedKey: header.hash
            )),
        ])
        let client = try makeClient(transport: transport)

        #expect(try await client.blockByHeight(7).hash == header.hash)
        #expect(try await client.state(for: header.hash).isLongestChain)
        #expect(try await client.isValidRoot(header.merkleRoot, atBlockHeight: 7))
        let page = try await client.merkleRoots(batchSize: 2, lastEvaluatedKey: header.hash)
        #expect(page.content == [BlockHeadersServiceMerkleRoot(
            merkleRoot: header.merkleRoot,
            blockHeight: 7
        )])
        #expect(page.lastEvaluatedKey == header.hash)

        let requests = await transport.requests()
        #expect(requests.map(\.method) == [.get, .get, .get, .get, .get, .get])
        #expect(requests.map(\.url.absoluteString) == [
            "https://headers.example.com/service/api/v1/chain/header/byHeight?height=7",
            "https://headers.example.com/service/api/v1/chain/header/state/\(header.hash.displayHex)",
            "https://headers.example.com/service/api/v1/chain/header/state/\(header.hash.displayHex)",
            "https://headers.example.com/service/api/v1/chain/header/byHeight?height=7",
            "https://headers.example.com/service/api/v1/chain/header/state/\(header.hash.displayHex)",
            "https://headers.example.com/service/api/v1/chain/merkleroot?batchSize=2&lastEvaluatedKey=\(header.hash.displayHex)",
        ])
        #expect(requests.allSatisfy { $0.headers == ["Authorization": "Bearer test-service-key"] })
        #expect(await transport.maximumBodyLimits() == Array(repeating: 1_024, count: 6))
    }

    @Test("selects only a matching longest-chain candidate")
    func longestChainSelection() async throws {
        let stale = fixtureHeader(timestamp: 11)
        let best = fixtureHeader(timestamp: 12)
        let transport = ScriptedHeadersTransport([
            .success(headersResponse(height: 44, headers: [stale, best])),
            .success(stateResponse(height: 44, header: stale, state: "STALE")),
            .success(stateResponse(height: 44, header: best)),
        ])
        let client = try makeClient(transport: transport)
        #expect(try await client.blockByHeight(44).hash == best.hash)

        let noLongest = ScriptedHeadersTransport([
            .success(headersResponse(height: 44, header: stale)),
            .success(stateResponse(height: 44, header: stale, state: "STALE")),
        ])
        let rejected = try makeClient(transport: noLongest)
        await #expect(throws: NetworkServiceError.inconsistentResponse) {
            try await rejected.blockByHeight(44)
        }
    }

    @Test("chain tip and current height require a consistent longest-chain state")
    func chainTipAndCurrentHeight() async throws {
        let header = fixtureHeader()
        let transport = ScriptedHeadersTransport([
            .success(stateResponse(height: 902_100, header: header)),
            .success(stateResponse(height: 902_100, header: header)),
        ])
        let client = try makeClient(transport: transport)
        #expect(try await client.chainTip().header.hash == header.hash)
        #expect(try await client.currentHeight() == 902_100)

        let stale = ScriptedHeadersTransport([
            .success(stateResponse(height: 902_100, header: header, state: "STALE")),
        ])
        let rejected = try makeClient(transport: stale)
        await #expect(throws: NetworkServiceError.inconsistentResponse) {
            try await rejected.chainTip()
        }
    }

    @Test("root verification uses the selected block header and preserves wire order")
    func rootVerification() async throws {
        let header = fixtureHeader()
        let transport = ScriptedHeadersTransport([
            .success(headersResponse(height: 19, header: header)),
            .success(stateResponse(height: 19, header: header)),
            .success(headersResponse(height: 19, header: header)),
            .success(stateResponse(height: 19, header: header)),
        ])
        let client = try makeClient(transport: transport)
        #expect(try await client.isValidRoot(header.merkleRoot, atBlockHeight: 19))
        #expect(!(try await client.isValidRoot(
            try Hash256(Array(header.merkleRoot.bytes.dropLast()) + [0xff]),
            atBlockHeight: 19
        )))
    }

    @Test("rejects noncanonical or inconsistent header, state, and numeric responses")
    func strictResponseValidation() async throws {
        let header = fixtureHeader()
        let valid = headersJSON(height: 3, headers: [header])
        let cases: [(String, String, NetworkServiceError)] = [
            ("empty", "[]", .malformedResponse),
            ("too-many", "[" + Array(repeating: headerJSON(height: 3, header: header), count: 65).joined(separator: ",") + "]", .malformedResponse),
            ("uppercase-hash", valid.replacingOccurrences(of: header.hash.displayHex, with: header.hash.displayHex.uppercased()), .malformedResponse),
            ("hash-mismatch", valid.replacingOccurrences(of: "\"hash\":\"\(header.hash.displayHex)\"", with: "\"hash\":\"" + String(repeating: "0", count: 64) + "\""), .inconsistentResponse),
            ("boolean-height", valid.replacingOccurrences(of: "\"height\":3", with: "\"height\":true"), .malformedResponse),
            ("floating-height", valid.replacingOccurrences(of: "\"height\":3", with: "\"height\":3.0"), .malformedResponse),
            ("missing-field", valid.replacingOccurrences(of: "\"nonce\":\(header.header.nonce),", with: ""), .malformedResponse),
        ]
        for (_, body, expected) in cases {
            let client = try makeClient(
                transport: ScriptedHeadersTransport([.success(response(status: 200, body: body))]),
                policy: try policy(maximumBody: 64 * 1_024)
            )
            await #expect(throws: expected) { try await client.blockByHeight(3) }
        }

        let mismatchedState = try makeClient(transport: ScriptedHeadersTransport([
            .success(stateResponse(
                height: 3,
                header: header,
                hashOverride: BlockHash(wireBytes: Array(repeating: 7, count: 32)).displayHex
            )),
        ]))
        await #expect(throws: NetworkServiceError.inconsistentResponse) {
            try await mismatchedState.state(for: header.hash)
        }

        let mismatchedHeight = try makeClient(transport: ScriptedHeadersTransport([
            .success(response(
                status: 200,
                body: "{\"header\":\(headerJSON(height: 2, header: header)),\"state\":\"LONGEST_CHAIN\",\"height\":3}"
            )),
        ]))
        await #expect(throws: NetworkServiceError.inconsistentResponse) {
            try await mismatchedHeight.state(for: header.hash)
        }
    }

    @Test("Merkle-root pages preserve cursors and enforce page, hash, and numeric bounds")
    func merkleRootPages() async throws {
        let header = fixtureHeader()
        let transport = ScriptedHeadersTransport([
            .success(merkleRootsResponse(
                roots: [(height: 0, root: header.merkleRoot), (height: UInt32.max, root: header.merkleRoot)],
                lastEvaluatedKey: header.hash
            )),
        ])
        let client = try makeClient(transport: transport)
        let page = try await client.merkleRoots(batchSize: 2)
        #expect(page.content.map(\.blockHeight) == [0, UInt32.max])
        #expect(page.lastEvaluatedKey == header.hash)

        for batchSize in [0, 1_001] {
            await #expect(throws: NetworkServiceError.invalidConfiguration) {
                try await client.merkleRoots(batchSize: batchSize)
            }
        }

        let oversized = try makeClient(transport: ScriptedHeadersTransport([
            .success(merkleRootsResponse(
                roots: [(height: 1, root: header.merkleRoot), (height: 2, root: header.merkleRoot)],
                lastEvaluatedKey: nil
            )),
        ]))
        await #expect(throws: NetworkServiceError.malformedResponse) {
            try await oversized.merkleRoots(batchSize: 1)
        }
        let malformed = try makeClient(transport: ScriptedHeadersTransport([
            .success(response(status: 200, body: "{\"content\":[{\"merkleRoot\":\"ABC\",\"blockHeight\":true}],\"page\":{}}")),
        ]))
        await #expect(throws: NetworkServiceError.malformedResponse) {
            try await malformed.merkleRoots(batchSize: 1)
        }
    }

    @Test("checks a status before parsing and returns bounded credential-redacted diagnostics")
    func statusAndRedaction() async throws {
        let unsafe = "Authorization: Bearer test-service-key\\n" + String(repeating: "a", count: 2_000)
        let client = try makeClient(
            transport: ScriptedHeadersTransport([.success(response(status: 418, body: unsafe))]),
            policy: try policy(maximumBody: 4_096)
        )
        do {
            _ = try await client.chainTip()
            Issue.record("Expected an HTTP error")
        } catch let NetworkServiceError.httpStatus(code, message) {
            #expect(code == 418)
            let message = try #require(message)
            #expect(!message.contains("test-service-key"))
            #expect(!message.contains("Authorization"))
            #expect(!message.contains("\n"))
            #expect(message.utf8.count <= 1_024)
        }

        let malformedStatus = try makeClient(transport: ScriptedHeadersTransport([
            .success(response(status: 503, body: "{")),
        ]), policy: try policy(maximumAttempts: 1))
        await #expect(throws: NetworkServiceError.httpStatus(code: 503, message: "{")) {
            try await malformedStatus.chainTip()
        }
    }

    @Test("bounds direct mock bodies and retries only transient GET failures")
    func boundsAndRetry() async throws {
        let header = fixtureHeader()
        let tooLarge = try makeClient(transport: ScriptedHeadersTransport([
            .success(HTTPResponse(statusCode: 200, body: Data(repeating: 0, count: 1_025))),
        ]))
        await #expect(throws: NetworkServiceError.responseBodyTooLarge(maximumByteCount: 1_024)) {
            try await tooLarge.chainTip()
        }

        let sleeper = RecordingHeadersSleeper()
        let transport = ScriptedHeadersTransport([
            .success(response(status: 503, body: "retry")),
            .failure(.timedOut),
            .success(stateResponse(height: 5, header: header)),
        ])
        let client = try makeClient(transport: transport, sleeper: sleeper)
        #expect(try await client.currentHeight() == 5)
        #expect(await transport.attemptCount() == 3)
        #expect(await sleeper.durations() == [.milliseconds(350), .milliseconds(700)])

        let deterministic = ScriptedHeadersTransport([.failure(.malformedResponse)])
        let noRetry = try makeClient(transport: deterministic)
        await #expect(throws: NetworkServiceError.malformedResponse) {
            try await noRetry.chainTip()
        }
        #expect(await deterministic.attemptCount() == 1)
    }

    @Test("cancellation is prompt and clients/configuration do not expose credentials")
    func cancellationAndSendableRedaction() async throws {
        let client = try makeClient(transport: CancellationAwareHeadersTransport())
        let task = Task { try await client.chainTip() }
        await Task.yield()
        task.cancel()
        await #expect(throws: NetworkServiceError.cancelled) { try await task.value }

        let configuration = try BlockHeadersServiceConfiguration(
            baseURL: URL(string: "https://headers.example.com")!,
            apiKey: "test-service-key"
        )
        #expect(!String(describing: configuration).contains("test-service-key"))
        #expect(!String(reflecting: configuration).contains("test-service-key"))
        #expect(!String(describing: client).contains("test-service-key"))
        #expect(Mirror(reflecting: configuration).children.isEmpty)
        #expect(Mirror(reflecting: client).children.isEmpty)
        acceptSendable(configuration)
        acceptSendable(client)
        acceptSendable(BlockHeadersServiceMerkleRootsPage(content: [], lastEvaluatedKey: nil))
    }

    @Test("configuration accepts only bounded credential-free HTTPS endpoints")
    func configurationValidation() throws {
        _ = try BlockHeadersServiceConfiguration(
            baseURL: URL(string: "https://headers.example.com/base")!,
            apiKey: "key"
        )
        for value in [
            "http://headers.example.com",
            "https://user:pass@headers.example.com",
            "https://headers.example.com/?query=1",
            "https://headers.example.com/#fragment",
            "https://headers.example.com/",
        ] {
            #expect(throws: NetworkServiceError.invalidConfiguration) {
                try BlockHeadersServiceConfiguration(
                    baseURL: try #require(URL(string: value)),
                    apiKey: "key"
                )
            }
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try BlockHeadersServiceConfiguration(
                baseURL: URL(string: "https://headers.example.com")!,
                apiKey: "bad\nkey"
            )
        }
    }
}

private func makeClient(
    transport: any HTTPTransport,
    policy: NetworkRequestPolicy = try! policy(),
    sleeper: any NetworkBackoffSleeper = RecordingHeadersSleeper()
) throws -> BlockHeadersServiceClient {
    BlockHeadersServiceClient(
        configuration: try BlockHeadersServiceConfiguration(
            baseURL: URL(string: "https://headers.example.com/service")!,
            apiKey: "test-service-key"
        ),
        policy: policy,
        transport: transport,
        sleeper: sleeper
    )
}

private func policy(
    maximumBody: Int = 1_024,
    maximumAttempts: Int = 3
) throws -> NetworkRequestPolicy {
    try NetworkRequestPolicy(
        requestTimeout: .seconds(1),
        resourceTimeout: .seconds(2),
        maximumResponseBodyByteCount: maximumBody,
        maximumAttempts: maximumAttempts,
        initialBackoff: .milliseconds(350),
        maximumBackoff: .seconds(2)
    )
}

private func fixtureHeader(timestamp: UInt32 = 10) -> BlockHeadersServiceHeader {
    let header = BlockHeader(
        version: 1,
        previousBlockHash: try! BlockHash(wireBytes: Array(repeating: 3, count: 32)),
        merkleRoot: try! Hash256(Array(0..<32)),
        timestamp: timestamp,
        bits: 0x1d00ffff,
        nonce: 99
    )
    return try! BlockHeadersServiceHeader(height: 0, hash: header.hash, header: header)
}

private func headersResponse(
    height: UInt32,
    header: BlockHeadersServiceHeader
) -> HTTPResponse {
    headersResponse(height: height, headers: [header])
}

private func headersResponse(
    height: UInt32,
    headers: [BlockHeadersServiceHeader]
) -> HTTPResponse {
    response(status: 200, body: headersJSON(height: height, headers: headers))
}

private func headersJSON(
    height: UInt32,
    headers: [BlockHeadersServiceHeader]
) -> String {
    "[" + headers.map { headerJSON(height: height, header: $0) }.joined(separator: ",") + "]"
}

private func headerJSON(height: UInt32, header: BlockHeadersServiceHeader) -> String {
    let block = header.header
    let displayRoot = Hex.encode(block.merkleRoot.bytes.reversed())
    return "{\"height\":\(height),\"hash\":\"\(header.hash.displayHex)\",\"version\":\(UInt32(bitPattern: block.version)),\"merkleRoot\":\"\(displayRoot)\",\"creationTimestamp\":\(block.timestamp),\"difficultyTarget\":\(block.bits),\"nonce\":\(block.nonce),\"prevBlockHash\":\"\(block.previousBlockHash.displayHex)\"}"
}

private func stateResponse(
    height: UInt32,
    header: BlockHeadersServiceHeader,
    state: String = "LONGEST_CHAIN",
    hashOverride: String? = nil
) -> HTTPResponse {
    var nested = headerJSON(height: height, header: header)
    if let hashOverride {
        nested = nested.replacingOccurrences(
            of: "\"hash\":\"\(header.hash.displayHex)\"",
            with: "\"hash\":\"\(hashOverride)\""
        )
    }
    return response(status: 200, body: "{\"header\":\(nested),\"state\":\"\(state)\",\"height\":\(height)}")
}

private func merkleRootsResponse(
    roots: [(height: UInt32, root: Hash256)],
    lastEvaluatedKey: BlockHash?
) -> HTTPResponse {
    let content = roots.map { root in
        "{\"merkleRoot\":\"\(Hex.encode(root.root.bytes.reversed()))\",\"blockHeight\":\(root.height)}"
    }.joined(separator: ",")
    let page = lastEvaluatedKey.map { "\"lastEvaluatedKey\":\"\($0.displayHex)\"" } ?? ""
    return response(status: 200, body: "{\"content\":[\(content)],\"page\":{\(page)}}")
}

private func response(status: Int, body: String) -> HTTPResponse {
    HTTPResponse(statusCode: status, body: Data(body.utf8))
}

private actor ScriptedHeadersTransport: HTTPTransport {
    private var results: [Result<HTTPResponse, NetworkServiceError>]
    private var recorded: [HTTPRequest] = []
    private var limits: [Int] = []

    init(_ results: [Result<HTTPResponse, NetworkServiceError>]) {
        self.results = results
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        recorded.append(request)
        limits.append(maximumResponseBodyByteCount)
        guard !results.isEmpty else { throw NetworkServiceError.malformedResponse }
        return try results.removeFirst().get()
    }

    func requests() -> [HTTPRequest] { recorded }
    func maximumBodyLimits() -> [Int] { limits }
    func attemptCount() -> Int { recorded.count }
}

private actor RecordingHeadersSleeper: NetworkBackoffSleeper {
    private var recorded: [Duration] = []

    func sleep(for duration: Duration) async throws {
        recorded.append(duration)
    }

    func durations() -> [Duration] { recorded }
}

private struct CancellationAwareHeadersTransport: HTTPTransport {
    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        try await Task.sleep(for: .seconds(60))
        return HTTPResponse(statusCode: 200, body: Data())
    }
}

private func acceptSendable<T: Sendable>(_ value: T) {}
