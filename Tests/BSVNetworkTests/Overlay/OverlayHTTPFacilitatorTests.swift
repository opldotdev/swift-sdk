import BSVCore
import BSVOverlay
import BSVScript
import BSVTransaction
import Foundation
import Testing

@testable import BSVNetwork

@Suite("Bounded overlay HTTP facilitators")
struct OverlayHTTPFacilitatorTests {
    @Test("lookup uses the exact Go endpoint, headers, and JSON shape")
    func lookupRequest() async throws {
        let response = HTTPResponse(
            statusCode: 200,
            headers: ["Content-Type": "application/json; charset=utf-8"],
            body: Data(#"{"type":"freeform","result":{"ok":true}}"#.utf8)
        )
        let transport = OverlayRecordingTransport(result: .success(response))
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: try configuration(),
            transport: transport
        )
        let question = try LookupQuestion(
            service: OverlayService(rawValue: "ls_test"),
            query: Array(#"{"value":1}"#.utf8)
        )
        let answer = try await facilitator.lookup(
            question: question,
            at: OverlayHost(rawValue: "https://overlay.example")
        )
        guard case .freeform(let result) = answer else {
            Issue.record("Expected freeform answer")
            return
        }
        #expect(String(decoding: result, as: UTF8.self) == #"{"ok":true}"#)

        let request = try #require(await transport.lastRequest())
        #expect(request.method == .post)
        #expect(request.url.absoluteString == "https://overlay.example/lookup")
        #expect(request.headers["Content-Type"] == "application/json")
        #expect(request.headers["X-Aggregation"] == "yes")
        #expect(
            request.body == Data(#"{"service":"ls_test","query":{"value":1}}"#.utf8)
        )
    }

    @Test("lookup JSON rejects duplicate, unknown, lossy, and oversized values")
    func strictLookupJSON() async throws {
        let bodies = [
            #"{"type":"freeform","type":"freeform","result":1}"#,
            #"{"type":"freeform","result":1,"extra":2}"#,
            #"{"type":"output-list","outputs":[{"beef":"AQ==","outputIndex":true}]}"#,
            #"{"type":"formula","result":{}}"#,
        ]
        for body in bodies {
            let facilitator = HTTPSOverlayLookupFacilitator(
                configuration: try configuration(),
                transport: OverlayRecordingTransport(
                    result: .success(
                        HTTPResponse(
                            statusCode: 200,
                            headers: ["Content-Type": "application/json"],
                            body: Data(body.utf8)
                        )
                    )
                )
            )
            await #expect(throws: OverlayHTTPError.malformedResponse) {
                try await facilitator.lookup(
                    question: try LookupQuestion(
                        service: OverlayService(rawValue: "ls_test"),
                        query: [0x6e, 0x75, 0x6c, 0x6c]
                    ),
                    at: OverlayHost(rawValue: "https://overlay.example")
                )
            }
        }

        let invalidQuestion = try LookupQuestion(
            service: OverlayService(rawValue: "ls_test"),
            query: Array(#"{"a":1,"a":2}"#.utf8)
        )
        let transport = OverlayRecordingTransport(
            result: .success(HTTPResponse(statusCode: 200, body: Data()))
        )
        await #expect(throws: OverlayHTTPError.invalidQuery) {
            try await HTTPSOverlayLookupFacilitator(
                configuration: configuration(), transport: transport
            ).lookup(
                question: invalidQuestion,
                at: OverlayHost(rawValue: "https://overlay.example")
            )
        }
        #expect(await transport.requestCount() == 0)
    }

    @Test("binary lookup validates canonical counts, BEEF, IDs, and output indexes")
    func binaryLookup() async throws {
        let fixture = try binaryFixture()
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: fixture.configuration,
            transport: OverlayRecordingTransport(
                result: .success(
                    HTTPResponse(
                        statusCode: 200,
                        headers: ["Content-Type": "application/octet-stream"],
                        body: Data(fixture.response)
                    )
                )
            )
        )
        let answer = try await facilitator.lookup(
            question: try LookupQuestion(
                service: OverlayService(rawValue: "ls_test"), query: [0x7b, 0x7d]
            ),
            at: OverlayHost(rawValue: "https://overlay.example")
        )
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected output list")
            return
        }
        #expect(outputs.count == 1)
        #expect(outputs[0].outputIndex == 0)
        #expect(outputs[0].beef == fixture.beef)

        var noncanonical = fixture.response
        noncanonical.replaceSubrange(0...0, with: [0xfd, 0x01, 0x00])
        await assertBinaryFailure(noncanonical, configuration: fixture.configuration)

        var badIndex = fixture.response
        badIndex[33] = 1
        await assertBinaryFailure(badIndex, configuration: fixture.configuration)

        var missingTransaction = fixture.response
        missingTransaction[1] ^= 0x01
        await assertBinaryFailure(missingTransaction, configuration: fixture.configuration)
    }

    @Test("topic submission is one POST and parses strict bounded STEAK")
    func topicSubmission() async throws {
        let transactionID = String(repeating: "01", count: 32)
        let responseBody = """
            {"tm_test":{"OutputsToAdmit":[0],"CoinsToRetain":[1],"CoinsRemoved":[],"AncillaryTxids":["\(transactionID)"]}}
            """
        let transport = OverlayRecordingTransport(
            result: .success(
                HTTPResponse(
                    statusCode: 200,
                    headers: ["Content-Type": "application/json"],
                    body: Data(responseBody.utf8)
                )
            )
        )
        let facilitator = HTTPSOverlayTopicFacilitator(
            configuration: try configuration(), transport: transport
        )
        let tagged = try TaggedBEEF(
            beef: [1, 2, 3], topics: [OverlayTopic(rawValue: "tm_test")]
        )
        let steak = try await facilitator.submit(
            tagged,
            to: OverlayHost(rawValue: "https://overlay.example")
        )
        #expect(steak.acknowledges(try OverlayTopic(rawValue: "tm_test")))
        let request = try #require(await transport.lastRequest())
        #expect(request.url.absoluteString == "https://overlay.example/submit")
        #expect(request.body == Data([1, 2, 3]))
        #expect(request.headers["X-Topics"] == #"["tm_test"]"#)
        #expect(await transport.requestCount() == 1)
    }

    @Test("host, response, cancellation, and uncertain delivery fail closed")
    func failures() async throws {
        let question = try LookupQuestion(
            service: OverlayService(rawValue: "ls_test"), query: [0x7b, 0x7d]
        )
        let lookupTransport = OverlayRecordingTransport(
            result: .success(HTTPResponse(statusCode: 200, body: Data()))
        )
        let lookup = HTTPSOverlayLookupFacilitator(
            configuration: try configuration(), transport: lookupTransport
        )
        for value in [
            "http://overlay.example", "https://user@overlay.example",
            "https://overlay.example/path", "https://overlay.example/",
        ] {
            await #expect(throws: OverlayHTTPError.invalidHost) {
                try await lookup.lookup(
                    question: question,
                    at: OverlayHost(rawValue: value)
                )
            }
        }
        #expect(await lookupTransport.requestCount() == 0)

        let tagged = try TaggedBEEF(
            beef: [1], topics: [OverlayTopic(rawValue: "tm_test")]
        )
        let topic = HTTPSOverlayTopicFacilitator(
            configuration: try configuration(),
            transport: OverlayRecordingTransport(result: .failure(NetworkServiceError.timedOut))
        )
        await #expect(throws: OverlayHTTPError.uncertainDelivery) {
            try await topic.submit(
                tagged,
                to: OverlayHost(rawValue: "https://overlay.example")
            )
        }
    }

    private func assertBinaryFailure(
        _ body: [UInt8],
        configuration: OverlayHTTPConfiguration
    ) async {
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: configuration,
            transport: OverlayRecordingTransport(
                result: .success(
                    HTTPResponse(
                        statusCode: 200,
                        headers: ["Content-Type": "application/octet-stream"],
                        body: Data(body)
                    )
                )
            )
        )
        await #expect(throws: OverlayHTTPError.self) {
            try await facilitator.lookup(
                question: LookupQuestion(
                    service: OverlayService(rawValue: "ls_test"), query: [0x7b, 0x7d]
                ),
                at: OverlayHost(rawValue: "https://overlay.example")
            )
        }
    }

    private func binaryFixture() throws -> (
        configuration: OverlayHTTPConfiguration,
        beef: [UInt8],
        response: [UInt8]
    ) {
        let limits = try beefLimits()
        let transaction = Transaction(
            outputs: [
                TransactionOutput(
                    satoshis: 1,
                    lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
                )
            ]
        )
        let transactionID = try transaction.transactionID(limits: limits.transactionLimits)
        let beef = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [.raw(transaction)],
            limits: limits
        ).serialized(limits: limits)
        var response = CompactSize.encode(1)
        response.append(contentsOf: transactionID.displayBytes)
        response.append(contentsOf: CompactSize.encode(0))
        response.append(contentsOf: CompactSize.encode(0))
        response.append(contentsOf: beef)
        return (
            try OverlayHTTPConfiguration(beefLimits: limits),
            beef,
            response
        )
    }

    private func configuration() throws -> OverlayHTTPConfiguration {
        try OverlayHTTPConfiguration(beefLimits: beefLimits())
    }

    private func beefLimits() throws -> BEEFLimits {
        let transactionLimits = try TransactionLimits(
            maximumTransactionByteCount: 1_000_000,
            maximumInputCount: 1_000,
            maximumOutputCount: 1_000,
            maximumScriptByteCount: 100_000
        )
        let merkleLimits = try MerklePathLimits(
            maximumByteCount: 1_000_000,
            maximumLeavesPerLevel: 1_000,
            maximumTotalLeaves: 1_000
        )
        return try BEEFLimits(
            maximumByteCount: 32 * 1_024 * 1_024,
            maximumMerklePathCount: 1_000,
            maximumTransactionCount: 1_000,
            transactionLimits: transactionLimits,
            merklePathLimits: merkleLimits
        )
    }
}

private actor OverlayRecordingTransport: HTTPTransport {
    private let result: Result<HTTPResponse, any Error>
    private var requests: [HTTPRequest] = []

    init(result: Result<HTTPResponse, any Error>) {
        self.result = result
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        requests.append(request)
        let response = try result.get()
        guard response.body.count <= maximumResponseBodyByteCount else {
            throw NetworkServiceError.responseBodyTooLarge(
                maximumByteCount: maximumResponseBodyByteCount
            )
        }
        return response
    }

    func lastRequest() -> HTTPRequest? { requests.last }
    func requestCount() -> Int { requests.count }
}
