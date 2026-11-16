import BSVCore
import BSVOverlay
import BSVTransaction
import Foundation
import Testing

@testable import BSVNetwork

/// Wire vectors produced by `@bsv/sdk` 4.1.1 (ts-stack `3b1abc569`) running its
/// own code: the Overlay Express aggregation writer
/// (`packages/overlays/overlay-express/src/OverlayExpress.ts:3063-3093`), the
/// SDK's `HTTPSOverlayLookupFacilitator.lookup`
/// (`packages/sdk/src/overlay-tools/LookupResolver.ts:746-950`) and
/// `HTTPSOverlayBroadcastFacilitator.send`
/// (`packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:323-383`).
@Suite("Overlay HTTP matches the @bsv/sdk wire")
struct OverlayTSWireTests {
    // Transactions: P (no inputs, one 5-sat OP_1 output), A spends P:0 (one
    // OP_2 output), B (no inputs, outputs OP_3, OP_4, OP_5). The answer lists
    // A:0 with no context and B:1 with context [1, 2, 3] over one BEEF
    // holding P, B, A.
    static let transactionA = "3269c6da874a2e369c06c2329a8da3ab2946e09783362ab7d11adc9e2723f109"
    static let transactionB = "2353d778130b8437b4dd336eb5448a68ce53e0fbdf5e1b38b7b472f6cb804344"
    static let aggregatedAnswer =
        "023269c6da874a2e369c06c2329a8da3ab2946e09783362ab7d11adc9e2723f10900002353d778130b84"
        + "37b4dd336eb5448a68ce53e0fbdf5e1b38b7b472f6cb80434401030102030200beef0003000100000000"
        + "01050000000000000001510000000000010000000003010000000000000001530200000000000000015403"
        + "000000000000000155000000000001000000017465e7c7ce5f8ca7b7bc9e66daa2d47295beb8b1404835"
        + "6dee48f4838428ce77000000000151ffffffff010400000000000000015200000000"
    // `extractAtomicOutputs` output: `beefObj.toBinaryAtomic(txid)` per output.
    static let atomicA =
        "0101010109f123279edc1ad1b72a368397e04629aba38d9a32c2069c362e4a87dac669320200beef0002"
        + "0001000000000105000000000000000151000000000001000000017465e7c7ce5f8ca7b7bc9e66daa2d4"
        + "7295beb8b14048356dee48f4838428ce77000000000151ffffffff010400000000000000015200000000"
    static let atomicB =
        "01010101444380cbf672b4b7381b5edffbe053ce688a44b56e33ddb437840b1378d753230200beef0001"
        + "0001000000000301000000000000000153020000000000000001540300000000000000015500000000"

    @Test("O1: an aggregated answer gives each output its own transaction as Atomic BEEF")
    func aggregatedAnswerKeepsEachTransaction() async throws {
        let answer = try await lookup(
            body: try bytes(Self.aggregatedAnswer),
            contentType: "application/octet-stream"
        )
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        #expect(outputs.count == 2)
        #expect(outputs[0].beef == (try bytes(Self.atomicA)))
        #expect(outputs[0].outputIndex == 0)
        #expect(outputs[0].context == nil)
        #expect(outputs[0].transactionID == (try TransactionID(displayHex: Self.transactionA)))
        #expect(outputs[1].beef == (try bytes(Self.atomicB)))
        #expect(outputs[1].outputIndex == 1)
        #expect(outputs[1].context == [1, 2, 3])
        #expect(outputs[1].transactionID == (try TransactionID(displayHex: Self.transactionB)))

        let limits = try beefLimits()
        let first = try overlayLookupTransaction(for: outputs[0], beefLimits: limits)
        let second = try overlayLookupTransaction(for: outputs[1], beefLimits: limits)
        #expect(try first.transactionID(limits: limits.transactionLimits).displayHex == Self.transactionA)
        #expect(try second.transactionID(limits: limits.transactionLimits).displayHex == Self.transactionB)
        #expect(second.outputs[1].satoshis == 2)
    }

    @Test("O1: the resolver keeps every outpoint of an aggregated answer")
    func resolverKeepsAggregatedOutpoints() async throws {
        let transport = OverlayTSRecordingTransport(
            response: HTTPResponse(
                statusCode: 200,
                headers: ["Content-Type": "application/octet-stream"],
                body: Data(try bytes(Self.aggregatedAnswer))
            )
        )
        let service = try OverlayService(rawValue: "ls_test")
        let limits = try beefLimits()
        let resolver = try LookupResolver(
            facilitator: HTTPSOverlayLookupFacilitator(
                configuration: try OverlayHTTPConfiguration(beefLimits: limits),
                transport: transport
            ),
            slapTrackers: [],
            hostOverrides: [service: [OverlayHost(rawValue: "https://overlay.example")]],
            beefLimits: limits
        )
        let answer = try await resolver.resolve(LookupQuestion(service: service, query: [0x7b, 0x7d]))
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        let keys = try outputs.map { output in
            let transaction = try overlayLookupTransaction(for: output, beefLimits: limits)
            return "\(try transaction.transactionID(limits: limits.transactionLimits).displayHex):\(output.outputIndex)"
        }
        #expect(keys == ["\(Self.transactionB):1", "\(Self.transactionA):0"])
    }

    @Test("O1: an output whose ancestry is incomplete still names its own transaction")
    func aggregatedAnswerWithMissingAncestor() async throws {
        // The same answer with P removed from the BEEF: A spends a transaction
        // the envelope lacks, so no Atomic BEEF exists for A.
        let limits = try beefLimits()
        var cursor = try bytes(Self.aggregatedAnswer)
        let shared = Array(cursor[(cursor.count - 131)...])
        let beef = try BEEF(bytes: shared, limits: limits, transactionOrder: .any)
        let trimmed = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: beef.transactions.filter { $0.transaction?.outputs.first?.satoshis != 5 },
            limits: limits
        ).serialized(limits: limits)
        #expect(trimmed.count < shared.count)
        cursor.removeLast(131)
        cursor.append(contentsOf: trimmed)

        let answer = try await lookup(body: cursor, contentType: "application/octet-stream")
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        #expect(outputs[0].beef == trimmed)
        let first = try overlayLookupTransaction(for: outputs[0], beefLimits: limits)
        #expect(try first.transactionID(limits: limits.transactionLimits).displayHex == Self.transactionA)
        #expect(outputs[1].beef == (try bytes(Self.atomicB)))
    }

    @Test("O1: per-output context up to 1 MiB is accepted, as in @bsv/sdk")
    func largeContext() async throws {
        var body = CompactSize.encode(1)
        body.append(contentsOf: try TransactionID(displayHex: Self.transactionB).displayBytes)
        body.append(contentsOf: CompactSize.encode(0))
        let context = [UInt8](repeating: 7, count: 1_024 * 1_024)
        body.append(contentsOf: CompactSize.encode(UInt64(context.count)))
        body.append(contentsOf: context)
        body.append(contentsOf: Array(try bytes(Self.atomicB).dropFirst(36)))
        let answer = try await lookup(body: body, contentType: "application/octet-stream")
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        #expect(outputs[0].context?.count == context.count)

        body = CompactSize.encode(1)
        body.append(contentsOf: try TransactionID(displayHex: Self.transactionB).displayBytes)
        body.append(contentsOf: CompactSize.encode(0))
        body.append(contentsOf: CompactSize.encode(UInt64(context.count + 1)))
        body.append(contentsOf: context + [7])
        body.append(contentsOf: Array(try bytes(Self.atomicB).dropFirst(36)))
        await #expect(throws: OverlayHTTPError.resourceLimit) {
            _ = try await lookup(body: body, contentType: "application/octet-stream")
        }
    }

    @Test("O6: a JSON output list with byte arrays, context, and txid decodes")
    func jsonOutputList() async throws {
        // `res.json(result)` from Overlay Express with an engine result, as
        // `HTTPSOverlayLookupFacilitator` reads it (`LookupResolver.ts:327-358`).
        let json = #"{"type":"output-list","outputs":[{"beef":[1,0,190,239,0,1,1,0,0,0,0,3,1,0,0,0,0,0,0,0,1,83,2,0,0,0,0,0,0,0,1,84,3,0,0,0,0,0,0,0,1,85,0,0,0,0,0],"outputIndex":2,"context":[9,8],"txid":"2353d778130b8437b4dd336eb5448a68ce53e0fbdf5e1b38b7b472f6cb804344"}]}"#
        let answer = try await lookup(body: Array(json.utf8), contentType: "application/json; charset=utf-8")
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        #expect(outputs.count == 1)
        #expect(outputs[0].outputIndex == 2)
        #expect(outputs[0].context == [9, 8])
        #expect(outputs[0].transactionID == (try TransactionID(displayHex: Self.transactionB)))
        #expect(Array(outputs[0].beef.prefix(4)) == [1, 0, 190, 239])
        let limits = try beefLimits()
        let transaction = try overlayLookupTransaction(for: outputs[0], beefLimits: limits)
        #expect(transaction.outputs[2].satoshis == 3)

        let accepted = [
            #"{"type":"output-list","outputs":[]}"#,
            // Unknown keys are kept by `normalizeLookupOutput`; uppercase txid hex is valid.
            #"{"type":"output-list","outputs":[],"extra":1}"#,
            #"{"type":"output-list","outputs":[{"beef":{"0":1,"1":2},"outputIndex":0,"note":"x","txid":"2353D778130B8437B4DD336EB5448A68CE53E0FBDF5E1B38B7B472F6CB804344"}]}"#,
            // Go hosts write `[]byte` as base64.
            #"{"type":"output-list","outputs":[{"beef":"AQI=","outputIndex":0}]}"#,
            #"{"type":"freeform","result":{"ok":true},"extra":2}"#,
        ]
        for body in accepted {
            _ = try await lookup(body: Array(body.utf8), contentType: "application/json")
        }

        let rejected = [
            #"{"type":"output-list","outputs":[{"beef":[],"outputIndex":0}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[256],"outputIndex":0}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":-1}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":0,"context":null}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":0,"txid":"00"}]}"#,
            #"{"type":"output-list","outputs":[{"beef":{"1":1},"outputIndex":0}]}"#,
        ]
        for body in rejected {
            await #expect(throws: OverlayHTTPError.self) {
                _ = try await lookup(body: Array(body.utf8), contentType: "application/json")
            }
        }
    }

    @Test("O6: a JSON output's txid selects its transaction in a multi-transaction BEEF")
    func jsonTransactionIDSelects() async throws {
        let shared = Array(try bytes(Self.aggregatedAnswer).suffix(131))
        let json = """
            {"type":"output-list","outputs":[{"beef":\(shared),"outputIndex":0,"txid":"\(Self.transactionA)"}]}
            """
        let answer = try await lookup(body: Array(json.utf8), contentType: "application/json")
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        let limits = try beefLimits()
        let transaction = try overlayLookupTransaction(for: outputs[0], beefLimits: limits)
        #expect(try transaction.transactionID(limits: limits.transactionLimits).displayHex == Self.transactionA)
    }

    @Test("O2: camelCase STEAK from a TS host is an acknowledgment")
    func camelCaseSteak() async throws {
        // `validateSTEAK` (`SHIPBroadcaster.ts:237-262`) and the engine's
        // `{ outputsToAdmit, coinsToRetain }` shape.
        let topic = try OverlayTopic(rawValue: "tm_test")
        for body in [
            #"{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[]}}"#,
            #"{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#,
            #"{"tm_test":{"OutputsToAdmit":[0],"CoinsToRetain":null}}"#,
        ] {
            let steak = try await submit(responseBody: body, topics: [topic]).steak
            #expect(steak.acknowledges(topic))
        }
        for body in [
            #"{"tm_test":{"outputsToAdmit":[0]}}"#,
            #"{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":null}}"#,
            #"{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[],"extra":[]}}"#,
            #"{"tm_test":{"outputsToAdmit":[0],"CoinsToRetain":[]}}"#,
            #"{"tm_other":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#,
        ] {
            await #expect(throws: OverlayHTTPError.malformedResponse) {
                _ = try await submit(responseBody: body, topics: [topic])
            }
        }
    }

    @Test("O8 and O12: submit sends comma-separated topics and length-prefixed off-chain values")
    func submitRequestShape() async throws {
        let a = try OverlayTopic(rawValue: "tm_a")
        let b = try OverlayTopic(rawValue: "tm_b")
        let response = #"{"tm_a":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#
        let withValues = try await submit(
            responseBody: response,
            topics: [a, b],
            beef: [0xaa, 0xbb, 0xcc],
            offChainValues: [1, 2],
            host: "https://overlay.example/"
        ).request
        #expect(withValues.url.absoluteString == "https://overlay.example/submit")
        #expect(withValues.headers["X-Topics"] == "tm_a,tm_b")
        #expect(withValues.headers["x-includes-off-chain-values"] == "true")
        #expect(withValues.headers["Content-Type"] == "application/octet-stream")
        #expect(withValues.body == Data([0x03, 0xaa, 0xbb, 0xcc, 0x01, 0x02]))

        let plain = try await submit(
            responseBody: response,
            topics: [a],
            beef: [0xaa, 0xbb, 0xcc]
        ).request
        #expect(plain.headers["X-Topics"] == "tm_a")
        #expect(plain.headers["x-includes-off-chain-values"] == nil)
        #expect(plain.body == Data([0xaa, 0xbb, 0xcc]))
    }

    @Test("O14 and O18: an origin with one trailing slash, any 2xx, and any JSON content type work")
    func hostAndStatusRules() async throws {
        let transport = OverlayTSRecordingTransport(
            response: HTTPResponse(
                statusCode: 201,
                headers: ["Content-Type": "text/plain"],
                body: Data(#"{"type":"freeform","result":1}"#.utf8)
            )
        )
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: try OverlayHTTPConfiguration(beefLimits: beefLimits()),
            transport: transport
        )
        let answer = try await facilitator.lookup(
            question: LookupQuestion(service: OverlayService(rawValue: "ls_test"), query: [0x7b, 0x7d]),
            at: OverlayHost(rawValue: "https://overlay.example/")
        )
        #expect(answer == .freeform(Array("1".utf8)))
        #expect(await transport.lastRequest()?.url.absoluteString == "https://overlay.example/lookup")
    }

    // MARK: Helpers

    private func lookup(body: [UInt8], contentType: String) async throws -> LookupAnswer {
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: try OverlayHTTPConfiguration(beefLimits: beefLimits()),
            transport: OverlayTSRecordingTransport(
                response: HTTPResponse(
                    statusCode: 200,
                    headers: ["Content-Type": contentType],
                    body: Data(body)
                )
            )
        )
        return try await facilitator.lookup(
            question: LookupQuestion(service: OverlayService(rawValue: "ls_test"), query: [0x7b, 0x7d]),
            at: OverlayHost(rawValue: "https://overlay.example")
        )
    }

    private func submit(
        responseBody: String,
        topics: [OverlayTopic],
        beef: [UInt8] = [1, 2, 3],
        offChainValues: [UInt8] = [],
        host: String = "https://overlay.example"
    ) async throws -> (steak: Steak, request: HTTPRequest) {
        let transport = OverlayTSRecordingTransport(
            response: HTTPResponse(
                statusCode: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(responseBody.utf8)
            )
        )
        let facilitator = HTTPSOverlayTopicFacilitator(
            configuration: try OverlayHTTPConfiguration(beefLimits: beefLimits()),
            transport: transport
        )
        let steak = try await facilitator.submit(
            TaggedBEEF(beef: beef, topics: topics, offChainValues: offChainValues),
            to: OverlayHost(rawValue: host)
        )
        return (steak, try #require(await transport.lastRequest()))
    }

    private func bytes(_ hex: String) throws -> [UInt8] {
        try Hex.decode(hex, maximumDecodedByteCount: hex.utf8.count / 2)
    }

    private func beefLimits() throws -> BEEFLimits {
        try BEEFLimits(
            maximumByteCount: 32 * 1_024 * 1_024,
            maximumMerklePathCount: 1_000,
            maximumTransactionCount: 1_000,
            transactionLimits: try TransactionLimits(
                maximumTransactionByteCount: 1_000_000,
                maximumInputCount: 1_000,
                maximumOutputCount: 1_000,
                maximumScriptByteCount: 100_000
            ),
            merklePathLimits: try MerklePathLimits(
                maximumByteCount: 1_000_000,
                maximumLeavesPerLevel: 1_000,
                maximumTotalLeaves: 1_000
            )
        )
    }
}

private actor OverlayTSRecordingTransport: HTTPTransport {
    private let response: HTTPResponse
    private var requests: [HTTPRequest] = []

    init(response: HTTPResponse) {
        self.response = response
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        requests.append(request)
        return response
    }

    func lastRequest() -> HTTPRequest? { requests.last }
}
