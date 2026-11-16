import BSVCore
import BSVOverlay
import BSVScript
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

    // A 4-transaction, 2-BUMP BEEF from `@bsv/sdk` `Beef.toBinary`, and
    // `toBinaryAtomic` of B (`transaction/Beef.ts:385-475`). M1 is proven by
    // BUMP 0 and M2 by BUMP 1; A spends M1:0 and B spends M2:0; the records are
    // written M1, M2, B, A. Atomic B keeps only BUMP 1, renumbered 0. The
    // records arrive parents first, so the bytes match TS; when a child comes
    // before its parents, Swift may write the kept BUMPs in another order.
    static let bumpedShared =
        "0200beef02640102000243c78955a7a87a2d73710d5f5708974577bbb50254cc172bee459f74345368ab"
        + "0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6501020000aaaaaa"
        + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0102de3b6fbd6a1b017db43276"
        + "5e31d2136d875f36d3583641d36bf794139b72bbdf0401000100000000010b0000000000000001530000"
        + "000001010100000000010c00000000000000015400000000000100000001de3b6fbd6a1b017db432765e"
        + "31d2136d875f36d3583641d36bf794139b72bbdf000000000151ffffffff02060000000000000001570700"
        + "00000000000001580000000000010000000143c78955a7a87a2d73710d5f5708974577bbb50254cc172b"
        + "ee459f74345368ab000000000151ffffffff010500000000000000015600000000"
    static let bumpedTransactionB = "72a7517cdd5eaab0a408c353151deb54740dee851816c940dc83938c3d0b3d0e"
    static let bumpedAtomicB =
        "010101010e3d0b3d8c9383dc40c9161885ee0d7454eb1d1553c308a4b0aa5edd7c51a7720200beef0165"
        + "01020000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0102de3b6fbd"
        + "6a1b017db432765e31d2136d875f36d3583641d36bf794139b72bbdf0201000100000000010c00000000"
        + "000000015400000000000100000001de3b6fbd6a1b017db432765e31d2136d875f36d3583641d36bf794"
        + "139b72bbdf000000000151ffffffff02060000000000000001570700000000000000015800000000"

    @Test("S4: Atomic BEEF keeps and renumbers only the Merkle paths its records use")
    func aggregatedAnswerWithMerklePaths() async throws {
        var body = CompactSize.encode(1)
        body.append(contentsOf: try TransactionID(displayHex: Self.bumpedTransactionB).displayBytes)
        body.append(contentsOf: CompactSize.encode(1))
        body.append(contentsOf: CompactSize.encode(0))
        body.append(contentsOf: try bytes(Self.bumpedShared))
        let answer = try await lookup(body: body, contentType: "application/octet-stream")
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output list")
            return
        }
        #expect(outputs.count == 1)
        #expect(outputs[0].beef == (try bytes(Self.bumpedAtomicB)))
        let limits = try beefLimits()
        let transaction = try outputs[0].transaction(beefLimits: limits)
        #expect(
            try transaction.transactionID(limits: limits.transactionLimits).displayHex
                == Self.bumpedTransactionB)
    }

    @Test("S1: only a missing ancestor falls back to the shared BEEF")
    func atomicFailureIsNotSwallowed() async throws {
        // B alone: its Atomic BEEF is 36 bytes longer than the shared BEEF, so
        // a BEEF limit equal to the shared size admits the answer but not the
        // Atomic BEEF. That must fail the answer, not quietly hand back the
        // shared BEEF.
        let shared = Array(try bytes(Self.atomicB).dropFirst(36))
        var body = CompactSize.encode(1)
        body.append(contentsOf: try TransactionID(displayHex: Self.transactionB).displayBytes)
        body.append(contentsOf: CompactSize.encode(0))
        body.append(contentsOf: CompactSize.encode(0))
        body.append(contentsOf: shared)
        let tight = try beefLimits(maximumByteCount: shared.count)
        await #expect(throws: OverlayHTTPError.resourceLimit) {
            _ = try await lookup(body: body, contentType: "application/octet-stream", beefLimits: tight)
        }
    }

    @Test("S2: an output's transaction is public API")
    func publicOutputTransaction() throws {
        let limits = try beefLimits()
        let shared = Array(try bytes(Self.aggregatedAnswer).suffix(131))
        for (id, satoshis) in [(Self.transactionA, UInt64(4)), (Self.transactionB, UInt64(1))] {
            let item = try OutputListItem(
                beef: shared, outputIndex: 0, transactionID: try TransactionID(displayHex: id))
            #expect(try item.transaction(beefLimits: limits).outputs[0].satoshis == satoshis)
        }
        let missing = try OutputListItem(
            beef: Array(try bytes(Self.atomicB).dropFirst(36)), outputIndex: 0,
            transactionID: try TransactionID(displayHex: Self.transactionA))
        #expect(throws: OverlayPolicyError.invalidLookupOutput) {
            _ = try missing.transaction(beefLimits: limits)
        }
    }

    @Test("S8: JSON answers are read without building every value")
    func jsonReaderShapes() async throws {
        let beef = Array(try bytes(Self.atomicB).dropFirst(36))
        let numbers = beef.map(String.init).joined(separator: ",")
        let keyed = beef.enumerated().reversed().map { "\"\($0.offset)\":\($0.element)" }
            .joined(separator: ",")
        let bodies = [
            // `outputs` before `type`, unknown nested values, whitespace.
            "{ \"outputs\" : [ {\"skip\":[[1,2],{\"a\":\"]}\\\"\"}],\"beef\": [\(numbers)] ,\"outputIndex\":1.0} ], \"type\":\"output-list\" }",
            // Numeric-key object in any key order.
            "{\"type\":\"output-list\",\"outputs\":[{\"outputIndex\":1,\"beef\":{\(keyed)}}]}",
        ]
        for body in bodies {
            let answer = try await lookup(body: Array(body.utf8), contentType: "application/json")
            guard case .outputList(let outputs) = answer else {
                Issue.record("Expected an output list")
                return
            }
            #expect(outputs.count == 1)
            #expect(outputs[0].beef == beef)
            #expect(outputs[0].outputIndex == 1)
        }

        // A freeform answer ignores `outputs`, whatever it holds.
        #expect(
            try await lookup(
                body: Array(#"{"outputs":7,"type":"freeform","result":[1,"a"]}"#.utf8),
                contentType: "application/json") == .freeform(Array(#"[1,"a"]"#.utf8)))

        // Repeated or out-of-range numeric keys, and non-byte elements, are malformed.
        for body in [
            #"{"type":"output-list","outputs":[{"beef":{"0":1,"2":1},"outputIndex":0}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[1,true],"outputIndex":0}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[1,1.5],"outputIndex":0}]}"#,
            #"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":"0"}]}"#,
            #"{"type":"output-list","outputs":{}}"#,
            #"{"type":1,"outputs":[]}"#,
            #"[{"type":"output-list"}]"#,
        ] {
            await #expect(throws: OverlayHTTPError.malformedResponse, "\(body)") {
                _ = try await lookup(body: Array(body.utf8), contentType: "application/json")
            }
        }
    }

    @Test("S8: a freeform result's text is bounded before it is parsed")
    func freeformTextBound() async throws {
        let limits = try OverlayLimits(
            maximumTaggedBEEFByteCount: 1_024,
            maximumOffChainValueByteCount: 1_024,
            maximumTopicCount: 16,
            maximumTopicUTF8ByteCount: 256,
            maximumServiceUTF8ByteCount: 256,
            maximumHostUTF8ByteCount: 2_048,
            maximumMetadataUTF8ByteCount: 1_024,
            maximumLookupQueryByteCount: 1_024,
            maximumLookupOutputCount: 16,
            maximumLookupOutputBEEFByteCount: 1_024,
            maximumFreeformByteCount: 64
        )
        let padded = "{\"type\":\"freeform\",\"result\":[1" + String(repeating: " ", count: 200) + "]}"
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: try OverlayHTTPConfiguration(overlayLimits: limits, beefLimits: beefLimits()),
            transport: OverlayTSRecordingTransport(
                response: HTTPResponse(
                    statusCode: 200, headers: ["Content-Type": "application/json"],
                    body: Data(padded.utf8))
            )
        )
        await #expect(throws: OverlayHTTPError.resourceLimit) {
            _ = try await facilitator.lookup(
                question: LookupQuestion(
                    service: OverlayService(rawValue: "ls_test"), query: [0x7b, 0x7d]),
                at: OverlayHost(rawValue: "https://overlay.example"))
        }
    }

    @Test("N5: an instruction object with no keys is malformed, as validateSTEAK finds")
    func emptyInstructionObject() async throws {
        let topic = try OverlayTopic(rawValue: "tm_test")
        await #expect(throws: OverlayHTTPError.malformedResponse) {
            _ = try await submit(responseBody: #"{"tm_test":{}}"#, topics: [topic])
        }
    }

    @Test("N6: a JSON answer over the answer limit is a resource limit")
    func oversizedJSONAnswer() throws {
        let configuration = try OverlayHTTPConfiguration(beefLimits: beefLimits())
        let limit = configuration.overlayLimits.maximumLookupAnswerByteCount
        let body = [UInt8]("{\"type\":\"freeform\",\"result\":\"".utf8)
            + [UInt8](repeating: 0x61, count: limit) + [UInt8]("\"}".utf8)
        #expect(throws: OverlayHTTPError.resourceLimit) {
            _ = try OverlayHTTPCodec.lookupJSONResponse(body, configuration: configuration)
        }
    }

    @Test("M1: Atomic BEEF built for an aggregated chain stops at the answer limit")
    func aggregatedChainIsBounded() throws {
        // 900 unproven transactions, each spending the one before and each
        // listed as an output: about 1 MB on the wire, but Atomic BEEF i holds
        // i transactions, so building all of them would take about 400 MB.
        // The build must stop once the answer limit is passed. Before the
        // fix this took about 40 seconds and 900 MB.
        let beefLimits = try beefLimits()
        let pad = [UInt8](repeating: 0, count: 1_000)
        let script = try Script(bytes: [0x00, 0x6a, 0x4d, 0xe8, 0x03] + pad, maximumByteCount: 2_000)
        let unlocking = try Script(bytes: [0x51], maximumByteCount: 1)
        var transactions: [BEEFTransaction] = []
        var identifiers: [TransactionID] = []
        for _ in 0..<900 {
            let inputs = identifiers.last.map {
                [
                    TransactionInput(
                        previousOutput: Outpoint(transactionID: $0, outputIndex: 0),
                        unlockingScript: unlocking)
                ]
            } ?? []
            let transaction = Transaction(
                inputs: inputs, outputs: [TransactionOutput(satoshis: 1, lockingScript: script)])
            identifiers.append(try transaction.transactionID(limits: beefLimits.transactionLimits))
            transactions.append(.raw(transaction))
        }
        let shared = try BEEF(
            version: .v2, merklePaths: [], transactions: transactions, limits: beefLimits
        ).serialized(limits: beefLimits)
        var body = CompactSize.encode(UInt64(identifiers.count))
        for identifier in identifiers {
            body.append(contentsOf: identifier.displayBytes)
            body.append(contentsOf: CompactSize.encode(0))
            body.append(contentsOf: CompactSize.encode(0))
        }
        body.append(contentsOf: shared)

        let configuration = try OverlayHTTPConfiguration(
            overlayLimits: try OverlayLimits(
                maximumTaggedBEEFByteCount: 1_024,
                maximumOffChainValueByteCount: 1_024,
                maximumTopicCount: 16,
                maximumTopicUTF8ByteCount: 256,
                maximumServiceUTF8ByteCount: 256,
                maximumHostUTF8ByteCount: 2_048,
                maximumMetadataUTF8ByteCount: 1_024,
                maximumLookupQueryByteCount: 1_024,
                maximumLookupOutputCount: 1_000,
                maximumLookupOutputBEEFByteCount: 32 * 1_024 * 1_024,
                maximumLookupAnswerByteCount: 4 * 1_024 * 1_024,
                maximumFreeformByteCount: 1_024
            ),
            beefLimits: beefLimits
        )
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            #expect(throws: OverlayHTTPError.resourceLimit) {
                _ = try OverlayHTTPCodec.lookupBinaryResponse(body, configuration: configuration)
            }
        }
        #expect(elapsed < .seconds(10))
    }

    // MARK: Helpers

    private func lookup(
        body: [UInt8],
        contentType: String,
        beefLimits: BEEFLimits? = nil
    ) async throws -> LookupAnswer {
        let facilitator = HTTPSOverlayLookupFacilitator(
            configuration: try OverlayHTTPConfiguration(beefLimits: beefLimits ?? self.beefLimits()),
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

    private func beefLimits(maximumByteCount: Int = 32 * 1_024 * 1_024) throws -> BEEFLimits {
        try BEEFLimits(
            maximumByteCount: maximumByteCount,
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
