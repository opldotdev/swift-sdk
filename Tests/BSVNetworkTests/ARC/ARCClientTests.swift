import BSVCore
import BSVTransaction
import Foundation
@testable import BSVNetwork
import Testing

@Suite("ARC broadcaster and status client")
struct ARCClientTests {
    @Test("builds exact POST URL, headers, and Extended Format body")
    func exactBroadcastRequest() async throws {
        let transaction = try transactionWithSourceOutput()
        let transactionID = try transaction.transactionID(limits: limits)
        let transport = ARCMockTransport([
            .success(arcResponse(transactionID: transactionID)),
        ])
        let configuration = try ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com/v1")!,
            apiKey: "api-secret",
            callbackURL: URL(string: "https://callback.example.com/hook?q=1")!,
            callbackToken: "callback-secret",
            callbackBatch: true,
            fullStatusUpdates: true,
            maximumTimeoutSeconds: 30,
            skipFeeValidation: true,
            skipScriptValidation: true,
            skipTransactionValidation: true,
            cumulativeFeeValidation: true,
            waitForStatus: "MINED",
            waitFor: .mined
        )
        let client = makeClient(
            configuration: configuration,
            broadcastTransport: transport
        )

        _ = try await client.submit(transaction, limits: limits)

        let request = try #require(await transport.requests().first)
        #expect(request.method == .post)
        #expect(request.url.absoluteString == "https://arc.example.com/v1/tx")
        #expect(request.headers == [
            "Authorization": "Bearer api-secret",
            "Content-Type": "application/octet-stream",
            "X-CallbackUrl": "https://callback.example.com/hook?q=1",
            "X-CallbackToken": "callback-secret",
            "X-CallbackBatch": "true",
            "X-FullStatusUpdates": "true",
            "X-MaxTimeout": "30",
            "X-SkipFeeValidation": "true",
            "X-SkipScriptValidation": "true",
            "X-SkipTxValidation": "true",
            "X-CumulativeFeeValidation": "true",
            "X-WaitForStatus": "MINED",
            "X-WaitFor": "MINED",
        ])
        #expect(request.body == Data(try transaction.serialized(
            format: .extended,
            limits: limits
        )))
        #expect(await transport.maximumBodyCounts() == [65_536])
    }

    @Test("status uses exact display txid URL and only authorization")
    func exactStatusRequest() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let transport = ARCMockTransport([
            .success(arcStatusResponse(transactionID: transactionID, txStatus: "MINED")),
        ])
        let configuration = try ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com")!,
            apiKey: "status-secret",
            callbackToken: "not-sent-on-get",
            waitFor: .confirmed
        )
        let client = makeClient(configuration: configuration, statusTransport: transport)

        let response = try await client.status(for: transactionID)

        #expect(response.transactionID == transactionID)
        let request = try #require(await transport.requests().first)
        #expect(request.method == .get)
        #expect(request.url.absoluteString ==
            "https://arc.example.com/tx/\(transactionID.displayHex)")
        #expect(request.headers == ["Authorization": "Bearer status-secret"])
        #expect(request.body == nil)
    }

    @Test("pins strict HTTPS base URL and trailing-slash rejection")
    func configurationValidation() throws {
        _ = try ARCConfiguration(baseURL: URL(string: "https://arc.example.com/path")!)

        for text in [
            "http://arc.example.com",
            "https://arc.example.com/",
            "https://user:password@arc.example.com",
            "https://arc.example.com?query=1",
            "https://arc.example.com#fragment",
        ] {
            #expect(throws: NetworkServiceError.invalidConfiguration) {
                try ARCConfiguration(baseURL: URL(string: text)!)
            }
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try ARCConfiguration(
                baseURL: URL(string: "https://arc.example.com")!,
                apiKey: "unsafe\r\nheader"
            )
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try ARCConfiguration(
                baseURL: URL(string: "https://arc.example.com")!,
                callbackURL: URL(string: "http://callback.example.com")!
            )
        }
        let longHost = String(repeating: "a", count: 2_100)
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try ARCConfiguration(baseURL: URL(string: "https://\(longHost).example")!)
        }

        let exactHeader = String(repeating: "a", count: 8_192)
        _ = try ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com")!,
            apiKey: exactHeader,
            callbackToken: exactHeader,
            waitForStatus: exactHeader
        )
        for value in [
            String(repeating: "a", count: 8_193),
            "bad\nvalue",
            "bad\u{200b}value",
        ] {
            #expect(throws: NetworkServiceError.invalidConfiguration) {
                try ARCConfiguration(
                    baseURL: URL(string: "https://arc.example.com")!,
                    callbackToken: value
                )
            }
            #expect(throws: NetworkServiceError.invalidConfiguration) {
                try ARCConfiguration(
                    baseURL: URL(string: "https://arc.example.com")!,
                    waitForStatus: value
                )
            }
        }
        #expect(throws: NetworkServiceError.invalidConfiguration) {
            try ARCConfiguration(
                baseURL: URL(string: "https://arc.example.com")!,
                waitFor: ARCStatus(rawValue: "bad\u{0000}value")
            )
        }
        for text in [
            "https://user:password@callback.example.com/hook",
            "https://callback.example.com/hook#fragment",
        ] {
            #expect(throws: NetworkServiceError.invalidConfiguration) {
                try ARCConfiguration(
                    baseURL: URL(string: "https://arc.example.com")!,
                    callbackURL: URL(string: text)!
                )
            }
        }
    }

    @Test("selects EF vacuously for zero inputs and for complete source metadata")
    func extendedFormatSelection() async throws {
        let transactions = [Transaction(), try transactionWithSourceOutput()]
        for transaction in transactions {
            let transactionID = try transaction.transactionID(limits: limits)
            let transport = ARCMockTransport([
                .success(arcResponse(transactionID: transactionID)),
            ])
            _ = try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
            let body = try #require(await transport.requests().first?.body)
            #expect(body == Data(try transaction.serialized(
                format: .extended,
                limits: limits
            )))
            #expect(body != Data(try transaction.serialized(
                format: .raw,
                limits: limits
            )))
        }
    }

    @Test("one missing source output selects raw format")
    func rawFormatSelection() async throws {
        let transaction = try transactionWithoutSourceOutput()
        let transactionID = try transaction.transactionID(limits: limits)
        let transport = ARCMockTransport([
            .success(arcResponse(transactionID: transactionID)),
        ])

        _ = try await makeClient(broadcastTransport: transport)
            .submit(transaction, limits: limits)

        let request = try #require(await transport.requests().first)
        #expect(request.headers == ["Content-Type": "application/octet-stream"])
        #expect(request.body == Data(
            try transaction.serialized(format: .raw, limits: limits)
        ))
    }

    @Test("EF serialization failure propagates without raw fallback or POST")
    func extendedFormatFailureDoesNotFallback() async throws {
        let transaction = try transactionWithSourceOutput()
        let rawCount = try transaction.serializedByteCount(format: .raw, limits: limits)
        let constrained = try TransactionLimits(
            maximumTransactionByteCount: rawCount,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 100
        )
        let transport = ARCMockTransport([])
        await #expect(throws: TransactionError.transactionTooLarge(
            actual: try transaction.serializedByteCount(format: .extended, limits: limits),
            maximum: rawCount
        )) {
            try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: constrained)
        }
        #expect(await transport.attemptCount() == 0)
    }

    @Test("preserves official, legacy, and unknown future statuses")
    func statuses() async throws {
        let known: [(ARCStatus, String)] = [
            (.rejected, "REJECTED"),
            (.unknown, "UNKNOWN"),
            (.queued, "QUEUED"),
            (.received, "RECEIVED"),
            (.stored, "STORED"),
            (.announcedToNetwork, "ANNOUNCED_TO_NETWORK"),
            (.requestedByNetwork, "REQUESTED_BY_NETWORK"),
            (.sentToNetwork, "SENT_TO_NETWORK"),
            (.acceptedByNetwork, "ACCEPTED_BY_NETWORK"),
            (.seenOnNetwork, "SEEN_ON_NETWORK"),
            (.mined, "MINED"),
            (.minedInStaleBlock, "MINED_IN_STALE_BLOCK"),
            (.confirmed, "CONFIRMED"),
            (.doubleSpendAttempted, "DOUBLE_SPEND_ATTEMPTED"),
            (.seenInOrphanMempool, "SEEN_IN_ORPHAN_MEMPOOL"),
        ]
        let transactionID = try Transaction().transactionID(limits: limits)
        let values = known.map(\.1) + ["FUTURE_PROVIDER_STATUS"]
        let transport = ARCMockTransport(values.map {
            .success(arcResponse(transactionID: transactionID, txStatus: $0))
        })
        let client = makeClient(statusTransport: transport)

        for (expected, raw) in known {
            let response = try await client.status(for: transactionID)
            #expect(response.txStatus == expected)
            #expect(response.txStatus?.rawValue == raw)
        }
        #expect(try await client.status(for: transactionID).txStatus ==
            ARCStatus(rawValue: "FUTURE_PROVIDER_STATUS"))

        let future = ARCStatus(rawValue: "DEADBEEF")
        let encoded = try JSONEncoder().encode(future)
        #expect(encoded == Data("\"DEADBEEF\"".utf8))
        #expect(try JSONDecoder().decode(ARCStatus.self, from: encoded) == future)
    }

    @Test("uses operation-specific required fields and strict types")
    func loadBearingFields() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let officialStatus = ARCMockTransport([
            .success(arcStatusResponse(
                transactionID: transactionID,
                txStatus: "QUEUED"
            )),
        ])
        let parsed = try await makeClient(statusTransport: officialStatus)
            .status(for: transactionID)
        #expect(parsed.status == nil)
        #expect(parsed.txStatus == .queued)

        let timestamp = "\"timestamp\":\"2026-08-08T12:00:00Z\""
        let invalid = [
            "{\(timestamp),\"status\":200,\"txid\":\"\(transactionID.displayHex)\"}",
            "{\(timestamp),\"status\":200,\"txStatus\":\"QUEUED\"}",
            "{\(timestamp),\"status\":true,\"txStatus\":\"QUEUED\",\"txid\":\"\(transactionID.displayHex)\"}",
            "{\(timestamp),\"status\":200.0,\"txStatus\":\"QUEUED\",\"txid\":\"\(transactionID.displayHex)\"}",
            "{\(timestamp),\"status\":200,\"txStatus\":7,\"txid\":\"\(transactionID.displayHex)\"}",
            "{\(timestamp),\"status\":200,\"txStatus\":\"QUEUED\",\"txid\":7}",
            "{\(timestamp),\"status\":200,\"txStatus\":\"QUEUED\",\"txid\":\"ABC\"}",
            "{\(timestamp),\"status\":200,\"txStatus\":\"QUEUED\",\"txid\":\"\(transactionID.displayHex.uppercased())\"}",
            "{\"txStatus\":\"QUEUED\",\"txid\":\"\(transactionID.displayHex)\"}",
        ]

        for json in invalid {
            let transport = ARCMockTransport([.success(response(body: json))])
            await #expect(throws: NetworkServiceError.malformedResponse) {
                try await makeClient(statusTransport: transport).status(for: transactionID)
            }
        }
    }

    @Test("ignores wrong-type optional metadata")
    func lossyOptionalMetadata() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let json = """
        {"status":200,"txStatus":"QUEUED","txid":"\(transactionID.displayHex)",
         "blockHash":7,"blockHeight":9.0,"extraInfo":false,
         "timestamp":"2026-08-08T12:00:00Z",
         "title":[],"instance":{},"detail":42,"merklePath":true}
        """
        let transport = ARCMockTransport([.success(response(body: json))])

        let parsed = try await makeClient(statusTransport: transport)
            .status(for: transactionID)

        #expect(parsed.blockHash == nil)
        #expect(parsed.blockHeight == nil)
        #expect(parsed.extraInfo == nil)
        #expect(parsed.timestamp != nil)
        #expect(parsed.title == nil)
        #expect(parsed.instance == nil)
        #expect(parsed.detail == nil)
        #expect(parsed.merklePath == nil)

        let malformedTimestamp = """
        {"txStatus":"QUEUED","txid":"\(transactionID.displayHex)",
         "timestamp":"not-a-date"}
        """
        let malformedTransport = ARCMockTransport([
            .success(response(body: malformedTimestamp)),
        ])
        await #expect(throws: NetworkServiceError.malformedResponse) {
            try await makeClient(statusTransport: malformedTransport)
                .status(for: transactionID)
        }
    }

    @Test("decodes bounded integer, timestamp, and status metadata")
    func platformSensitiveMetadata() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let heightCases: [(String, UInt64?)] = [
            ("0", 0),
            ("4294967295", 4_294_967_295),
            ("18446744073709551615", .max),
            ("-1", nil),
            ("4294967296", 4_294_967_296),
            ("true", nil),
            ("1.5", nil),
            ("\"1\"", nil),
        ]
        for (rawHeight, expected) in heightCases {
            let json = """
            {"status":200,"txStatus":"QUEUED","txid":"\(transactionID.displayHex)",
             "blockHeight":\(rawHeight)}
            """
            let parsed = try ARCResponse(body: Data(json.utf8), redacting: [])
            #expect(parsed.blockHeight == expected)
        }

        let whole = try ARCResponse(body: try arcJSONData(
            transactionID: transactionID,
            txStatus: "QUEUED",
            optional: ["timestamp": "2026-08-08T12:00:00Z"]
        ), redacting: [])
        let fractional = try ARCResponse(body: try arcJSONData(
            transactionID: transactionID,
            txStatus: "QUEUED",
            optional: ["timestamp": "2026-08-08T12:00:00.000Z"]
        ), redacting: [])
        #expect(whole.timestamp != nil)
        #expect(fractional.timestamp == whole.timestamp)

        let exactStatus = String(repeating: "A", count: 128)
        let accepted = try ARCResponse(body: try arcJSONData(
            transactionID: transactionID,
            txStatus: exactStatus
        ), redacting: [])
        #expect(accepted.txStatus?.rawValue == exactStatus)

        for invalidStatus in [
            String(repeating: "A", count: 129),
            "",
            "\u{202e}\u{200b}",
            "\n\t",
        ] {
            #expect(throws: NetworkServiceError.malformedResponse) {
                try ARCResponse(body: try arcJSONData(
                    transactionID: transactionID,
                    txStatus: invalidStatus
                ), redacting: [])
            }
        }
    }

    @Test("accepts only canonical lowercase hexadecimal block and merkle metadata")
    func canonicalHexMetadata() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let blockHash = String(repeating: "ab", count: 32)
        let merklePath = String(repeating: "cd", count: 100)
        let cases: [(String, String, String, String?, String?)] = [
            ("valid", blockHash, merklePath, blockHash, merklePath),
            (
                "format-scalars",
                String(blockHash.prefix(32)) + "\u{202e}\u{200b}" + blockHash.dropFirst(32),
                String(merklePath.prefix(100)) + "\u{202e}\u{200b}" + merklePath.dropFirst(100),
                nil,
                nil
            ),
            (
                "maximum-merkle-bound",
                blockHash,
                String(repeating: "ab", count: 32_768),
                blockHash,
                String(repeating: "ab", count: 32_768)
            ),
            ("uppercase", blockHash.uppercased(), merklePath.uppercased(), nil, nil),
            ("odd", String(blockHash.dropLast()), "abc", nil, nil),
            ("nonhex", String(blockHash.dropLast()) + "g", "cdg0", nil, nil),
            ("truncated", String(blockHash.dropLast(2)), "", nil, nil),
            (
                "overlong",
                blockHash + "00",
                String(repeating: "ab", count: 32_769),
                nil,
                nil
            ),
        ]

        for (name, candidateBlock, candidateMerkle, expectedBlock, expectedMerkle) in cases {
            let body = try JSONSerialization.data(withJSONObject: [
                "status": 200,
                "txStatus": "DEADBEEF",
                "txid": transactionID.displayHex,
                "blockHash": candidateBlock,
                "merklePath": candidateMerkle,
            ])
            let parsed = try ARCResponse(body: body, redacting: [])

            #expect(parsed.txStatus?.rawValue == "DEADBEEF", Comment(rawValue: name))
            #expect(parsed.blockHash == expectedBlock, Comment(rawValue: name))
            #expect(parsed.merklePath == expectedMerkle, Comment(rawValue: name))
        }
    }

    @Test("sanitizes every surfaced provider prose field")
    func responseStringSanitization() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let secret = "provider-secret"
        let obfuscatedSecret = "provider\u{202e}\u{200b}-secret"
        let json = """
        {"status":200,"txStatus":"FUTURE_STATUS","txid":"\(transactionID.displayHex)",
         "timestamp":"2026-08-08T12:00:00Z",
         "title":"title\\n \(obfuscatedSecret)",
         "extraInfo":"extra\\u0000 \(obfuscatedSecret)",
         "detail":"detail\\r \(obfuscatedSecret)",
         "instance":"instance\\t \(obfuscatedSecret)"}
        """
        let transport = ARCMockTransport([.success(response(body: json))])
        let configuration = try ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com")!,
            apiKey: secret
        )

        let parsed = try await makeClient(
            configuration: configuration,
            statusTransport: transport
        ).status(for: transactionID)

        for value in [parsed.title, parsed.extraInfo, parsed.detail, parsed.instance] {
            let value = try #require(value)
            #expect(!value.contains(secret))
            #expect(!value.contains(where: { $0.isNewline }))
            #expect(!value.unicodeScalars.contains("\u{202e}"))
            #expect(!value.unicodeScalars.contains("\u{200b}"))
            #expect(value.contains("[redacted]"))
            #expect(value.utf8.count <= 1_024)
        }
        #expect(parsed.txStatus?.rawValue == "FUTURE_STATUS")
    }

    @Test("non-2xx parseable rejection remains an explicit ARC rejection")
    func nonSuccessHTTPRejectedPayload() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let transport = ARCMockTransport([
            .success(arcResponse(
                httpStatus: 422,
                transactionID: transactionID,
                payloadStatus: 400,
                txStatus: "REJECTED"
            )),
        ])

        do {
            _ = try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
            Issue.record("Expected rejection")
        } catch let ARCError.rejected(httpStatusCode, response) {
            #expect(httpStatusCode == 422)
            #expect(response.status == 400)
            #expect(response.txStatus == .rejected)
            #expect(response.transactionID == transactionID)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("official validation error without txStatus is an explicit rejection")
    func officialValidationErrorPayload() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let rejectionStatuses = [
            460, 461, 462, 463, 464, 465, 467, 468, 469, 471, 472, 473,
        ]
        for status in rejectionStatuses {
            let body = """
            {"status":\(status),"title":"Validation failed","detail":"Invalid transaction",
             "txid":"\(transactionID.displayHex)"}
            """
            let transport = ARCMockTransport([
                .success(response(status: status, body: body)),
            ])

            do {
                _ = try await makeClient(broadcastTransport: transport)
                    .submit(transaction, limits: limits)
                Issue.record("Expected rejection for ARC status \(status)")
            } catch let ARCError.rejected(httpStatusCode, response) {
                #expect(httpStatusCode == status)
                #expect(response.status == status)
                #expect(response.txStatus == nil)
                #expect(response.transactionID == transactionID)
            } catch {
                Issue.record("Unexpected error for ARC status \(status): \(error)")
            }
            #expect(await transport.attemptCount() == 1)
        }

        for status in [466, 474, 475] {
            let conflictBody = """
            {"status":\(status),"title":"Unknown result",
             "detail":"No documented definite rejection",
             "txid":"\(transactionID.displayHex)"}
            """
            let conflict = ARCMockTransport([
                .success(response(status: status, body: conflictBody)),
            ])
            await #expect(throws: ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: .providerResponse(httpStatusCode: status, status: status)
            )) {
                try await makeClient(broadcastTransport: conflict)
                    .submit(transaction, limits: limits)
            }
            #expect(await conflict.attemptCount() == 1)
        }
    }

    @Test("POST requires the official success fields without semantic repair")
    func officialSubmissionFields() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let requiredFields = [
            "\"status\":200",
            "\"title\":\"OK\"",
            "\"timestamp\":\"2026-08-08T12:00:00Z\"",
            "\"txStatus\":\"QUEUED\"",
            "\"txid\":\"\(transactionID.displayHex)\"",
        ]

        for missingIndex in requiredFields.indices {
            let body = "{" + requiredFields.enumerated().compactMap { index, field in
                index == missingIndex ? nil : field
            }.joined(separator: ",") + "}"
            let transport = ARCMockTransport([.success(response(body: body))])
            let cause: ARCUncertainDeliveryCause = switch missingIndex {
            case 0:
                .providerResponse(httpStatusCode: 200, status: nil)
            case 1, 2, 3:
                .providerResponse(httpStatusCode: 200, status: 200)
            default:
                .invalidResponse
            }
            await #expect(throws: ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: cause
            )) {
                try await makeClient(broadcastTransport: transport)
                    .submit(transaction, limits: limits)
            }
            #expect(await transport.attemptCount() == 1)
        }

        let malformedStatus = """
        {"status":200,"title":"OK","timestamp":"2026-08-08T12:00:00Z",
         "txStatus":"REJ\\nECTED","txid":"\(transactionID.displayHex)"}
        """
        let transport = ARCMockTransport([
            .success(response(body: malformedStatus)),
        ])
        await #expect(throws: ARCError.uncertainDelivery(
            transactionID: transactionID,
            cause: .invalidResponse
        )) {
            try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("requires both HTTP and ARC payload success and handles rejection")
    func semanticSuccessAndFailure() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)

        let alternateSuccess = ARCMockTransport([
            .success(arcResponse(httpStatus: 201, transactionID: transactionID)),
        ])
        #expect(try await makeClient(broadcastTransport: alternateSuccess)
            .submit(transaction, limits: limits).status == 200)

        for httpStatus in [100, 300, 400, 404, 500] {
            let transport = ARCMockTransport([
                .success(arcResponse(
                    httpStatus: httpStatus,
                    transactionID: transactionID,
                    payloadStatus: 200
                )),
            ])
            await #expect(throws: ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: .providerResponse(
                    httpStatusCode: httpStatus,
                    status: 200
                )
            )) {
                try await makeClient(broadcastTransport: transport)
                    .submit(transaction, limits: limits)
            }
        }

        let payloadFailure = ARCMockTransport([
            .success(arcResponse(transactionID: transactionID, payloadStatus: 500)),
        ])
        await #expect(throws: ARCError.uncertainDelivery(
            transactionID: transactionID,
            cause: .providerResponse(httpStatusCode: 200, status: 500)
        )) {
            try await makeClient(broadcastTransport: payloadFailure)
                .submit(transaction, limits: limits)
        }

        let rejected = ARCMockTransport([
            .success(arcResponse(
                transactionID: transactionID,
                payloadStatus: 400,
                txStatus: "REJECTED"
            )),
        ])
        do {
            _ = try await makeClient(broadcastTransport: rejected)
                .submit(transaction, limits: limits)
            Issue.record("Expected rejection")
        } catch let ARCError.rejected(httpStatusCode, response) {
            #expect(httpStatusCode == 200)
            #expect(response.txStatus == .rejected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("rejects a provider txid that differs from the local or queried txid")
    func mismatchedTransactionID() async throws {
        let transaction = Transaction()
        let local = try transaction.transactionID(limits: limits)
        let other = try Transaction(version: 2).transactionID(limits: limits)

        let post = ARCMockTransport([.success(arcResponse(transactionID: other))])
        await #expect(throws: ARCError.uncertainDelivery(
            transactionID: local,
            cause: .invalidResponse
        )) {
            try await makeClient(broadcastTransport: post)
                .submit(transaction, limits: limits)
        }

        let get = ARCMockTransport([.success(arcResponse(transactionID: other))])
        await #expect(throws: NetworkServiceError.inconsistentResponse) {
            try await makeClient(statusTransport: get).status(for: local)
        }
    }

    @Test("malformed POST response is uncertain delivery")
    func malformedPOSTResponse() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let transport = ARCMockTransport([
            .success(response(body: "{not-json")),
        ])

        await #expect(throws: ARCError.uncertainDelivery(
            transactionID: transactionID,
            cause: .invalidResponse
        )) {
            try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("non-JSON HTTP failures expose only bounded redacted text")
    func sanitizedHTTPFailure() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let secret = "very-secret-token"
        let unsafe = "failed\\n \(secret) " + String(repeating: "x", count: 2_000)
        let transport = ARCMockTransport([
            .success(HTTPResponse(statusCode: 401, body: Data(unsafe.utf8))),
        ])
        let configuration = try ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com")!,
            apiKey: secret
        )

        do {
            _ = try await makeClient(
                configuration: configuration,
                statusTransport: transport
            ).status(for: transactionID)
            Issue.record("Expected HTTP failure")
        } catch let NetworkServiceError.httpStatus(code, message) {
            #expect(code == 401)
            let message = try #require(message)
            #expect(!message.contains(secret))
            #expect(!message.contains("\n"))
            #expect(message.contains("[redacted]"))
            #expect(message.utf8.count <= 1_024)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("POST never retries and transport loss is uncertain delivery")
    func noPostRetryAndUncertainDelivery() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let cases: [(NetworkServiceError, ARCUncertainDeliveryCause)] = [
            (.timedOut, .timedOut),
            (.transport(code: -1005), .transport(code: -1005)),
            (.cancelled, .cancelled),
        ]
        for (failure, expectedCause) in cases {
            let transport = ARCMockTransport([
                .failure(failure),
                .success(arcResponse(transactionID: transactionID)),
            ])
            do {
                _ = try await makeClient(
                    broadcastPolicy: try policy(maximumAttempts: 5),
                    broadcastTransport: transport
                ).submit(transaction, limits: limits)
                Issue.record("Expected uncertain delivery")
            } catch let ARCError.uncertainDelivery(returnedID, cause) {
                #expect(returnedID == transactionID)
                #expect(cause == expectedCause)
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
            #expect(await transport.attemptCount() == 1)
        }
    }

    @Test("cancellation before POST returns cancelled without a request")
    func cancellationBeforePOST() async throws {
        let transport = ARCMockTransport([])
        let transaction = Transaction()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
        }

        await #expect(throws: NetworkServiceError.cancelled) {
            try await task.value
        }
        #expect(await transport.attemptCount() == 0)
    }

    @Test("a complete valid POST response remains definite after cancellation")
    func cancellationAfterPOSTResponse() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let transport = ARCCancelOnReturnTransport(
            response: arcResponse(transactionID: transactionID)
        )
        let task = Task {
            try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
        }

        let response = try await task.value
        #expect(response.transactionID == transactionID)
        #expect(response.status == 200)
        #expect(await transport.attemptCount() == 1)
    }

    @Test("POST does not retry uncertain redirect or response-limit failures")
    func noPostRetryForDeterministicFailures() async throws {
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let cases: [(NetworkServiceError, ARCUncertainDeliveryCause)] = [
            (.redirect(statusCode: 307), .redirect(statusCode: 307)),
            (
                .responseBodyTooLarge(maximumByteCount: 65_536),
                .responseBodyTooLarge(maximumByteCount: 65_536)
            ),
        ]
        for (failure, cause) in cases {
            let transport = ARCMockTransport([.failure(failure)])
            await #expect(throws: ARCError.uncertainDelivery(
                transactionID: transactionID,
                cause: cause
            )) {
                try await makeClient(
                    broadcastPolicy: try policy(maximumAttempts: 5),
                    broadcastTransport: transport
                ).submit(transaction, limits: limits)
            }
            #expect(await transport.attemptCount() == 1)
        }
    }

    @Test("cancellation after POST begins is prompt and uncertain")
    func postCancellation() async throws {
        let transport = ARCStallingTransport()
        let transaction = Transaction()
        let transactionID = try transaction.transactionID(limits: limits)
        let task = Task {
            try await makeClient(broadcastTransport: transport)
                .submit(transaction, limits: limits)
        }
        while await transport.attemptCount() == 0 { await Task.yield() }
        task.cancel()

        await #expect(throws: ARCError.uncertainDelivery(
            transactionID: transactionID,
            cause: .cancelled
        )) {
            try await task.value
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("status retries only bounded transient failures")
    func statusRetries() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let transport = ARCMockTransport([
            .failure(.transport(code: -1005)),
            .success(HTTPResponse(
                statusCode: 429,
                headers: ["retry-after": "999"],
                body: Data()
            )),
            .success(arcResponse(transactionID: transactionID)),
        ])
        let sleeper = ARCRecordingSleeper()
        let client = makeClient(statusTransport: transport, sleeper: sleeper)

        #expect(try await client.status(for: transactionID).txStatus == .queued)
        #expect(await transport.attemptCount() == 3)
        #expect(await sleeper.durations() == [.milliseconds(350), .seconds(2)])
    }

    @Test("status stops during cancelled backoff")
    func statusCancellationDuringBackoff() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let transport = ARCMockTransport([
            .failure(.transport(code: -1005)),
            .success(arcResponse(transactionID: transactionID)),
        ])
        let sleeper = ARCStallingSleeper()
        let task = Task {
            try await makeClient(
                statusPolicy: try policy(maximumAttempts: 3),
                statusTransport: transport,
                sleeper: sleeper
            ).status(for: transactionID)
        }
        while await sleeper.attemptCount() == 0 { await Task.yield() }
        task.cancel()

        await #expect(throws: NetworkServiceError.cancelled) {
            try await task.value
        }
        #expect(await transport.attemptCount() == 1)
        #expect(await sleeper.attemptCount() == 1)
    }

    @Test("status exhausts the retry limit and returns the final error")
    func statusRetryExhaustion() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let final = NetworkServiceError.transport(code: -1009)
        let transport = ARCMockTransport([
            .failure(.timedOut),
            .failure(.transport(code: -1005)),
            .failure(final),
            .success(arcResponse(transactionID: transactionID)),
        ])
        let sleeper = ARCRecordingSleeper()

        await #expect(throws: final) {
            try await makeClient(
                statusPolicy: try policy(maximumAttempts: 3),
                statusTransport: transport,
                sleeper: sleeper
            ).status(for: transactionID)
        }
        #expect(await transport.attemptCount() == 3)
        #expect(await sleeper.durations() == [.milliseconds(350), .milliseconds(700)])
    }

    @Test("oversized transient response is not retried")
    func oversizedTransientResponseDoesNotRetry() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let transport = ARCMockTransport([
            .success(HTTPResponse(
                statusCode: 503,
                body: Data(repeating: 0x61, count: 65_537)
            )),
            .success(arcResponse(transactionID: transactionID)),
        ])

        await #expect(throws: NetworkServiceError.responseBodyTooLarge(
            maximumByteCount: 65_536
        )) {
            try await makeClient(
                statusPolicy: try policy(maximumAttempts: 3),
                statusTransport: transport
            ).status(for: transactionID)
        }
        #expect(await transport.attemptCount() == 1)
    }

    @Test("accepts an exact 64 KiB valid response")
    func exactResponseLimit() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let core = arcResponseData(transactionID: transactionID)
        let paddingCount = 65_536 - core.count
        let exact = core + Data(repeating: 0x20, count: paddingCount)
        #expect(exact.count == 65_536)
        let transport = ARCMockTransport([
            .success(HTTPResponse(statusCode: 200, body: exact)),
        ])

        let response = try await makeClient(statusTransport: transport)
            .status(for: transactionID)
        #expect(response.transactionID == transactionID)
        #expect(await transport.maximumBodyCounts() == [65_536])
    }

    @Test("status does not retry deterministic, redirect, or cancellation failures")
    func statusNoRetry() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        for error in [
            NetworkServiceError.cancelled,
            .redirect(statusCode: 307),
            .responseBodyTooLarge(maximumByteCount: 65_536),
            .malformedResponse,
        ] {
            let transport = ARCMockTransport([.failure(error)])
            await #expect(throws: error) {
                try await makeClient(statusTransport: transport).status(for: transactionID)
            }
            #expect(await transport.attemptCount() == 1)
        }
    }

    @Test("enforces the 64 KiB response cap even with a larger policy")
    func responseLimit() async throws {
        let transactionID = try Transaction().transactionID(limits: limits)
        let oversized = HTTPResponse(
            statusCode: 200,
            body: Data(repeating: 0x61, count: 65_537)
        )
        let transport = ARCMockTransport([.success(oversized)])
        let generous = try NetworkRequestPolicy(
            requestTimeout: .seconds(1),
            resourceTimeout: .seconds(2),
            maximumResponseBodyByteCount: 1_000_000,
            maximumAttempts: 1,
            initialBackoff: .zero,
            maximumBackoff: .zero
        )

        await #expect(throws: NetworkServiceError.responseBodyTooLarge(
            maximumByteCount: 65_536
        )) {
            try await makeClient(
                statusPolicy: generous,
                statusTransport: transport
            ).status(for: transactionID)
        }
        #expect(await transport.maximumBodyCounts() == [65_536])

        let transaction = Transaction()
        let postTransport = ARCMockTransport([.success(oversized)])
        let transactionIDForPost = try transaction.transactionID(limits: limits)
        await #expect(throws: ARCError.uncertainDelivery(
            transactionID: transactionIDForPost,
            cause: .responseBodyTooLarge(maximumByteCount: 65_536)
        )) {
            try await makeClient(
                broadcastPolicy: generous,
                broadcastTransport: postTransport
            ).submit(transaction, limits: limits)
        }
        #expect(await postTransport.maximumBodyCounts() == [65_536])
    }

    @Test("configuration and client redact credentials in descriptions and reflection")
    func credentialRedaction() throws {
        let apiKey = "api-sentinel-secret"
        let callbackToken = "callback-sentinel-secret"
        let configuration = try ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com")!,
            apiKey: apiKey,
            callbackToken: callbackToken
        )
        let client = ARCClient(configuration: configuration)

        for text in [
            configuration.description,
            String(reflecting: configuration),
            String(describing: client),
            String(reflecting: client),
        ] {
            #expect(!text.contains(apiKey))
            #expect(!text.contains(callbackToken))
            #expect(text.contains("redacted"))
        }
        acceptSendable(configuration)
        acceptSendable(client)
        acceptHashable(configuration)
        acceptHashable(ARCStatus.mined)
    }
}

private let limits: TransactionLimits = {
    do {
        return try TransactionLimits(
            maximumTransactionByteCount: 1_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 100
        )
    } catch {
        preconditionFailure("Static ARC test limits must be valid")
    }
}()

private func transactionWithoutSourceOutput() throws -> Transaction {
    try Transaction(
        hex: "01000000" + "01" + String(repeating: "00", count: 32)
            + "00000000" + "00" + "ffffffff"
            + "01" + "0100000000000000" + "00" + "00000000",
        limits: limits
    )
}

private func transactionWithSourceOutput() throws -> Transaction {
    var transaction = try transactionWithoutSourceOutput()
    transaction.inputs[0].sourceOutput = transaction.outputs[0]
    return transaction
}

private func arcResponse(
    httpStatus: Int = 200,
    transactionID: TransactionID,
    payloadStatus: Int = 200,
    txStatus: String = "QUEUED"
) -> HTTPResponse {
    HTTPResponse(
        statusCode: httpStatus,
        body: arcResponseData(
            transactionID: transactionID,
            payloadStatus: payloadStatus,
            txStatus: txStatus
        )
    )
}

private func arcResponseData(
    transactionID: TransactionID,
    payloadStatus: Int = 200,
    txStatus: String = "QUEUED"
) -> Data {
    Data("""
    {"blockHash":"hash","blockHeight":7,"extraInfo":"extra","status":\(payloadStatus),
     "timestamp":"2026-08-08T12:00:00Z","title":"Accepted","txStatus":"\(txStatus)",
     "instance":"instance","txid":"\(transactionID.displayHex)","detail":"detail",
     "merklePath":"path"}
    """.utf8)
}

private func arcStatusResponse(
    transactionID: TransactionID,
    txStatus: String
) -> HTTPResponse {
    response(body: """
    {"timestamp":"2026-08-08T12:00:00Z","txStatus":"\(txStatus)",
     "txid":"\(transactionID.displayHex)"}
    """)
}

private func arcJSONData(
    transactionID: TransactionID,
    txStatus: String,
    optional: [String: Any] = [:]
) throws -> Data {
    var object: [String: Any] = [
        "status": 200,
        "txStatus": txStatus,
        "txid": transactionID.displayHex,
    ]
    for (key, value) in optional {
        object[key] = value
    }
    return try JSONSerialization.data(withJSONObject: object)
}

private func response(status: Int = 200, body: String) -> HTTPResponse {
    HTTPResponse(statusCode: status, body: Data(body.utf8))
}

private func policy(maximumAttempts: Int) throws -> NetworkRequestPolicy {
    try NetworkRequestPolicy(
        requestTimeout: .seconds(1),
        resourceTimeout: .seconds(2),
        maximumResponseBodyByteCount: 65_536,
        maximumAttempts: maximumAttempts,
        initialBackoff: .milliseconds(350),
        maximumBackoff: .seconds(2)
    )
}

private func makeClient(
    configuration: ARCConfiguration? = nil,
    broadcastPolicy: NetworkRequestPolicy = .broadcast,
    statusPolicy: NetworkRequestPolicy = .chainLookup,
    broadcastTransport: (any HTTPTransport)? = nil,
    statusTransport: (any HTTPTransport)? = nil,
    sleeper: any NetworkBackoffSleeper = ARCRecordingSleeper()
) -> ARCClient {
    let fallback = ARCMockTransport([])
    return ARCClient(
        configuration: configuration ?? (try! ARCConfiguration(
            baseURL: URL(string: "https://arc.example.com")!
        )),
        broadcastPolicy: broadcastPolicy,
        statusPolicy: statusPolicy,
        broadcastTransport: broadcastTransport ?? fallback,
        statusTransport: statusTransport ?? fallback,
        sleeper: sleeper
    )
}

private actor ARCMockTransport: HTTPTransport {
    private var results: [Result<HTTPResponse, NetworkServiceError>]
    private var recordedRequests: [HTTPRequest] = []
    private var recordedMaximumBodyCounts: [Int] = []

    init(_ results: [Result<HTTPResponse, NetworkServiceError>]) {
        self.results = results
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        recordedRequests.append(request)
        recordedMaximumBodyCounts.append(maximumResponseBodyByteCount)
        guard !results.isEmpty else { throw NetworkServiceError.malformedResponse }
        return try results.removeFirst().get()
    }

    func requests() -> [HTTPRequest] { recordedRequests }
    func maximumBodyCounts() -> [Int] { recordedMaximumBodyCounts }
    func attemptCount() -> Int { recordedRequests.count }
}

private actor ARCStallingTransport: HTTPTransport {
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

private actor ARCCancelOnReturnTransport: HTTPTransport {
    private let response: HTTPResponse
    private var attempts = 0

    init(response: HTTPResponse) {
        self.response = response
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        attempts += 1
        withUnsafeCurrentTask { $0?.cancel() }
        return response
    }

    func attemptCount() -> Int { attempts }
}

private actor ARCRecordingSleeper: NetworkBackoffSleeper {
    private var recorded: [Duration] = []

    func sleep(for duration: Duration) async throws {
        recorded.append(duration)
    }

    func durations() -> [Duration] { recorded }
}

private actor ARCStallingSleeper: NetworkBackoffSleeper {
    private var attempts = 0

    func sleep(for duration: Duration) async throws {
        attempts += 1
        try await Task.sleep(for: .seconds(60))
    }

    func attemptCount() -> Int { attempts }
}

private func acceptSendable<T: Sendable>(_ value: T) {}
private func acceptHashable<T: Hashable>(_ value: T) {}
