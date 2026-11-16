import BSVCore
import BSVCrypto
import BSVKeys
import BSVOverlay
import BSVScript
import BSVStorage
import BSVTransaction
import Foundation
import Testing

@testable import BSVNetwork

@Suite("Bounded UHRP downloader")
struct UHRPDownloaderTests {
    @Test("discovery sends canonical query and returns sorted current hosts")
    func discovery() async throws {
        let identifier = try UHRPURL(fileBytes: [1, 2, 3])
        let limits = try beefLimits()
        let outputs = try [
            advertisement(
                identifier: identifier,
                host: "https://z.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://a.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://a.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://expired.example/file",
                expiry: 999,
                beefLimits: limits
            ),
        ]
        let resolver = UHRPRecordingResolver(
            answer: try LookupAnswer(outputList: outputs)
        )
        let downloader = UHRPDownloader(
            resolver: resolver,
            configuration: try configuration(beefLimits: limits),
            transport: UHRPRecordingTransport(responses: [:]),
            now: { 1_000 }
        )

        let hosts = try await downloader.hosts(for: identifier)
        #expect(
            hosts.map(\.absoluteString) == [
                "https://a.example/file", "https://z.example/file",
            ])
        let question = try #require(await resolver.lastQuestion())
        #expect(question.service.rawValue == "ls_uhrp")
        // TypeScript storage/StorageDownloader.ts:69-76 sends
        // { uhrpUrl, limit: 100, offset: 0 }.
        #expect(
            question.query
                == Array(
                    "{\"uhrpUrl\":\"\(identifier.encoded)\",\"limit\":100,\"offset\":0}".utf8)
        )
    }

    @Test("discovery rejects unbound and unsafe advertisements")
    func hostileAdvertisements() async throws {
        let identifier = try UHRPURL(fileBytes: [4, 5, 6])
        let other = try UHRPURL(fileBytes: [7, 8, 9])
        // Each output below breaks one rule of
        // storage/UHRPAdvertisementValidation.ts (TypeScript 4.1.1).
        let limits = try beefLimits()
        let outputs = try [
            advertisement(
                identifier: identifier,
                advertisedHash: other.hash.bytes,
                host: "https://wrong-hash.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "http://cleartext.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://user@example.com/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://example.com/file#fragment",
                expiry: 1_001,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://noncanonical.example/file",
                expiry: 1_001,
                expiryBytes: [0xfe, 0xe9, 0x03, 0, 0],
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://trailing.example/file",
                expiry: 1_001,
                expiryBytes: CompactSize.encode(1_001) + [0],
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://unlinked.example/file",
                expiry: 1_001,
                linkedLock: false,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://unsigned.example/file",
                expiry: 1_001,
                signed: false,
                beefLimits: limits
            ),
            previousSwiftAdvertisement(
                identifier: identifier,
                host: "https://four-field.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
            try OutputListItem(beef: [1], outputIndex: 0),
        ]
        let downloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(
                answer: try LookupAnswer(outputList: outputs)
            ),
            configuration: try configuration(beefLimits: limits),
            transport: UHRPRecordingTransport(responses: [:]),
            now: { 1_000 }
        )
        #expect(try await downloader.hosts(for: identifier).isEmpty)

        // Each skipped output keeps its reason.
        let lookup = try await downloader.advertisements(for: identifier)
        #expect(lookup.accepted.isEmpty)
        let reasons = lookup.rejected.map(\.reason)
        #expect(lookup.rejected.map(\.answerIndex) == Array(0..<10))
        #expect(
            Array(reasons.prefix(9)) == [
                .hashMismatch,
                .invalidAdvertisement(.invalidURL),
                .invalidAdvertisement(.invalidURL),
                .invalidAdvertisement(.invalidURL),
                .invalidAdvertisement(.invalidExpiryTime),
                .invalidAdvertisement(.invalidExpiryTime),
                .invalidAdvertisement(.lockingKeyNotLinkedToHost),
                .invalidAdvertisement(.invalidSignature),
                .invalidAdvertisement(.unexpectedFieldCount(actual: 4)),
            ])
        guard case .invalidTransaction(let detail) = reasons[9] else {
            Issue.record("expected an invalid transaction, got \(reasons[9])")
            return
        }
        #expect(!detail.isEmpty)

        // The final error carries the same list, with a short description
        // and the full list in debugDescription.
        do {
            _ = try await downloader.content(for: identifier)
            Issue.record("content(for:) should have failed")
        } catch let error as UHRPDownloadError {
            #expect(error == .noAvailableHosts(rejected: lookup.rejected))
            #expect(
                error.description
                    == "No current UHRP host advertisement is available (10 rejected; first: advertisement is for other content)"
            )
            #expect(error.debugDescription.split(separator: "\n").count == 11)
            #expect(error.debugDescription.contains("output 8: UHRP advertisement must have 6 fields (found 4)"))
        }
    }

    @Test("an empty lookup reports no advertisements")
    func emptyLookup() async throws {
        let identifier = try UHRPURL(fileBytes: [1])
        let downloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(answer: try LookupAnswer(outputList: [])),
            configuration: try configuration(beefLimits: try beefLimits()),
            transport: UHRPRecordingTransport(responses: [:]),
            now: { 0 }
        )
        await #expect(throws: UHRPDownloadError.noAvailableHosts(rejected: [])) {
            try await downloader.content(for: identifier)
        }
    }

    @Test("download tries each host once and verifies the content hash")
    func download() async throws {
        let bytes: [UInt8] = [10, 20, 30, 40]
        let identifier = try UHRPURL(fileBytes: bytes)
        let limits = try beefLimits()
        let outputs = try [
            advertisement(
                identifier: identifier,
                host: "https://a.example/file",
                expiry: 2_000,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://b.example/file",
                expiry: 2_000,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://c.example/file",
                expiry: 2_000,
                beefLimits: limits
            ),
        ]
        let transport = UHRPRecordingTransport(responses: [
            "https://a.example/file": .success(
                HTTPResponse(statusCode: 503, body: Data())
            ),
            "https://b.example/file": .success(
                HTTPResponse(statusCode: 200, body: Data([0]))
            ),
            "https://c.example/file": .success(
                HTTPResponse(
                    statusCode: 200,
                    headers: ["Content-Type": "application/octet-stream"],
                    body: Data(bytes)
                )
            ),
        ])
        let configuration = try configuration(
            beefLimits: limits,
            uhrpLimits: UHRPLimits(
                maximumURLUTF8ByteCount: 256,
                maximumContentByteCount: 4,
                maximumMIMETypeUTF8ByteCount: 64
            )
        )
        let downloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(
                answer: try LookupAnswer(outputList: outputs)
            ),
            configuration: configuration,
            transport: transport,
            now: { 1_000 }
        )

        let content = try await downloader.content(for: identifier)
        #expect(content.bytes == bytes)
        #expect(content.mimeType == "application/octet-stream")
        #expect(
            await transport.requestURLs() == [
                "https://a.example/file", "https://b.example/file", "https://c.example/file",
            ])
        #expect(await transport.responseLimits() == [4, 4, 4])
    }

    @Test("every failed host is reported with its reason")
    func allHostsFailed() async throws {
        let identifier = try UHRPURL(fileBytes: [10, 20, 30, 40])
        let limits = try beefLimits()
        let outputs = try ["a", "b", "c"].map {
            try advertisement(
                identifier: identifier,
                host: "https://\($0).example/file",
                expiry: 2_000,
                beefLimits: limits
            )
        }
        let transport = UHRPRecordingTransport(responses: [
            "https://a.example/file": .success(HTTPResponse(statusCode: 503, body: Data())),
            "https://b.example/file": .success(HTTPResponse(statusCode: 200, body: Data([0]))),
        ])
        let downloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(answer: try LookupAnswer(outputList: outputs)),
            configuration: try configuration(beefLimits: limits),
            transport: transport,
            now: { 1_000 }
        )
        let expected: [UHRPHostFailure] = [
            .init(host: URL(string: "https://a.example/file")!, reason: .httpStatus(503)),
            .init(host: URL(string: "https://b.example/file")!, reason: .contentHashMismatch),
            .init(
                host: URL(string: "https://c.example/file")!,
                reason: .transport(.transport(code: nil))
            ),
        ]
        do {
            _ = try await downloader.content(for: identifier)
            Issue.record("content(for:) should have failed")
        } catch let error as UHRPDownloadError {
            #expect(error == .allHostsFailed(expected))
            #expect(
                error.description
                    == "All 3 UHRP content hosts failed (first: https://a.example/file: HTTP status 503)"
            )
            #expect(error.debugDescription.contains("- https://b.example/file: content does not match its UHRP hash"))
        }
    }

    @Test("lookup form, counts, and cancellation fail closed")
    func boundaries() async throws {
        let identifier = try UHRPURL(fileBytes: [1])
        let limits = try beefLimits()
        let freeformDownloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(answer: try LookupAnswer(freeform: [1])),
            configuration: try configuration(beefLimits: limits),
            transport: UHRPRecordingTransport(responses: [:]),
            now: { 0 }
        )
        await #expect(throws: UHRPDownloadError.unexpectedLookupAnswer) {
            try await freeformDownloader.hosts(for: identifier)
        }

        let twoOutputs = try [
            advertisement(
                identifier: identifier,
                host: "https://a.example/file",
                expiry: 1,
                beefLimits: limits
            ),
            advertisement(
                identifier: identifier,
                host: "https://b.example/file",
                expiry: 1,
                beefLimits: limits
            ),
        ]
        let boundedDownloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(
                answer: try LookupAnswer(outputList: twoOutputs)
            ),
            configuration: try configuration(
                beefLimits: limits,
                maximumAdvertisementCount: 1,
                maximumHostCount: 1
            ),
            transport: UHRPRecordingTransport(responses: [:]),
            now: { 0 }
        )
        await #expect(
            throws: UHRPDownloadError.tooManyAdvertisements(actual: 2, maximum: 1)
        ) {
            try await boundedDownloader.hosts(for: identifier)
        }

        let cancelledResolver = UHRPRecordingResolver(
            answer: try LookupAnswer(outputList: [])
        )
        let cancelledDownloader = UHRPDownloader(
            resolver: cancelledResolver,
            configuration: try configuration(beefLimits: limits),
            transport: UHRPRecordingTransport(responses: [:]),
            now: { 0 }
        )
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await cancelledDownloader.content(for: identifier)
        }
        await #expect(throws: CancellationError.self) {
            try await task.value
        }
        #expect(await cancelledResolver.requestCount() == 0)
    }

    @Test("download rejects a response that exceeds the content limit")
    func responseLimit() async throws {
        let bytes: [UInt8] = [1, 2, 3, 4]
        let identifier = try UHRPURL(fileBytes: bytes)
        let limits = try beefLimits()
        let output = try advertisement(
            identifier: identifier,
            host: "https://large.example/file",
            expiry: 1,
            beefLimits: limits
        )
        let transport = UHRPRecordingTransport(responses: [
            "https://large.example/file": .success(
                HTTPResponse(statusCode: 200, body: Data(bytes + [5]))
            )
        ])
        let downloader = UHRPDownloader(
            resolver: UHRPRecordingResolver(
                answer: try LookupAnswer(outputList: [output])
            ),
            configuration: try configuration(
                beefLimits: limits,
                uhrpLimits: UHRPLimits(
                    maximumURLUTF8ByteCount: 256,
                    maximumContentByteCount: 4,
                    maximumMIMETypeUTF8ByteCount: 64
                )
            ),
            transport: transport,
            now: { 0 }
        )
        await #expect(
            throws: UHRPDownloadError.allHostsFailed([
                UHRPHostFailure(
                    host: URL(string: "https://large.example/file")!,
                    reason: .transport(.responseBodyTooLarge(maximumByteCount: 4))
                )
            ])
        ) {
            try await downloader.content(for: identifier)
        }
        #expect(await transport.responseLimits() == [4])
    }

    @Test("configuration rejects invalid practical limits")
    func configurationLimits() throws {
        let limits = try beefLimits()
        #expect(throws: UHRPDownloadError.invalidConfiguration) {
            try UHRPDownloadConfiguration(
                beefLimits: limits,
                maximumAdvertisementCount: 0
            )
        }
        #expect(throws: UHRPDownloadError.invalidConfiguration) {
            try UHRPDownloadConfiguration(
                beefLimits: limits,
                maximumHostCount: 0
            )
        }
        #expect(throws: UHRPDownloadError.invalidConfiguration) {
            try UHRPDownloadConfiguration(
                beefLimits: limits,
                requestTimeout: .zero
            )
        }
    }

    /// Builds the six-field signed advertisement that TypeScript hosts
    /// publish (storage/UHRPAdvertisementValidation.ts:37-112): host key,
    /// hash, URL, expiry, size, then a signature over fields 0-4 by the key
    /// linked to the host under "2-uhrp advertisement-1" and the anyone key.
    private func advertisement(
        identifier: UHRPURL,
        advertisedHash: [UInt8]? = nil,
        host: String,
        expiry: UInt64,
        expiryBytes: [UInt8]? = nil,
        linkedLock: Bool = true,
        signed: Bool = true,
        beefLimits: BEEFLimits
    ) throws -> OutputListItem {
        let hostKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [7])
        let anyone = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let lockingKey = linkedLock
            ? try hostKey.derivedChild(
                with: anyone.publicKey,
                invoiceNumber: "2-uhrp advertisement-1"
            )
            : hostKey
        let fields = [
            hostKey.publicKey.compressedBytes,
            advertisedHash ?? identifier.hash.bytes,
            Array(host.utf8),
            expiryBytes ?? CompactSize.encode(expiry),
            CompactSize.encode(4_096),
        ]
        let signedBytes = Array(fields.joined()) + (signed ? [] : [0])
        let signature = try lockingKey.sign(digest: BSVHashing.sha256(signedBytes))
        let script = try PushDrop.lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: lockingKey.publicKey,
            lockPosition: .beforeCompatibility,
            limits: .standard
        )
        return try outputListItem(script, beefLimits: beefLimits)
    }

    /// The unsigned four-field shape Swift used before it matched TypeScript.
    private func previousSwiftAdvertisement(
        identifier: UHRPURL,
        host: String,
        expiry: UInt64,
        beefLimits: BEEFLimits
    ) throws -> OutputListItem {
        let key = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let script = try PushDrop.lockingScript(
            fields: [
                identifier.hash.bytes,
                Array(identifier.encoded.utf8),
                Array(host.utf8),
                CompactSize.encode(expiry),
            ],
            publicKey: key.publicKey,
            lockPosition: .beforeCompatibility,
            limits: .standard
        )
        return try outputListItem(script, beefLimits: beefLimits)
    }

    private func outputListItem(
        _ script: Script,
        beefLimits: BEEFLimits
    ) throws -> OutputListItem {
        let transaction = Transaction(
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script)]
        )
        let beef = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [.raw(transaction)],
            limits: beefLimits
        ).serialized(limits: beefLimits)
        return try OutputListItem(beef: beef, outputIndex: 0)
    }

    private func configuration(
        beefLimits: BEEFLimits,
        uhrpLimits: UHRPLimits = .standard,
        maximumAdvertisementCount: Int = 256,
        maximumHostCount: Int = 64
    ) throws -> UHRPDownloadConfiguration {
        try UHRPDownloadConfiguration(
            beefLimits: beefLimits,
            uhrpLimits: uhrpLimits,
            maximumAdvertisementCount: maximumAdvertisementCount,
            maximumHostCount: maximumHostCount
        )
    }

    private func beefLimits() throws -> BEEFLimits {
        let transactionLimits = try TransactionLimits(
            maximumTransactionByteCount: 1_000_000,
            maximumInputCount: 100,
            maximumOutputCount: 100,
            maximumScriptByteCount: 100_000
        )
        return try BEEFLimits(
            maximumByteCount: 1_000_000,
            maximumMerklePathCount: 100,
            maximumTransactionCount: 100,
            transactionLimits: transactionLimits,
            merklePathLimits: MerklePathLimits(
                maximumByteCount: 1_000_000,
                maximumLeavesPerLevel: 100,
                maximumTotalLeaves: 100
            )
        )
    }
}

private actor UHRPRecordingResolver: OverlayLookupResolving {
    private let answer: LookupAnswer
    private var questions: [LookupQuestion] = []

    init(answer: LookupAnswer) {
        self.answer = answer
    }

    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        questions.append(question)
        return answer
    }

    func lastQuestion() -> LookupQuestion? { questions.last }
    func requestCount() -> Int { questions.count }
}

private actor UHRPRecordingTransport: HTTPTransport {
    private let responses: [String: Result<HTTPResponse, any Error>]
    private var requests: [HTTPRequest] = []
    private var limits: [Int] = []

    init(responses: [String: Result<HTTPResponse, any Error>]) {
        self.responses = responses
    }

    func send(
        _ request: HTTPRequest,
        maximumResponseBodyByteCount: Int
    ) async throws -> HTTPResponse {
        requests.append(request)
        limits.append(maximumResponseBodyByteCount)
        guard let result = responses[request.url.absoluteString] else {
            throw NetworkServiceError.transport(code: nil)
        }
        let response = try result.get()
        guard response.body.count <= maximumResponseBodyByteCount else {
            throw NetworkServiceError.responseBodyTooLarge(
                maximumByteCount: maximumResponseBodyByteCount
            )
        }
        return response
    }

    func requestURLs() -> [String] { requests.map(\.url.absoluteString) }
    func responseLimits() -> [Int] { limits }
}
