import BSVCore
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
        #expect(
            question.query
                == Array("{\"uhrpUrl\":\"\(identifier.encoded)\"}".utf8)
        )
    }

    @Test("discovery rejects unbound and unsafe advertisements")
    func hostileAdvertisements() async throws {
        let identifier = try UHRPURL(fileBytes: [4, 5, 6])
        let other = try UHRPURL(fileBytes: [7, 8, 9])
        let limits = try beefLimits()
        let outputs = try [
            advertisement(
                identifier: identifier,
                advertisedIdentifier: other,
                host: "https://wrong-id.example/file",
                expiry: 1_001,
                beefLimits: limits
            ),
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
                host: "https://extra-field.example/file",
                expiry: 1_001,
                extraFields: [[1]],
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
        await #expect(throws: UHRPDownloadError.noAvailableHosts) {
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
        await #expect(throws: UHRPDownloadError.allHostsFailed) {
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

    private func advertisement(
        identifier: UHRPURL,
        advertisedIdentifier: UHRPURL? = nil,
        advertisedHash: [UInt8]? = nil,
        host: String,
        expiry: UInt64,
        expiryBytes: [UInt8]? = nil,
        extraFields: [[UInt8]] = [],
        beefLimits: BEEFLimits
    ) throws -> OutputListItem {
        let key = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        var fields = [
            advertisedHash ?? identifier.hash.bytes,
            Array((advertisedIdentifier ?? identifier).encoded.utf8),
            Array(host.utf8),
            expiryBytes ?? CompactSize.encode(expiry),
        ]
        fields.append(contentsOf: extraFields)
        let script = try PushDrop.lockingScript(
            fields: fields,
            publicKey: key.publicKey,
            lockPosition: .beforeCompatibility,
            limits: .standard
        )
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
