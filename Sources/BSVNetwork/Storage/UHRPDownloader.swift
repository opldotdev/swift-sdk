import BSVCore
import BSVOverlay
import BSVScript
import BSVStorage
import BSVTransaction
import Foundation

/// Why one lookup output did not yield a usable host advertisement.
///
/// Discovery skips such an output, as TypeScript `StorageDownloader` does, but
/// keeps the reason so a caller can see why no host was found.
public struct UHRPAdvertisementRejection: Equatable, Sendable, CustomStringConvertible {
    public enum Reason: Error, Equatable, Sendable, CustomStringConvertible {
        /// The output's BEEF did not yield a transaction. The text is the
        /// underlying error's description.
        case invalidTransaction(String)
        case outputIndexOutOfRange(index: UInt32, outputCount: Int)
        case invalidAdvertisement(UHRPAdvertisementError)
        /// The advertisement is for other content.
        case hashMismatch
        case expired(expiryTime: UInt64, currentTime: UInt64)

        public var description: String {
            switch self {
            case .invalidTransaction(let detail):
                "lookup output is not a valid transaction (\(detail))"
            case .outputIndexOutOfRange(let index, let outputCount):
                "lookup output index \(index) is out of range (\(outputCount) outputs)"
            case .invalidAdvertisement(let error):
                error.description
            case .hashMismatch:
                "advertisement is for other content"
            case .expired(let expiryTime, let currentTime):
                "advertisement expired at \(expiryTime) (now \(currentTime))"
            }
        }
    }

    /// The output's position in the lookup answer.
    public let answerIndex: Int
    public let reason: Reason

    public init(answerIndex: Int, reason: Reason) {
        self.answerIndex = answerIndex
        self.reason = reason
    }

    public var description: String { "output \(answerIndex): \(reason)" }
}

/// Why one content host did not return the requested file.
public struct UHRPHostFailure: Equatable, Sendable, CustomStringConvertible {
    public enum Reason: Equatable, Sendable, CustomStringConvertible {
        case httpStatus(Int)
        case transport(NetworkServiceError)
        case invalidContent(UHRPError)
        /// The returned bytes do not hash to the requested identifier.
        case contentHashMismatch
        /// Any other error, by its description.
        case other(String)

        public var description: String {
            switch self {
            case .httpStatus(let code): "HTTP status \(code)"
            case .transport(let error): "transport error \(error)"
            case .invalidContent(let error): error.description
            case .contentHashMismatch: "content does not match its UHRP hash"
            case .other(let detail): detail
            }
        }
    }

    public let host: URL
    public let reason: Reason

    public init(host: URL, reason: Reason) {
        self.host = host
        self.reason = reason
    }

    public var description: String { "\(host.absoluteString): \(reason)" }
}

/// Bounded failures from UHRP host discovery and content download.
///
/// `description` is a short message. `debugDescription` lists every
/// rejected advertisement or failed host for logs.
public enum UHRPDownloadError: Error, Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    case invalidConfiguration
    case unexpectedLookupAnswer
    case tooManyAdvertisements(actual: Int, maximum: Int)
    case tooManyHosts(actual: Int, maximum: Int)
    /// No advertisement was usable. Each lookup output that was skipped is
    /// listed with its reason; the list is empty when the lookup found none.
    case noAvailableHosts(rejected: [UHRPAdvertisementRejection])
    /// Every advertised host failed, in the order they were tried.
    case allHostsFailed([UHRPHostFailure])

    public var description: String {
        switch self {
        case .invalidConfiguration:
            "UHRP downloader configuration is invalid"
        case .unexpectedLookupAnswer:
            "UHRP lookup did not return an output list"
        case .tooManyAdvertisements(let actual, let maximum):
            "UHRP advertisement count exceeds its limit (\(actual) > \(maximum))"
        case .tooManyHosts(let actual, let maximum):
            "UHRP host count exceeds its limit (\(actual) > \(maximum))"
        case .noAvailableHosts(let rejected):
            if let first = rejected.first {
                "No current UHRP host advertisement is available (\(rejected.count) rejected; first: \(first.reason))"
            } else {
                "No UHRP host advertisement was found"
            }
        case .allHostsFailed(let failures):
            if let first = failures.first {
                "All \(failures.count) UHRP content hosts failed (first: \(first))"
            } else {
                "All UHRP content hosts failed"
            }
        }
    }

    public var debugDescription: String {
        switch self {
        case .noAvailableHosts(let rejected) where !rejected.isEmpty:
            ([description] + rejected.map { "- \($0)" }).joined(separator: "\n")
        case .allHostsFailed(let failures) where !failures.isEmpty:
            ([description] + failures.map { "- \($0)" }).joined(separator: "\n")
        default:
            description
        }
    }
}

/// The advertisements one lookup returned, split into those that passed every
/// check and those that were skipped.
public struct UHRPAdvertisementLookup: Equatable, Sendable {
    /// Current advertisements for the requested content, in answer order.
    public let accepted: [UHRPAdvertisement]
    public let rejected: [UHRPAdvertisementRejection]

    /// The distinct hosted-file URLs of the accepted advertisements, sorted.
    public var hosts: [URL] {
        Set(accepted.map(\.hostedFileLocation)).sorted { $0.absoluteString < $1.absoluteString }
    }
}

/// Explicit limits and timeouts for UHRP discovery and download.
public struct UHRPDownloadConfiguration: Hashable, Sendable {
    public let beefLimits: BEEFLimits
    public let overlayLimits: OverlayLimits
    public let uhrpLimits: UHRPLimits
    public let maximumAdvertisementCount: Int
    public let maximumHostCount: Int
    public let requestTimeout: Duration
    public let resourceTimeout: Duration

    public init(
        beefLimits: BEEFLimits,
        overlayLimits: OverlayLimits = .standard,
        uhrpLimits: UHRPLimits = .standard,
        maximumAdvertisementCount: Int = 256,
        maximumHostCount: Int = 64,
        requestTimeout: Duration = .seconds(10),
        resourceTimeout: Duration = .seconds(30)
    ) throws {
        guard maximumAdvertisementCount > 0,
            maximumHostCount > 0,
            requestTimeout > .zero,
            resourceTimeout > .zero,
            requestTimeout.networkTimeInterval.isFinite,
            resourceTimeout.networkTimeInterval.isFinite
        else {
            throw UHRPDownloadError.invalidConfiguration
        }
        self.beefLimits = beefLimits
        self.overlayLimits = overlayLimits
        self.uhrpLimits = uhrpLimits
        self.maximumAdvertisementCount = maximumAdvertisementCount
        self.maximumHostCount = maximumHostCount
        self.requestTimeout = requestTimeout
        self.resourceTimeout = resourceTimeout
    }
}

/// A bounded UHRP downloader with injected overlay discovery.
///
/// The downloader queries `ls_uhrp`, authenticates each six-field signed
/// advertisement with `UHRPAdvertisement`, and makes at most one GET request
/// to each valid HTTPS host.
/// It has no implicit tracker, retry, proxy, cookie, cache, or persistence
/// policy.
public struct UHRPDownloader: UHRPContentProvider, Sendable {
    private let resolver: any OverlayLookupResolving
    private let configuration: UHRPDownloadConfiguration
    private let transport: any HTTPTransport
    private let now: @Sendable () -> UInt64

    public init(
        resolver: any OverlayLookupResolving,
        configuration: UHRPDownloadConfiguration
    ) {
        self.resolver = resolver
        self.configuration = configuration
        self.transport = URLSessionHTTPTransport(
            requestTimeout: configuration.requestTimeout,
            resourceTimeout: configuration.resourceTimeout
        )
        self.now = {
            let seconds = Date().timeIntervalSince1970
            return seconds > 0 ? UInt64(seconds) : 0
        }
    }

    package init(
        resolver: any OverlayLookupResolving,
        configuration: UHRPDownloadConfiguration,
        transport: any HTTPTransport,
        now: @escaping @Sendable () -> UInt64
    ) {
        self.resolver = resolver
        self.configuration = configuration
        self.transport = transport
        self.now = now
    }

    /// Resolves current, hash-bound, HTTPS advertisements in deterministic order.
    public func hosts(for identifier: UHRPURL) async throws -> [URL] {
        try await advertisements(for: identifier).hosts
    }

    /// Looks up every advertisement for `identifier` and checks each one.
    ///
    /// An output that fails a check is skipped, as TypeScript does, so one bad
    /// advertisement cannot hide valid hosts. Its reason is kept in `rejected`.
    public func advertisements(for identifier: UHRPURL) async throws -> UHRPAdvertisementLookup {
        try Task.checkCancellation()
        let service: OverlayService
        let question: LookupQuestion
        do {
            service = try OverlayService(
                rawValue: "ls_uhrp",
                limits: configuration.overlayLimits
            )
            question = try LookupQuestion(
                service: service,
                query: Self.query(
                    for: identifier,
                    maximumAdvertisementCount: configuration.maximumAdvertisementCount
                ),
                limits: configuration.overlayLimits
            )
        } catch {
            throw UHRPDownloadError.invalidConfiguration
        }

        let answer = try await resolver.resolve(question)
        try Task.checkCancellation()
        guard case .outputList(let outputs) = answer else {
            throw UHRPDownloadError.unexpectedLookupAnswer
        }
        guard outputs.count <= configuration.maximumAdvertisementCount else {
            throw UHRPDownloadError.tooManyAdvertisements(
                actual: outputs.count,
                maximum: configuration.maximumAdvertisementCount
            )
        }

        var accepted: [UHRPAdvertisement] = []
        var rejected: [UHRPAdvertisementRejection] = []
        var hosts: Set<URL> = []
        let currentTime = now()
        for (answerIndex, output) in outputs.enumerated() {
            try Task.checkCancellation()
            switch Self.advertisement(
                from: output,
                for: identifier,
                currentTime: currentTime,
                configuration: configuration
            ) {
            case .failure(let reason):
                rejected.append(UHRPAdvertisementRejection(answerIndex: answerIndex, reason: reason))
            case .success(let advertisement):
                accepted.append(advertisement)
                hosts.insert(advertisement.hostedFileLocation)
                guard hosts.count <= configuration.maximumHostCount else {
                    throw UHRPDownloadError.tooManyHosts(
                        actual: hosts.count,
                        maximum: configuration.maximumHostCount
                    )
                }
            }
        }
        return UHRPAdvertisementLookup(accepted: accepted, rejected: rejected)
    }

    /// Downloads and verifies content from the first successful resolved host.
    public func content(for identifier: UHRPURL) async throws -> StorageContent {
        let lookup = try await advertisements(for: identifier)
        let hosts = lookup.hosts
        guard !hosts.isEmpty else {
            throw UHRPDownloadError.noAvailableHosts(rejected: lookup.rejected)
        }

        var failures: [UHRPHostFailure] = []
        for host in hosts {
            try Task.checkCancellation()
            do {
                let response = try await transport.send(
                    HTTPRequest(method: .get, url: host),
                    maximumResponseBodyByteCount: configuration.uhrpLimits.maximumContentByteCount
                )
                try Task.checkCancellation()
                guard (200...299).contains(response.statusCode) else {
                    failures.append(.init(host: host, reason: .httpStatus(response.statusCode)))
                    continue
                }
                let content = try StorageContent(
                    bytes: [UInt8](response.body),
                    mimeType: response.headerValue(for: "Content-Type") ?? "",
                    limits: configuration.uhrpLimits
                )
                guard content.matches(identifier) else {
                    failures.append(.init(host: host, reason: .contentHashMismatch))
                    continue
                }
                return content
            } catch is CancellationError {
                throw CancellationError()
            } catch NetworkServiceError.cancelled {
                throw CancellationError()
            } catch let error as NetworkServiceError {
                failures.append(.init(host: host, reason: .transport(error)))
            } catch let error as UHRPError {
                failures.append(.init(host: host, reason: .invalidContent(error)))
            } catch {
                failures.append(.init(host: host, reason: .other(String(describing: error))))
            }
        }
        try Task.checkCancellation()
        throw UHRPDownloadError.allHostsFailed(failures)
    }

    /// The `ls_uhrp` query that `@bsv/sdk` 4.1.1 sends
    /// (`storage/StorageDownloader.ts`): the bare Base58Check identifier,
    /// one page of at most 100 results, starting at offset zero.
    private static func query(for identifier: UHRPURL, maximumAdvertisementCount: Int) -> [UInt8] {
        let limit = min(maximumLookupResultCount, maximumAdvertisementCount)
        return Array(
            "{\"uhrpUrl\":\"\(identifier.encoded)\",\"limit\":\(limit),\"offset\":0}".utf8
        )
    }

    private static let maximumLookupResultCount = 100

    private static func advertisement(
        from output: OutputListItem,
        for identifier: UHRPURL,
        currentTime: UInt64,
        configuration: UHRPDownloadConfiguration
    ) -> Result<UHRPAdvertisement, UHRPAdvertisementRejection.Reason> {
        let transaction: Transaction
        do {
            transaction = try overlayLookupTransaction(
                for: output,
                beefLimits: configuration.beefLimits
            )
        } catch {
            return .failure(.invalidTransaction(String(describing: error)))
        }
        let index = Int(output.outputIndex)
        guard index < transaction.outputs.count else {
            return .failure(
                .outputIndexOutOfRange(
                    index: output.outputIndex,
                    outputCount: transaction.outputs.count
                ))
        }
        let advertisement: UHRPAdvertisement
        do {
            advertisement = try UHRPAdvertisement.decode(transaction.outputs[index].lockingScript)
        } catch let error as UHRPAdvertisementError {
            return .failure(.invalidAdvertisement(error))
        } catch {
            return .failure(.invalidTransaction(String(describing: error)))
        }
        guard advertisement.hash == identifier.hash else {
            return .failure(.hashMismatch)
        }
        guard advertisement.expiryTime >= currentTime else {
            return .failure(
                .expired(expiryTime: advertisement.expiryTime, currentTime: currentTime))
        }
        return .success(advertisement)
    }
}
