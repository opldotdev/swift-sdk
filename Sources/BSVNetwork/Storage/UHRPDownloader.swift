import BSVCore
import BSVOverlay
import BSVScript
import BSVStorage
import BSVTransaction
import Foundation

/// Bounded failures from UHRP host discovery and content download.
public enum UHRPDownloadError: Error, Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    case invalidConfiguration
    case unexpectedLookupAnswer
    case tooManyAdvertisements(actual: Int, maximum: Int)
    case tooManyHosts(actual: Int, maximum: Int)
    case noAvailableHosts
    case allHostsFailed

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
        case .noAvailableHosts:
            "No current UHRP host advertisement is available"
        case .allHostsFailed:
            "All UHRP content hosts failed"
        }
    }

    public var debugDescription: String { description }
}

/// Explicit limits and timeouts for UHRP discovery and download.
public struct UHRPDownloadConfiguration: Hashable, Sendable {
    public let beefLimits: BEEFLimits
    public let pushDropLimits: PushDropLimits
    public let overlayLimits: OverlayLimits
    public let uhrpLimits: UHRPLimits
    public let maximumAdvertisementCount: Int
    public let maximumHostCount: Int
    public let requestTimeout: Duration
    public let resourceTimeout: Duration

    public init(
        beefLimits: BEEFLimits,
        pushDropLimits: PushDropLimits = .standard,
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
        self.pushDropLimits = pushDropLimits
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
/// The downloader queries `ls_uhrp`, validates each four-field PushDrop
/// advertisement, and makes at most one GET request to each valid HTTPS host.
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
                query: Self.query(for: identifier),
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

        var hosts: Set<URL> = []
        let currentTime = now()
        for output in outputs {
            try Task.checkCancellation()
            guard
                let host = Self.host(
                    from: output,
                    for: identifier,
                    currentTime: currentTime,
                    configuration: configuration
                )
            else {
                continue
            }
            hosts.insert(host)
            guard hosts.count <= configuration.maximumHostCount else {
                throw UHRPDownloadError.tooManyHosts(
                    actual: hosts.count,
                    maximum: configuration.maximumHostCount
                )
            }
        }
        return hosts.sorted { $0.absoluteString < $1.absoluteString }
    }

    /// Downloads and verifies content from the first successful resolved host.
    public func content(for identifier: UHRPURL) async throws -> StorageContent {
        let hosts = try await hosts(for: identifier)
        guard !hosts.isEmpty else { throw UHRPDownloadError.noAvailableHosts }

        for host in hosts {
            try Task.checkCancellation()
            do {
                let response = try await transport.send(
                    HTTPRequest(method: .get, url: host),
                    maximumResponseBodyByteCount: configuration.uhrpLimits.maximumContentByteCount
                )
                try Task.checkCancellation()
                guard (200...299).contains(response.statusCode) else { continue }
                let content = try StorageContent(
                    bytes: [UInt8](response.body),
                    mimeType: response.headerValue(for: "Content-Type") ?? "",
                    limits: configuration.uhrpLimits
                )
                guard content.matches(identifier) else { continue }
                return content
            } catch is CancellationError {
                throw CancellationError()
            } catch NetworkServiceError.cancelled {
                throw CancellationError()
            } catch {
                continue
            }
        }
        try Task.checkCancellation()
        throw UHRPDownloadError.allHostsFailed
    }

    private static func query(for identifier: UHRPURL) -> [UInt8] {
        Array("{\"uhrpUrl\":\"\(identifier.encoded)\"}".utf8)
    }

    private static func host(
        from output: OutputListItem,
        for identifier: UHRPURL,
        currentTime: UInt64,
        configuration: UHRPDownloadConfiguration
    ) -> URL? {
        guard
            let transaction = try? overlayLookupTransaction(
                for: output,
                beefLimits: configuration.beefLimits
            ),
            Int(output.outputIndex) < transaction.outputs.count,
            let decoded = try? PushDrop.decode(
                transaction.outputs[Int(output.outputIndex)].lockingScript,
                lockPosition: .beforeCompatibility,
                limits: configuration.pushDropLimits
            ),
            decoded.fields.count == 4,
            decoded.fields[0] == identifier.hash.bytes,
            let advertisedIdentifierText = String(
                bytes: decoded.fields[1],
                encoding: .utf8
            ),
            let advertisedIdentifier = try? UHRPURL(
                parsing: advertisedIdentifierText,
                limits: configuration.uhrpLimits
            ),
            advertisedIdentifier == identifier,
            let expiry = try? CompactSize.decode(
                decoded.fields[3],
                canonicality: .required
            ).value,
            expiry >= currentTime,
            let hostText = String(bytes: decoded.fields[2], encoding: .utf8),
            hostText.utf8.count <= configuration.uhrpLimits.maximumURLUTF8ByteCount,
            isValidHTTPText(hostText),
            let components = URLComponents(string: hostText),
            components.scheme?.lowercased() == "https",
            components.host?.isEmpty == false,
            components.user == nil,
            components.password == nil,
            components.fragment == nil,
            let host = components.url
        else {
            return nil
        }
        return host
    }

    private static func isValidHTTPText(_ value: String) -> Bool {
        !value.unicodeScalars.contains { scalar in
            scalar.value < 0x20 || scalar.value == 0x7f
        }
    }
}
