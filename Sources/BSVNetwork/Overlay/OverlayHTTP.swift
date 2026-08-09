import BSVCore
import BSVOverlay
import BSVTransaction
import Foundation

/// Resource and timeout policy for one overlay HTTP request.
public struct OverlayHTTPConfiguration: Sendable {
    public static let maximumAllowedRequestByteCount = 64 * 1_024 * 1_024
    public static let maximumAllowedResponseByteCount = 64 * 1_024 * 1_024
    public static let maximumAllowedContextByteCount = 1 * 1_024 * 1_024

    public let overlayLimits: OverlayLimits
    public let beefLimits: BEEFLimits
    public let maximumContextByteCount: Int
    public let requestTimeout: Duration
    public let resourceTimeout: Duration

    public init(
        overlayLimits: OverlayLimits = .standard,
        beefLimits: BEEFLimits,
        maximumContextByteCount: Int = 64 * 1_024,
        requestTimeout: Duration = .seconds(30),
        resourceTimeout: Duration = .seconds(30)
    ) throws {
        guard
            overlayLimits.maximumLookupQueryByteCount
                <= Self.maximumAllowedRequestByteCount,
            overlayLimits.maximumTaggedBEEFByteCount
                <= Self.maximumAllowedRequestByteCount,
            overlayLimits.maximumLookupAnswerByteCount
                <= Self.maximumAllowedResponseByteCount,
            (0...Self.maximumAllowedContextByteCount).contains(maximumContextByteCount),
            requestTimeout > .zero,
            resourceTimeout > .zero
        else {
            throw OverlayHTTPError.invalidConfiguration
        }
        self.overlayLimits = overlayLimits
        self.beefLimits = beefLimits
        self.maximumContextByteCount = maximumContextByteCount
        self.requestTimeout = requestTimeout
        self.resourceTimeout = resourceTimeout
    }
}

/// A stable, redacted overlay HTTP failure.
public enum OverlayHTTPError: Error, Equatable, Sendable {
    case invalidConfiguration
    case invalidHost
    case invalidQuery
    case malformedResponse
    case unsupportedContentType
    case rejected(statusCode: Int)
    case resourceLimit
    case transport
    case uncertainDelivery
}

/// A bounded HTTPS implementation of the SLAP lookup facilitator.
public struct HTTPSOverlayLookupFacilitator: LookupFacilitator, Sendable {
    private let configuration: OverlayHTTPConfiguration
    private let transport: any HTTPTransport

    public init(configuration: OverlayHTTPConfiguration) {
        self.configuration = configuration
        self.transport = URLSessionHTTPTransport(
            requestTimeout: configuration.requestTimeout,
            resourceTimeout: configuration.resourceTimeout
        )
    }

    package init(
        configuration: OverlayHTTPConfiguration,
        transport: any HTTPTransport
    ) {
        self.configuration = configuration
        self.transport = transport
    }

    public func lookup(
        question: LookupQuestion,
        at host: OverlayHost
    ) async throws -> LookupAnswer {
        try Task.checkCancellation()
        let url = try overlayURL(host: host, path: "/lookup")
        let body = try OverlayHTTPCodec.lookupRequest(
            question,
            limits: configuration.overlayLimits
        )
        let response: HTTPResponse
        do {
            response = try await transport.send(
                HTTPRequest(
                    method: .post,
                    url: url,
                    headers: [
                        "Content-Type": "application/json",
                        "X-Aggregation": "yes",
                    ],
                    body: Data(body)
                ),
                maximumResponseBodyByteCount: configuration.overlayLimits
                    .maximumLookupAnswerByteCount
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch NetworkServiceError.cancelled {
            throw CancellationError()
        } catch NetworkServiceError.responseBodyTooLarge {
            throw OverlayHTTPError.resourceLimit
        } catch {
            throw OverlayHTTPError.transport
        }
        try Task.checkCancellation()
        guard response.statusCode == 200 else {
            throw OverlayHTTPError.rejected(statusCode: response.statusCode)
        }
        let bytes = [UInt8](response.body)
        switch mediaType(response.headerValue(for: "Content-Type")) {
        case "application/json":
            return try OverlayHTTPCodec.lookupJSONResponse(
                bytes,
                limits: configuration.overlayLimits
            )
        case "application/octet-stream":
            return try OverlayHTTPCodec.lookupBinaryResponse(
                bytes,
                configuration: configuration
            )
        default:
            throw OverlayHTTPError.unsupportedContentType
        }
    }
}

/// A bounded one-shot HTTPS implementation of the SHIP topic facilitator.
///
/// Submission is never retried. A transport failure or cancellation after the
/// POST begins has uncertain delivery.
public struct HTTPSOverlayTopicFacilitator: TopicFacilitator, Sendable {
    private let configuration: OverlayHTTPConfiguration
    private let transport: any HTTPTransport

    public init(configuration: OverlayHTTPConfiguration) {
        self.configuration = configuration
        self.transport = URLSessionHTTPTransport(
            requestTimeout: configuration.requestTimeout,
            resourceTimeout: configuration.resourceTimeout
        )
    }

    package init(
        configuration: OverlayHTTPConfiguration,
        transport: any HTTPTransport
    ) {
        self.configuration = configuration
        self.transport = transport
    }

    public func submit(
        _ taggedBEEF: TaggedBEEF,
        to host: OverlayHost
    ) async throws -> Steak {
        try Task.checkCancellation()
        let url = try overlayURL(host: host, path: "/submit")
        let topics = try OverlayHTTPCodec.topicsHeader(
            taggedBEEF.topics,
            limits: configuration.overlayLimits
        )
        let request = HTTPRequest(
            method: .post,
            url: url,
            headers: [
                "Content-Type": "application/octet-stream",
                "X-Topics": topics,
            ],
            body: Data(taggedBEEF.beef)
        )
        let response: HTTPResponse
        do {
            response = try await transport.send(
                request,
                maximumResponseBodyByteCount: configuration.overlayLimits
                    .maximumLookupAnswerByteCount
            )
        } catch {
            throw OverlayHTTPError.uncertainDelivery
        }
        guard !Task.isCancelled else { throw OverlayHTTPError.uncertainDelivery }
        guard response.statusCode == 200 else {
            throw OverlayHTTPError.rejected(statusCode: response.statusCode)
        }
        guard mediaType(response.headerValue(for: "Content-Type")) == "application/json" else {
            throw OverlayHTTPError.unsupportedContentType
        }
        return try OverlayHTTPCodec.steakResponse(
            [UInt8](response.body),
            limits: configuration.overlayLimits
        )
    }
}

private func overlayURL(host: OverlayHost, path: String) throws -> URL {
    guard host.rawValue.utf8.count <= 2_048,
        !host.rawValue.hasSuffix("/"),
        let base = URL(string: host.rawValue),
        let components = URLComponents(url: base, resolvingAgainstBaseURL: false),
        components.scheme?.lowercased() == "https",
        components.host?.isEmpty == false,
        components.user == nil,
        components.password == nil,
        components.query == nil,
        components.fragment == nil,
        components.path.isEmpty
    else {
        throw OverlayHTTPError.invalidHost
    }
    guard let result = URL(string: path, relativeTo: base)?.absoluteURL else {
        throw OverlayHTTPError.invalidHost
    }
    return result
}

private func mediaType(_ value: String?) -> String? {
    guard let value else { return nil }
    return value.split(separator: ";", maxSplits: 1).first?
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
}
