import BSVCore
import BSVKeys

/// BRC-104 header names used for authenticated HTTP messages.
public enum BRC104HTTPHeaderName {
    public static let authenticationPrefix = "x-bsv-auth"
    public static let version = "x-bsv-auth-version"
    public static let messageType = "x-bsv-auth-message-type"
    public static let identityKey = "x-bsv-auth-identity-key"
    public static let nonce = "x-bsv-auth-nonce"
    public static let yourNonce = "x-bsv-auth-your-nonce"
    public static let signature = "x-bsv-auth-signature"
    public static let requestID = "x-bsv-auth-request-id"
    public static let requestedCertificates = "x-bsv-auth-requested-certificates"
    public static let handshakePath = "/.well-known/auth"
}

/// Limits for transport-neutral BRC-104 HTTP frames.
public struct BRC104HTTPFramingLimits: Equatable, Sendable {
    public static let maximumAllowedHeaderCount = 1_024
    public static let maximumAllowedHeaderNameByteCount = 1_024
    public static let maximumAllowedHeaderValueByteCount = 1 << 20
    public static let maximumAllowedAggregateHeaderByteCount = 8 << 20
    public static let maximumAllowedMethodByteCount = 1_024
    public static let maximumAllowedPathByteCount = 1 << 20
    public static let maximumAllowedQueryByteCount = 1 << 20

    public let authLimits: AuthLimits
    public let payloadLimits: BRC104Limits
    public let maximumHeaderCount: Int
    public let maximumHeaderNameByteCount: Int
    public let maximumHeaderValueByteCount: Int
    public let maximumAggregateHeaderByteCount: Int
    public let maximumMethodByteCount: Int
    public let maximumPathByteCount: Int
    public let maximumQueryByteCount: Int

    public init(
        authLimits: AuthLimits = .standard,
        payloadLimits: BRC104Limits = .standard,
        maximumHeaderCount: Int = 128,
        maximumHeaderNameByteCount: Int = 256,
        maximumHeaderValueByteCount: Int = 64 << 10,
        maximumAggregateHeaderByteCount: Int = 256 << 10,
        maximumMethodByteCount: Int = 32,
        maximumPathByteCount: Int = 8 << 10,
        maximumQueryByteCount: Int = 64 << 10
    ) throws {
        guard (0...Self.maximumAllowedHeaderCount).contains(maximumHeaderCount),
            (0...Self.maximumAllowedHeaderNameByteCount).contains(
                maximumHeaderNameByteCount
            ),
            (0...Self.maximumAllowedHeaderValueByteCount).contains(
                maximumHeaderValueByteCount
            ),
            (0...Self.maximumAllowedAggregateHeaderByteCount).contains(
                maximumAggregateHeaderByteCount
            ),
            (0...Self.maximumAllowedMethodByteCount).contains(maximumMethodByteCount),
            (0...Self.maximumAllowedPathByteCount).contains(maximumPathByteCount),
            (0...Self.maximumAllowedQueryByteCount).contains(maximumQueryByteCount),
            payloadLimits.maximumPayloadBytes <= authLimits.maximumPayloadBytes
        else {
            throw BRC104HTTPFramingError.resourceLimit
        }
        self.authLimits = authLimits
        self.payloadLimits = payloadLimits
        self.maximumHeaderCount = maximumHeaderCount
        self.maximumHeaderNameByteCount = maximumHeaderNameByteCount
        self.maximumHeaderValueByteCount = maximumHeaderValueByteCount
        self.maximumAggregateHeaderByteCount = maximumAggregateHeaderByteCount
        self.maximumMethodByteCount = maximumMethodByteCount
        self.maximumPathByteCount = maximumPathByteCount
        self.maximumQueryByteCount = maximumQueryByteCount
    }

    private init(standard: Void) {
        authLimits = .standard
        payloadLimits = .standard
        maximumHeaderCount = 128
        maximumHeaderNameByteCount = 256
        maximumHeaderValueByteCount = 64 << 10
        maximumAggregateHeaderByteCount = 256 << 10
        maximumMethodByteCount = 32
        maximumPathByteCount = 8 << 10
        maximumQueryByteCount = 64 << 10
    }

    public static let standard = BRC104HTTPFramingLimits(standard: ())
}

/// A transport-neutral HTTP request frame.
public struct BRC104HTTPRequestFrame: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let method: String
    public let path: String
    public let query: String?
    public let headers: [BRC104Header]
    public let body: [UInt8]?

    public init(
        method: String,
        path: String,
        query: String? = nil,
        headers: [BRC104Header] = [],
        body: [UInt8]? = nil,
        limits: BRC104HTTPFramingLimits = .standard
    ) throws {
        try BRC104HTTPFrameCodec.validateRequestComponents(
            method: method,
            path: path,
            query: query,
            limits: limits
        )
        try BRC104HTTPFrameCodec.validateFrame(headers: headers, body: body, limits: limits)
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
    }

    public var description: String { "<redacted BRC-104 HTTP request frame>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// A transport-neutral HTTP response frame.
public struct BRC104HTTPResponseFrame: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let status: Int
    public let headers: [BRC104Header]
    public let body: [UInt8]?

    public init(
        status: Int,
        headers: [BRC104Header] = [],
        body: [UInt8]? = nil,
        limits: BRC104HTTPFramingLimits = .standard
    ) throws {
        guard (100...599).contains(status) else {
            throw BRC104HTTPFramingError.invalidFrame
        }
        try BRC104HTTPFrameCodec.validateFrame(headers: headers, body: body, limits: limits)
        self.status = status
        self.headers = headers
        self.body = body
    }

    public var description: String { "<redacted BRC-104 HTTP response frame>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// Failures at the authenticated HTTP framing boundary.
public enum BRC104HTTPFramingError: Error, Equatable, Sendable {
    case invalidFrame
    case invalidAuthenticationHeader
    case duplicateAuthenticationHeader
    case missingAuthenticationHeader
    case unknownAuthenticationHeader
    case certificateExchangeUnavailable
    case requestIDMismatch
    case resourceLimit
}

/// Converts BRC-104 general messages to and from transport-neutral HTTP frames.
public enum BRC104HTTPFrameCodec {
    public static func encodeRequest(
        _ message: AuthMessage,
        limits: BRC104HTTPFramingLimits = .standard
    ) throws -> BRC104HTTPRequestFrame {
        try validateGeneral(message, limits: limits)
        guard let payload = message.payload else {
            throw BRC104HTTPFramingError.invalidFrame
        }
        let request: BRC104Request
        do {
            request = try BRC104Codec.decodeRequest(payload, limits: limits.payloadLimits)
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        let authentication = try authenticationHeaders(
            for: message,
            requestID: request.requestID
        )
        return try BRC104HTTPRequestFrame(
            method: request.method,
            path: request.path,
            query: request.query,
            headers: authentication + request.headers,
            body: request.body,
            limits: limits
        )
    }

    public static func decodeRequest(
        _ frame: BRC104HTTPRequestFrame,
        limits: BRC104HTTPFramingLimits = .standard
    ) throws -> AuthMessage {
        try validateRequestComponents(
            method: frame.method,
            path: frame.path,
            query: frame.query,
            limits: limits
        )
        try validateFrame(headers: frame.headers, body: frame.body, limits: limits)
        let split = try split(frame.headers, kind: .request, limits: limits)
        let authentication = try parseAuthentication(split.authentication)
        let request: BRC104Request
        do {
            request = try BRC104Request(
                requestID: authentication.requestID,
                method: frame.method,
                path: frame.path,
                query: frame.query,
                headers: split.signed,
                body: frame.body,
                limits: limits.payloadLimits
            )
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        let payload: [UInt8]
        do {
            payload = try BRC104Codec.encode(request, limits: limits.payloadLimits)
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        return try makeMessage(authentication: authentication, payload: payload, limits: limits)
    }

    public static func encodeResponse(
        _ message: AuthMessage,
        limits: BRC104HTTPFramingLimits = .standard
    ) throws -> BRC104HTTPResponseFrame {
        try validateGeneral(message, limits: limits)
        guard let payload = message.payload else {
            throw BRC104HTTPFramingError.invalidFrame
        }
        let response: BRC104Response
        do {
            response = try BRC104Codec.decodeResponse(payload, limits: limits.payloadLimits)
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        let authentication = try authenticationHeaders(
            for: message,
            requestID: response.requestID
        )
        return try BRC104HTTPResponseFrame(
            status: response.status,
            headers: authentication + response.headers,
            body: response.body,
            limits: limits
        )
    }

    public static func decodeResponse(
        _ frame: BRC104HTTPResponseFrame,
        expectedRequestID: [UInt8],
        limits: BRC104HTTPFramingLimits = .standard
    ) throws -> AuthMessage {
        guard expectedRequestID.count == 32 else {
            throw BRC104HTTPFramingError.requestIDMismatch
        }
        try validateFrame(headers: frame.headers, body: frame.body, limits: limits)
        let split = try split(frame.headers, kind: .response, limits: limits)
        let authentication = try parseAuthentication(split.authentication)
        guard authentication.requestID == expectedRequestID else {
            throw BRC104HTTPFramingError.requestIDMismatch
        }
        let response: BRC104Response
        do {
            response = try BRC104Response(
                requestID: authentication.requestID,
                status: frame.status,
                headers: split.signed,
                body: frame.body,
                limits: limits.payloadLimits
            )
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        let payload: [UInt8]
        do {
            payload = try BRC104Codec.encode(response, limits: limits.payloadLimits)
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        return try makeMessage(authentication: authentication, payload: payload, limits: limits)
    }

    static func validateRequestComponents(
        method: String,
        path: String,
        query: String?,
        limits: BRC104HTTPFramingLimits
    ) throws {
        guard method.utf8.count <= limits.maximumMethodByteCount,
            path.utf8.count <= limits.maximumPathByteCount,
            query?.utf8.count ?? 0 <= limits.maximumQueryByteCount
        else {
            throw BRC104HTTPFramingError.resourceLimit
        }
        guard BRC104Codec.validToken(method), !path.isEmpty, path.utf8.first == 47,
            BRC104Codec.safeText(path), !path.contains("?"), !path.contains("#")
        else {
            throw BRC104HTTPFramingError.invalidFrame
        }
        if let query {
            guard query.utf8.first == 63, !query.contains("#"), BRC104Codec.safeText(query) else {
                throw BRC104HTTPFramingError.invalidFrame
            }
        }
    }

    static func validateFrame(
        headers: [BRC104Header],
        body: [UInt8]?,
        limits: BRC104HTTPFramingLimits
    ) throws {
        guard headers.count <= limits.maximumHeaderCount,
            body?.count ?? 0 <= limits.payloadLimits.maximumPayloadBytes
        else {
            throw BRC104HTTPFramingError.resourceLimit
        }
        var aggregate = 0
        for header in headers {
            let nameCount = header.name.utf8.count
            let valueCount = header.value.utf8.count
            guard nameCount <= limits.maximumHeaderNameByteCount,
                valueCount <= limits.maximumHeaderValueByteCount
            else {
                throw BRC104HTTPFramingError.resourceLimit
            }
            let (fieldCount, fieldOverflow) = nameCount.addingReportingOverflow(valueCount)
            let (next, totalOverflow) = aggregate.addingReportingOverflow(fieldCount)
            guard !fieldOverflow, !totalOverflow,
                next <= limits.maximumAggregateHeaderByteCount
            else {
                throw BRC104HTTPFramingError.resourceLimit
            }
            guard BRC104Codec.validToken(header.name), BRC104Codec.safeText(header.value) else {
                throw BRC104HTTPFramingError.invalidFrame
            }
            aggregate = next
        }
    }

    private struct ParsedAuthentication {
        let version: String
        let identityKey: PublicKey
        let nonce: String
        let yourNonce: String
        let signature: [UInt8]
        let requestID: [UInt8]
    }

    private struct SplitHeaders {
        let authentication: [String: String]
        let signed: [BRC104Header]
    }

    private static func split(
        _ headers: [BRC104Header],
        kind: BRC104Codec.HeaderKind,
        limits: BRC104HTTPFramingLimits
    ) throws -> SplitHeaders {
        var authentication: [String: String] = [:]
        var signed: [BRC104Header] = []
        signed.reserveCapacity(min(headers.count, limits.payloadLimits.maximumHeaders))
        for header in headers {
            let name = header.name.lowercased()
            if name == BRC104HTTPHeaderName.requestedCertificates {
                throw BRC104HTTPFramingError.certificateExchangeUnavailable
            }
            if knownAuthenticationHeader(name) {
                guard authentication[name] == nil else {
                    throw BRC104HTTPFramingError.duplicateAuthenticationHeader
                }
                authentication[name] = header.value
            } else if name.hasPrefix(BRC104HTTPHeaderName.authenticationPrefix) {
                throw BRC104HTTPFramingError.unknownAuthenticationHeader
            } else if BRC104Codec.permitted(name, kind: kind) {
                signed.append(.init(name: name, value: header.value))
            }
        }
        do {
            signed = try BRC104Codec.normalized(
                signed,
                kind: kind,
                limits: limits.payloadLimits
            )
        } catch BRC104Error.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch {
            throw BRC104HTTPFramingError.invalidFrame
        }
        return SplitHeaders(authentication: authentication, signed: signed)
    }

    private static func knownAuthenticationHeader(_ name: String) -> Bool {
        switch name {
        case BRC104HTTPHeaderName.version,
            BRC104HTTPHeaderName.messageType,
            BRC104HTTPHeaderName.identityKey,
            BRC104HTTPHeaderName.nonce,
            BRC104HTTPHeaderName.yourNonce,
            BRC104HTTPHeaderName.signature,
            BRC104HTTPHeaderName.requestID:
            return true
        default:
            return false
        }
    }

    private static func required(_ name: String, in headers: [String: String]) throws -> String {
        guard let value = headers[name] else {
            throw BRC104HTTPFramingError.missingAuthenticationHeader
        }
        return value
    }

    private static func parseAuthentication(
        _ headers: [String: String]
    ) throws
        -> ParsedAuthentication
    {
        let version = try required(BRC104HTTPHeaderName.version, in: headers)
        let messageType = try required(BRC104HTTPHeaderName.messageType, in: headers)
        let keyText = try required(BRC104HTTPHeaderName.identityKey, in: headers)
        let nonce = try required(BRC104HTTPHeaderName.nonce, in: headers)
        let yourNonce = try required(BRC104HTTPHeaderName.yourNonce, in: headers)
        let signatureText = try required(BRC104HTTPHeaderName.signature, in: headers)
        let requestIDText = try required(BRC104HTTPHeaderName.requestID, in: headers)

        guard version == "0.1", messageType == AuthMessageType.general.rawValue,
            keyText.utf8.count == 66,
            let keyBytes = try? Hex.decode(keyText, maximumDecodedByteCount: 33),
            Hex.encode(keyBytes) == keyText,
            let identityKey = try? PublicKey(keyBytes),
            let signature = try? Hex.decode(signatureText, maximumDecodedByteCount: 72),
            Hex.encode(signature) == signatureText,
            let requestID = try? Base64Encoding.decode(
                requestIDText,
                maximumDecodedByteCount: 32
            ),
            requestID.count == 32,
            Base64Encoding.encode(requestID) == requestIDText
        else {
            throw BRC104HTTPFramingError.invalidAuthenticationHeader
        }
        return ParsedAuthentication(
            version: version,
            identityKey: identityKey,
            nonce: nonce,
            yourNonce: yourNonce,
            signature: signature,
            requestID: requestID
        )
    }

    private static func authenticationHeaders(
        for message: AuthMessage,
        requestID: [UInt8]
    ) throws -> [BRC104Header] {
        guard requestID.count == 32, let nonce = message.nonce,
            let yourNonce = message.yourNonce, let signature = message.signature
        else {
            throw BRC104HTTPFramingError.invalidFrame
        }
        return [
            .init(name: BRC104HTTPHeaderName.version, value: message.version),
            .init(name: BRC104HTTPHeaderName.messageType, value: message.messageType.rawValue),
            .init(
                name: BRC104HTTPHeaderName.identityKey,
                value: Hex.encode(message.identityKey.compressedBytes)
            ),
            .init(name: BRC104HTTPHeaderName.nonce, value: nonce),
            .init(name: BRC104HTTPHeaderName.yourNonce, value: yourNonce),
            .init(name: BRC104HTTPHeaderName.signature, value: Hex.encode(signature)),
            .init(name: BRC104HTTPHeaderName.requestID, value: Base64Encoding.encode(requestID)),
        ]
    }

    private static func makeMessage(
        authentication: ParsedAuthentication,
        payload: [UInt8],
        limits: BRC104HTTPFramingLimits
    ) throws -> AuthMessage {
        let message = AuthMessage(
            version: authentication.version,
            messageType: .general,
            identityKey: authentication.identityKey,
            nonce: authentication.nonce,
            yourNonce: authentication.yourNonce,
            payload: payload,
            signature: authentication.signature
        )
        do {
            try AuthMessageCodec.validate(message, limits: limits.authLimits)
        } catch AuthError.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch AuthError.certificateExchangeUnavailable {
            throw BRC104HTTPFramingError.certificateExchangeUnavailable
        } catch {
            throw BRC104HTTPFramingError.invalidAuthenticationHeader
        }
        return message
    }

    private static func validateGeneral(
        _ message: AuthMessage,
        limits: BRC104HTTPFramingLimits
    ) throws {
        guard !message.hasCertificates, !message.hasRequestedCertificates else {
            throw BRC104HTTPFramingError.certificateExchangeUnavailable
        }
        do {
            try AuthMessageCodec.validate(message, limits: limits.authLimits)
        } catch AuthError.resourceLimit {
            throw BRC104HTTPFramingError.resourceLimit
        } catch AuthError.certificateExchangeUnavailable {
            throw BRC104HTTPFramingError.certificateExchangeUnavailable
        } catch {
            throw BRC104HTTPFramingError.invalidAuthenticationHeader
        }
    }
}
