import BSVCore

/// A transport-neutral, signed HTTP request representation (BRC-104).
public struct BRC104Request: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let requestID: [UInt8]
    public let method: String
    public let path: String
    public let query: String?
    public let headers: [BRC104Header]
    public let body: [UInt8]?

    public init(
        requestID: [UInt8], method: String, path: String, query: String? = nil,
        headers: [BRC104Header] = [], body: [UInt8]? = nil,
        limits: BRC104Limits = .standard
    ) throws {
        guard requestID.count == 32 else { throw BRC104Error.invalidRequestID }
        guard BRC104Codec.validMethod(method) else { throw BRC104Error.invalidMethod }
        guard !path.isEmpty, path.utf8.first == 47, BRC104Codec.safeText(path),
            !path.contains("?"), !path.contains("#")
        else { throw BRC104Error.invalidPath }
        if let query {
            guard query.utf8.first == 63, !query.contains("#"), BRC104Codec.safeText(query) else {
                throw BRC104Error.invalidPath
            }
        }
        guard BRC104Codec.validTargetLength(path: path, query: query) else {
            throw BRC104Error.invalidPath
        }
        self.requestID = requestID
        self.method = method
        self.path = path
        self.query = query
        self.headers = try BRC104Codec.normalized(headers, kind: .request, limits: limits)
        self.body = body
    }
    public var description: String { "<redacted BRC-104 request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// A transport-neutral, signed HTTP response representation (BRC-104).
public struct BRC104Response: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let requestID: [UInt8]
    public let status: Int
    public let headers: [BRC104Header]
    public let body: [UInt8]?

    public init(
        requestID: [UInt8],
        status: Int,
        headers: [BRC104Header] = [],
        body: [UInt8]? = nil,
        limits: BRC104Limits = .standard
    ) throws {
        guard requestID.count == 32 else { throw BRC104Error.invalidRequestID }
        // `AuthFetch` rejects an authenticated status outside 200...599
        // (`clients/AuthFetch.ts:587-589`).
        guard (200...599).contains(status) else { throw BRC104Error.invalidStatus }
        self.requestID = requestID
        self.status = status
        self.headers = try BRC104Codec.normalized(headers, kind: .response, limits: limits)
        self.body = body
    }
    public var description: String { "<redacted BRC-104 response>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

public struct BRC104Header: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let name: String
    public let value: String
    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
    public var description: String { "<redacted BRC-104 header>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// Limits for BRC-104 payloads.
///
/// The defaults are the `@bsv/sdk` 4.1.1 limits: 512 signed headers, 1024-byte
/// names, 32 KiB values, 256 KiB of signed headers in total
/// (`transports/SimplifiedFetchTransport.ts:25-28`), a 256 KiB `x-bsv-payment`
/// request header (`:655-661`), and a 16 MiB body plus 512 KiB of framing
/// (`clients/AuthFetch.ts:147`, `:571`).
public struct BRC104Limits: Equatable, Sendable {
    public let maximumPayloadBytes: Int
    public let maximumHeaders: Int
    public let maximumHeaderNameBytes: Int
    public let maximumHeaderValueBytes: Int
    /// The value limit for the `x-bsv-payment` request header, which carries a
    /// BRC-105 Atomic BEEF.
    public let maximumPaymentHeaderValueBytes: Int
    public let maximumHeaderBytes: Int
    public init(
        maximumPayloadBytes: Int = AuthLimits.defaultPayloadBytes, maximumHeaders: Int = 512,
        maximumHeaderNameBytes: Int = 1 << 10,
        maximumHeaderValueBytes: Int = 32 << 10, maximumHeaderBytes: Int = 256 << 10,
        maximumPaymentHeaderValueBytes: Int = 256 << 10
    ) throws {
        guard maximumPayloadBytes >= 0, maximumHeaders >= 0, maximumHeaderNameBytes >= 0,
            maximumHeaderValueBytes >= 0, maximumHeaderBytes >= 0,
            maximumPaymentHeaderValueBytes >= 0
        else { throw BRC104Error.resourceLimit }
        self.maximumPayloadBytes = maximumPayloadBytes
        self.maximumHeaders = maximumHeaders
        self.maximumHeaderNameBytes = maximumHeaderNameBytes
        self.maximumHeaderValueBytes = maximumHeaderValueBytes
        self.maximumPaymentHeaderValueBytes = maximumPaymentHeaderValueBytes
        self.maximumHeaderBytes = maximumHeaderBytes
    }
    private init(
        validatedPayload: Int, headers: Int, headerName: Int, headerValue: Int,
        paymentHeaderValue: Int, headerBytes: Int
    ) {
        maximumPayloadBytes = validatedPayload
        maximumHeaders = headers
        maximumHeaderNameBytes = headerName
        maximumHeaderValueBytes = headerValue
        maximumPaymentHeaderValueBytes = paymentHeaderValue
        maximumHeaderBytes = headerBytes
    }
    public static let standard = BRC104Limits(
        validatedPayload: AuthLimits.defaultPayloadBytes, headers: 512, headerName: 1 << 10,
        headerValue: 32 << 10, paymentHeaderValue: 256 << 10, headerBytes: 256 << 10)

    static let paymentHeaderName = "x-bsv-payment"

    func maximumValueBytes(forHeader name: String, kind: BRC104Codec.HeaderKind) -> Int {
        kind == .request && name == Self.paymentHeaderName
            ? max(maximumHeaderValueBytes, maximumPaymentHeaderValueBytes)
            : maximumHeaderValueBytes
    }
}

public enum BRC104Error: Error, Equatable, Sendable {
    case invalidRequestID, invalidMethod, invalidPath, invalidStatus, invalidHeader
    case duplicateHeader, headerNotPermitted, resourceLimit, malformedPayload, trailingData
}

/// Strict BRC-104 bytes codec. It deliberately has no dependency on URLSession or HTTP transports.
public enum BRC104Codec {
    public static func requireCorrelation(requestID: [UInt8], response: BRC104Response) throws {
        guard requestID.count == 32, response.requestID == requestID else {
            throw BRC104Error.invalidRequestID
        }
    }
    /// Encodes a request a client is about to sign.
    ///
    /// Like `AuthFetch` (`clients/AuthFetch.ts:755-760`), a POST, PUT, PATCH
    /// or DELETE with a JSON content type and a `nil` body signs and sends
    /// `{}`: `BRC104HTTPFrameCodec.encodeRequest` takes the body from this
    /// payload. An empty body stays empty and is written as -1, never 0
    /// (`clients/AuthFetch.ts:762-770`).
    public static func encode(_ request: BRC104Request, limits: BRC104Limits = .standard) throws
        -> [UInt8]
    {
        try encode(request, applyingClientBodyDefault: true, limits: limits)
    }

    /// Encodes a request. A server rebuilding the payload of a received
    /// request passes `false`: the TypeScript server signs -1 for a bodyless
    /// JSON request (`authMiddlewareHelpers.ts:155-185`).
    static func encode(
        _ request: BRC104Request, applyingClientBodyDefault: Bool, limits: BRC104Limits
    ) throws -> [UInt8] {
        var writer = Writer(limits: limits)
        try writer.bytes(request.requestID)
        try writer.string(request.method)
        try writer.string(request.path)
        try writer.optionalString(request.query)
        try writer.headers(request.headers, kind: .request)
        try writer.body(
            applyingClientBodyDefault
                ? normalizedBody(request.body, method: request.method, headers: request.headers)
                : request.body)
        return writer.output
    }
    public static func decodeRequest(_ bytes: [UInt8], limits: BRC104Limits = .standard) throws
        -> BRC104Request
    {
        guard bytes.count <= limits.maximumPayloadBytes else { throw BRC104Error.resourceLimit }
        var reader = Reader(bytes, limits: limits)
        let id = try reader.fixed(32)
        let method = try reader.string()
        let path = try reader.string()
        let query = try reader.optionalString()
        let headers = try reader.headers(kind: .request)
        let body = try reader.optionalBytes()
        guard reader.finished else { throw BRC104Error.trailingData }
        return try BRC104Request(
            requestID: id, method: method, path: path, query: query, headers: headers, body: body,
            limits: limits)
    }
    public static func encode(_ response: BRC104Response, limits: BRC104Limits = .standard) throws
        -> [UInt8]
    {
        var writer = Writer(limits: limits)
        try writer.bytes(response.requestID)
        try writer.compact(UInt64(response.status))
        try writer.headers(response.headers, kind: .response)
        // An empty body is written as -1, never 0 (`SimplifiedFetchTransport.ts:314-321`,
        // `auth-express-middleware/src/index.ts:2112-2117`).
        try writer.body(response.body)
        return writer.output
    }
    public static func decodeResponse(_ bytes: [UInt8], limits: BRC104Limits = .standard) throws
        -> BRC104Response
    {
        guard bytes.count <= limits.maximumPayloadBytes else { throw BRC104Error.resourceLimit }
        var reader = Reader(bytes, limits: limits)
        let id = try reader.fixed(32)
        let rawStatus = try reader.compact()
        guard let status = Int(exactly: rawStatus) else { throw BRC104Error.invalidStatus }
        let headers = try reader.headers(kind: .response)
        let body = try reader.optionalBytes()
        guard reader.finished else { throw BRC104Error.trailingData }
        return try BRC104Response(
            requestID: id, status: status, headers: headers, body: body, limits: limits)
    }

    enum HeaderKind { case request, response }
    static func normalized(
        _ headers: [BRC104Header], kind: HeaderKind, limits: BRC104Limits = .standard
    ) throws -> [BRC104Header] {
        guard headers.count <= limits.maximumHeaders else { throw BRC104Error.resourceLimit }
        var names = Set<String>()
        var total = 0
        var result: [BRC104Header] = []
        for header in headers {
            let name = header.name.lowercased()
            guard validToken(name), name.utf8.count <= limits.maximumHeaderNameBytes,
                header.value.utf8.count <= limits.maximumValueBytes(forHeader: name, kind: kind),
                safeText(header.value), permitted(name, kind: kind)
            else { throw BRC104Error.invalidHeader }
            guard names.insert(name).inserted else { throw BRC104Error.duplicateHeader }
            let (fieldBytes, fieldOverflow) = name.utf8.count.addingReportingOverflow(
                header.value.utf8.count)
            let (newTotal, totalOverflow) = total.addingReportingOverflow(fieldBytes)
            guard !fieldOverflow, !totalOverflow, newTotal <= limits.maximumHeaderBytes else {
                throw BRC104Error.resourceLimit
            }
            total = newTotal
            let value = name == "content-type" ? signedContentType(header.value) : header.value
            guard name != "content-type" || !value.isEmpty else { throw BRC104Error.invalidHeader }
            result.append(.init(name: name, value: value))
        }
        // `@bsv/sdk` sorts signed header names with `localeCompare`
        // (`clients/AuthFetch.ts:740`, `transports/SimplifiedFetchTransport.ts:286`).
        return result.sorted { LocaleCompareOrder.areInIncreasingOrder($0.name, $1.name) }
    }
    /// The signed form of a `content-type` value, as `authenticatedContentType`
    /// in `utils/paymentTransport.ts:84-90` computes it: a `multipart/form-data`
    /// value is kept whole so its boundary is signed; any other value is cut at
    /// the first `;` and trimmed.
    static func signedContentType(_ value: String) -> String {
        let mediaType = ecmaScriptTrim(
            String(value.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]))
        return mediaType.lowercased() == "multipart/form-data" ? value : mediaType
    }

    /// `String.prototype.trim`: ECMAScript white space and line terminators.
    static func ecmaScriptTrim(_ value: String) -> String {
        func isSpace(_ scalar: Unicode.Scalar) -> Bool {
            switch scalar.value {
            case 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0xfeff, 0x2028, 0x2029: return true
            default: return scalar.properties.generalCategory == .spaceSeparator
            }
        }
        let scalars = value.unicodeScalars
        guard let first = scalars.firstIndex(where: { !isSpace($0) }),
            let last = scalars.lastIndex(where: { !isSpace($0) })
        else { return "" }
        return String(scalars[first...last])
    }

    static func permitted(_ name: String, kind: HeaderKind) -> Bool {
        if name.hasPrefix("x-bsv-auth-") { return false }
        if name.hasPrefix("x-bsv-") { return true }
        switch kind {
        case .request: return name == "authorization" || name == "content-type"
        case .response: return name == "authorization"
        }
    }
    /// The methods the TypeScript middleware accepts: 1 to 32 uppercase token
    /// characters, no digits (`auth-express-middleware/src/index.ts:2002`).
    /// `AuthFetch` uppercases the method it sends (`clients/AuthFetch.ts:1310`).
    static func validMethod(_ value: String) -> Bool {
        (1...32).contains(value.utf8.count)
            && value.utf8.allSatisfy { b in
                (65...90).contains(b) || "!#$%&'*+.^_`|~-".utf8.contains(b)
            }
    }
    /// The TypeScript middleware rejects a request target (`originalUrl`, the
    /// path and query) longer than 8192 UTF-16 code units
    /// (`auth-express-middleware/src/index.ts:2024`).
    static let maximumRequestTargetLength = 8_192
    static func validTargetLength(path: String, query: String?) -> Bool {
        path.utf16.count + (query?.utf16.count ?? 0) <= maximumRequestTargetLength
    }
    static func validToken(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.allSatisfy { b in
                (48...57).contains(b) || (65...90).contains(b) || (97...122).contains(b)
                    || "!#$%&'*+-.^_`|~".utf8.contains(b)
            }
    }
    static func safeText(_ value: String) -> Bool {
        value.utf8.allSatisfy { $0 >= 0x20 && $0 != 0x7f }
    }
    static func normalizedBody(_ body: [UInt8]?, method: String, headers: [BRC104Header])
        -> [UInt8]?
    {
        // `#defaultRequestBody` replaces only an absent body (`body !== undefined`)
        // and matches `application/json` case-sensitively; an empty body stays
        // empty and is written as -1.
        guard body == nil,
            ["POST", "PUT", "PATCH", "DELETE"].contains(method.uppercased()),
            headers.contains(where: {
                $0.name.lowercased() == "content-type" && $0.value.contains("application/json")
            })
        else { return body }
        return Array("{}".utf8)
    }

    struct Writer {
        var output: [UInt8] = []
        let limits: BRC104Limits
        mutating func bytes(_ value: [UInt8]) throws {
            let (total, overflow) = output.count.addingReportingOverflow(value.count)
            guard !overflow, total <= limits.maximumPayloadBytes else {
                throw BRC104Error.resourceLimit
            }
            output += value
        }
        mutating func compact(_ value: UInt64) throws { try bytes(CompactSize.encode(value)) }
        mutating func string(_ value: String) throws { try counted(Array(value.utf8)) }
        mutating func counted(_ value: [UInt8]) throws {
            guard value.count <= limits.maximumPayloadBytes else { throw BRC104Error.resourceLimit }
            try compact(UInt64(value.count))
            try bytes(value)
        }
        mutating func optionalString(_ value: String?) throws {
            if let value { try string(value) } else { try compact(UInt64.max) }
        }
        /// BRC-104 writes an absent or empty body as -1.
        mutating func body(_ value: [UInt8]?) throws {
            if let value, !value.isEmpty { try counted(value) } else { try compact(UInt64.max) }
        }
        mutating func headers(_ value: [BRC104Header], kind: HeaderKind) throws {
            let canonical = try BRC104Codec.normalized(value, kind: kind, limits: limits)
            try compact(UInt64(canonical.count))
            for h in canonical {
                try string(h.name)
                try string(h.value)
            }
        }
    }
    struct Reader {
        let data: [UInt8]
        var offset = 0
        let limits: BRC104Limits
        init(_ data: [UInt8], limits: BRC104Limits) {
            self.data = data
            self.limits = limits
        }
        var finished: Bool { offset == data.count }
        mutating func fixed(_ count: Int) throws -> [UInt8] {
            guard count >= 0, data.count - offset >= count else {
                throw BRC104Error.malformedPayload
            }
            defer { offset += count }
            return Array(data[offset..<(offset + count)])
        }
        mutating func compact() throws -> UInt64 {
            guard offset < data.count else { throw BRC104Error.malformedPayload }
            let first = data[offset]
            let width = first < 253 ? 1 : first == 253 ? 3 : first == 254 ? 5 : 9
            guard data.count - offset >= width else { throw BRC104Error.malformedPayload }
            let value: UInt64
            switch first {
            case 0...252: value = UInt64(first)
            case 253: value = UInt64(data[offset + 1]) | UInt64(data[offset + 2]) << 8
            case 254:
                value = (0..<4).reduce(0) { $0 | UInt64(data[offset + $1 + 1]) << UInt64(8 * $1) }
            default:
                value = (0..<8).reduce(0) { $0 | UInt64(data[offset + $1 + 1]) << UInt64(8 * $1) }
            }
            guard CompactSize.encodedLength(of: value) == width else {
                throw BRC104Error.malformedPayload
            }
            offset += width
            return value
        }
        mutating func counted() throws -> [UInt8] {
            let length = try compact()
            guard length != UInt64.max, length <= UInt64(limits.maximumPayloadBytes),
                let n = Int(exactly: length)
            else { throw BRC104Error.resourceLimit }
            return try fixed(n)
        }
        mutating func string() throws -> String {
            let b = try counted()
            guard let value = String(bytes: b, encoding: .utf8) else {
                throw BRC104Error.malformedPayload
            }
            return value
        }
        mutating func optionalString() throws -> String? {
            let length = try compact()
            if length == UInt64.max { return nil }
            guard length <= UInt64(limits.maximumPayloadBytes), let n = Int(exactly: length),
                let s = String(bytes: try fixed(n), encoding: .utf8)
            else { throw BRC104Error.malformedPayload }
            return s
        }
        mutating func optionalBytes() throws -> [UInt8]? {
            let length = try compact()
            if length == UInt64.max { return nil }
            guard length <= UInt64(limits.maximumPayloadBytes), let n = Int(exactly: length) else {
                throw BRC104Error.resourceLimit
            }
            return try fixed(n)
        }
        mutating func headers(kind: HeaderKind) throws -> [BRC104Header] {
            let count = try compact()
            guard count <= UInt64(limits.maximumHeaders), let n = Int(exactly: count) else {
                throw BRC104Error.resourceLimit
            }
            var result: [BRC104Header] = []
            for _ in 0..<n { result.append(.init(name: try string(), value: try string())) }
            return try BRC104Codec.normalized(result, kind: kind, limits: limits)
        }
    }
}
