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
        guard BRC104Codec.validToken(method) else { throw BRC104Error.invalidMethod }
        guard !path.isEmpty, path.utf8.first == 47, BRC104Codec.safeText(path),
            !path.contains("?"), !path.contains("#")
        else { throw BRC104Error.invalidPath }
        if let query {
            guard query.utf8.first == 63, !query.contains("#"), BRC104Codec.safeText(query) else {
                throw BRC104Error.invalidPath
            }
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
        guard (100...599).contains(status) else { throw BRC104Error.invalidStatus }
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

public struct BRC104Limits: Equatable, Sendable {
    public let maximumPayloadBytes: Int
    public let maximumHeaders: Int
    public let maximumHeaderNameBytes: Int
    public let maximumHeaderValueBytes: Int
    public let maximumHeaderBytes: Int
    public init(
        maximumPayloadBytes: Int = 1 << 20, maximumHeaders: Int = 64,
        maximumHeaderNameBytes: Int = 256,
        maximumHeaderValueBytes: Int = 8 << 10, maximumHeaderBytes: Int = 64 << 10
    ) throws {
        guard maximumPayloadBytes >= 0, maximumHeaders >= 0, maximumHeaderNameBytes >= 0,
            maximumHeaderValueBytes >= 0, maximumHeaderBytes >= 0
        else { throw BRC104Error.resourceLimit }
        self.maximumPayloadBytes = maximumPayloadBytes
        self.maximumHeaders = maximumHeaders
        self.maximumHeaderNameBytes = maximumHeaderNameBytes
        self.maximumHeaderValueBytes = maximumHeaderValueBytes
        self.maximumHeaderBytes = maximumHeaderBytes
    }
    private init(
        validatedPayload: Int, headers: Int, headerName: Int, headerValue: Int, headerBytes: Int
    ) {
        maximumPayloadBytes = validatedPayload
        maximumHeaders = headers
        maximumHeaderNameBytes = headerName
        maximumHeaderValueBytes = headerValue
        maximumHeaderBytes = headerBytes
    }
    public static let standard = BRC104Limits(
        validatedPayload: 1 << 20, headers: 64, headerName: 256, headerValue: 8 << 10,
        headerBytes: 64 << 10)
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
    public static func encode(_ request: BRC104Request, limits: BRC104Limits = .standard) throws
        -> [UInt8]
    {
        var writer = Writer(limits: limits)
        try writer.bytes(request.requestID)
        try writer.string(request.method)
        try writer.string(request.path)
        try writer.optionalString(request.query)
        try writer.headers(request.headers, kind: .request)
        try writer.optionalBytes(
            normalizedBody(request.body, method: request.method, headers: request.headers))
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
        try writer.optionalBytes(response.body)
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
                header.value.utf8.count <= limits.maximumHeaderValueBytes,
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
            let value =
                name == "content-type"
                ? String(
                    header.value.split(
                        separator: ";", maxSplits: 1, omittingEmptySubsequences: false
                    )[0]
                )
                : header.value
            guard name != "content-type" || !value.isEmpty else { throw BRC104Error.invalidHeader }
            result.append(.init(name: name, value: value))
        }
        return result.sorted { Array($0.name.utf8).lexicographicallyPrecedes(Array($1.name.utf8)) }
    }
    static func permitted(_ name: String, kind: HeaderKind) -> Bool {
        if name.hasPrefix("x-bsv-auth-") { return false }
        if name.hasPrefix("x-bsv-") { return true }
        switch kind {
        case .request: return name == "authorization" || name == "content-type"
        case .response: return name == "authorization"
        }
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
        guard body?.isEmpty != false,
            ["POST", "PUT", "PATCH", "DELETE"].contains(method.uppercased()),
            headers.contains(where: {
                $0.name.lowercased() == "content-type"
                    && $0.value.lowercased().contains("application/json")
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
        mutating func optionalBytes(_ value: [UInt8]?) throws {
            if let value { try counted(value) } else { try compact(UInt64.max) }
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
