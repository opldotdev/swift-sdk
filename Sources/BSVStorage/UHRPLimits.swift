/// Explicit hostile-input limits for UHRP identifiers and content values.
public struct UHRPLimits: Hashable, Sendable {
    public let maximumURLUTF8ByteCount: Int
    public let maximumContentByteCount: Int
    public let maximumMIMETypeUTF8ByteCount: Int

    public init(
        maximumURLUTF8ByteCount: Int,
        maximumContentByteCount: Int,
        maximumMIMETypeUTF8ByteCount: Int
    ) throws {
        let values = [
            ("maximumURLUTF8ByteCount", maximumURLUTF8ByteCount),
            ("maximumContentByteCount", maximumContentByteCount),
            ("maximumMIMETypeUTF8ByteCount", maximumMIMETypeUTF8ByteCount),
        ]
        if let invalid = values.first(where: { $0.1 <= 0 }) {
            throw UHRPError.nonPositiveLimit(name: invalid.0, value: invalid.1)
        }
        self.maximumURLUTF8ByteCount = maximumURLUTF8ByteCount
        self.maximumContentByteCount = maximumContentByteCount
        self.maximumMIMETypeUTF8ByteCount = maximumMIMETypeUTF8ByteCount
    }

    private init(standard: Void) {
        maximumURLUTF8ByteCount = 256
        maximumContentByteCount = 64 * 1_024 * 1_024
        maximumMIMETypeUTF8ByteCount = 256
    }

    public static let standard = Self(standard: ())
}

/// UHRP parsing and resource-limit errors. Diagnostics never include content bytes.
public enum UHRPError: Error, Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    case nonPositiveLimit(name: String, value: Int)
    case limitExceeded(name: String, actual: Int, maximum: Int)
    case invalidIdentifier
    case invalidVersion
    case invalidMIMEType

    public var description: String {
        switch self {
        case .nonPositiveLimit(let name, let value):
            "UHRP limit \(name) must be positive (received \(value))"
        case .limitExceeded(let name, let actual, let maximum):
            "UHRP \(name) exceeds its limit (\(actual) > \(maximum))"
        case .invalidIdentifier: "UHRP identifier is invalid"
        case .invalidVersion: "UHRP identifier has an unsupported version"
        case .invalidMIMEType: "UHRP MIME type is invalid"
        }
    }

    public var debugDescription: String { description }
}
