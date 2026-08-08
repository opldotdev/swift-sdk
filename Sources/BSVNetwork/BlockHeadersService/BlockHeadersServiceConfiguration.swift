import Foundation

/// Validated configuration for a block-headers-service endpoint.
///
/// The service key is intentionally write-only: descriptions and reflection do
/// not expose it, and provider diagnostics redact it before returning an error.
public struct BlockHeadersServiceConfiguration: Hashable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maximumBaseURLUTF8ByteCount = 2_048
    public static let maximumAPIKeyUTF8ByteCount = 8_192

    package let baseURL: URL
    package let apiKey: String

    /// Creates a configuration for an absolute HTTPS endpoint.
    ///
    /// `baseURL` may include a path prefix but cannot include credentials, a
    /// query, a fragment, or a trailing slash.
    public init(baseURL: URL, apiKey: String) throws {
        guard Self.isValidBaseURL(baseURL), Self.isValidHeaderValue(apiKey) else {
            throw NetworkServiceError.invalidConfiguration
        }
        self.baseURL = baseURL
        self.apiKey = apiKey
    }

    public var description: String { "<redacted block headers service configuration>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    private static func isValidBaseURL(_ url: URL) -> Bool {
        guard url.absoluteString.utf8.count <= maximumBaseURLUTF8ByteCount,
              !url.absoluteString.hasSuffix("/"),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil
        else {
            return false
        }
        return true
    }

    private static func isValidHeaderValue(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumAPIKeyUTF8ByteCount else {
            return false
        }
        return !value.unicodeScalars.contains {
            let category = $0.properties.generalCategory
            return category == .control || category == .format
        }
    }
}
