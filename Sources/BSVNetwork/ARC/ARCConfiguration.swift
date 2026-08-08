import Foundation

/// Validated ARC endpoint and request-header configuration.
///
/// A base URL must be an absolute HTTPS URL without credentials, a query,
/// a fragment, or a trailing slash. Rejecting a trailing slash makes the
/// resulting `/tx` and `/tx/{txid}` URLs unambiguous.
public struct ARCConfiguration: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable {
    public static let maximumBaseURLUTF8ByteCount = 2_048
    public static let maximumHeaderValueUTF8ByteCount = 8_192

    package let baseURL: URL
    package let apiKey: String?
    package let callbackURL: URL?
    package let callbackToken: String?
    package let callbackBatch: Bool
    package let fullStatusUpdates: Bool
    package let maximumTimeoutSeconds: UInt32?
    package let skipFeeValidation: Bool
    package let skipScriptValidation: Bool
    package let skipTransactionValidation: Bool
    package let cumulativeFeeValidation: Bool
    package let waitForStatus: String?
    package let waitFor: ARCStatus?

    /// Creates a bounded ARC configuration.
    ///
    /// - Parameter maximumTimeoutSeconds: Value for `X-MaxTimeout`, in seconds.
    public init(
        baseURL: URL,
        apiKey: String? = nil,
        callbackURL: URL? = nil,
        callbackToken: String? = nil,
        callbackBatch: Bool = false,
        fullStatusUpdates: Bool = false,
        maximumTimeoutSeconds: UInt32? = nil,
        skipFeeValidation: Bool = false,
        skipScriptValidation: Bool = false,
        skipTransactionValidation: Bool = false,
        cumulativeFeeValidation: Bool = false,
        waitForStatus: String? = nil,
        waitFor: ARCStatus? = nil
    ) throws {
        guard Self.isValidBaseURL(baseURL),
              Self.isValidHeaderValue(apiKey),
              Self.isValidCallbackURL(callbackURL),
              Self.isValidHeaderValue(callbackToken),
              Self.isValidHeaderValue(waitForStatus),
              Self.isValidHeaderValue(waitFor?.rawValue)
        else {
            throw NetworkServiceError.invalidConfiguration
        }

        self.baseURL = baseURL
        self.apiKey = apiKey
        self.callbackURL = callbackURL
        self.callbackToken = callbackToken
        self.callbackBatch = callbackBatch
        self.fullStatusUpdates = fullStatusUpdates
        self.maximumTimeoutSeconds = maximumTimeoutSeconds
        self.skipFeeValidation = skipFeeValidation
        self.skipScriptValidation = skipScriptValidation
        self.skipTransactionValidation = skipTransactionValidation
        self.cumulativeFeeValidation = cumulativeFeeValidation
        self.waitForStatus = waitForStatus
        self.waitFor = waitFor
    }

    public var description: String { "<redacted ARC configuration>" }
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

    private static func isValidCallbackURL(_ url: URL?) -> Bool {
        guard let url else { return true }
        guard url.absoluteString.utf8.count <= maximumHeaderValueUTF8ByteCount,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.fragment == nil
        else {
            return false
        }
        return isValidHeaderValue(url.absoluteString)
    }

    private static func isValidHeaderValue(_ value: String?) -> Bool {
        guard let value else { return true }
        guard value.utf8.count <= maximumHeaderValueUTF8ByteCount else { return false }
        return !value.unicodeScalars.contains {
            let category = $0.properties.generalCategory
            return category == .control || category == .format
        }
    }
}
