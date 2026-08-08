import BSVCrypto

/// A bounded file value returned by an injected UHRP content provider.
public struct StorageContent: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let bytes: [UInt8]
    /// The MIME type supplied by the provider. An empty value represents absent
    /// MIME metadata and is allowed for parity with a missing HTTP Content-Type.
    public let mimeType: String

    public init(
        bytes: [UInt8],
        mimeType: String,
        limits: UHRPLimits = .standard
    ) throws {
        guard bytes.count <= limits.maximumContentByteCount else {
            throw UHRPError.limitExceeded(
                name: "content",
                actual: bytes.count,
                maximum: limits.maximumContentByteCount)
        }
        let mimeBytes = mimeType.utf8
        guard mimeBytes.count <= limits.maximumMIMETypeUTF8ByteCount else {
            throw UHRPError.limitExceeded(
                name: "MIME type",
                actual: mimeBytes.count,
                maximum: limits.maximumMIMETypeUTF8ByteCount)
        }
        guard !mimeBytes.contains(0),
            mimeBytes.allSatisfy({ byte in
                byte >= 0x20 && byte != 0x7f
            })
        else {
            throw UHRPError.invalidMIMEType
        }
        self.bytes = bytes
        self.mimeType = mimeType
    }

    /// Returns whether this content's SHA-256 equals the identifier's hash.
    public func matches(_ identifier: UHRPURL) -> Bool {
        BSVHashing.sha256(bytes) == identifier.hash
    }

    public var description: String { "<redacted UHRP content>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// A transport-neutral asynchronous content boundary. Implementations own host
/// discovery, HTTP policy, cancellation propagation, and response validation.
public protocol UHRPContentProvider: Sendable {
    func content(for identifier: UHRPURL) async throws -> StorageContent
}
