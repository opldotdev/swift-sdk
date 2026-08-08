import BSVCore
import BSVCrypto
import BSVKeys

/// A canonical UHRP identifier carrying one SHA-256 content hash.
public struct UHRPURL: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    private static let version: [UInt8] = [0xce, 0x00]
    private static let expectedPayloadByteCount = 34

    public let hash: Hash256

    public init(hash: Hash256) {
        self.hash = hash
    }

    /// Hashes bounded file bytes and creates the corresponding UHRP identifier.
    public init(fileBytes: [UInt8], limits: UHRPLimits = .standard) throws {
        guard fileBytes.count <= limits.maximumContentByteCount else {
            throw UHRPError.limitExceeded(
                name: "content",
                actual: fileBytes.count,
                maximum: limits.maximumContentByteCount)
        }
        self.hash = BSVHashing.sha256(fileBytes)
    }

    /// Parses the Go-compatible bare, `uhrp://`, or `web+uhrp://` form.
    public init(parsing value: String, limits: UHRPLimits = .standard) throws {
        let byteCount = value.utf8.count
        guard byteCount <= limits.maximumURLUTF8ByteCount else {
            throw UHRPError.limitExceeded(
                name: "URL", actual: byteCount, maximum: limits.maximumURLUTF8ByteCount)
        }

        let source = Array(value.utf8)
        let identifier = String(
            decoding: source.dropFirst(Self.normalizedStart(in: source)),
            as: UTF8.self)
        let payload: [UInt8]
        do {
            payload = try Base58Check.decode(
                identifier,
                maximumPayloadByteCount: Self.expectedPayloadByteCount)
        } catch {
            throw UHRPError.invalidIdentifier
        }
        guard payload.count == Self.expectedPayloadByteCount else {
            throw UHRPError.invalidIdentifier
        }
        guard Array(payload.prefix(Self.version.count)) == Self.version else {
            throw UHRPError.invalidVersion
        }
        guard let hash = try? Hash256(Array(payload.dropFirst(Self.version.count))) else {
            throw UHRPError.invalidIdentifier
        }
        self.hash = hash
    }

    /// The canonical bare Base58Check representation used by the pinned Go and TypeScript SDKs.
    public var encoded: String { Base58Check.encode(Self.version + hash.bytes) }

    public var uhrpURL: String { "uhrp://\(encoded)" }
    public var webUHRPURL: String { "web+uhrp://\(encoded)" }
    public var description: String { encoded }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    private static func normalizedStart(in source: [UInt8]) -> Int {
        if hasPrefix(source, ascii: Array("web+uhrp://".utf8)) {
            return "web+uhrp://".utf8.count
        }
        if hasPrefix(source, ascii: Array("uhrp://".utf8)) {
            return "uhrp://".utf8.count
        }
        return 0
    }

    private static func hasPrefix(_ source: [UInt8], ascii prefix: [UInt8]) -> Bool {
        guard source.count >= prefix.count else { return false }
        for index in prefix.indices {
            let byte = source[index]
            let lowered = (65...90).contains(byte) ? byte + 32 : byte
            guard lowered == prefix[index] else { return false }
        }
        return true
    }
}
