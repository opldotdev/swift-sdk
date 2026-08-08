/// A transaction identifier stored in its 32-byte wire/internal order.
public struct TransactionID: Hashable, Sendable {
    private let storage: FixedByteStorage

    /// Creates an identifier from exactly 32 bytes in wire/internal order.
    public init(wireBytes: [UInt8]) throws {
        self.storage = try FixedByteStorage(wireBytes, count: 32)
    }

    /// Creates an identifier from its 64-character human-display hexadecimal form.
    public init(displayHex: String) throws {
        guard displayHex.utf8.prefix(65).count == 64 else {
            throw TextEncodingError.invalidLength
        }
        let displayBytes = try Hex.decode(displayHex, maximumDecodedByteCount: 32)
        self.storage = try FixedByteStorage(Array(displayBytes.reversed()), count: 32)
    }

    /// Creates an identifier from a package-generated digest whose width is guaranteed.
    package init(exactDigestBytesGuaranteed bytes: [UInt8]) {
        self.storage = FixedByteStorage(exactByteCountGuaranteed: bytes, count: 32)
    }

    /// The identifier in stored wire/internal order.
    public var wireBytes: [UInt8] {
        storage.bytes
    }

    /// The identifier bytes in reversed human-display order.
    public var displayBytes: [UInt8] {
        Array(storage.bytes.reversed())
    }

    /// The conventional lowercase transaction identifier shown to users.
    public var displayHex: String {
        Hex.encode(displayBytes)
    }
}
