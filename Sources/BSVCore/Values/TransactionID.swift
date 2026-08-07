/// A transaction identifier stored in its 32-byte wire/internal order.
public struct TransactionID: Hashable, Sendable {
    private let storage: FixedByteStorage

    /// Creates an identifier from exactly 32 bytes in wire/internal order.
    public init(wireBytes: [UInt8]) throws {
        self.storage = try FixedByteStorage(wireBytes, count: 32)
    }

    /// The identifier in stored wire/internal order.
    public var wireBytes: [UInt8] {
        storage.bytes
    }

    /// The identifier bytes in reversed human-display order.
    public var displayBytes: [UInt8] {
        Array(storage.bytes.reversed())
    }
}
