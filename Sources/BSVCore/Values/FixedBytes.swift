/// An exact-width constructor failure.
public enum FixedByteCountError: Error, Equatable, Sendable {
    /// The supplied byte count did not equal the value's required width.
    case invalidByteCount(expected: Int, actual: Int)
}

/// Shared package storage for exact-width byte values.
package struct FixedByteStorage: Hashable, Sendable {
    private let value: [UInt8]

    package init(_ bytes: [UInt8], count: Int) throws {
        guard bytes.count == count else {
            throw FixedByteCountError.invalidByteCount(
                expected: count,
                actual: bytes.count
            )
        }
        self.value = bytes
    }

    /// Stores bytes whose exact width is guaranteed by a package-owned primitive.
    package init(exactByteCountGuaranteed bytes: [UInt8], count: Int) {
        assert(bytes.count == count, "package primitive returned an invalid digest width")
        self.value = bytes
    }

    package var bytes: [UInt8] {
        value
    }
}

/// A 20-byte hash value that preserves the supplied byte order.
public struct Hash160: Hashable, Sendable {
    private let storage: FixedByteStorage

    /// Creates a hash from exactly 20 bytes without reversing them.
    public init(_ bytes: [UInt8]) throws {
        self.storage = try FixedByteStorage(bytes, count: 20)
    }

    /// Creates a value from a package-generated digest whose 20-byte width is guaranteed.
    package init(exactDigestBytesGuaranteed bytes: [UInt8]) {
        self.storage = FixedByteStorage(exactByteCountGuaranteed: bytes, count: 20)
    }

    /// The hash bytes in their stored order.
    public var bytes: [UInt8] {
        storage.bytes
    }
}

/// A 32-byte hash value that preserves the supplied byte order.
public struct Hash256: Hashable, Sendable {
    private let storage: FixedByteStorage

    /// Creates a hash from exactly 32 bytes without reversing them.
    public init(_ bytes: [UInt8]) throws {
        self.storage = try FixedByteStorage(bytes, count: 32)
    }

    /// Creates a value from a package-generated digest whose 32-byte width is guaranteed.
    package init(exactDigestBytesGuaranteed bytes: [UInt8]) {
        self.storage = FixedByteStorage(exactByteCountGuaranteed: bytes, count: 32)
    }

    /// The hash bytes in their stored order.
    public var bytes: [UInt8] {
        storage.bytes
    }
}

/// A 64-byte hash value that preserves the supplied byte order.
public struct Hash512: Hashable, Sendable {
    private let storage: FixedByteStorage

    /// Creates a hash from exactly 64 bytes without reversing them.
    public init(_ bytes: [UInt8]) throws {
        self.storage = try FixedByteStorage(bytes, count: 64)
    }

    /// Creates a value from a package-generated digest whose 64-byte width is guaranteed.
    package init(exactDigestBytesGuaranteed bytes: [UInt8]) {
        self.storage = FixedByteStorage(exactByteCountGuaranteed: bytes, count: 64)
    }

    /// The hash bytes in their stored order.
    public var bytes: [UInt8] {
        storage.bytes
    }
}
