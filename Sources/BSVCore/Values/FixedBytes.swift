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

    /// The hash bytes in their stored order.
    public var bytes: [UInt8] {
        storage.bytes
    }
}
