/// An append-only writer for explicit Bitcoin wire encodings.
package struct ByteWriter {
    /// The bytes emitted so far.
    package private(set) var bytes: [UInt8]

    /// Creates an empty writer.
    package init() {
        self.bytes = []
    }

    /// Creates an empty writer with bounded capacity already reserved.
    package init(capacity: Int) {
        self.bytes = []
        self.bytes.reserveCapacity(capacity)
    }

    /// Appends bytes without transformation.
    package mutating func write(_ bytes: [UInt8]) {
        self.bytes.append(contentsOf: bytes)
    }

    /// Appends bytes in reverse order.
    package mutating func writeReversed(_ bytes: [UInt8]) {
        self.bytes.append(contentsOf: bytes.reversed())
    }

    /// Appends an unsigned 16-bit little-endian integer.
    package mutating func writeUInt16LE(_ value: UInt16) {
        write([
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
        ])
    }

    /// Appends an unsigned 16-bit big-endian integer.
    package mutating func writeUInt16BE(_ value: UInt16) {
        write([
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }

    /// Appends an unsigned 32-bit little-endian integer.
    package mutating func writeUInt32LE(_ value: UInt32) {
        write([
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 24),
        ])
    }

    /// Appends an unsigned 32-bit big-endian integer.
    package mutating func writeUInt32BE(_ value: UInt32) {
        write([
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }

    /// Appends an unsigned 64-bit little-endian integer.
    package mutating func writeUInt64LE(_ value: UInt64) {
        write([
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 32),
            UInt8(truncatingIfNeeded: value >> 40),
            UInt8(truncatingIfNeeded: value >> 48),
            UInt8(truncatingIfNeeded: value >> 56),
        ])
    }

    /// Appends an unsigned 64-bit big-endian integer.
    package mutating func writeUInt64BE(_ value: UInt64) {
        write([
            UInt8(truncatingIfNeeded: value >> 56),
            UInt8(truncatingIfNeeded: value >> 48),
            UInt8(truncatingIfNeeded: value >> 40),
            UInt8(truncatingIfNeeded: value >> 32),
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }

    /// Appends the canonical CompactSize representation of `value`.
    package mutating func writeCompactSize(_ value: UInt64) {
        switch value {
        case 0...0xfc:
            write([UInt8(value)])
        case 0xfd...0xffff:
            write([0xfd])
            writeUInt16LE(UInt16(value))
        case 0x1_0000...0xffff_ffff:
            write([0xfe])
            writeUInt32LE(UInt32(value))
        default:
            write([0xff])
            writeUInt64LE(value)
        }
    }

    /// Appends bytes prefixed by their canonical CompactSize length.
    package mutating func writeVarBytes(_ value: [UInt8]) {
        writeCompactSize(UInt64(value.count))
        write(value)
    }
}
