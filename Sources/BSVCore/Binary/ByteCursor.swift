/// A bounded, forward-only byte reader.
///
/// Failed reads leave `position` unchanged, including compound CompactSize and
/// VarBytes reads.
package struct ByteCursor {
    private let bytes: [UInt8]

    /// The offset of the next unread byte.
    package private(set) var position: Int

    /// Creates a cursor positioned at the start of `bytes`.
    package init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.position = 0
    }

    /// The number of bytes not yet consumed.
    package var remaining: Int {
        bytes.count - position
    }

    /// Reads exactly `count` bytes, without advancing on failure.
    package mutating func read(count: Int) throws -> [UInt8] {
        guard count >= 0 else {
            throw BinaryDecodingError.invalidCount(count)
        }
        guard count <= remaining else {
            throw BinaryDecodingError.truncatedInput(expected: count, remaining: remaining)
        }

        let start = position
        let end = start + count
        let result = Array(bytes[start..<end])
        position = end
        return result
    }

    /// Reads exactly `count` bytes and returns them in reverse order.
    package mutating func readReversed(count: Int) throws -> [UInt8] {
        Array(try read(count: count).reversed())
    }

    /// Reads an unsigned 16-bit little-endian integer.
    package mutating func readUInt16LE() throws -> UInt16 {
        let value = try read(count: 2)
        return UInt16(value[0]) | (UInt16(value[1]) << 8)
    }

    /// Reads an unsigned 16-bit big-endian integer.
    package mutating func readUInt16BE() throws -> UInt16 {
        let value = try read(count: 2)
        return (UInt16(value[0]) << 8) | UInt16(value[1])
    }

    /// Reads an unsigned 32-bit little-endian integer.
    package mutating func readUInt32LE() throws -> UInt32 {
        let value = try read(count: 4)
        return UInt32(value[0])
            | (UInt32(value[1]) << 8)
            | (UInt32(value[2]) << 16)
            | (UInt32(value[3]) << 24)
    }

    /// Reads an unsigned 32-bit big-endian integer.
    package mutating func readUInt32BE() throws -> UInt32 {
        let value = try read(count: 4)
        return (UInt32(value[0]) << 24)
            | (UInt32(value[1]) << 16)
            | (UInt32(value[2]) << 8)
            | UInt32(value[3])
    }

    /// Reads an unsigned 64-bit little-endian integer.
    package mutating func readUInt64LE() throws -> UInt64 {
        let value = try read(count: 8)
        return UInt64(value[0])
            | (UInt64(value[1]) << 8)
            | (UInt64(value[2]) << 16)
            | (UInt64(value[3]) << 24)
            | (UInt64(value[4]) << 32)
            | (UInt64(value[5]) << 40)
            | (UInt64(value[6]) << 48)
            | (UInt64(value[7]) << 56)
    }

    /// Reads an unsigned 64-bit big-endian integer.
    package mutating func readUInt64BE() throws -> UInt64 {
        let value = try read(count: 8)
        return (UInt64(value[0]) << 56)
            | (UInt64(value[1]) << 48)
            | (UInt64(value[2]) << 40)
            | (UInt64(value[3]) << 32)
            | (UInt64(value[4]) << 24)
            | (UInt64(value[5]) << 16)
            | (UInt64(value[6]) << 8)
            | UInt64(value[7])
    }

    /// Reads one CompactSize value under the requested canonicality policy.
    package mutating func readCompactSize(
        canonicality: CompactSizeCanonicality
    ) throws -> DecodedCompactSize {
        var candidate = self
        let prefix = try candidate.read(count: 1)[0]
        let value: UInt64

        if prefix <= 0xfc {
            value = UInt64(prefix)
        } else if prefix == 0xfd {
            value = UInt64(try candidate.readUInt16LE())
        } else if prefix == 0xfe {
            value = UInt64(try candidate.readUInt32LE())
        } else {
            value = try candidate.readUInt64LE()
        }

        let bytesConsumed = candidate.position - position
        let isCanonical = bytesConsumed == CompactSize.encodedLength(of: value)
        switch canonicality {
        case .required where !isCanonical:
            throw BinaryDecodingError.nonCanonicalCompactSize
        case .required, .permissive:
            break
        }

        self = candidate
        return DecodedCompactSize(
            value: value,
            bytesConsumed: bytesConsumed,
            isCanonical: isCanonical
        )
    }

    /// Reads CompactSize-prefixed bytes within the caller's length limit.
    ///
    /// The declared length is checked for native `Int` representability before
    /// the payload is copied.
    package mutating func readVarBytes(
        maximumLength: UInt64,
        canonicality: CompactSizeCanonicality
    ) throws -> DecodedVarBytes {
        var candidate = self
        let decodedLength = try candidate.readCompactSize(canonicality: canonicality)
        let length = decodedLength.value

        guard length <= maximumLength else {
            throw BinaryDecodingError.lengthExceedsLimit(
                length: length,
                maximum: maximumLength
            )
        }
        guard length <= UInt64(Int.max) else {
            throw BinaryDecodingError.lengthNotRepresentable(length)
        }

        let payload = try candidate.read(count: Int(length))
        let bytesConsumed = candidate.position - position
        self = candidate
        return DecodedVarBytes(
            bytes: payload,
            bytesConsumed: bytesConsumed,
            isCanonical: decodedLength.isCanonical
        )
    }

    /// Rejects any trailing bytes, making full-input consumption explicit.
    package func requireFinished() throws {
        guard remaining == 0 else {
            throw BinaryDecodingError.trailingBytes(remaining)
        }
    }
}
