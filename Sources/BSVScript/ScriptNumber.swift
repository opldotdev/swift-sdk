import BSVBigNum

/// A Bitcoin Script integer encoded as little-endian signed magnitude.
///
/// Script numbers are not two's-complement integers. Zero is the empty byte
/// string and the high bit of the final byte carries the sign. Parsing always
/// requires an explicit byte-count ceiling because the applicable limit is a
/// consensus or policy decision made by the calling opcode/interpreter era.
public struct ScriptNumber: Hashable, Sendable {
    /// The pre-Genesis input limit used by most numeric opcodes.
    public static let legacyMaximumByteCount = 4

    private let value: BigSigned

    /// Creates a Script number from a native signed integer.
    public init(_ value: Int64) {
        self.value = BigSigned(
            sign: value < 0 ? .minus : .plus,
            magnitude: BigMagnitude(value.magnitude)
        )
    }

    /// Decodes a little-endian signed-magnitude Script number.
    public init(
        encoded bytes: [UInt8],
        maximumByteCount: Int,
        requireMinimal: Bool = true
    ) throws {
        guard maximumByteCount >= 0 else {
            throw ScriptNumberError.invalidMaximumByteCount(maximumByteCount)
        }
        guard bytes.count <= maximumByteCount else {
            throw ScriptNumberError.numberTooLarge(
                actual: bytes.count,
                maximum: maximumByteCount
            )
        }
        if requireMinimal, !Self.isMinimallyEncoded(bytes) {
            throw ScriptNumberError.nonMinimalEncoding
        }
        guard var finalByte = bytes.last else {
            value = BigSigned(sign: .plus, magnitude: .zero)
            return
        }

        let isNegative = finalByte & 0x80 != 0
        finalByte &= 0x7f
        var magnitudeBytes = bytes
        magnitudeBytes[magnitudeBytes.index(before: magnitudeBytes.endIndex)] = finalByte
        magnitudeBytes.reverse()

        let magnitude = try BigMagnitude(
            bigEndian: magnitudeBytes,
            maximumByteCount: maximumByteCount
        )
        value = BigSigned(
            sign: isNegative ? .minus : .plus,
            magnitude: magnitude
        )
    }

    /// `true` only for a nonzero negative value.
    public var isNegative: Bool { value.sign == .minus }

    /// `true` when the numeric value is zero, including permissively decoded
    /// negative-zero encodings.
    public var isZero: Bool { value.magnitude.isZero }

    /// Returns the canonical little-endian signed-magnitude encoding.
    ///
    /// Serialization is pure: it never mutates the receiver.
    public func serialized(maximumByteCount: Int) throws -> [UInt8] {
        guard maximumByteCount >= 0 else {
            throw ScriptNumberError.invalidMaximumByteCount(maximumByteCount)
        }
        guard !isZero else { return [] }
        guard value.magnitude.byteCount <= maximumByteCount else {
            throw ScriptNumberError.numberTooLarge(
                actual: value.magnitude.byteCount,
                maximum: maximumByteCount
            )
        }

        var bytes = try value.magnitude.bigEndianBytes(
            maximumByteCount: maximumByteCount
        )
        bytes.reverse()

        if bytes[bytes.index(before: bytes.endIndex)] & 0x80 != 0 {
            bytes.append(isNegative ? 0x80 : 0x00)
        } else if isNegative {
            bytes[bytes.index(before: bytes.endIndex)] |= 0x80
        }

        guard bytes.count <= maximumByteCount else {
            throw ScriptNumberError.numberTooLarge(
                actual: bytes.count,
                maximum: maximumByteCount
            )
        }
        return bytes
    }

    /// Returns whether `bytes` already use the unique minimal encoding.
    public static func isMinimallyEncoded(_ bytes: [UInt8]) -> Bool {
        guard let last = bytes.last else { return true }
        guard last & 0x7f == 0 else { return true }
        guard bytes.count > 1 else { return false }
        return bytes[bytes.index(bytes.endIndex, offsetBy: -2)] & 0x80 != 0
    }

    /// Removes redundant sign/zero bytes without interpreting the value.
    public static func minimallyEncoded(_ bytes: [UInt8]) -> [UInt8] {
        guard let last = bytes.last, last & 0x7f == 0 else { return bytes }
        guard bytes.count > 1 else { return [] }
        guard bytes[bytes.index(bytes.endIndex, offsetBy: -2)] & 0x80 == 0 else {
            return bytes
        }

        var result = bytes
        var index = result.count - 1
        while index > 0 {
            let preceding = result[index - 1]
            if preceding != 0 {
                if preceding & 0x80 != 0 {
                    result[index] = last
                    index += 1
                } else {
                    result[index - 1] |= last
                }
                return Array(result[..<index])
            }
            index -= 1
        }
        return []
    }

    /// Returns the value clamped to Bitcoin Script's Int32 conversion range.
    public func int32Clamped() -> Int32 {
        let wide = int64Clamped()
        if wide > Int64(Int32.max) { return Int32.max }
        if wide < Int64(Int32.min) { return Int32.min }
        return Int32(wide)
    }

    /// Returns the value clamped instead of truncating on native overflow.
    public func int64Clamped() -> Int64 {
        guard value.magnitude.bitWidth <= 64,
              let magnitude = try? value.magnitude.uint64()
        else {
            return isNegative ? Int64.min : Int64.max
        }

        if isNegative {
            let minimumMagnitude = UInt64(Int64.max) + 1
            guard magnitude < minimumMagnitude else { return Int64.min }
            return -Int64(magnitude)
        }
        guard magnitude <= UInt64(Int64.max) else { return Int64.max }
        return Int64(magnitude)
    }
}
