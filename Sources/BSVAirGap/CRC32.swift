/// IEEE CRC-32 of `bytes`, using the reflected `0xEDB88320` polynomial.
///
/// BRC-141 uses this for accidental transport corruption only. It is not an authenticator.
public func crc32(_ bytes: [UInt8]) -> UInt32 {
    var value = UInt32.max
    for byte in bytes {
        let index = Int((value ^ UInt32(byte)) & 0xff)
        value = crc32Table[index] ^ (value >> 8)
    }
    return value ^ UInt32.max
}

private let crc32Table: [UInt32] = (0..<256).map { entry in
    var value = UInt32(entry)
    for _ in 0..<8 {
        value = value & 1 == 1 ? 0xedb8_8320 ^ (value >> 1) : value >> 1
    }
    return value
}
