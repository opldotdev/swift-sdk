/// Returns whether text has the BRC-141 routing prefix.
///
/// This is deliberately only a cheap prefix test. Use ``AirGapDecoder/accept(_:)`` to validate a
/// complete part.
public func isAirGapPart(_ text: String) -> Bool {
    text.hasPrefix(AirGap.prefix)
}

/// Exact number of characters in every encoded part for `blockBytes`.
public func estimatePartCharLength(
    _ blockBytes: Int = AirGap.defaultBlockBytes
) throws -> Int {
    guard (1...AirGap.maximumBlockBytes).contains(blockBytes) else {
        throw AirGapError.invalidBlockByteCount(blockBytes)
    }
    return airGapPartCharLength(blockBytes)
}

package func airGapPartCharLength(_ blockBytes: Int) -> Int {
    let byteCount = AirGap.headerByteCount + blockBytes
    let remainder = byteCount % 3
    let encoded = (byteCount / 3) * 4 + (remainder == 0 ? 0 : remainder + 1)
    return AirGap.prefix.utf8.count + encoded
}
