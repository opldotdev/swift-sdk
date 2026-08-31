/// Construction failures for BRC-141 encoders and sizing helpers.
///
/// Camera-fed decoding never throws; unusable scans are ordinary rejected progress values.
public enum AirGapError: Error, Equatable, Sendable {
    case emptyMessage
    case messageTooLarge(actual: Int, maximum: Int)
    case invalidBlockByteCount(Int)
    case tooManyBlocks(actual: Int, maximum: Int)
    case invalidSessionIDByteCount(Int)
    case randomGenerationFailed
}
