/// BRC-141 version-1 wire and resource limits.
public enum AirGap {
    /// ASCII prefix on every encoded part.
    public static let prefix = "air-gap:"

    /// Version byte in the binary header.
    public static let wireVersion: UInt8 = 1

    /// Size of the session identifier in bytes.
    public static let sessionIDByteCount = 8

    /// Default source-block size.
    public static let defaultBlockBytes = 1_200

    /// Largest source-block size permitted by version 1.
    public static let maximumBlockBytes = 2_048

    /// Largest message permitted by version 1.
    public static let maximumMessageBytes = 65_536

    /// Consecutive parts of one foreign session required before switching.
    public static let sessionSwitchPartCount = 3

    package static let headerByteCount = 23
    package static let maximumBlockCount = Int(UInt16.max)
    package static let maximumTrackedSequences = 65_536
    package static let maximumPendingParts = 1_024
    package static let maximumPendingIndices = 4_096
}
