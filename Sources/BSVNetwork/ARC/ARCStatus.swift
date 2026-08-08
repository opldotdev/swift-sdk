/// An ARC transaction lifecycle status.
///
/// This is a raw-value type rather than a closed enum so newer provider
/// statuses remain observable instead of becoming decoding failures.
public struct ARCStatus: RawRepresentable, Codable, Hashable, Sendable,
    CustomStringConvertible {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        rawValue = try container.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static let rejected = Self(rawValue: "REJECTED")
    public static let unknown = Self(rawValue: "UNKNOWN")
    public static let queued = Self(rawValue: "QUEUED")
    public static let received = Self(rawValue: "RECEIVED")
    public static let stored = Self(rawValue: "STORED")
    public static let announcedToNetwork = Self(rawValue: "ANNOUNCED_TO_NETWORK")
    public static let requestedByNetwork = Self(rawValue: "REQUESTED_BY_NETWORK")
    public static let sentToNetwork = Self(rawValue: "SENT_TO_NETWORK")
    public static let acceptedByNetwork = Self(rawValue: "ACCEPTED_BY_NETWORK")
    public static let seenOnNetwork = Self(rawValue: "SEEN_ON_NETWORK")
    public static let mined = Self(rawValue: "MINED")
    public static let minedInStaleBlock = Self(rawValue: "MINED_IN_STALE_BLOCK")
    /// A legacy Go SDK status that current ARC does not define.
    public static let confirmed = Self(rawValue: "CONFIRMED")
    public static let doubleSpendAttempted = Self(rawValue: "DOUBLE_SPEND_ATTEMPTED")
    public static let seenInOrphanMempool = Self(rawValue: "SEEN_IN_ORPHAN_MEMPOOL")

    public var description: String { rawValue }
}
