/// A transport implementation capable of submitting tagged BEEF to one SHIP endpoint.
public protocol TopicFacilitator: Sendable {
    func submit(_ taggedBEEF: TaggedBEEF, to host: OverlayHost) async throws -> Steak
}

public enum RequireAck: String, CaseIterable, Hashable, Sendable {
    case none
    case any
    case some
    case all
}

/// An acknowledgment requirement suitable for a higher-level broadcaster policy.
public struct AckFrom: Hashable, Sendable {
    public let requirement: RequireAck
    public let topics: [OverlayTopic]

    public init(
        requirement: RequireAck,
        topics: [OverlayTopic] = [],
        limits: OverlayLimits = .standard
    ) throws {
        if requirement == .some, topics.isEmpty {
            throw OverlayError.emptyValue(name: "topics")
        }
        guard topics.count <= limits.maximumTopicCount else {
            throw OverlayError.limitExceeded(
                name: "topics",
                actual: topics.count,
                maximum: limits.maximumTopicCount
            )
        }
        guard Set(topics).count == topics.count else {
            throw OverlayError.duplicateValue(name: "topics")
        }
        self.requirement = requirement
        self.topics = topics
    }
}
