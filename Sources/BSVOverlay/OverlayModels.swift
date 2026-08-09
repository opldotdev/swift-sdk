import BSVCore
import BSVTransaction

/// Resource limits for transport-neutral overlay values.
public struct OverlayLimits: Hashable, Sendable {
    public let maximumTaggedBEEFByteCount: Int
    public let maximumOffChainValueByteCount: Int
    public let maximumTopicCount: Int
    public let maximumTopicUTF8ByteCount: Int
    public let maximumServiceUTF8ByteCount: Int
    public let maximumHostUTF8ByteCount: Int
    public let maximumMetadataUTF8ByteCount: Int
    public let maximumLookupQueryByteCount: Int
    public let maximumLookupOutputCount: Int
    public let maximumLookupOutputBEEFByteCount: Int
    public let maximumLookupAnswerByteCount: Int
    public let maximumFreeformByteCount: Int
    public let maximumDependencyCount: Int
    public let maximumInstructionIndexCount: Int
    public let maximumAncillaryTransactionCount: Int
    public let maximumSteakTopicCount: Int
    public let maximumResolutionHostCount: Int
    public let maximumConcurrentRequestCount: Int

    public init(
        maximumTaggedBEEFByteCount: Int,
        maximumOffChainValueByteCount: Int,
        maximumTopicCount: Int,
        maximumTopicUTF8ByteCount: Int,
        maximumServiceUTF8ByteCount: Int,
        maximumHostUTF8ByteCount: Int,
        maximumMetadataUTF8ByteCount: Int,
        maximumLookupQueryByteCount: Int,
        maximumLookupOutputCount: Int,
        maximumLookupOutputBEEFByteCount: Int,
        maximumLookupAnswerByteCount: Int = 64 * 1_024 * 1_024,
        maximumFreeformByteCount: Int,
        maximumDependencyCount: Int = 10_000,
        maximumInstructionIndexCount: Int = 10_000,
        maximumAncillaryTransactionCount: Int = 10_000,
        maximumSteakTopicCount: Int = 256,
        maximumResolutionHostCount: Int = 64,
        maximumConcurrentRequestCount: Int = 8
    ) throws {
        let values = [
            ("maximumTaggedBEEFByteCount", maximumTaggedBEEFByteCount),
            ("maximumOffChainValueByteCount", maximumOffChainValueByteCount),
            ("maximumTopicCount", maximumTopicCount),
            ("maximumTopicUTF8ByteCount", maximumTopicUTF8ByteCount),
            ("maximumServiceUTF8ByteCount", maximumServiceUTF8ByteCount),
            ("maximumHostUTF8ByteCount", maximumHostUTF8ByteCount),
            ("maximumMetadataUTF8ByteCount", maximumMetadataUTF8ByteCount),
            ("maximumLookupQueryByteCount", maximumLookupQueryByteCount),
            ("maximumLookupOutputCount", maximumLookupOutputCount),
            ("maximumLookupOutputBEEFByteCount", maximumLookupOutputBEEFByteCount),
            ("maximumLookupAnswerByteCount", maximumLookupAnswerByteCount),
            ("maximumFreeformByteCount", maximumFreeformByteCount),
            ("maximumDependencyCount", maximumDependencyCount),
            ("maximumInstructionIndexCount", maximumInstructionIndexCount),
            ("maximumAncillaryTransactionCount", maximumAncillaryTransactionCount),
            ("maximumSteakTopicCount", maximumSteakTopicCount),
            ("maximumResolutionHostCount", maximumResolutionHostCount),
            ("maximumConcurrentRequestCount", maximumConcurrentRequestCount),
        ]
        if let invalid = values.first(where: { $0.1 <= 0 }) {
            throw OverlayError.nonPositiveLimit(name: invalid.0, value: invalid.1)
        }
        self.maximumTaggedBEEFByteCount = maximumTaggedBEEFByteCount
        self.maximumOffChainValueByteCount = maximumOffChainValueByteCount
        self.maximumTopicCount = maximumTopicCount
        self.maximumTopicUTF8ByteCount = maximumTopicUTF8ByteCount
        self.maximumServiceUTF8ByteCount = maximumServiceUTF8ByteCount
        self.maximumHostUTF8ByteCount = maximumHostUTF8ByteCount
        self.maximumMetadataUTF8ByteCount = maximumMetadataUTF8ByteCount
        self.maximumLookupQueryByteCount = maximumLookupQueryByteCount
        self.maximumLookupOutputCount = maximumLookupOutputCount
        self.maximumLookupOutputBEEFByteCount = maximumLookupOutputBEEFByteCount
        self.maximumLookupAnswerByteCount = maximumLookupAnswerByteCount
        self.maximumFreeformByteCount = maximumFreeformByteCount
        self.maximumDependencyCount = maximumDependencyCount
        self.maximumInstructionIndexCount = maximumInstructionIndexCount
        self.maximumAncillaryTransactionCount = maximumAncillaryTransactionCount
        self.maximumSteakTopicCount = maximumSteakTopicCount
        self.maximumResolutionHostCount = maximumResolutionHostCount
        self.maximumConcurrentRequestCount = maximumConcurrentRequestCount
    }

    private init(standard: Void) {
        maximumTaggedBEEFByteCount = 32 * 1_024 * 1_024
        maximumOffChainValueByteCount = 1 * 1_024 * 1_024
        maximumTopicCount = 256
        maximumTopicUTF8ByteCount = 256
        maximumServiceUTF8ByteCount = 256
        maximumHostUTF8ByteCount = 2_048
        maximumMetadataUTF8ByteCount = 4_096
        maximumLookupQueryByteCount = 1 * 1_024 * 1_024
        maximumLookupOutputCount = 10_000
        maximumLookupOutputBEEFByteCount = 32 * 1_024 * 1_024
        maximumLookupAnswerByteCount = 64 * 1_024 * 1_024
        maximumFreeformByteCount = 1 * 1_024 * 1_024
        maximumDependencyCount = 10_000
        maximumInstructionIndexCount = 10_000
        maximumAncillaryTransactionCount = 10_000
        maximumSteakTopicCount = 256
        maximumResolutionHostCount = 64
        maximumConcurrentRequestCount = 8
    }

    public static let standard = Self(standard: ())
}

public enum OverlayError: Error, Equatable, Sendable {
    case nonPositiveLimit(name: String, value: Int)
    case invalidProtocolIdentifier
    case invalidTopic
    case invalidService
    case invalidHost
    case emptyValue(name: String)
    case duplicateValue(name: String)
    case limitExceeded(name: String, actual: Int, maximum: Int)
}

/// The two overlay protocols implemented by the pinned Go SDK.
public enum OverlayProtocol: String, CaseIterable, Hashable, Sendable {
    case ship = "SHIP"
    case slap = "SLAP"

    public var identifier: OverlayProtocolIdentifier {
        switch self {
        case .ship: .ship
        case .slap: .slap
        }
    }
}

public enum OverlayProtocolIdentifier: String, Hashable, Sendable {
    case ship = "service host interconnect"
    case slap = "service lookup availability"
}

public enum OverlayNetwork: String, CaseIterable, Hashable, Sendable {
    case mainnet
    case testnet
    case local
}

/// A BRC-87 topic-manager name.
public struct OverlayTopic: Hashable, Sendable, Comparable {
    public let rawValue: String

    public init(rawValue: String, limits: OverlayLimits = .standard) throws {
        try enforceOverlayUTF8Limit(
            rawValue, name: "topic", maximum: limits.maximumTopicUTF8ByteCount)
        guard rawValue.hasPrefix("tm_"), validOverlayIdentifier(rawValue) else {
            throw OverlayError.invalidTopic
        }
        self.rawValue = rawValue
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A BRC-87 lookup-service name.
public struct OverlayService: Hashable, Sendable, Comparable {
    public let rawValue: String

    public init(rawValue: String, limits: OverlayLimits = .standard) throws {
        try enforceOverlayUTF8Limit(
            rawValue, name: "service", maximum: limits.maximumServiceUTF8ByteCount)
        guard rawValue.hasPrefix("ls_"), validOverlayIdentifier(rawValue) else {
            throw OverlayError.invalidService
        }
        self.rawValue = rawValue
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A transport-selected overlay endpoint. This value deliberately does not impose an URL scheme.
public struct OverlayHost: Hashable, Sendable, Comparable {
    public let rawValue: String

    public init(rawValue: String, limits: OverlayLimits = .standard) throws {
        try enforceOverlayUTF8Limit(
            rawValue, name: "host", maximum: limits.maximumHostUTF8ByteCount)
        guard !rawValue.isEmpty,
            rawValue.unicodeScalars.allSatisfy({
                !$0.properties.isWhitespace && !($0.value < 0x20 || $0.value == 0x7f)
            })
        else {
            throw OverlayError.invalidHost
        }
        self.rawValue = rawValue
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A BEEF payload tagged for submission to one or more SHIP topics.
public struct TaggedBEEF: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let beef: [UInt8]
    public let topics: [OverlayTopic]
    public let offChainValues: [UInt8]

    public init(
        beef: [UInt8],
        topics: [OverlayTopic],
        offChainValues: [UInt8] = [],
        limits: OverlayLimits = .standard
    ) throws {
        guard !beef.isEmpty else { throw OverlayError.emptyValue(name: "beef") }
        guard !topics.isEmpty else { throw OverlayError.emptyValue(name: "topics") }
        guard topics.count <= limits.maximumTopicCount else {
            throw OverlayError.limitExceeded(
                name: "topics", actual: topics.count, maximum: limits.maximumTopicCount)
        }
        guard Set(topics).count == topics.count else {
            throw OverlayError.duplicateValue(name: "topics")
        }
        try enforceOverlayByteLimit(beef, name: "beef", maximum: limits.maximumTaggedBEEFByteCount)
        try enforceOverlayByteLimit(
            offChainValues, name: "offChainValues", maximum: limits.maximumOffChainValueByteCount)
        self.beef = beef
        self.topics = topics
        self.offChainValues = offChainValues
    }

    public var description: String { "<redacted tagged BEEF>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}

public struct AppliedTransaction: Hashable, Sendable {
    public let transactionID: TransactionID
    public let topic: OverlayTopic

    public init(transactionID: TransactionID, topic: OverlayTopic) {
        self.transactionID = transactionID
        self.topic = topic
    }
}

/// Strongly typed topic-associated payload and its output dependencies.
public struct TopicData<Payload: Hashable & Sendable>: Hashable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable
{
    public let payload: Payload
    public let dependencies: [Outpoint]

    public init(
        payload: Payload,
        dependencies: [Outpoint] = [],
        limits: OverlayLimits = .standard
    ) throws {
        guard dependencies.count <= limits.maximumDependencyCount else {
            throw OverlayError.limitExceeded(
                name: "dependencies",
                actual: dependencies.count,
                maximum: limits.maximumDependencyCount
            )
        }
        guard Set(dependencies).count == dependencies.count else {
            throw OverlayError.duplicateValue(name: "dependencies")
        }
        self.payload = payload
        self.dependencies = dependencies
    }

    public var description: String { "<redacted overlay topic data>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}

public struct AdmittanceInstructions: Hashable, Sendable {
    public let outputsToAdmit: [UInt32]
    public let coinsToRetain: [UInt32]
    public let coinsRemoved: [UInt32]
    public let ancillaryTransactionIDs: [TransactionID]

    public init(
        outputsToAdmit: [UInt32] = [],
        coinsToRetain: [UInt32] = [],
        coinsRemoved: [UInt32] = [],
        ancillaryTransactionIDs: [TransactionID] = [],
        limits: OverlayLimits = .standard
    ) throws {
        for (name, values) in [
            ("outputsToAdmit", outputsToAdmit),
            ("coinsToRetain", coinsToRetain),
            ("coinsRemoved", coinsRemoved),
        ] {
            guard values.count <= limits.maximumInstructionIndexCount else {
                throw OverlayError.limitExceeded(
                    name: name,
                    actual: values.count,
                    maximum: limits.maximumInstructionIndexCount
                )
            }
            guard Set(values).count == values.count else {
                throw OverlayError.duplicateValue(name: name)
            }
        }
        guard ancillaryTransactionIDs.count <= limits.maximumAncillaryTransactionCount else {
            throw OverlayError.limitExceeded(
                name: "ancillaryTransactionIDs",
                actual: ancillaryTransactionIDs.count,
                maximum: limits.maximumAncillaryTransactionCount
            )
        }
        guard Set(ancillaryTransactionIDs).count == ancillaryTransactionIDs.count else {
            throw OverlayError.duplicateValue(name: "ancillaryTransactionIDs")
        }
        self.outputsToAdmit = outputsToAdmit
        self.coinsToRetain = coinsToRetain
        self.coinsRemoved = coinsRemoved
        self.ancillaryTransactionIDs = ancillaryTransactionIDs
    }

    public var acknowledgesTopic: Bool {
        !outputsToAdmit.isEmpty || !coinsToRetain.isEmpty || !coinsRemoved.isEmpty
    }
}

/// A SHIP submitted-transaction execution acknowledgment.
public struct Steak: Hashable, Sendable {
    public let instructions: [OverlayTopic: AdmittanceInstructions]

    public init(
        instructions: [OverlayTopic: AdmittanceInstructions] = [:],
        limits: OverlayLimits = .standard
    ) throws {
        guard instructions.count <= limits.maximumSteakTopicCount else {
            throw OverlayError.limitExceeded(
                name: "steakTopics",
                actual: instructions.count,
                maximum: limits.maximumSteakTopicCount
            )
        }
        self.instructions = instructions
    }

    public func acknowledges(_ topic: OverlayTopic) -> Bool {
        instructions[topic]?.acknowledgesTopic == true
    }
}

public struct OverlayMetadata: Hashable, Sendable {
    public let name: String
    public let shortDescription: String
    public let iconURL: String
    public let version: String
    public let informationURL: String

    public init(
        name: String,
        shortDescription: String,
        iconURL: String,
        version: String,
        informationURL: String,
        limits: OverlayLimits = .standard
    ) throws {
        for (label, value) in [
            ("name", name), ("shortDescription", shortDescription), ("iconURL", iconURL),
            ("version", version), ("informationURL", informationURL),
        ] {
            try enforceOverlayUTF8Limit(
                value, name: label, maximum: limits.maximumMetadataUTF8ByteCount)
        }
        self.name = name
        self.shortDescription = shortDescription
        self.iconURL = iconURL
        self.version = version
        self.informationURL = informationURL
    }
}

package func validOverlayIdentifier(_ value: String) -> Bool {
    value.utf8.count > 3
        && value.utf8.allSatisfy { byte in
            (0x30...0x39).contains(byte) || (0x41...0x5a).contains(byte)
                || (0x61...0x7a).contains(byte) || byte == 0x5f || byte == 0x2d
        }
}

package func enforceOverlayUTF8Limit(_ value: String, name: String, maximum: Int) throws {
    try enforceOverlayByteLimit(Array(value.utf8), name: name, maximum: maximum)
}

package func enforceOverlayByteLimit(_ value: [UInt8], name: String, maximum: Int) throws {
    guard value.count <= maximum else {
        throw OverlayError.limitExceeded(name: name, actual: value.count, maximum: maximum)
    }
}
