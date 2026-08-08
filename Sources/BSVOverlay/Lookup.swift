/// A transport-neutral lookup request with an opaque, caller-defined bounded query payload.
public struct LookupQuestion: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let service: OverlayService
    public let query: [UInt8]

    public init(
        service: OverlayService,
        query: [UInt8],
        limits: OverlayLimits = .standard
    ) throws {
        try enforceOverlayByteLimit(
            query, name: "query", maximum: limits.maximumLookupQueryByteCount)
        self.service = service
        self.query = query
    }

    public var description: String { "<redacted overlay lookup question>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}

public struct OutputListItem: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let beef: [UInt8]
    public let outputIndex: UInt32

    public init(
        beef: [UInt8],
        outputIndex: UInt32,
        limits: OverlayLimits = .standard
    ) throws {
        guard !beef.isEmpty else { throw OverlayError.emptyValue(name: "beef") }
        try enforceOverlayByteLimit(
            beef, name: "lookupOutputBEEF", maximum: limits.maximumLookupOutputBEEFByteCount)
        self.beef = beef
        self.outputIndex = outputIndex
    }

    public var description: String { "<redacted overlay output item>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}

/// The closed set of lookup-answer representations safely handled without type erasure.
public enum LookupAnswer: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    case outputList([OutputListItem])
    case freeform([UInt8])

    public init(outputList: [OutputListItem], limits: OverlayLimits = .standard) throws {
        guard outputList.count <= limits.maximumLookupOutputCount else {
            throw OverlayError.limitExceeded(
                name: "lookupOutputs",
                actual: outputList.count,
                maximum: limits.maximumLookupOutputCount
            )
        }
        var totalByteCount = 0
        for output in outputList {
            let (next, overflow) = totalByteCount.addingReportingOverflow(output.beef.count)
            guard !overflow, next <= limits.maximumLookupAnswerByteCount else {
                throw OverlayError.limitExceeded(
                    name: "lookupAnswer",
                    actual: overflow ? Int.max : next,
                    maximum: limits.maximumLookupAnswerByteCount
                )
            }
            totalByteCount = next
        }
        self = .outputList(outputList)
    }

    public init(freeform: [UInt8], limits: OverlayLimits = .standard) throws {
        try enforceOverlayByteLimit(
            freeform, name: "freeform", maximum: limits.maximumFreeformByteCount)
        self = .freeform(freeform)
    }

    public var description: String { "<redacted overlay lookup answer>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}

/// A transport implementation capable of resolving one lookup request at one endpoint.
public protocol LookupFacilitator: Sendable {
    func lookup(question: LookupQuestion, at host: OverlayHost) async throws -> LookupAnswer
}
