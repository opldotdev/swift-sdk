import BSVCore

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

/// One output in a lookup answer, in the `@bsv/sdk` `LookupAnswer` output shape.
///
/// `beef` holds the output's transaction, normally as Atomic BEEF. When
/// `transactionID` is present it names the transaction that holds the output,
/// and `beef` alone is not enough to find it: `beef` may be a standard BEEF
/// carrying several transactions. Use ``transaction(beefLimits:)`` to read the
/// transaction the output belongs to.
///
/// `context` is the lookup service's optional per-output data. It is host
/// data that nothing verifies. When several hosts return the same outpoint,
/// ``LookupResolver`` keeps the first host's item, context included.
public struct OutputListItem: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let beef: [UInt8]
    public let outputIndex: UInt32
    public let context: [UInt8]?
    public let transactionID: TransactionID?

    public init(
        beef: [UInt8],
        outputIndex: UInt32,
        context: [UInt8]? = nil,
        transactionID: TransactionID? = nil,
        limits: OverlayLimits = .standard
    ) throws {
        guard !beef.isEmpty else { throw OverlayError.emptyValue(name: "beef") }
        try enforceOverlayByteLimit(
            beef, name: "lookupOutputBEEF", maximum: limits.maximumLookupOutputBEEFByteCount)
        if let context {
            try enforceOverlayByteLimit(
                context, name: "lookupOutputContext",
                maximum: limits.maximumLookupContextByteCount)
        }
        self.beef = beef
        self.outputIndex = outputIndex
        self.context = context
        self.transactionID = transactionID
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
            let (withBEEF, beefOverflow) = totalByteCount.addingReportingOverflow(
                output.beef.count)
            let (next, contextOverflow) = withBEEF.addingReportingOverflow(
                output.context?.count ?? 0)
            let overflow = beefOverflow || contextOverflow
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
