/// Arguments for a BRC-307 1Sat Ordinals inscription output.
public struct InscriptionArgs: Hashable, Sendable {
    public let lockingScript: Script
    public let data: [UInt8]
    public let contentType: String
    public let enrichedArguments: EnrichedInscriptionArgs?

    public init(
        lockingScript: Script,
        data: [UInt8],
        contentType: String,
        enrichedArguments: EnrichedInscriptionArgs? = nil
    ) {
        self.lockingScript = lockingScript
        self.data = data
        self.contentType = contentType
        self.enrichedArguments = enrichedArguments
    }

    /// Builds `<ord envelope><locking script>[OP_RETURN <enriched pushes>...]`.
    ///
    /// Pinned Go v1.3.3 creates its output script before appending enriched
    /// pushes to a temporary buffer, so those pushes are accidentally omitted.
    /// Swift intentionally emits the BRC-307 documented post-locking-script
    /// metadata placement instead of preserving that artifact.
    public func brc307LockingScript(limits: InscriptionLimits) throws -> Script {
        try validate(limits: limits)
        let requiredByteCount = try requiredScriptByteCount(
            maximumScriptByteCount: limits.maximumScriptByteCount
        )
        guard requiredByteCount <= limits.maximumScriptByteCount else {
            throw InscriptionError.scriptTooLarge(
                actual: requiredByteCount,
                maximum: limits.maximumScriptByteCount
            )
        }

        do {
            var envelope = try Script(bytes: [], maximumByteCount: limits.maximumScriptByteCount)
            try envelope.append(.false, maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.append(.if, maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.appendPushData(Array("ord".utf8), maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.append(.one, maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.appendPushData(Array(contentType.utf8), maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.append(.zero, maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.appendPushData(data, maximumScriptByteCount: limits.maximumScriptByteCount)
            try envelope.append(.endIf, maximumScriptByteCount: limits.maximumScriptByteCount)

            var result = try Script(
                bytes: envelope.bytes + lockingScript.bytes,
                maximumByteCount: limits.maximumScriptByteCount
            )
            if let enrichedArguments, !enrichedArguments.opReturnData.isEmpty {
                try result.append(.return, maximumScriptByteCount: limits.maximumScriptByteCount)
                for item in enrichedArguments.opReturnData {
                    try result.appendPushData(item, maximumScriptByteCount: limits.maximumScriptByteCount)
                }
            }
            return result
        } catch ScriptError.scriptTooLarge(let actual, let maximum) {
            // Keep BRC-307's public error surface independent of the Script
            // builder used internally.
            throw InscriptionError.scriptTooLarge(actual: actual, maximum: maximum)
        }
    }

    private func validate(limits: InscriptionLimits) throws {
        guard data.count <= limits.maximumContentByteCount else {
            throw InscriptionError.contentTooLarge(actual: data.count, maximum: limits.maximumContentByteCount)
        }
        let inspectionLimit = limits.maximumContentTypeByteCount == Int.max
            ? Int.max : limits.maximumContentTypeByteCount + 1
        let contentTypeBytes = Array(contentType.utf8.prefix(inspectionLimit))
        guard contentTypeBytes.count <= limits.maximumContentTypeByteCount else {
            throw InscriptionError.contentTypeTooLarge(
                actual: contentTypeBytes.count,
                maximum: limits.maximumContentTypeByteCount
            )
        }
        // Swift String already guarantees valid UTF-8. BRC-307 calls this a
        // MIME string but does not define a narrower grammar; accept bounded,
        // nonempty UTF-8 so valid quoted parameters and extension forms remain
        // interoperable with the Go SDK.
        guard !contentTypeBytes.isEmpty else {
            throw InscriptionError.invalidContentType
        }
        guard lockingScript.byteCount <= limits.maximumScriptByteCount else {
            throw InscriptionError.scriptTooLarge(
                actual: lockingScript.byteCount,
                maximum: limits.maximumScriptByteCount
            )
        }
        do {
            _ = try lockingScript.operations(maximumPushDataByteCount: limits.maximumScriptByteCount)
        } catch {
            throw InscriptionError.malformedLockingScript
        }
        if let enrichedArguments {
            guard enrichedArguments.opReturnData.count <= limits.maximumEnrichedItemCount else {
                throw InscriptionError.tooManyEnrichedItems(
                    actual: enrichedArguments.opReturnData.count,
                    maximum: limits.maximumEnrichedItemCount
                )
            }
            for (index, item) in enrichedArguments.opReturnData.enumerated()
                where item.count > limits.maximumEnrichedItemByteCount {
                throw InscriptionError.enrichedItemTooLarge(
                    index: index,
                    actual: item.count,
                    maximum: limits.maximumEnrichedItemByteCount
                )
            }
        }
    }

    private func requiredScriptByteCount(maximumScriptByteCount: Int) throws -> Int {
        var total = 5 // OP_FALSE, OP_IF, OP_1, OP_0, OP_ENDIF
        try Self.addPushByteCount(3, to: &total, maximum: maximumScriptByteCount) // "ord"
        try Self.addPushByteCount(
            contentType.utf8.count,
            to: &total,
            maximum: maximumScriptByteCount
        )
        try Self.addPushByteCount(data.count, to: &total, maximum: maximumScriptByteCount)
        try Self.add(lockingScript.byteCount, to: &total, maximum: maximumScriptByteCount)
        if let enrichedArguments, !enrichedArguments.opReturnData.isEmpty {
            try Self.add(1, to: &total, maximum: maximumScriptByteCount) // OP_RETURN
            for item in enrichedArguments.opReturnData {
                try Self.addPushByteCount(item.count, to: &total, maximum: maximumScriptByteCount)
            }
        }
        return total
    }

    private static func addPushByteCount(
        _ byteCount: Int,
        to total: inout Int,
        maximum: Int
    ) throws {
        let prefixByteCount = try Script.pushDataPrefix(forByteCount: byteCount).count
        try add(prefixByteCount, to: &total, maximum: maximum)
        try add(byteCount, to: &total, maximum: maximum)
    }

    private static func add(_ amount: Int, to total: inout Int, maximum: Int) throws {
        let (next, overflow) = total.addingReportingOverflow(amount)
        guard !overflow else {
            throw InscriptionError.scriptTooLarge(actual: Int.max, maximum: maximum)
        }
        total = next
    }

}

public struct EnrichedInscriptionArgs: Hashable, Sendable {
    public let opReturnData: [[UInt8]]

    public init(opReturnData: [[UInt8]]) {
        self.opReturnData = opReturnData
    }
}

public struct InscriptionLimits: Hashable, Sendable {
    public let maximumScriptByteCount: Int
    public let maximumContentTypeByteCount: Int
    public let maximumContentByteCount: Int
    public let maximumEnrichedItemCount: Int
    public let maximumEnrichedItemByteCount: Int

    public init(
        maximumScriptByteCount: Int,
        maximumContentTypeByteCount: Int,
        maximumContentByteCount: Int,
        maximumEnrichedItemCount: Int,
        maximumEnrichedItemByteCount: Int
    ) throws {
        guard maximumScriptByteCount >= 0, maximumContentTypeByteCount >= 0,
              maximumContentByteCount >= 0, maximumEnrichedItemCount >= 0,
              maximumEnrichedItemByteCount >= 0 else {
            throw InscriptionError.invalidLimits
        }
        self.maximumScriptByteCount = maximumScriptByteCount
        self.maximumContentTypeByteCount = maximumContentTypeByteCount
        self.maximumContentByteCount = maximumContentByteCount
        self.maximumEnrichedItemCount = maximumEnrichedItemCount
        self.maximumEnrichedItemByteCount = maximumEnrichedItemByteCount
    }
}

public enum InscriptionError: Error, Equatable, Sendable {
    case invalidLimits
    case contentTypeTooLarge(actual: Int, maximum: Int)
    case invalidContentType
    case contentTooLarge(actual: Int, maximum: Int)
    case scriptTooLarge(actual: Int, maximum: Int)
    case malformedLockingScript
    case tooManyEnrichedItems(actual: Int, maximum: Int)
    case enrichedItemTooLarge(index: Int, actual: Int, maximum: Int)
}
