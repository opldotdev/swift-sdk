import BSVCore
import BSVOverlay
import BSVTransaction
import CoreFoundation
import Foundation

enum OverlayHTTPCodec {
    static func lookupRequest(
        _ question: LookupQuestion,
        limits: OverlayLimits
    ) throws -> [UInt8] {
        guard question.query.count <= limits.maximumLookupQueryByteCount,
            StrictOverlayJSONPreflight.accepts(question.query)
        else { throw OverlayHTTPError.invalidQuery }

        let prefix = Array(#"{"service":""#.utf8)
        let service = Array(question.service.rawValue.utf8)
        let middle = Array(#"","query":"#.utf8)
        let suffix: [UInt8] = [0x7d]
        var count = 0
        for value in [
            prefix.count, service.count, middle.count, question.query.count, suffix.count,
        ] {
            let (next, overflow) = count.addingReportingOverflow(value)
            guard !overflow, next <= OverlayHTTPConfiguration.maximumAllowedRequestByteCount else {
                throw OverlayHTTPError.resourceLimit
            }
            count = next
        }
        var result: [UInt8] = []
        result.reserveCapacity(count)
        result.append(contentsOf: prefix)
        result.append(contentsOf: service)
        result.append(contentsOf: middle)
        result.append(contentsOf: question.query)
        result.append(contentsOf: suffix)
        return result
    }

    /// The `X-Topics` value `@bsv/sdk` sends: topic names joined by commas
    /// (`SHIPBroadcaster.ts:340-345`). Names cannot contain a comma.
    static func topicsHeader(
        _ topics: [OverlayTopic],
        limits: OverlayLimits
    ) throws -> String {
        guard !topics.isEmpty, topics.count <= limits.maximumTopicCount else {
            throw OverlayHTTPError.invalidQuery
        }
        let value = topics.map(\.rawValue).joined(separator: ",")
        guard value.utf8.count <= 8_192 else { throw OverlayHTTPError.resourceLimit }
        return value
    }

    /// The `/submit` body. With off-chain values it is
    /// `CompactSize(beef.count) || beef || offChainValues`, which `@bsv/sdk`
    /// sends with `x-includes-off-chain-values: true` (`SHIPBroadcaster.ts:346-355`).
    static func submitBody(_ taggedBEEF: TaggedBEEF) throws -> [UInt8] {
        guard !taggedBEEF.offChainValues.isEmpty else { return taggedBEEF.beef }
        let prefix = CompactSize.encode(UInt64(taggedBEEF.beef.count))
        var count = 0
        for value in [prefix.count, taggedBEEF.beef.count, taggedBEEF.offChainValues.count] {
            let (next, overflow) = count.addingReportingOverflow(value)
            guard !overflow, next <= OverlayHTTPConfiguration.maximumAllowedRequestByteCount
            else { throw OverlayHTTPError.resourceLimit }
            count = next
        }
        var body: [UInt8] = []
        body.reserveCapacity(count)
        body.append(contentsOf: prefix)
        body.append(contentsOf: taggedBEEF.beef)
        body.append(contentsOf: taggedBEEF.offChainValues)
        return body
    }

    /// A JSON lookup answer in the `@bsv/sdk` shape (`LookupResolver.ts:43-52,327-447`).
    ///
    /// An output's `beef` and `context` are JSON byte arrays, or the
    /// numeric-key objects `JSON.stringify(Uint8Array)` once produced. `beef`
    /// may also be base64 text, the form Go overlay hosts write. `txid` names
    /// the output's transaction. Unknown keys are ignored, as in `@bsv/sdk`.
    static func lookupJSONResponse(
        _ bytes: [UInt8],
        configuration: OverlayHTTPConfiguration
    ) throws -> LookupAnswer {
        let limits = configuration.overlayLimits
        guard bytes.count <= limits.maximumLookupAnswerByteCount,
            StrictOverlayJSONPreflight.accepts(bytes),
            let value = try? JSONSerialization.jsonObject(with: Data(bytes)),
            let object = value as? [String: Any],
            let type = object["type"] as? String
        else { throw OverlayHTTPError.malformedResponse }

        switch type {
        case "output-list":
            let rawOutputs: [Any]
            if object["outputs"] == nil || object["outputs"] is NSNull {
                rawOutputs = []
            } else if let outputs = object["outputs"] as? [Any] {
                rawOutputs = outputs
            } else {
                throw OverlayHTTPError.malformedResponse
            }
            guard rawOutputs.count <= limits.maximumLookupOutputCount else {
                throw OverlayHTTPError.resourceLimit
            }
            let maximumContext = min(
                configuration.maximumContextByteCount,
                limits.maximumLookupContextByteCount
            )
            var outputs: [OutputListItem] = []
            outputs.reserveCapacity(rawOutputs.count)
            for raw in rawOutputs {
                guard let item = raw as? [String: Any],
                    let index = uint32(item["outputIndex"])
                else { throw OverlayHTTPError.malformedResponse }
                let beef = try beefBytes(
                    item["beef"],
                    maximum: limits.maximumLookupOutputBEEFByteCount
                )
                guard !beef.isEmpty else { throw OverlayHTTPError.malformedResponse }
                var context: [UInt8]?
                if let rawContext = item["context"] {
                    context = try byteArray(rawContext, maximum: maximumContext)
                }
                var transactionID: TransactionID?
                if let rawTransactionID = item["txid"] {
                    guard let text = rawTransactionID as? String,
                        text.utf8.count == 64,
                        let parsed = try? TransactionID(displayHex: text.lowercased())
                    else { throw OverlayHTTPError.malformedResponse }
                    transactionID = parsed
                }
                do {
                    outputs.append(
                        try OutputListItem(
                            beef: beef,
                            outputIndex: index,
                            context: context,
                            transactionID: transactionID,
                            limits: limits
                        )
                    )
                } catch {
                    throw OverlayHTTPError.resourceLimit
                }
            }
            do {
                return try LookupAnswer(outputList: outputs, limits: limits)
            } catch {
                throw OverlayHTTPError.resourceLimit
            }

        case "freeform":
            guard let result = object["result"] else { throw OverlayHTTPError.malformedResponse }
            let encoded: Data
            do {
                encoded = try JSONSerialization.data(
                    withJSONObject: result,
                    options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes]
                )
            } catch {
                throw OverlayHTTPError.malformedResponse
            }
            do {
                return try LookupAnswer(freeform: [UInt8](encoded), limits: limits)
            } catch {
                throw OverlayHTTPError.resourceLimit
            }

        default:
            throw OverlayHTTPError.malformedResponse
        }
    }

    /// A lookup output's `beef`: a byte array (see ``byteArray(_:maximum:)``)
    /// or canonical base64 text.
    private static func beefBytes(_ value: Any?, maximum: Int) throws -> [UInt8] {
        if let text = value as? String {
            guard
                let beef = try? Base64Encoding.decode(text, maximumDecodedByteCount: maximum),
                Base64Encoding.encode(beef) == text
            else { throw OverlayHTTPError.malformedResponse }
            return beef
        }
        guard let value else { throw OverlayHTTPError.malformedResponse }
        return try byteArray(value, maximum: maximum)
    }

    /// A JSON array of integers 0...255, or an object whose keys are exactly
    /// "0" through "n-1" with byte values, as `normalizeBRC100ByteArray` in
    /// `@bsv/sdk` reads it (`wallet/BRC100ByteEncoding.ts:45-87,126-146`). An
    /// empty object is an empty byte array there.
    private static func byteArray(_ value: Any, maximum: Int) throws -> [UInt8] {
        if let values = value as? [Any] {
            guard values.count <= maximum else { throw OverlayHTTPError.resourceLimit }
            var bytes: [UInt8] = []
            bytes.reserveCapacity(values.count)
            for value in values {
                guard let byte = byte(value) else { throw OverlayHTTPError.malformedResponse }
                bytes.append(byte)
            }
            return bytes
        }
        guard let object = value as? [String: Any] else {
            throw OverlayHTTPError.malformedResponse
        }
        guard object.count <= maximum else { throw OverlayHTTPError.resourceLimit }
        var bytes = [UInt8](repeating: 0, count: object.count)
        for (key, value) in object {
            guard let index = Int(key), String(index) == key,
                bytes.indices.contains(index),
                let byte = byte(value)
            else { throw OverlayHTTPError.malformedResponse }
            bytes[index] = byte
        }
        return bytes
    }

    private static func byte(_ value: Any) -> UInt8? {
        guard let number = uint32(value), number <= 255 else { return nil }
        return UInt8(number)
    }

    /// The aggregated answer Overlay Express sends for `X-Aggregation: yes`
    /// (`OverlayExpress.ts:3063-3093`): a count, then per output its display
    /// transaction ID, output index and context, then one BEEF holding every
    /// transaction.
    ///
    /// Like `parseOctetStreamLookup` and `extractAtomicOutputs` in `@bsv/sdk`
    /// (`LookupResolver.ts:877-950`), each output gets its own transaction as
    /// Atomic BEEF, plus its transaction ID and context. If that transaction's
    /// ancestry in the shared BEEF is incomplete, so that no valid Atomic BEEF
    /// can be built, the output keeps the shared BEEF and names its
    /// transaction with `transactionID` instead.
    static func lookupBinaryResponse(
        _ bytes: [UInt8],
        configuration: OverlayHTTPConfiguration
    ) throws -> LookupAnswer {
        let limits = configuration.overlayLimits
        guard bytes.count <= limits.maximumLookupAnswerByteCount else {
            throw OverlayHTTPError.resourceLimit
        }
        var cursor = ByteCursor(bytes)
        let countValue: UInt64
        do {
            countValue = try cursor.readCompactSize(canonicality: .required).value
        } catch {
            throw OverlayHTTPError.malformedResponse
        }
        guard countValue <= UInt64(limits.maximumLookupOutputCount),
            countValue <= UInt64(Int.max)
        else { throw OverlayHTTPError.resourceLimit }

        struct Metadata {
            let transactionID: TransactionID
            let outputIndex: UInt32
            let context: [UInt8]?
        }
        let maximumContext = min(
            configuration.maximumContextByteCount,
            limits.maximumLookupContextByteCount
        )
        var metadata: [Metadata] = []
        metadata.reserveCapacity(min(Int(countValue), cursor.remaining / 34))
        for _ in 0..<Int(countValue) {
            do {
                let displayBytes = try cursor.read(count: 32)
                let transactionID = try TransactionID(displayHex: Hex.encode(displayBytes))
                let outputIndex = try cursor.readCompactSize(canonicality: .required).value
                guard outputIndex <= UInt64(UInt32.max) else {
                    throw OverlayHTTPError.resourceLimit
                }
                let contextCount = try cursor.readCompactSize(canonicality: .required).value
                guard contextCount <= UInt64(maximumContext) else {
                    throw OverlayHTTPError.resourceLimit
                }
                let context = try cursor.read(count: Int(contextCount))
                metadata.append(
                    Metadata(
                        transactionID: transactionID,
                        outputIndex: UInt32(outputIndex),
                        context: context.isEmpty ? nil : context
                    )
                )
            } catch let error as OverlayHTTPError {
                throw error
            } catch {
                throw OverlayHTTPError.malformedResponse
            }
        }
        guard cursor.remaining > 0, cursor.remaining <= configuration.beefLimits.maximumByteCount
        else {
            throw OverlayHTTPError.malformedResponse
        }
        let sharedBytes: [UInt8]
        let beef: BEEF
        let entries: [TransactionID: BEEFTransaction]
        do {
            sharedBytes = try cursor.read(count: cursor.remaining)
            // Overlay services write BEEF with `@bsv/sdk`, whose writer can list a
            // child before its parents; read it in any order, as that SDK does.
            beef = try BEEF(
                bytes: sharedBytes,
                limits: configuration.beefLimits,
                transactionOrder: .any
            )
            entries = try beef.indexedEntries(
                limits: configuration.beefLimits.transactionLimits
            )
        } catch {
            throw OverlayHTTPError.malformedResponse
        }
        var atomicByTransactionID: [TransactionID: [UInt8]] = [:]
        var outputs: [OutputListItem] = []
        outputs.reserveCapacity(metadata.count)
        for item in metadata {
            guard let transaction = entries[item.transactionID]?.transaction,
                UInt64(item.outputIndex) < UInt64(transaction.outputs.count)
            else { throw OverlayHTTPError.malformedResponse }
            let outputBEEF: [UInt8]
            if let cached = atomicByTransactionID[item.transactionID] {
                outputBEEF = cached
            } else {
                outputBEEF =
                    (try? beef.atomicBEEF(for: item.transactionID, limits: configuration.beefLimits)
                        .serialized(limits: configuration.beefLimits)) ?? sharedBytes
                atomicByTransactionID[item.transactionID] = outputBEEF
            }
            do {
                outputs.append(
                    try OutputListItem(
                        beef: outputBEEF,
                        outputIndex: item.outputIndex,
                        context: item.context,
                        transactionID: item.transactionID,
                        limits: limits
                    )
                )
            } catch {
                throw OverlayHTTPError.resourceLimit
            }
        }
        do {
            return try LookupAnswer(outputList: outputs, limits: limits)
        } catch {
            throw OverlayHTTPError.resourceLimit
        }
    }

    static func steakResponse(
        _ bytes: [UInt8],
        limits: OverlayLimits
    ) throws -> Steak {
        guard bytes.count <= limits.maximumLookupAnswerByteCount,
            StrictOverlayJSONPreflight.accepts(bytes),
            let value = try? JSONSerialization.jsonObject(with: Data(bytes)),
            let object = value as? [String: Any],
            object.count <= limits.maximumSteakTopicCount
        else { throw OverlayHTTPError.malformedResponse }

        var entries: [OverlayTopic: AdmittanceInstructions] = [:]
        entries.reserveCapacity(object.count)
        for (rawTopic, rawInstructions) in object {
            let topic: OverlayTopic
            do {
                topic = try OverlayTopic(rawValue: rawTopic, limits: limits)
            } catch {
                throw OverlayHTTPError.malformedResponse
            }
            guard let instructionObject = rawInstructions as? [String: Any] else {
                throw OverlayHTTPError.malformedResponse
            }
            let keys = Set(instructionObject.keys)
            let outputs: [UInt32]
            let retained: [UInt32]
            let removed: [UInt32]
            let ancillary: [TransactionID]
            if keys.isSubset(of: ["outputsToAdmit", "coinsToRetain", "coinsRemoved"]) {
                // `validateSTEAK` in `@bsv/sdk` (`SHIPBroadcaster.ts:237-262`):
                // `outputsToAdmit` and `coinsToRetain` are required arrays and
                // `coinsRemoved` is an optional array.
                guard instructionObject["outputsToAdmit"] is [Any],
                    instructionObject["coinsToRetain"] is [Any],
                    instructionObject["coinsRemoved"] == nil
                        || instructionObject["coinsRemoved"] is [Any]
                else { throw OverlayHTTPError.malformedResponse }
                outputs = try uint32Array(instructionObject["outputsToAdmit"], limits: limits)
                retained = try uint32Array(instructionObject["coinsToRetain"], limits: limits)
                removed = try uint32Array(instructionObject["coinsRemoved"], limits: limits)
                ancillary = []
            } else if keys.isSubset(of: [
                "OutputsToAdmit", "CoinsToRetain", "CoinsRemoved", "AncillaryTxids",
            ]) {
                // The Go overlay engine's untagged field names.
                outputs = try uint32Array(instructionObject["OutputsToAdmit"], limits: limits)
                retained = try uint32Array(instructionObject["CoinsToRetain"], limits: limits)
                removed = try uint32Array(instructionObject["CoinsRemoved"], limits: limits)
                ancillary = try transactionIDArray(
                    instructionObject["AncillaryTxids"],
                    limits: limits
                )
            } else {
                throw OverlayHTTPError.malformedResponse
            }
            do {
                entries[topic] = try AdmittanceInstructions(
                    outputsToAdmit: outputs,
                    coinsToRetain: retained,
                    coinsRemoved: removed,
                    ancillaryTransactionIDs: ancillary,
                    limits: limits
                )
            } catch {
                throw OverlayHTTPError.resourceLimit
            }
        }
        do {
            return try Steak(instructions: entries, limits: limits)
        } catch {
            throw OverlayHTTPError.resourceLimit
        }
    }

    private static func uint32Array(_ value: Any?, limits: OverlayLimits) throws -> [UInt32] {
        if value == nil || value is NSNull { return [] }
        guard let values = value as? [Any],
            values.count <= limits.maximumInstructionIndexCount
        else { throw OverlayHTTPError.resourceLimit }
        var result: [UInt32] = []
        result.reserveCapacity(values.count)
        for value in values {
            guard let item = uint32(value) else { throw OverlayHTTPError.malformedResponse }
            result.append(item)
        }
        return result
    }

    private static func transactionIDArray(
        _ value: Any?,
        limits: OverlayLimits
    ) throws -> [TransactionID] {
        if value == nil || value is NSNull { return [] }
        guard let values = value as? [Any],
            values.count <= limits.maximumAncillaryTransactionCount
        else { throw OverlayHTTPError.resourceLimit }
        var result: [TransactionID] = []
        result.reserveCapacity(values.count)
        for value in values {
            guard let text = value as? String,
                text.count == 64,
                text == text.lowercased(),
                let transactionID = try? TransactionID(displayHex: text),
                transactionID.displayHex == text
            else { throw OverlayHTTPError.malformedResponse }
            result.append(transactionID)
        }
        return result
    }

    private static func uint32(_ value: Any?) -> UInt32? {
        guard let number = value as? NSNumber,
            CFGetTypeID(number) != CFBooleanGetTypeID(),
            number.doubleValue.isFinite,
            number.doubleValue.rounded(.towardZero) == number.doubleValue,
            number.doubleValue >= 0,
            number.doubleValue <= Double(UInt32.max)
        else { return nil }
        return UInt32(number.uint64Value)
    }

    private static func append(
        _ value: [UInt8],
        to bytes: inout [UInt8],
        maximum: Int
    ) throws {
        let (next, overflow) = bytes.count.addingReportingOverflow(value.count)
        guard !overflow, next <= maximum else { throw OverlayHTTPError.resourceLimit }
        bytes.append(contentsOf: value)
    }
}
