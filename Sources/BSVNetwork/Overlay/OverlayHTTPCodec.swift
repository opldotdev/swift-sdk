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

    static func topicsHeader(
        _ topics: [OverlayTopic],
        limits: OverlayLimits
    ) throws -> String {
        guard !topics.isEmpty, topics.count <= limits.maximumTopicCount else {
            throw OverlayHTTPError.invalidQuery
        }
        var bytes: [UInt8] = [0x5b]
        bytes.reserveCapacity(min(8_192, 2 + topics.count * 16))
        for index in topics.indices {
            if index > 0 { try append([0x2c], to: &bytes, maximum: 8_192) }
            try append([0x22], to: &bytes, maximum: 8_192)
            try append(Array(topics[index].rawValue.utf8), to: &bytes, maximum: 8_192)
            try append([0x22], to: &bytes, maximum: 8_192)
        }
        try append([0x5d], to: &bytes, maximum: 8_192)
        guard let result = String(bytes: bytes, encoding: .utf8) else {
            throw OverlayHTTPError.invalidQuery
        }
        return result
    }

    static func lookupJSONResponse(
        _ bytes: [UInt8],
        limits: OverlayLimits
    ) throws -> LookupAnswer {
        guard bytes.count <= limits.maximumLookupAnswerByteCount,
            StrictOverlayJSONPreflight.accepts(bytes),
            let value = try? JSONSerialization.jsonObject(with: Data(bytes)),
            let object = value as? [String: Any],
            let type = object["type"] as? String
        else { throw OverlayHTTPError.malformedResponse }

        switch type {
        case "output-list":
            guard Set(object.keys).isSubset(of: ["type", "outputs"]),
                object["result"] == nil
            else { throw OverlayHTTPError.malformedResponse }
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
            var outputs: [OutputListItem] = []
            outputs.reserveCapacity(rawOutputs.count)
            for raw in rawOutputs {
                guard let item = raw as? [String: Any],
                    Set(item.keys) == ["beef", "outputIndex"],
                    let text = item["beef"] as? String,
                    let beef = try? Base64Encoding.decode(
                        text,
                        maximumDecodedByteCount: limits.maximumLookupOutputBEEFByteCount
                    ),
                    Base64Encoding.encode(beef) == text,
                    let index = uint32(item["outputIndex"])
                else { throw OverlayHTTPError.malformedResponse }
                do {
                    outputs.append(
                        try OutputListItem(
                            beef: beef,
                            outputIndex: index,
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
            guard Set(object.keys) == ["type", "result"],
                let result = object["result"]
            else { throw OverlayHTTPError.malformedResponse }
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
        }
        var metadata: [Metadata] = []
        metadata.reserveCapacity(min(Int(countValue), cursor.remaining / 34))
        var aggregateContext = 0
        for _ in 0..<Int(countValue) {
            do {
                let displayBytes = try cursor.read(count: 32)
                let transactionID = try TransactionID(displayHex: Hex.encode(displayBytes))
                let outputIndex = try cursor.readCompactSize(canonicality: .required).value
                guard outputIndex <= UInt64(UInt32.max) else {
                    throw OverlayHTTPError.resourceLimit
                }
                let contextCount = try cursor.readCompactSize(canonicality: .required).value
                guard contextCount <= UInt64(configuration.maximumContextByteCount),
                    contextCount <= UInt64(Int.max)
                else { throw OverlayHTTPError.resourceLimit }
                let (next, overflow) = aggregateContext.addingReportingOverflow(Int(contextCount))
                guard !overflow, next <= configuration.maximumContextByteCount else {
                    throw OverlayHTTPError.resourceLimit
                }
                aggregateContext = next
                _ = try cursor.read(count: Int(contextCount))
                metadata.append(
                    Metadata(transactionID: transactionID, outputIndex: UInt32(outputIndex))
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
        do {
            sharedBytes = try cursor.read(count: cursor.remaining)
            beef = try BEEF(bytes: sharedBytes, limits: configuration.beefLimits)
        } catch {
            throw OverlayHTTPError.malformedResponse
        }
        var outputs: [OutputListItem] = []
        outputs.reserveCapacity(metadata.count)
        for item in metadata {
            let transaction: Transaction
            do {
                guard
                    let found = try beef.transaction(
                        for: item.transactionID,
                        limits: configuration.beefLimits.transactionLimits
                    )
                else { throw OverlayHTTPError.malformedResponse }
                transaction = found
            } catch let error as OverlayHTTPError {
                throw error
            } catch {
                throw OverlayHTTPError.malformedResponse
            }
            guard UInt64(item.outputIndex) < UInt64(transaction.outputs.count) else {
                throw OverlayHTTPError.malformedResponse
            }
            do {
                outputs.append(
                    try OutputListItem(
                        beef: sharedBytes,
                        outputIndex: item.outputIndex,
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
            guard let instructionObject = rawInstructions as? [String: Any],
                Set(instructionObject.keys).isSubset(of: [
                    "OutputsToAdmit", "CoinsToRetain", "CoinsRemoved", "AncillaryTxids",
                ])
            else { throw OverlayHTTPError.malformedResponse }
            let outputs = try uint32Array(instructionObject["OutputsToAdmit"], limits: limits)
            let retained = try uint32Array(instructionObject["CoinsToRetain"], limits: limits)
            let removed = try uint32Array(instructionObject["CoinsRemoved"], limits: limits)
            let ancillary = try transactionIDArray(
                instructionObject["AncillaryTxids"],
                limits: limits
            )
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
