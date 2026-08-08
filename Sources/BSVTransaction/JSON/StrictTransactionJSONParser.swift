import BSVCore
import BSVScript

package let transactionJSONMaximumSafeInteger: UInt64 = 9_007_199_254_740_991
package let transactionJSONHexDigits = Array("0123456789abcdef".utf8)
private let transactionJSONMaximumObjectKeyByteCount = 64

package struct ParsedTransactionJSON {
    let transactionID: String
    let hex: String
    let inputs: [TransactionInput]
    let outputs: [TransactionOutput]
    let version: UInt32
    let lockTime: UInt32
}

package struct StrictTransactionJSONParser {
    private let bytes: [UInt8]
    private let limits: TransactionJSONLimits
    private var offset = 0

    package init(bytes: [UInt8], limits: TransactionJSONLimits) throws {
        guard bytes.count <= limits.maximumJSONByteCount else {
            throw TransactionJSONError.documentTooLarge(
                actual: bytes.count,
                maximum: limits.maximumJSONByteCount
            )
        }
        guard isValidTransactionJSONUTF8(bytes) else {
            throw TransactionJSONError.invalidUTF8
        }
        self.bytes = bytes
        self.limits = limits
    }

    package mutating func parseTransaction() throws -> ParsedTransactionJSON {
        try skipWhitespace()
        try consume(0x7b)
        var seen: Set<String> = []
        var transactionID: String?
        var hex: String?
        var inputs: [TransactionInput]?
        var outputs: [TransactionOutput]?
        var version: UInt32?
        var lockTime: UInt32?
        let maximumTransactionByteCount = limits.transactionLimits.maximumTransactionByteCount

        try Self.parseObjectMembers(&self) { parser, key in
            try Self.requireNew(key, seen: &seen)
            switch key {
            case "txid":
                transactionID = try parser.parseLowercaseHex(field: key, exactDecodedByteCount: 32)
            case "hex":
                hex = try parser.parseLowercaseHex(
                    field: key,
                    maximumDecodedByteCount: maximumTransactionByteCount
                )
            case "inputs":
                inputs = try parser.parseInputs()
            case "outputs":
                outputs = try parser.parseOutputs()
            case "version":
                version = try parser.parseUInt32(field: key)
            case "lockTime":
                lockTime = try parser.parseUInt32(field: key)
            default:
                throw TransactionJSONError.unknownKey(key)
            }
        }
        try finish()
        return ParsedTransactionJSON(
            transactionID: try require(transactionID, key: "txid"),
            hex: try require(hex, key: "hex"),
            inputs: try require(inputs, key: "inputs"),
            outputs: try require(outputs, key: "outputs"),
            version: try require(version, key: "version"),
            lockTime: try require(lockTime, key: "lockTime")
        )
    }

    package mutating func parseInputDocument() throws -> TransactionInput {
        try skipWhitespace()
        let input = try parseInput()
        try finish()
        return input
    }

    package mutating func parseOutputDocument() throws -> TransactionOutput {
        try skipWhitespace()
        let output = try parseOutput()
        try finish()
        return output
    }

    private mutating func parseInputs() throws -> [TransactionInput] {
        if try consumeNullIfPresent() { return [] }
        try consume(0x5b)
        try skipWhitespace()
        if consumeIf(0x5d) { return [] }
        var result: [TransactionInput] = []
        while true {
            let nextCount = UInt64(result.count) + 1
            guard nextCount <= limits.transactionLimits.maximumInputCount else {
                throw TransactionJSONError.inputCountExceedsLimit(
                    actual: nextCount,
                    maximum: limits.transactionLimits.maximumInputCount
                )
            }
            result.append(try parseInput())
            try skipWhitespace()
            if consumeIf(0x5d) { return result }
            try consume(0x2c)
            try skipWhitespace()
        }
    }

    private mutating func parseOutputs() throws -> [TransactionOutput] {
        if try consumeNullIfPresent() { return [] }
        try consume(0x5b)
        try skipWhitespace()
        if consumeIf(0x5d) { return [] }
        var result: [TransactionOutput] = []
        while true {
            let nextCount = UInt64(result.count) + 1
            guard nextCount <= limits.transactionLimits.maximumOutputCount else {
                throw TransactionJSONError.outputCountExceedsLimit(
                    actual: nextCount,
                    maximum: limits.transactionLimits.maximumOutputCount
                )
            }
            result.append(try parseOutput())
            try skipWhitespace()
            if consumeIf(0x5d) { return result }
            try consume(0x2c)
            try skipWhitespace()
        }
    }

    private mutating func parseInput() throws -> TransactionInput {
        try consume(0x7b)
        var seen: Set<String> = []
        var unlockingScript: Script?
        var transactionID: TransactionID?
        var outputIndex: UInt32?
        var sequence: UInt32?
        try Self.parseObjectMembers(&self) { parser, key in
            try Self.requireNew(key, seen: &seen)
            switch key {
            case "unlockingScript":
                unlockingScript = try parser.parseScript(field: key)
            case "txid":
                let text = try parser.parseLowercaseHex(field: key, exactDecodedByteCount: 32)
                do {
                    transactionID = try TransactionID(displayHex: text)
                } catch {
                    throw TransactionJSONError.nonCanonicalHex(field: key)
                }
            case "vout":
                outputIndex = try parser.parseUInt32(field: key)
            case "sequence":
                sequence = try parser.parseUInt32(field: key)
            default:
                throw TransactionJSONError.unknownKey(key)
            }
        }
        return TransactionInput(
            previousOutput: Outpoint(
                transactionID: try require(transactionID, key: "txid"),
                outputIndex: try require(outputIndex, key: "vout")
            ),
            unlockingScript: try require(unlockingScript, key: "unlockingScript"),
            sequence: try require(sequence, key: "sequence")
        )
    }

    private mutating func parseOutput() throws -> TransactionOutput {
        try consume(0x7b)
        var seen: Set<String> = []
        var satoshis: UInt64?
        var lockingScript: Script?
        try Self.parseObjectMembers(&self) { parser, key in
            try Self.requireNew(key, seen: &seen)
            switch key {
            case "satoshis":
                satoshis = try parser.parseSafeUInt64(field: key)
            case "lockingScript":
                lockingScript = try parser.parseScript(field: key)
            default:
                throw TransactionJSONError.unknownKey(key)
            }
        }
        return TransactionOutput(
            satoshis: try require(satoshis, key: "satoshis"),
            lockingScript: try require(lockingScript, key: "lockingScript")
        )
    }

    private mutating func parseScript(field: String) throws -> Script {
        try skipWhitespace()
        let start = offset
        _ = try parseLowercaseHex(
            field: field,
            maximumDecodedByteCount: Int(limits.transactionLimits.maximumScriptByteCount)
        )
        let document = Array(bytes[start..<offset])
        do {
            return try Script(
                jsonBytes: document,
                limits: ScriptJSONLimits(
                    maximumJSONByteCount: document.count,
                    maximumScriptByteCount: Int(limits.transactionLimits.maximumScriptByteCount)
                )
            )
        } catch let error as ScriptError {
            throw TransactionJSONError.script(error)
        }
    }

    private static func parseObjectMembers(
        _ parser: inout Self,
        _ body: (inout Self, String) throws -> Void
    ) throws {
        try parser.skipWhitespace()
        if parser.consumeIf(0x7d) { return }
        while true {
            let key = try parser.parsePlainASCIIString(
                maximumByteCount: transactionJSONMaximumObjectKeyByteCount
            )
            try parser.skipWhitespace()
            try parser.consume(0x3a)
            try parser.skipWhitespace()
            try body(&parser, key)
            try parser.skipWhitespace()
            if parser.consumeIf(0x7d) { return }
            try parser.consume(0x2c)
            try parser.skipWhitespace()
        }
    }

    private mutating func parsePlainASCIIString(maximumByteCount: Int? = nil) throws -> String {
        try consume(0x22)
        let start = offset
        while offset < bytes.count, bytes[offset] != 0x22 {
            let byte = bytes[offset]
            guard byte >= 0x20, byte <= 0x7e, byte != 0x5c else {
                throw TransactionJSONError.malformedJSON(offset: offset)
            }
            offset += 1
            if let maximumByteCount, offset - start > maximumByteCount {
                throw TransactionJSONError.valueTooLarge(
                    field: "objectKey",
                    actual: maximumByteCount + 1,
                    maximum: maximumByteCount
                )
            }
        }
        guard offset < bytes.count else {
            throw TransactionJSONError.malformedJSON(offset: offset)
        }
        let value = String(decoding: bytes[start..<offset], as: UTF8.self)
        offset += 1
        return value
    }

    private mutating func parseLowercaseHex(
        field: String,
        exactDecodedByteCount: Int? = nil,
        maximumDecodedByteCount: Int? = nil
    ) throws -> String {
        let value = try parsePlainASCIIString()
        let utf8 = Array(value.utf8)
        guard utf8.count.isMultiple(of: 2), utf8.allSatisfy({
            (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
        }) else {
            throw TransactionJSONError.nonCanonicalHex(field: field)
        }
        let decodedCount = utf8.count / 2
        if let exactDecodedByteCount, decodedCount != exactDecodedByteCount {
            throw TransactionJSONError.nonCanonicalHex(field: field)
        }
        if let maximumDecodedByteCount, decodedCount > maximumDecodedByteCount {
            throw TransactionJSONError.valueTooLarge(
                field: field,
                actual: decodedCount,
                maximum: maximumDecodedByteCount
            )
        }
        return value
    }

    private mutating func parseUInt32(field: String) throws -> UInt32 {
        let value = try parseSafeUInt64(field: field)
        guard value <= UInt64(UInt32.max) else {
            throw TransactionJSONError.numberOutOfRange(field: field)
        }
        return UInt32(value)
    }

    private mutating func parseSafeUInt64(field: String) throws -> UInt64 {
        guard offset < bytes.count, (0x30...0x39).contains(bytes[offset]) else {
            throw TransactionJSONError.malformedJSON(offset: offset)
        }
        if bytes[offset] == 0x30 {
            offset += 1
            if offset < bytes.count, (0x30...0x39).contains(bytes[offset]) {
                throw TransactionJSONError.malformedJSON(offset: offset)
            }
            return 0
        }
        var result: UInt64 = 0
        while offset < bytes.count, (0x30...0x39).contains(bytes[offset]) {
            let digit = UInt64(bytes[offset] - 0x30)
            let (product, multipliedOverflow) = result.multipliedReportingOverflow(by: 10)
            let (sum, addedOverflow) = product.addingReportingOverflow(digit)
            guard !multipliedOverflow, !addedOverflow else {
                throw TransactionJSONError.numberOutOfRange(field: field)
            }
            result = sum
            offset += 1
        }
        guard result <= transactionJSONMaximumSafeInteger else {
            throw TransactionJSONError.unsafeJSONNumber(field: field, value: result)
        }
        return result
    }

    private static func requireNew(_ key: String, seen: inout Set<String>) throws {
        guard seen.insert(key).inserted else {
            throw TransactionJSONError.duplicateKey(key)
        }
    }

    private func require<T>(_ value: T?, key: String) throws -> T {
        guard let value else { throw TransactionJSONError.missingKey(key) }
        return value
    }

    private mutating func skipWhitespace() throws {
        while offset < bytes.count {
            switch bytes[offset] {
            case 0x20, 0x09, 0x0a, 0x0d: offset += 1
            default: return
            }
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIf(expected) else {
            throw TransactionJSONError.malformedJSON(offset: offset)
        }
    }

    private mutating func consumeIf(_ expected: UInt8) -> Bool {
        guard offset < bytes.count, bytes[offset] == expected else { return false }
        offset += 1
        return true
    }

    private mutating func consumeNullIfPresent() throws -> Bool {
        guard offset < bytes.count, bytes[offset] == 0x6e else { return false }
        let literal = Array("null".utf8)
        guard bytes.count - offset >= literal.count,
              bytes[offset..<(offset + literal.count)].elementsEqual(literal) else {
            throw TransactionJSONError.malformedJSON(offset: offset)
        }
        offset += literal.count
        return true
    }

    private mutating func finish() throws {
        try skipWhitespace()
        guard offset == bytes.count else {
            throw TransactionJSONError.malformedJSON(offset: offset)
        }
    }
}

private func isValidTransactionJSONUTF8(_ bytes: [UInt8]) -> Bool {
    var index = 0
    while index < bytes.count {
        let first = bytes[index]
        let continuationCount: Int
        let minimumSecond: UInt8
        let maximumSecond: UInt8
        switch first {
        case 0x00...0x7f:
            index += 1
            continue
        case 0xc2...0xdf:
            continuationCount = 1
            minimumSecond = 0x80
            maximumSecond = 0xbf
        case 0xe0:
            continuationCount = 2
            minimumSecond = 0xa0
            maximumSecond = 0xbf
        case 0xe1...0xec, 0xee...0xef:
            continuationCount = 2
            minimumSecond = 0x80
            maximumSecond = 0xbf
        case 0xed:
            continuationCount = 2
            minimumSecond = 0x80
            maximumSecond = 0x9f
        case 0xf0:
            continuationCount = 3
            minimumSecond = 0x90
            maximumSecond = 0xbf
        case 0xf1...0xf3:
            continuationCount = 3
            minimumSecond = 0x80
            maximumSecond = 0xbf
        case 0xf4:
            continuationCount = 3
            minimumSecond = 0x80
            maximumSecond = 0x8f
        default:
            return false
        }
        guard index + continuationCount < bytes.count,
              (minimumSecond...maximumSecond).contains(bytes[index + 1]) else {
            return false
        }
        if continuationCount >= 2, !(0x80...0xbf).contains(bytes[index + 2]) {
            return false
        }
        if continuationCount == 3, !(0x80...0xbf).contains(bytes[index + 3]) {
            return false
        }
        index += continuationCount + 1
    }
    return true
}

package func requireSafeJSONNumber(_ value: UInt64, field: String) throws {
    guard value <= transactionJSONMaximumSafeInteger else {
        throw TransactionJSONError.unsafeJSONNumber(field: field, value: value)
    }
}

package struct TransactionJSONWriter {
    private(set) var bytes: [UInt8]
    private let maximumByteCount: Int

    package init(limits: TransactionJSONLimits) {
        maximumByteCount = limits.maximumJSONByteCount
        bytes = []
        bytes.reserveCapacity(min(maximumByteCount, 1_024))
    }

    package mutating func append(_ byte: UInt8) throws {
        try preflight(additionalByteCount: 1)
        bytes.append(byte)
    }

    package mutating func append(_ value: String) throws {
        try preflight(additionalByteCount: value.utf8.count)
        bytes.append(contentsOf: value.utf8)
    }

    package mutating func appendJSONString(_ value: String) throws {
        let (withQuotes, overflow) = value.utf8.count.addingReportingOverflow(2)
        guard !overflow else {
            throw TransactionJSONError.documentTooLarge(
                actual: .max,
                maximum: maximumByteCount
            )
        }
        try preflight(additionalByteCount: withQuotes)
        bytes.append(0x22)
        bytes.append(contentsOf: value.utf8)
        bytes.append(0x22)
    }

    package mutating func appendScriptJSON(
        _ script: Script,
        limits: TransactionJSONLimits
    ) throws {
        guard UInt64(script.byteCount) <= limits.transactionLimits.maximumScriptByteCount else {
            throw TransactionJSONError.script(.scriptTooLarge(
                actual: script.byteCount,
                maximum: Int(limits.transactionLimits.maximumScriptByteCount)
            ))
        }
        let (hexByteCount, multipliedOverflow) = script.byteCount.multipliedReportingOverflow(by: 2)
        let (documentByteCount, addedOverflow) = hexByteCount.addingReportingOverflow(2)
        guard !multipliedOverflow, !addedOverflow else {
            throw TransactionJSONError.documentTooLarge(
                actual: .max,
                maximum: maximumByteCount
            )
        }
        try preflight(additionalByteCount: documentByteCount)
        do {
            let document = try script.jsonBytes(limits: ScriptJSONLimits(
                maximumJSONByteCount: documentByteCount,
                maximumScriptByteCount: Int(limits.transactionLimits.maximumScriptByteCount)
            ))
            bytes.append(contentsOf: document)
        } catch let error as ScriptError {
            throw TransactionJSONError.script(error)
        }
    }

    private func preflight(additionalByteCount: Int) throws {
        let (actual, overflow) = bytes.count.addingReportingOverflow(additionalByteCount)
        guard !overflow, actual <= maximumByteCount else {
            throw TransactionJSONError.documentTooLarge(
                actual: overflow ? .max : actual,
                maximum: maximumByteCount
            )
        }
    }
}
