import BSVCore

extension Transaction {
    /// Parses one complete bounded Go SDK v1.3.3 transaction JSON document.
    ///
    /// All six fields are required. The expanded fields and transaction ID
    /// must agree with `hex`; this prevents Go's lossy "hex wins" behavior.
    public init(jsonBytes: [UInt8], limits: TransactionJSONLimits) throws {
        var parser = try StrictTransactionJSONParser(bytes: jsonBytes, limits: limits)
        let value = try parser.parseTransaction()
        let raw: Transaction
        do {
            raw = try Transaction(
                hex: value.hex,
                format: .raw,
                limits: limits.transactionLimits
            )
        } catch let error as TransactionError {
            throw TransactionJSONError.transaction(error)
        }
        let actualID: String
        do {
            actualID = try raw.transactionID(limits: limits.transactionLimits).displayHex
        } catch let error as TransactionError {
            throw TransactionJSONError.transaction(error)
        }
        guard value.transactionID == actualID else {
            throw TransactionJSONError.transactionIDMismatch(
                expected: actualID,
                actual: value.transactionID
            )
        }
        guard value.version == raw.version else {
            throw TransactionJSONError.versionMismatch(expected: raw.version, actual: value.version)
        }
        guard value.lockTime == raw.lockTime else {
            throw TransactionJSONError.lockTimeMismatch(expected: raw.lockTime, actual: value.lockTime)
        }
        guard value.inputs.count == raw.inputs.count else {
            throw TransactionJSONError.inputMismatch(index: min(value.inputs.count, raw.inputs.count))
        }
        for index in raw.inputs.indices where value.inputs[index] != raw.inputs[index] {
            throw TransactionJSONError.inputMismatch(index: index)
        }
        guard value.outputs.count == raw.outputs.count else {
            throw TransactionJSONError.outputMismatch(index: min(value.outputs.count, raw.outputs.count))
        }
        for index in raw.outputs.indices where value.outputs[index] != raw.outputs[index] {
            throw TransactionJSONError.outputMismatch(index: index)
        }
        self = raw
    }

    /// Returns canonical compact JSON in Go's documented struct-field order.
    ///
    /// Source outputs, unlocking-size estimates, and change markers are
    /// construction metadata and are not part of this raw-transaction JSON.
    public func jsonBytes(limits: TransactionJSONLimits) throws -> [UInt8] {
        let rawByteCount: Int
        do {
            rawByteCount = try serializedByteCount(
                format: .raw,
                limits: limits.transactionLimits
            )
        } catch let error as TransactionError {
            throw TransactionJSONError.transaction(error)
        }
        try preflightJSONByteCount(rawByteCount: rawByteCount, limits: limits)

        let raw: String
        let transactionID: String
        do {
            raw = try hex(format: .raw, limits: limits.transactionLimits)
            transactionID = try self.transactionID(limits: limits.transactionLimits).displayHex
        } catch let error as TransactionError {
            throw TransactionJSONError.transaction(error)
        }
        var writer = TransactionJSONWriter(limits: limits)
        try writer.append(#"{"txid":"#)
        try writer.appendJSONString(transactionID)
        try writer.append(",\"hex\":")
        try writer.appendJSONString(raw)
        try writer.append(",\"inputs\":")
        if inputs.isEmpty {
            try writer.append("null")
        } else {
            try writer.append(0x5b)
            for (index, input) in inputs.enumerated() {
                if index != 0 { try writer.append(0x2c) }
                try input.appendJSON(to: &writer, limits: limits)
            }
            try writer.append(0x5d)
        }
        try writer.append(",\"outputs\":")
        if outputs.isEmpty {
            try writer.append("null")
        } else {
            try writer.append(0x5b)
            for (index, output) in outputs.enumerated() {
                if index != 0 { try writer.append(0x2c) }
                try output.appendJSON(to: &writer, limits: limits)
            }
            try writer.append(0x5d)
        }
        try writer.append(",\"version\":")
        try writer.append(String(version))
        try writer.append(",\"lockTime\":")
        try writer.append(String(lockTime))
        try writer.append(0x7d)
        return writer.bytes
    }

    private func preflightJSONByteCount(
        rawByteCount: Int,
        limits: TransactionJSONLimits
    ) throws {
        var count = 0
        func add(_ increment: Int) throws {
            let (actual, overflow) = count.addingReportingOverflow(increment)
            guard !overflow, actual <= limits.maximumJSONByteCount else {
                throw TransactionJSONError.documentTooLarge(
                    actual: overflow ? .max : actual,
                    maximum: limits.maximumJSONByteCount
                )
            }
            count = actual
        }
        func scriptJSONByteCount(_ byteCount: Int) throws -> Int {
            let (hexCount, multipliedOverflow) = byteCount.multipliedReportingOverflow(by: 2)
            let (jsonCount, addedOverflow) = hexCount.addingReportingOverflow(2)
            guard !multipliedOverflow, !addedOverflow else {
                throw TransactionJSONError.documentTooLarge(
                    actual: .max,
                    maximum: limits.maximumJSONByteCount
                )
            }
            return jsonCount
        }

        try add(#"{"txid":"#.utf8.count + 66)
        let (rawHexCount, rawHexOverflow) = rawByteCount.multipliedReportingOverflow(by: 2)
        guard !rawHexOverflow else {
            throw TransactionJSONError.documentTooLarge(
                actual: .max,
                maximum: limits.maximumJSONByteCount
            )
        }
        try add(",\"hex\":".utf8.count + rawHexCount + 2)
        try add(",\"inputs\":".utf8.count)
        if inputs.isEmpty {
            try add("null".utf8.count)
        } else {
            try add(1)
            for (index, input) in inputs.enumerated() {
                if index != 0 { try add(1) }
                try add(#"{"unlockingScript":"#.utf8.count)
                try add(try scriptJSONByteCount(input.unlockingScript.byteCount))
                try add(",\"txid\":".utf8.count + 66)
                try add(",\"vout\":".utf8.count + transactionJSONDecimalDigitCount(input.previousOutput.outputIndex))
                try add(",\"sequence\":".utf8.count + transactionJSONDecimalDigitCount(input.sequence) + 1)
            }
            try add(1)
        }
        try add(",\"outputs\":".utf8.count)
        if outputs.isEmpty {
            try add("null".utf8.count)
        } else {
            try add(1)
            for (index, output) in outputs.enumerated() {
                try requireSafeJSONNumber(output.satoshis, field: "satoshis")
                if index != 0 { try add(1) }
                try add(#"{"satoshis":"#.utf8.count + transactionJSONDecimalDigitCount(output.satoshis))
                try add(",\"lockingScript\":".utf8.count)
                try add(try scriptJSONByteCount(output.lockingScript.byteCount) + 1)
            }
            try add(1)
        }
        try add(",\"version\":".utf8.count + transactionJSONDecimalDigitCount(version))
        try add(",\"lockTime\":".utf8.count + transactionJSONDecimalDigitCount(lockTime) + 1)
    }
}

private func transactionJSONDecimalDigitCount<T: BinaryInteger>(_ value: T) -> Int {
    var remaining = value
    var count = 1
    while remaining >= 10 {
        remaining /= 10
        count += 1
    }
    return count
}
