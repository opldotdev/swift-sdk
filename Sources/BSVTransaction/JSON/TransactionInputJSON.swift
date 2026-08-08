import BSVScript

extension TransactionInput {
    /// Parses one strict bounded Go SDK v1.3.3 input JSON value.
    public init(jsonBytes: [UInt8], limits: TransactionJSONLimits) throws {
        var parser = try StrictTransactionJSONParser(bytes: jsonBytes, limits: limits)
        self = try parser.parseInputDocument()
    }

    /// Returns the canonical compact Go SDK v1.3.3 input JSON value.
    public func jsonBytes(limits: TransactionJSONLimits) throws -> [UInt8] {
        var writer = TransactionJSONWriter(limits: limits)
        try appendJSON(to: &writer, limits: limits)
        return writer.bytes
    }

    package func appendJSON(
        to writer: inout TransactionJSONWriter,
        limits: TransactionJSONLimits
    ) throws {
        try writer.append(#"{"unlockingScript":"#)
        try writer.appendScriptJSON(unlockingScript, limits: limits)
        try writer.append(",\"txid\":")
        try writer.appendJSONString(previousOutput.transactionID.displayHex)
        try writer.append(",\"vout\":")
        try writer.append(String(previousOutput.outputIndex))
        try writer.append(",\"sequence\":")
        try writer.append(String(sequence))
        try writer.append(0x7d)
    }
}
