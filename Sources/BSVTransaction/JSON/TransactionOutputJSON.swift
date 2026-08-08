import BSVScript

extension TransactionOutput {
    /// Parses one strict bounded Go SDK v1.3.3 output JSON value.
    public init(jsonBytes: [UInt8], limits: TransactionJSONLimits) throws {
        var parser = try StrictTransactionJSONParser(bytes: jsonBytes, limits: limits)
        self = try parser.parseOutputDocument()
    }

    /// Returns the canonical compact Go SDK v1.3.3 output JSON value.
    public func jsonBytes(limits: TransactionJSONLimits) throws -> [UInt8] {
        try requireSafeJSONNumber(satoshis, field: "satoshis")
        var writer = TransactionJSONWriter(limits: limits)
        try appendJSON(to: &writer, limits: limits)
        return writer.bytes
    }

    package func appendJSON(
        to writer: inout TransactionJSONWriter,
        limits: TransactionJSONLimits
    ) throws {
        try requireSafeJSONNumber(satoshis, field: "satoshis")
        try writer.append(#"{"satoshis":"#)
        try writer.append(String(satoshis))
        try writer.append(",\"lockingScript\":")
        try writer.appendScriptJSON(lockingScript, limits: limits)
        try writer.append(0x7d)
    }
}
