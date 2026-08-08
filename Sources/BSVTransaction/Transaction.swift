import BSVCore
import BSVCrypto
import BSVScript

/// A value-semantic legacy Bitcoin transaction.
///
/// This type covers the canonical transaction wire format. BRC-30 extended
/// format, BEEF, and signing preimages are separate layers built on this model.
public struct Transaction: Hashable, Sendable {
    public var version: UInt32
    public var inputs: [TransactionInput]
    public var outputs: [TransactionOutput]
    public var lockTime: UInt32

    public init(
        version: UInt32 = 1,
        inputs: [TransactionInput] = [],
        outputs: [TransactionOutput] = [],
        lockTime: UInt32 = 0
    ) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }

    /// Parses exactly one bounded transaction and rejects trailing bytes.
    public init(
        bytes: [UInt8],
        limits: TransactionLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        guard bytes.count <= limits.maximumTransactionByteCount else {
            throw TransactionError.transactionTooLarge(
                actual: bytes.count,
                maximum: limits.maximumTransactionByteCount
            )
        }

        var cursor = ByteCursor(bytes)
        try self.init(
            consuming: &cursor,
            limits: limits,
            compactSizeCanonicality: compactSizeCanonicality
        )
        do {
            try cursor.requireFinished()
        } catch let error as BinaryDecodingError {
            throw TransactionError.malformed(
                field: .trailingBytes,
                offset: cursor.position,
                cause: error
            )
        }
    }

    /// Consumes one raw transaction from an enclosing package format.
    package init(
        consuming cursor: inout ByteCursor,
        limits: TransactionLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        let startPosition = cursor.position
        let version = try Self.read(.version, from: &cursor) {
            try $0.readUInt32LE()
        }
        let inputCountValue = try Self.read(.inputCount, from: &cursor) {
            try $0.readCompactSize(canonicality: compactSizeCanonicality).value
        }
        guard inputCountValue <= limits.maximumInputCount else {
            throw TransactionError.inputCountExceedsLimit(
                actual: inputCountValue,
                maximum: limits.maximumInputCount
            )
        }
        guard inputCountValue <= UInt64(Int.max) else {
            throw TransactionError.countNotRepresentable(inputCountValue)
        }

        var inputs: [TransactionInput] = []
        inputs.reserveCapacity(min(Int(inputCountValue), cursor.remaining / 41))
        for _ in 0..<Int(inputCountValue) {
            let transactionIDBytes = try Self.read(.previousTransactionID, from: &cursor) {
                try $0.read(count: 32)
            }
            let outputIndex = try Self.read(.previousOutputIndex, from: &cursor) {
                try $0.readUInt32LE()
            }
            let scriptBytes = try Self.read(.unlockingScript, from: &cursor) {
                try $0.readVarBytes(
                    maximumLength: limits.maximumScriptByteCount,
                    canonicality: compactSizeCanonicality
                ).bytes
            }
            let sequence = try Self.read(.sequence, from: &cursor) {
                try $0.readUInt32LE()
            }
            inputs.append(TransactionInput(
                previousOutput: Outpoint(
                    transactionID: try TransactionID(wireBytes: transactionIDBytes),
                    outputIndex: outputIndex
                ),
                unlockingScript: try Script(
                    bytes: scriptBytes,
                    maximumByteCount: Int(limits.maximumScriptByteCount)
                ),
                sequence: sequence
            ))
        }

        let outputCountValue = try Self.read(.outputCount, from: &cursor) {
            try $0.readCompactSize(canonicality: compactSizeCanonicality).value
        }
        guard outputCountValue <= limits.maximumOutputCount else {
            throw TransactionError.outputCountExceedsLimit(
                actual: outputCountValue,
                maximum: limits.maximumOutputCount
            )
        }
        guard outputCountValue <= UInt64(Int.max) else {
            throw TransactionError.countNotRepresentable(outputCountValue)
        }

        var outputs: [TransactionOutput] = []
        outputs.reserveCapacity(min(Int(outputCountValue), cursor.remaining / 9))
        for _ in 0..<Int(outputCountValue) {
            let satoshis = try Self.read(.satoshis, from: &cursor) {
                try $0.readUInt64LE()
            }
            let scriptBytes = try Self.read(.lockingScript, from: &cursor) {
                try $0.readVarBytes(
                    maximumLength: limits.maximumScriptByteCount,
                    canonicality: compactSizeCanonicality
                ).bytes
            }
            outputs.append(TransactionOutput(
                satoshis: satoshis,
                lockingScript: try Script(
                    bytes: scriptBytes,
                    maximumByteCount: Int(limits.maximumScriptByteCount)
                )
            ))
        }

        let lockTime = try Self.read(.lockTime, from: &cursor) {
            try $0.readUInt32LE()
        }
        let byteCount = cursor.position - startPosition
        guard byteCount <= limits.maximumTransactionByteCount else {
            throw TransactionError.transactionTooLarge(
                actual: byteCount,
                maximum: limits.maximumTransactionByteCount
            )
        }

        self.init(version: version, inputs: inputs, outputs: outputs, lockTime: lockTime)
    }

    /// Parses lowercase or uppercase hexadecimal within the same byte limit.
    public init(
        hex: String,
        limits: TransactionLimits,
        compactSizeCanonicality: CompactSizeCanonicality = .required
    ) throws {
        do {
            if limits.maximumTransactionByteCount <= (Int.max - 1) / 2 {
                let maximumHexByteCount = limits.maximumTransactionByteCount * 2
                guard hex.utf8.prefix(maximumHexByteCount + 1).count <= maximumHexByteCount else {
                    throw TextEncodingError.decodedSizeLimitExceeded(
                        maximum: limits.maximumTransactionByteCount
                    )
                }
            }
            let bytes = try Hex.decode(
                hex,
                maximumDecodedByteCount: limits.maximumTransactionByteCount
            )
            try self.init(
                bytes: bytes,
                limits: limits,
                compactSizeCanonicality: compactSizeCanonicality
            )
        } catch let error as TextEncodingError {
            throw TransactionError.invalidHex(error)
        }
    }

    /// Serializes using canonical CompactSize prefixes after a complete size preflight.
    public func serialized(limits: TransactionLimits) throws -> [UInt8] {
        let byteCount = try serializedByteCount(limits: limits)
        var writer = ByteWriter(capacity: byteCount)
        writer.writeUInt32LE(version)
        writer.writeCompactSize(UInt64(inputs.count))
        for input in inputs {
            writer.write(input.previousOutput.wireBytes)
            writer.writeVarBytes(input.unlockingScript.bytes)
            writer.writeUInt32LE(input.sequence)
        }
        writer.writeCompactSize(UInt64(outputs.count))
        for output in outputs {
            writer.writeUInt64LE(output.satoshis)
            writer.writeVarBytes(output.lockingScript.bytes)
        }
        writer.writeUInt32LE(lockTime)
        return writer.bytes
    }

    public func hex(limits: TransactionLimits) throws -> String {
        Hex.encode(try serialized(limits: limits))
    }

    public func transactionID(limits: TransactionLimits) throws -> TransactionID {
        TransactionID(
            exactDigestBytesGuaranteed: BSVHashing.sha256d(
                try serialized(limits: limits)
            ).bytes
        )
    }

    public func serializedByteCount(limits: TransactionLimits) throws -> Int {
        try serializedByteCount(
            unlockingScriptByteCounts: inputs.map { $0.unlockingScript.byteCount },
            limits: limits
        )
    }

    package func serializedByteCount(
        unlockingScriptByteCounts: [Int],
        limits: TransactionLimits
    ) throws -> Int {
        guard UInt64(inputs.count) <= limits.maximumInputCount else {
            throw TransactionError.inputCountExceedsLimit(
                actual: UInt64(inputs.count),
                maximum: limits.maximumInputCount
            )
        }
        guard UInt64(outputs.count) <= limits.maximumOutputCount else {
            throw TransactionError.outputCountExceedsLimit(
                actual: UInt64(outputs.count),
                maximum: limits.maximumOutputCount
            )
        }
        guard unlockingScriptByteCounts.count == inputs.count else {
            throw TransactionError.serializedSizeOverflow
        }

        var total = 4
        try Self.add(CompactSize.encodedLength(of: UInt64(inputs.count)), to: &total)
        for (inputIndex, scriptByteCount) in unlockingScriptByteCounts.enumerated() {
            guard scriptByteCount >= 0 else {
                throw TransactionError.invalidUnlockingScriptEstimate(
                    inputIndex: inputIndex,
                    byteCount: scriptByteCount
                )
            }
            let scriptByteCount64 = UInt64(scriptByteCount)
            guard scriptByteCount64 <= limits.maximumScriptByteCount else {
                throw TransactionError.scriptTooLarge(
                    actual: scriptByteCount64,
                    maximum: limits.maximumScriptByteCount
                )
            }
            try Self.add(32 + 4 + 4, to: &total)
            try Self.add(
                CompactSize.encodedLength(of: scriptByteCount64),
                to: &total
            )
            try Self.add(scriptByteCount, to: &total)
        }
        try Self.add(CompactSize.encodedLength(of: UInt64(outputs.count)), to: &total)
        for output in outputs {
            try Self.validate(script: output.lockingScript, limits: limits)
            try Self.add(8, to: &total)
            try Self.add(
                CompactSize.encodedLength(of: UInt64(output.lockingScript.byteCount)),
                to: &total
            )
            try Self.add(output.lockingScript.byteCount, to: &total)
        }
        try Self.add(4, to: &total)
        guard total <= limits.maximumTransactionByteCount else {
            throw TransactionError.transactionTooLarge(
                actual: total,
                maximum: limits.maximumTransactionByteCount
            )
        }
        return total
    }

    /// Coinbase detection follows the consensus outpoint shape: one zero hash
    /// and output index `UInt32.max`. Sequence is intentionally irrelevant.
    public var isCoinbase: Bool {
        inputs.count == 1
            && inputs[0].previousOutput.transactionID.wireBytes.allSatisfy { $0 == 0 }
            && inputs[0].previousOutput.outputIndex == UInt32.max
    }

    public func totalOutputSatoshis() throws -> UInt64 {
        try outputs.reduce(into: UInt64.zero) { total, output in
            let (next, overflow) = total.addingReportingOverflow(output.satoshis)
            guard !overflow else { throw TransactionError.satoshiTotalOverflow }
            total = next
        }
    }

    public func totalInputSatoshis() throws -> UInt64 {
        var total: UInt64 = 0
        for (index, input) in inputs.enumerated() {
            guard let sourceOutput = input.sourceOutput else {
                throw TransactionError.missingSourceOutput(inputIndex: index)
            }
            let (next, overflow) = total.addingReportingOverflow(sourceOutput.satoshis)
            guard !overflow else { throw TransactionError.satoshiTotalOverflow }
            total = next
        }
        return total
    }

    private static func read<T>(
        _ field: TransactionField,
        from cursor: inout ByteCursor,
        _ operation: (inout ByteCursor) throws -> T
    ) throws -> T {
        let offset = cursor.position
        do {
            return try operation(&cursor)
        } catch let error as BinaryDecodingError {
            throw TransactionError.malformed(field: field, offset: offset, cause: error)
        }
    }

    private static func validate(script: Script, limits: TransactionLimits) throws {
        guard UInt64(script.byteCount) <= limits.maximumScriptByteCount else {
            throw TransactionError.scriptTooLarge(
                actual: UInt64(script.byteCount),
                maximum: limits.maximumScriptByteCount
            )
        }
    }

    private static func add(_ value: Int, to total: inout Int) throws {
        let (next, overflow) = total.addingReportingOverflow(value)
        guard !overflow else { throw TransactionError.serializedSizeOverflow }
        total = next
    }
}
