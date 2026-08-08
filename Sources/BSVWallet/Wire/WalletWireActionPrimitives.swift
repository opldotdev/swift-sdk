import BSVCore
import BSVTransaction

func walletWireWriteText(
    _ value: String,
    kind: String,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    try walletWireRequireText(value, kind: kind, maximum: walletWireMaximumText(limits))
    try writer.writeString(value)
}

func walletWireWriteOptionalText(
    _ value: String?,
    kind: String,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    if value == "" {
        throw WalletWireError.nonRoundTrippableValue(kind: "empty optional \(kind)")
    }
    if let value {
        try walletWireRequireText(value, kind: kind, maximum: walletWireMaximumText(limits))
    }
    try writer.writeOptionalString(value)
}

func walletWireRequireActionBytes(
    _ count: Int,
    kind: String,
    limits: WalletWireLimits
) throws {
    guard count <= limits.abiLimits.maximumBytePayloadCount else {
        throw WalletWireError.byteLimitExceeded(
            kind: kind, actual: count, maximum: limits.abiLimits.maximumBytePayloadCount
        )
    }
}

func walletWireMapABIError(_ error: WalletABIError) -> WalletWireError {
    switch error {
    case .countLimitExceeded(let kind, let actual, let maximum):
        return .countLimitExceeded(kind: kind, actual: UInt64(max(0, actual)), maximum: maximum)
    case .byteLimitExceeded(let kind, let actual, let maximum):
        return .byteLimitExceeded(kind: kind, actual: actual, maximum: maximum)
    case .aggregatePayloadTooLarge(let actual, let maximum):
        return .byteLimitExceeded(kind: "aggregate wallet payload", actual: actual, maximum: maximum)
    case .sizeOverflow:
        return .byteLimitExceeded(kind: "aggregate wallet payload", actual: Int.max, maximum: Int.max)
    default:
        return .nonRoundTrippableValue(kind: "wallet action value")
    }
}

extension WalletWireWriter {
    mutating func writeActionOutpoint(_ value: Outpoint) {
        writeBytes(value.transactionID.displayBytes)
        writeCompactSize(UInt64(value.outputIndex))
    }

    mutating func writeWireTransactionID(_ value: TransactionID) {
        writeBytes(value.wireBytes)
    }

    mutating func writeDisplayTransactionID(_ value: TransactionID) {
        writeBytes(value.displayBytes)
    }
}

extension WalletWireReader {
    mutating func readActionOutpoint() throws -> Outpoint {
        let displayBytes = try readBytes(count: 32)
        let index = try readCompactSize()
        guard let outputIndex = UInt32(exactly: index) else { throw WalletWireError.uint32Overflow }
        return Outpoint(
            transactionID: try TransactionID(wireBytes: Array(displayBytes.reversed())),
            outputIndex: outputIndex
        )
    }

    mutating func readWireTransactionID() throws -> TransactionID {
        try TransactionID(wireBytes: readBytes(count: 32))
    }

    mutating func readDisplayTransactionID() throws -> TransactionID {
        try TransactionID(wireBytes: Array(readBytes(count: 32).reversed()))
    }
}

func walletWireWriteStringSlice(
    _ values: [String]?,
    kind: String,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    guard let values else {
        writer.writeCompactSize(UInt64.max)
        return
    }
    let maximum = kind == "labels" ? limits.abiLimits.maximumLabelCount
        : kind == "tags" ? limits.abiLimits.maximumTagCount
        : limits.abiLimits.maximumCollectionCount
    guard values.count <= maximum else {
        throw WalletWireError.countLimitExceeded(
            kind: kind, actual: UInt64(values.count), maximum: maximum
        )
    }
    writer.writeCompactSize(UInt64(values.count))
    for value in values {
        try walletWireRequireText(value, kind: kind, maximum: walletWireMaximumText(limits))
        if value.isEmpty { writer.writeCompactSize(UInt64.max) }
        else { try writer.writeString(value) }
    }
}

func walletWireReadStringSlice(
    from reader: inout WalletWireReader,
    kind: String,
    optional: Bool,
    limits: WalletWireLimits
) throws -> [String]? {
    let encodedCount = try reader.readCompactSize()
    if encodedCount == UInt64.max {
        if optional { return nil }
        throw WalletWireError.nonRoundTrippableValue(kind: "absent \(kind)")
    }
    let maximum = kind == "labels" ? limits.abiLimits.maximumLabelCount
        : kind == "tags" ? limits.abiLimits.maximumTagCount
        : limits.abiLimits.maximumCollectionCount
    guard encodedCount <= UInt64(maximum), encodedCount <= UInt64(Int.max) else {
        throw WalletWireError.countLimitExceeded(kind: kind, actual: encodedCount, maximum: maximum)
    }
    var result: [String] = []
    result.reserveCapacity(min(Int(encodedCount), reader.remainingCount))
    for _ in 0..<Int(encodedCount) {
        let value = try reader.readCompactSize()
        if value == UInt64.max {
            result.append("")
            continue
        }
        if value == 0 {
            throw WalletWireError.nonRoundTrippableValue(
                kind: "zero-length \(kind) entry"
            )
        }
        guard value <= UInt64(walletWireMaximumText(limits)), value <= UInt64(Int.max) else {
            throw WalletWireError.countLimitExceeded(
                kind: kind, actual: value, maximum: walletWireMaximumText(limits)
            )
        }
        let bytes = try reader.readBytes(count: Int(value))
        guard let text = String(bytes: bytes, encoding: .utf8) else {
            throw WalletWireError.invalidUTF8(kind: kind)
        }
        result.append(text)
    }
    return result
}

func walletWireWriteTransactionIDs(
    _ values: [TransactionID]?,
    kind: String,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    guard let values else {
        writer.writeCompactSize(UInt64.max)
        return
    }
    guard values.count <= limits.abiLimits.maximumCollectionCount else {
        throw WalletWireError.countLimitExceeded(
            kind: kind, actual: UInt64(values.count), maximum: limits.abiLimits.maximumCollectionCount
        )
    }
    writer.writeCompactSize(UInt64(values.count))
    for value in values { writer.writeWireTransactionID(value) }
}

func walletWireReadTransactionIDs(
    from reader: inout WalletWireReader,
    kind: String,
    limits: WalletWireLimits
) throws -> [TransactionID]? {
    let count = try reader.readCompactSize()
    if count == UInt64.max { return nil }
    guard count <= UInt64(limits.abiLimits.maximumCollectionCount), count <= UInt64(Int.max) else {
        throw WalletWireError.countLimitExceeded(
            kind: kind, actual: count, maximum: limits.abiLimits.maximumCollectionCount
        )
    }
    guard count <= UInt64(reader.remainingCount / 32) else { throw WalletWireError.truncated }
    var result: [TransactionID] = []
    result.reserveCapacity(Int(count))
    for _ in 0..<Int(count) { result.append(try reader.readWireTransactionID()) }
    return result
}

func walletWireWriteOutpointCollection(
    _ values: [Outpoint]?,
    kind: String,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    guard let values else {
        writer.writeCompactSize(UInt64.max)
        return
    }
    guard values.count <= limits.abiLimits.maximumCollectionCount else {
        throw WalletWireError.countLimitExceeded(
            kind: kind, actual: UInt64(values.count), maximum: limits.abiLimits.maximumCollectionCount
        )
    }
    writer.writeCompactSize(UInt64(values.count))
    for value in values { writer.writeActionOutpoint(value) }
}

func walletWireOutpointCollectionByteCount(
    _ values: [Outpoint],
    kind: String,
    limits: WalletWireLimits
) throws -> Int {
    guard values.count <= limits.abiLimits.maximumCollectionCount else {
        throw WalletWireError.countLimitExceeded(
            kind: kind, actual: UInt64(values.count), maximum: limits.abiLimits.maximumCollectionCount
        )
    }
    var total = walletWireCompactSizeByteCount(UInt64(values.count))
    for value in values {
        let encodedCount = 32 + walletWireCompactSizeByteCount(UInt64(value.outputIndex))
        let (next, overflow) = total.addingReportingOverflow(encodedCount)
        guard !overflow else {
            throw WalletWireError.byteLimitExceeded(
                kind: kind, actual: Int.max, maximum: limits.maximumPayloadByteCount
            )
        }
        total = next
    }
    return total
}

private func walletWireCompactSizeByteCount(_ value: UInt64) -> Int {
    switch value {
    case 0...0xFC: 1
    case 0xFD...0xFFFF: 3
    case 0x1_0000...0xFFFF_FFFF: 5
    default: 9
    }
}

func walletWireReadOutpointCollection(
    from reader: inout WalletWireReader,
    kind: String,
    limits: WalletWireLimits
) throws -> [Outpoint]? {
    let count = try reader.readCompactSize()
    if count == UInt64.max { return nil }
    guard count <= UInt64(limits.abiLimits.maximumCollectionCount), count <= UInt64(Int.max) else {
        throw WalletWireError.countLimitExceeded(
            kind: kind, actual: count, maximum: limits.abiLimits.maximumCollectionCount
        )
    }
    guard count <= UInt64(reader.remainingCount / 33) else { throw WalletWireError.truncated }
    var result: [Outpoint] = []
    result.reserveCapacity(Int(count))
    for _ in 0..<Int(count) { result.append(try reader.readActionOutpoint()) }
    return result
}

func walletWireParseBEEF(_ bytes: [UInt8], limits: BEEFLimits) throws -> BEEF {
    guard bytes.count <= limits.maximumByteCount else {
        throw WalletWireError.byteLimitExceeded(
            kind: "BEEF", actual: bytes.count, maximum: limits.maximumByteCount
        )
    }
    do { return try BEEF(bytes: bytes, limits: limits) }
    catch { throw WalletWireError.nonRoundTrippableValue(kind: "BEEF") }
}

func walletWireParseAtomicBEEF(_ bytes: [UInt8], limits: BEEFLimits) throws -> AtomicBEEF {
    guard bytes.count <= limits.maximumByteCount else {
        throw WalletWireError.byteLimitExceeded(
            kind: "Atomic BEEF", actual: bytes.count, maximum: limits.maximumByteCount
        )
    }
    do { return try AtomicBEEF(bytes: bytes, limits: limits) }
    catch { throw WalletWireError.nonRoundTrippableValue(kind: "Atomic BEEF") }
}

func walletWireBEEFBytes(_ value: BEEF, limits: BEEFLimits) throws -> [UInt8] {
    do { return try value.serialized(limits: limits) }
    catch { throw WalletWireError.nonRoundTrippableValue(kind: "BEEF") }
}

func walletWireAtomicBEEFBytes(_ value: AtomicBEEF, limits: BEEFLimits) throws -> [UInt8] {
    do { return try value.serialized(limits: limits) }
    catch { throw WalletWireError.nonRoundTrippableValue(kind: "Atomic BEEF") }
}
