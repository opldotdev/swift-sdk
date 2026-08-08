import BSVCore
import BSVKeys

struct WalletWireWriter {
    private(set) var bytes: [UInt8] = []

    mutating func writeByte(_ value: UInt8) { bytes.append(value) }
    mutating func writeBytes(_ value: [UInt8]) { bytes.append(contentsOf: value) }

    mutating func writeCompactSize(_ value: UInt64) {
        switch value {
        case 0...0xFC:
            writeByte(UInt8(value))
        case 0xFD...0xFFFF:
            writeByte(0xFD)
            writeLittleEndian(value, count: 2)
        case 0x1_0000...0xFFFF_FFFF:
            writeByte(0xFE)
            writeLittleEndian(value, count: 4)
        default:
            writeByte(0xFF)
            writeLittleEndian(value, count: 8)
        }
    }

    mutating func writeCount(_ count: Int) throws {
        guard count >= 0 else {
            throw WalletWireError.invalidLimit(name: "encoded count", value: count)
        }
        writeCompactSize(UInt64(count))
    }

    mutating func writeVarBytes(_ value: [UInt8]) throws {
        try writeCount(value.count)
        writeBytes(value)
    }

    mutating func writeString(_ value: String) throws {
        let encoded = Array(value.utf8)
        try writeCount(encoded.count)
        writeBytes(encoded)
    }

    mutating func writeOptionalBoolean(_ value: Bool?) {
        switch value {
        case .some(false): writeByte(0)
        case .some(true): writeByte(1)
        case .none: writeByte(0xFF)
        }
    }

    private mutating func writeLittleEndian(_ value: UInt64, count: Int) {
        for shift in 0..<count { writeByte(UInt8(truncatingIfNeeded: value >> (shift * 8))) }
    }
}

struct WalletWireReader {
    private let bytes: [UInt8]
    private(set) var position = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var remainingCount: Int { bytes.count - position }
    var isAtEnd: Bool { position == bytes.count }

    mutating func readByte() throws -> UInt8 {
        guard position < bytes.count else { throw WalletWireError.truncated }
        defer { position += 1 }
        return bytes[position]
    }

    mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0, count <= remainingCount else { throw WalletWireError.truncated }
        let end = position + count
        defer { position = end }
        return Array(bytes[position..<end])
    }

    mutating func readRemainder(maximum: Int, kind: String) throws -> [UInt8] {
        guard remainingCount <= maximum else {
            throw WalletWireError.byteLimitExceeded(
                kind: kind,
                actual: remainingCount,
                maximum: maximum
            )
        }
        return try readBytes(count: remainingCount)
    }

    mutating func readCompactSize() throws -> UInt64 {
        let prefix = try readByte()
        switch prefix {
        case 0...0xFC:
            return UInt64(prefix)
        case 0xFD:
            let value = try readLittleEndian(count: 2)
            guard value >= 0xFD else { throw WalletWireError.noncanonicalCompactSize }
            return value
        case 0xFE:
            let value = try readLittleEndian(count: 4)
            guard value > 0xFFFF else { throw WalletWireError.noncanonicalCompactSize }
            return value
        case 0xFF:
            let value = try readLittleEndian(count: 8)
            guard value > 0xFFFF_FFFF else { throw WalletWireError.noncanonicalCompactSize }
            return value
        default:
            preconditionFailure("all byte values are covered")
        }
    }

    mutating func readCount(maximum: Int, kind: String) throws -> Int {
        let value = try readCompactSize()
        guard value <= UInt64(Int.max) else { throw WalletWireError.countLimitExceeded(kind: kind, actual: value, maximum: maximum) }
        guard value <= UInt64(maximum) else {
            throw WalletWireError.countLimitExceeded(kind: kind, actual: value, maximum: maximum)
        }
        return Int(value)
    }

    mutating func readVarBytes(maximum: Int, kind: String) throws -> [UInt8] {
        let count = try readCount(maximum: maximum, kind: kind)
        return try readBytes(count: count)
    }

    mutating func readString(maximum: Int, kind: String) throws -> String {
        let count = try readCount(maximum: maximum, kind: kind)
        let encoded = try readBytes(count: count)
        guard let value = String(bytes: encoded, encoding: .utf8) else {
            throw WalletWireError.invalidUTF8(kind: kind)
        }
        return value
    }

    mutating func readOptionalBoolean(kind: String) throws -> Bool? {
        switch try readByte() {
        case 0: return false
        case 1: return true
        case 0xFF: return nil
        case let value: throw WalletWireError.invalidDiscriminator(kind: kind, value: value)
        }
    }

    mutating func readOptionalReason(maximum: Int) throws -> String? {
        let marker = try readByte()
        if marker == 0xFF { return nil }
        position -= 1
        let reason = try readString(maximum: maximum, kind: "privileged reason")
        guard !reason.isEmpty else {
            throw WalletWireError.nonRoundTrippableValue(kind: "empty privileged reason")
        }
        return reason
    }

    mutating func requireEnd() throws {
        guard isAtEnd else { throw WalletWireError.trailingBytes }
    }

    private mutating func readLittleEndian(count: Int) throws -> UInt64 {
        let encoded = try readBytes(count: count)
        var value: UInt64 = 0
        for (offset, byte) in encoded.enumerated() {
            value |= UInt64(byte) << UInt64(offset * 8)
        }
        return value
    }
}

struct WalletWireKeyParameters {
    let protocolID: WalletProtocolID
    let keyID: WalletKeyID
    let counterparty: WalletCounterparty
    let access: WalletKeyAccess
}

func walletWireMaximumText(_ limits: WalletWireLimits) -> Int {
    min(limits.maximumTextUTF8ByteCount, limits.abiLimits.maximumTextUTF8ByteCount)
}

func walletWireEncodeProtocol(
    _ protocolID: WalletProtocolID,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    try walletWireRequireText(
        protocolID.name,
        kind: "protocol name",
        maximum: walletWireMaximumText(limits)
    )
    writer.writeByte(protocolID.securityLevel.rawValue)
    try writer.writeString(protocolID.name)
}

func walletWireDecodeProtocol(
    from reader: inout WalletWireReader,
    limits: WalletWireLimits
) throws -> WalletProtocolID {
    let levelByte = try reader.readByte()
    guard let level = WalletSecurityLevel(rawValue: levelByte) else {
        throw WalletWireError.invalidDiscriminator(kind: "protocol security level", value: levelByte)
    }
    let name = try reader.readString(
        maximum: min(walletWireMaximumText(limits), WalletProtocolID.maximumNameUTF8ByteCount),
        kind: "protocol name"
    )
    do {
        let protocolID = try WalletProtocolID(securityLevel: level, name: name)
        guard protocolID.name.utf8.elementsEqual(name.utf8) else {
            throw WalletWireError.nonRoundTrippableValue(kind: "protocol name")
        }
        return protocolID
    } catch let error as WalletWireError {
        throw error
    } catch {
        throw WalletWireError.nonRoundTrippableValue(kind: "protocol identifier")
    }
}

func walletWireEncodeCounterparty(
    _ counterparty: WalletCounterparty,
    to writer: inout WalletWireWriter
) {
    switch counterparty {
    case .self: writer.writeByte(0x0B)
    case .anyone: writer.writeByte(0x0C)
    case .publicKey(let key): writer.writeBytes(key.compressedBytes)
    }
}

func walletWireDecodeCounterparty(from reader: inout WalletWireReader) throws -> WalletCounterparty {
    let discriminator = try reader.readByte()
    switch discriminator {
    case 0x0B: return .self
    case 0x0C: return .anyone
    case 0x02, 0x03:
        let encoded = [discriminator] + (try reader.readBytes(count: 32))
        do {
            let key = try PublicKey(encoded)
            guard key.compressedBytes == encoded else { throw WalletWireError.invalidPublicKey }
            return .publicKey(key)
        } catch {
            throw WalletWireError.invalidPublicKey
        }
    default:
        throw WalletWireError.invalidDiscriminator(kind: "counterparty", value: discriminator)
    }
}

func walletWireEncodeAccess(
    _ access: WalletKeyAccess,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    writer.writeOptionalBoolean(access.privileged)
    if let reason = access.privilegedReason {
        guard !reason.isEmpty else {
            throw WalletWireError.nonRoundTrippableValue(kind: "empty privileged reason")
        }
        try walletWireRequireText(
            reason,
            kind: "privileged reason",
            maximum: min(walletWireMaximumText(limits), WalletKeyAccess.maximumPrivilegedReasonUTF8ByteCount)
        )
        try writer.writeString(reason)
    } else {
        writer.writeByte(0xFF)
    }
}

func walletWireDecodeAccess(
    from reader: inout WalletWireReader,
    limits: WalletWireLimits
) throws -> WalletKeyAccess {
    let privileged = try reader.readOptionalBoolean(kind: "privileged") ?? false
    let reason = try reader.readOptionalReason(
        maximum: min(walletWireMaximumText(limits), WalletKeyAccess.maximumPrivilegedReasonUTF8ByteCount)
    )
    do {
        return try WalletKeyAccess(privileged: privileged, privilegedReason: reason)
    } catch {
        throw WalletWireError.nonRoundTrippableValue(kind: "key access")
    }
}

func walletWireEncodeKeyParameters(
    protocolID: WalletProtocolID,
    keyID: WalletKeyID,
    counterparty: WalletCounterparty,
    access: WalletKeyAccess,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    try walletWireEncodeProtocol(protocolID, to: &writer, limits: limits)
    try walletWireRequireText(
        keyID.value,
        kind: "key ID",
        maximum: min(walletWireMaximumText(limits), WalletKeyID.maximumUTF8ByteCount)
    )
    try writer.writeString(keyID.value)
    walletWireEncodeCounterparty(counterparty, to: &writer)
    try walletWireEncodeAccess(access, to: &writer, limits: limits)
}

func walletWireDecodeKeyParameters(
    from reader: inout WalletWireReader,
    limits: WalletWireLimits
) throws -> WalletWireKeyParameters {
    let protocolID = try walletWireDecodeProtocol(from: &reader, limits: limits)
    let keyText = try reader.readString(
        maximum: min(walletWireMaximumText(limits), WalletKeyID.maximumUTF8ByteCount),
        kind: "key ID"
    )
    let keyID: WalletKeyID
    do { keyID = try WalletKeyID(keyText) }
    catch { throw WalletWireError.nonRoundTrippableValue(kind: "key ID") }
    let counterparty = try walletWireDecodeCounterparty(from: &reader)
    let access = try walletWireDecodeAccess(from: &reader, limits: limits)
    return WalletWireKeyParameters(
        protocolID: protocolID,
        keyID: keyID,
        counterparty: counterparty,
        access: access
    )
}

func walletWireAccessWithSeek(_ access: WalletKeyAccess, seek: Bool) throws -> WalletKeyAccess {
    do {
        return try WalletKeyAccess(
            privileged: access.privileged,
            privilegedReason: access.privilegedReason,
            seekPermission: seek
        )
    } catch {
        throw WalletWireError.nonRoundTrippableValue(kind: "key access")
    }
}
