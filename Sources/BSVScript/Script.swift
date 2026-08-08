import BSVCore

/// One structurally decoded Bitcoin Script operation.
public enum ScriptOperation: Hashable, Sendable {
    case opcode(Opcode)
    case push(opcode: Opcode, data: [UInt8])

    public var opcode: Opcode {
        switch self {
        case .opcode(let opcode), .push(let opcode, _): opcode
        }
    }

    public var pushedData: [UInt8]? {
        guard case .push(_, let data) = self else { return nil }
        return data
    }
}

/// Value-semantic Bitcoin Script bytes with bounded parsing and construction.
public struct Script: Hashable, Sendable {
    private var storage: [UInt8]

    public init(bytes: [UInt8], maximumByteCount: Int) throws {
        guard maximumByteCount >= 0 else {
            throw ScriptError.invalidMaximumScriptByteCount(maximumByteCount)
        }
        guard bytes.count <= maximumByteCount else {
            throw ScriptError.scriptTooLarge(actual: bytes.count, maximum: maximumByteCount)
        }
        storage = bytes
    }

    public init(hex: String, maximumByteCount: Int) throws {
        guard maximumByteCount >= 0 else {
            throw ScriptError.invalidMaximumScriptByteCount(maximumByteCount)
        }
        do {
            try self.init(
                bytes: Hex.decode(hex, maximumDecodedByteCount: maximumByteCount),
                maximumByteCount: maximumByteCount
            )
        } catch let error as TextEncodingError {
            throw ScriptError.invalidHex(error)
        }
    }

    public var bytes: [UInt8] { storage }
    public var hex: String { Hex.encode(storage) }
    public var isEmpty: Bool { storage.isEmpty }
    public var byteCount: Int { storage.count }

    /// Parses every operation and enforces a separate ceiling for each pushed value.
    public func operations(maximumPushDataByteCount: Int) throws -> [ScriptOperation] {
        guard maximumPushDataByteCount >= 0 else {
            throw ScriptError.invalidMaximumPushDataByteCount(maximumPushDataByteCount)
        }

        var result: [ScriptOperation] = []
        result.reserveCapacity(storage.count)
        var offset = 0
        while offset < storage.count {
            let opcodeOffset = offset
            let opcode = Opcode(rawValue: storage[offset])
            offset += 1

            let length: Int
            switch opcode.rawValue {
            case 0x01...0x4b:
                length = Int(opcode.rawValue)
            case 0x4c:
                guard storage.count - offset >= 1 else {
                    throw ScriptError.truncatedPushDataLength(
                        offset: opcodeOffset,
                        expected: 1,
                        remaining: storage.count - offset
                    )
                }
                length = Int(storage[offset])
                offset += 1
            case 0x4d:
                guard storage.count - offset >= 2 else {
                    throw ScriptError.truncatedPushDataLength(
                        offset: opcodeOffset,
                        expected: 2,
                        remaining: storage.count - offset
                    )
                }
                length = Int(storage[offset]) | (Int(storage[offset + 1]) << 8)
                offset += 2
            case 0x4e:
                guard storage.count - offset >= 4 else {
                    throw ScriptError.truncatedPushDataLength(
                        offset: opcodeOffset,
                        expected: 4,
                        remaining: storage.count - offset
                    )
                }
                let declared = UInt32(storage[offset])
                    | (UInt32(storage[offset + 1]) << 8)
                    | (UInt32(storage[offset + 2]) << 16)
                    | (UInt32(storage[offset + 3]) << 24)
                guard UInt64(declared) <= UInt64(Int.max) else {
                    throw ScriptError.pushDataLengthNotRepresentable(declared)
                }
                length = Int(declared)
                offset += 4
            default:
                result.append(.opcode(opcode))
                continue
            }

            guard length <= maximumPushDataByteCount else {
                throw ScriptError.pushDataTooLarge(
                    actual: length,
                    maximum: maximumPushDataByteCount
                )
            }
            let remaining = storage.count - offset
            guard length <= remaining else {
                throw ScriptError.truncatedPushData(
                    offset: opcodeOffset,
                    expected: length,
                    remaining: remaining
                )
            }
            result.append(.push(
                opcode: opcode,
                data: Array(storage[offset..<(offset + length)])
            ))
            offset += length
        }
        return result
    }

    /// Appends a non-push opcode while preserving the script size ceiling.
    public mutating func append(
        _ opcode: Opcode,
        maximumScriptByteCount: Int
    ) throws {
        guard !opcode.isDataPush else {
            throw ScriptError.pushOpcodeRequiresData(opcode)
        }
        try requireAppendCapacity(1, maximum: maximumScriptByteCount)
        storage.append(opcode.rawValue)
    }

    /// Appends data using the shortest length-prefix form used by the Go SDK.
    ///
    /// Empty data uses OP_0. One-byte integers are encoded as a one-byte data
    /// push; use `appendMinimalPush` when Script minimal-push policy is required.
    public mutating func appendPushData(
        _ data: [UInt8],
        maximumScriptByteCount: Int
    ) throws {
        let prefix = try Self.pushDataPrefix(forByteCount: data.count)
        let (additional, overflow) = prefix.count.addingReportingOverflow(data.count)
        guard !overflow else {
            throw ScriptError.scriptTooLarge(
                actual: Int.max,
                maximum: maximumScriptByteCount
            )
        }
        try requireAppendCapacity(additional, maximum: maximumScriptByteCount)
        storage.append(contentsOf: prefix)
        storage.append(contentsOf: data)
    }

    /// Appends the policy-minimal representation, using OP_1...OP_16 and
    /// OP_1NEGATE for their single-byte Script-number encodings.
    public mutating func appendMinimalPush(
        _ data: [UInt8],
        maximumScriptByteCount: Int
    ) throws {
        if data.isEmpty {
            try requireAppendCapacity(1, maximum: maximumScriptByteCount)
            storage.append(Opcode.zero.rawValue)
            return
        }
        if data.count == 1, (1...16).contains(data[0]) {
            try requireAppendCapacity(1, maximum: maximumScriptByteCount)
            storage.append(Opcode.one.rawValue + data[0] - 1)
            return
        }
        if data == [0x81] {
            try requireAppendCapacity(1, maximum: maximumScriptByteCount)
            storage.append(Opcode.oneNegate.rawValue)
            return
        }
        try appendPushData(data, maximumScriptByteCount: maximumScriptByteCount)
    }

    public static func pushDataPrefix(forByteCount byteCount: Int) throws -> [UInt8] {
        guard byteCount >= 0 else {
            throw ScriptError.dataTooLargeForPush(actual: byteCount)
        }
        switch byteCount {
        case 0...75:
            return [UInt8(byteCount)]
        case 76...Int(UInt8.max):
            return [Opcode.pushData1.rawValue, UInt8(byteCount)]
        case 256...Int(UInt16.max):
            return [
                Opcode.pushData2.rawValue,
                UInt8(truncatingIfNeeded: byteCount),
                UInt8(truncatingIfNeeded: byteCount >> 8),
            ]
        default:
            guard UInt64(byteCount) <= UInt64(UInt32.max) else {
                throw ScriptError.dataTooLargeForPush(actual: byteCount)
            }
            return [
                Opcode.pushData4.rawValue,
                UInt8(truncatingIfNeeded: byteCount),
                UInt8(truncatingIfNeeded: byteCount >> 8),
                UInt8(truncatingIfNeeded: byteCount >> 16),
                UInt8(truncatingIfNeeded: byteCount >> 24),
            ]
        }
    }

    public var isPayToPublicKeyHash: Bool {
        storage.count == 25
            && storage[0] == Opcode.dup.rawValue
            && storage[1] == Opcode.hash160.rawValue
            && storage[2] == 20
            && storage[23] == Opcode.equalVerify.rawValue
            && storage[24] == Opcode.checkSig.rawValue
    }

    public var isPayToScriptHash: Bool {
        storage.count == 23
            && storage[0] == Opcode.hash160.rawValue
            && storage[1] == 20
            && storage[22] == Opcode.equal.rawValue
    }

    public var isData: Bool {
        storage.first == Opcode.return.rawValue
            || (storage.count > 1
                && storage[0] == Opcode.zero.rawValue
                && storage[1] == Opcode.return.rawValue)
    }

    public var publicKeyHash: [UInt8]? {
        guard isPayToPublicKeyHash else { return nil }
        return Array(storage[3..<23])
    }

    public func isPushOnly(maximumPushDataByteCount: Int) throws -> Bool {
        try operations(maximumPushDataByteCount: maximumPushDataByteCount).allSatisfy {
            $0.opcode.rawValue <= Opcode.sixteen.rawValue
        }
    }

    private func requireAppendCapacity(_ additional: Int, maximum: Int) throws {
        guard maximum >= 0 else {
            throw ScriptError.invalidMaximumScriptByteCount(maximum)
        }
        let (total, overflow) = storage.count.addingReportingOverflow(additional)
        guard !overflow, total <= maximum else {
            throw ScriptError.scriptTooLarge(actual: overflow ? Int.max : total, maximum: maximum)
        }
    }
}
