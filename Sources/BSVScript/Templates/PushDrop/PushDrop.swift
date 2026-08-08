import BSVKeys

/// The position of the public-key lock in a BRC-48 PushDrop script.
public enum PushDropLockPosition: String, Hashable, Sendable {
    /// The BRC-48 layout: fields, drops, compressed public key, `OP_CHECKSIG`.
    case after

    /// The pinned Go SDK compatibility layout: public-key lock, fields, drops.
    case beforeCompatibility
}

/// Caller-selected construction and decoding limits for PushDrop scripts.
public struct PushDropLimits: Hashable, Sendable {
    public static let standard = PushDropLimits(
        validatedMaximumFieldCount: 1_000_000,
        maximumFieldByteCount: 32 * 1_024 * 1_024,
        maximumScriptByteCount: 32 * 1_024 * 1_024
    )

    public let maximumFieldCount: Int
    public let maximumFieldByteCount: Int
    public let maximumScriptByteCount: Int

    public init(
        maximumFieldCount: Int,
        maximumFieldByteCount: Int,
        maximumScriptByteCount: Int
    ) throws {
        guard maximumFieldCount >= 0 else {
            throw PushDropError.invalidMaximumFieldCount(maximumFieldCount)
        }
        guard maximumFieldByteCount >= 0 else {
            throw PushDropError.invalidMaximumFieldByteCount(maximumFieldByteCount)
        }
        guard maximumScriptByteCount >= 0 else {
            throw PushDropError.invalidMaximumScriptByteCount(maximumScriptByteCount)
        }
        self.init(
            validatedMaximumFieldCount: maximumFieldCount,
            maximumFieldByteCount: maximumFieldByteCount,
            maximumScriptByteCount: maximumScriptByteCount
        )
    }

    private init(
        validatedMaximumFieldCount: Int,
        maximumFieldByteCount: Int,
        maximumScriptByteCount: Int
    ) {
        maximumFieldCount = validatedMaximumFieldCount
        self.maximumFieldByteCount = maximumFieldByteCount
        self.maximumScriptByteCount = maximumScriptByteCount
    }
}

/// A strictly decoded PushDrop locking script.
public struct PushDropDecoded: Hashable, Sendable {
    public let publicKey: PublicKey

    /// Decoded fields.
    ///
    /// `OP_0` decodes as `[0]` for Go SDK parity. Consequently, Script cannot
    /// distinguish an original empty field from `[0]` after minimal encoding.
    public let fields: [[UInt8]]
    public let lockPosition: PushDropLockPosition

    public init(
        publicKey: PublicKey,
        fields: [[UInt8]],
        lockPosition: PushDropLockPosition
    ) {
        self.publicKey = publicKey
        self.fields = fields
        self.lockPosition = lockPosition
    }
}

/// Typed structural, canonicality, resource, and signing failures for PushDrop.
public enum PushDropError: Error, Equatable, Sendable {
    case invalidMaximumFieldCount(Int)
    case invalidMaximumFieldByteCount(Int)
    case invalidMaximumScriptByteCount(Int)
    case fieldCountExceedsLimit(actual: Int, maximum: Int)
    case fieldByteCountExceedsLimit(index: Int, actual: Int, maximum: Int)
    case scriptByteCountExceedsLimit(actual: Int, maximum: Int)
    case scriptSizeOverflow
    case malformedPush(offset: Int)
    case nonMinimalFieldPush(index: Int)
    case unexpectedFieldOperation(index: Int, opcode: Opcode)
    case invalidDropSequence(fieldCount: Int)
    case invalidLockingScriptLayout(PushDropLockPosition)
    case invalidCompressedPublicKey
    case privateKeyDoesNotMatchPublicKey(inputIndex: Int)
}

/// Wallet-independent BRC-48 PushDrop locking-script construction and decoding.
public enum PushDrop {
    public static func lockingScript(
        fields: [[UInt8]],
        publicKey: PublicKey,
        lockPosition: PushDropLockPosition = .after,
        limits: PushDropLimits = .standard
    ) throws -> Script {
        try preflight(fields: fields, limits: limits)

        var script = try Script(bytes: [], maximumByteCount: limits.maximumScriptByteCount)
        switch lockPosition {
        case .after:
            try appendFieldsAndDrops(fields, to: &script, limits: limits)
            try appendPublicKeyLock(publicKey, to: &script, limits: limits)
        case .beforeCompatibility:
            try appendPublicKeyLock(publicKey, to: &script, limits: limits)
            try appendFieldsAndDrops(fields, to: &script, limits: limits)
        }
        return script
    }

    public static func decode(
        _ script: Script,
        lockPosition: PushDropLockPosition = .after,
        limits: PushDropLimits = .standard
    ) throws -> PushDropDecoded {
        let bytes = script.bytes
        guard bytes.count <= limits.maximumScriptByteCount else {
            throw PushDropError.scriptByteCountExceedsLimit(
                actual: bytes.count,
                maximum: limits.maximumScriptByteCount
            )
        }

        let fieldRange: Range<Int>
        let keyOffset: Int
        switch lockPosition {
        case .after:
            guard bytes.count >= publicKeyLockByteCount else {
                throw PushDropError.invalidLockingScriptLayout(lockPosition)
            }
            keyOffset = bytes.count - publicKeyLockByteCount
            fieldRange = 0..<keyOffset
        case .beforeCompatibility:
            guard bytes.count >= publicKeyLockByteCount else {
                throw PushDropError.invalidLockingScriptLayout(lockPosition)
            }
            keyOffset = 0
            fieldRange = publicKeyLockByteCount..<bytes.count
        }

        let publicKey = try decodePublicKeyLock(bytes, at: keyOffset, mode: lockPosition)
        let fields = try decodeFieldsAndDrops(bytes, range: fieldRange, limits: limits)
        return PushDropDecoded(
            publicKey: publicKey,
            fields: fields,
            lockPosition: lockPosition
        )
    }

    private static let publicKeyLockByteCount = 35

    package static func preflight(fields: [[UInt8]], limits: PushDropLimits) throws {
        guard fields.count <= limits.maximumFieldCount else {
            throw PushDropError.fieldCountExceedsLimit(
                actual: fields.count,
                maximum: limits.maximumFieldCount
            )
        }

        var byteCount = publicKeyLockByteCount
        for (index, field) in fields.enumerated() {
            guard field.count <= limits.maximumFieldByteCount else {
                throw PushDropError.fieldByteCountExceedsLimit(
                    index: index,
                    actual: field.count,
                    maximum: limits.maximumFieldByteCount
                )
            }
            let encodedCount: Int
            if field.isEmpty || field == [0] || field == [0x81]
                || (field.count == 1 && (1...16).contains(field[0])) {
                encodedCount = 1
            } else {
                guard UInt64(field.count) <= UInt64(UInt32.max) else {
                    throw PushDropError.scriptSizeOverflow
                }
                let prefixCount = try Script.pushDataPrefix(forByteCount: field.count).count
                let (total, overflow) = prefixCount.addingReportingOverflow(field.count)
                guard !overflow else { throw PushDropError.scriptSizeOverflow }
                encodedCount = total
            }
            let (next, overflow) = byteCount.addingReportingOverflow(encodedCount)
            guard !overflow else { throw PushDropError.scriptSizeOverflow }
            byteCount = next
        }
        let dropCount = fields.count / 2 + fields.count % 2
        let (total, overflow) = byteCount.addingReportingOverflow(dropCount)
        guard !overflow else { throw PushDropError.scriptSizeOverflow }
        guard total <= limits.maximumScriptByteCount else {
            throw PushDropError.scriptByteCountExceedsLimit(
                actual: total,
                maximum: limits.maximumScriptByteCount
            )
        }
    }

    private static func appendFieldsAndDrops(
        _ fields: [[UInt8]],
        to script: inout Script,
        limits: PushDropLimits
    ) throws {
        for field in fields {
            // Bitcoin minimal-data encoding represents both empty and numeric
            // zero with OP_0. Decode deliberately returns the Go-compatible [0].
            let canonicalField = field == [0] ? [] : field
            try script.appendMinimalPush(
                canonicalField,
                maximumScriptByteCount: limits.maximumScriptByteCount
            )
        }
        for _ in 0..<(fields.count / 2) {
            try script.append(.twoDrop, maximumScriptByteCount: limits.maximumScriptByteCount)
        }
        if fields.count % 2 == 1 {
            try script.append(.drop, maximumScriptByteCount: limits.maximumScriptByteCount)
        }
    }

    private static func appendPublicKeyLock(
        _ publicKey: PublicKey,
        to script: inout Script,
        limits: PushDropLimits
    ) throws {
        try script.appendMinimalPush(
            publicKey.compressedBytes,
            maximumScriptByteCount: limits.maximumScriptByteCount
        )
        try script.append(.checkSig, maximumScriptByteCount: limits.maximumScriptByteCount)
    }

    private static func decodePublicKeyLock(
        _ bytes: [UInt8],
        at offset: Int,
        mode: PushDropLockPosition
    ) throws -> PublicKey {
        guard offset >= 0,
              bytes.count - offset >= publicKeyLockByteCount,
              bytes[offset] == 33,
              bytes[offset + 34] == Opcode.checkSig.rawValue else {
            throw PushDropError.invalidLockingScriptLayout(mode)
        }
        let keyBytes = Array(bytes[(offset + 1)..<(offset + 34)])
        guard keyBytes[0] == 0x02 || keyBytes[0] == 0x03,
              let publicKey = try? PublicKey(keyBytes),
              publicKey.compressedBytes == keyBytes else {
            throw PushDropError.invalidCompressedPublicKey
        }
        return publicKey
    }

    private static func decodeFieldsAndDrops(
        _ bytes: [UInt8],
        range: Range<Int>,
        limits: PushDropLimits
    ) throws -> [[UInt8]] {
        var fields: [[UInt8]] = []
        var offset = range.lowerBound

        while offset < range.upperBound {
            let opcode = Opcode(rawValue: bytes[offset])
            if opcode == .drop || opcode == .twoDrop { break }
            guard fields.count < limits.maximumFieldCount else {
                throw PushDropError.fieldCountExceedsLimit(
                    actual: fields.count + 1,
                    maximum: limits.maximumFieldCount
                )
            }
            let field = try decodeCanonicalField(
                bytes,
                offset: &offset,
                end: range.upperBound,
                index: fields.count,
                maximumByteCount: limits.maximumFieldByteCount
            )
            fields.append(field)
        }

        let expectedTwoDrops = fields.count / 2
        for _ in 0..<expectedTwoDrops {
            guard offset < range.upperBound, bytes[offset] == Opcode.twoDrop.rawValue else {
                throw PushDropError.invalidDropSequence(fieldCount: fields.count)
            }
            offset += 1
        }
        if fields.count % 2 == 1 {
            guard offset < range.upperBound, bytes[offset] == Opcode.drop.rawValue else {
                throw PushDropError.invalidDropSequence(fieldCount: fields.count)
            }
            offset += 1
        }
        guard offset == range.upperBound else {
            throw PushDropError.invalidDropSequence(fieldCount: fields.count)
        }
        return fields
    }

    private static func decodeCanonicalField(
        _ bytes: [UInt8],
        offset: inout Int,
        end: Int,
        index: Int,
        maximumByteCount: Int
    ) throws -> [UInt8] {
        let opcodeOffset = offset
        let opcode = Opcode(rawValue: bytes[offset])
        offset += 1

        switch opcode.rawValue {
        case Opcode.zero.rawValue:
            return [0]
        case Opcode.oneNegate.rawValue:
            return [0x81]
        case Opcode.one.rawValue...Opcode.sixteen.rawValue:
            return [opcode.rawValue - Opcode.one.rawValue + 1]
        default:
            break
        }

        let length: Int
        switch opcode.rawValue {
        case 1...75:
            length = Int(opcode.rawValue)
        case Opcode.pushData1.rawValue:
            guard end - offset >= 1 else {
                throw PushDropError.malformedPush(offset: opcodeOffset)
            }
            length = Int(bytes[offset])
            offset += 1
            guard length >= 76 else {
                throw PushDropError.nonMinimalFieldPush(index: index)
            }
        case Opcode.pushData2.rawValue:
            guard end - offset >= 2 else {
                throw PushDropError.malformedPush(offset: opcodeOffset)
            }
            length = Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
            offset += 2
            guard length >= 256 else {
                throw PushDropError.nonMinimalFieldPush(index: index)
            }
        case Opcode.pushData4.rawValue:
            guard end - offset >= 4 else {
                throw PushDropError.malformedPush(offset: opcodeOffset)
            }
            let declared = UInt32(bytes[offset])
                | (UInt32(bytes[offset + 1]) << 8)
                | (UInt32(bytes[offset + 2]) << 16)
                | (UInt32(bytes[offset + 3]) << 24)
            offset += 4
            guard UInt64(declared) <= UInt64(Int.max) else {
                throw PushDropError.malformedPush(offset: opcodeOffset)
            }
            length = Int(declared)
            guard length >= 65_536 else {
                throw PushDropError.nonMinimalFieldPush(index: index)
            }
        default:
            throw PushDropError.unexpectedFieldOperation(index: index, opcode: opcode)
        }

        guard length <= maximumByteCount else {
            throw PushDropError.fieldByteCountExceedsLimit(
                index: index,
                actual: length,
                maximum: maximumByteCount
            )
        }
        guard length <= end - offset else {
            throw PushDropError.malformedPush(offset: opcodeOffset)
        }
        if length == 1 {
            let byte = bytes[offset]
            if byte == 0 || byte == 0x81 || (1...16).contains(byte) {
                throw PushDropError.nonMinimalFieldPush(index: index)
            }
        }
        let field = Array(bytes[offset..<(offset + length)])
        offset += length
        return field
    }
}
