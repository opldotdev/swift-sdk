import BSVCore
import BSVKeys

extension Script {
    /// Creates `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
    public static func payToPublicKeyHash(
        _ publicKeyHash: Hash160,
        maximumByteCount: Int
    ) throws -> Script {
        try Script(
            bytes: [Opcode.dup.rawValue, Opcode.hash160.rawValue, 20]
                + publicKeyHash.bytes
                + [Opcode.equalVerify.rawValue, Opcode.checkSig.rawValue],
            maximumByteCount: maximumByteCount
        )
    }

    /// Creates the P2PKH locking script represented by an address.
    public static func payToPublicKeyHash(
        _ address: Address,
        maximumByteCount: Int
    ) throws -> Script {
        try payToPublicKeyHash(address.publicKeyHash, maximumByteCount: maximumByteCount)
    }

    /// Creates `<SEC1 public key> OP_CHECKSIG`.
    public static func payToPublicKey(
        _ publicKey: PublicKey,
        format: PublicKeyFormat = .compressed,
        maximumByteCount: Int
    ) throws -> Script {
        var script = try Script(bytes: [], maximumByteCount: maximumByteCount)
        try script.appendPushData(
            publicKey.serialized(as: format),
            maximumScriptByteCount: maximumByteCount
        )
        try script.append(.checkSig, maximumScriptByteCount: maximumByteCount)
        return script
    }

    /// Creates `OP_HASH160 <20-byte script hash> OP_EQUAL`.
    public static func payToScriptHash(
        _ scriptHash: Hash160,
        maximumByteCount: Int
    ) throws -> Script {
        try Script(
            bytes: [Opcode.hash160.rawValue, 20] + scriptHash.bytes + [Opcode.equal.rawValue],
            maximumByteCount: maximumByteCount
        )
    }

    /// Creates the BRC-18 form `OP_FALSE OP_RETURN <part>...`.
    public static func falseReturn(
        _ parts: [[UInt8]],
        maximumByteCount: Int,
        maximumPartByteCount: Int
    ) throws -> Script {
        guard maximumPartByteCount >= 0 else {
            throw ScriptError.invalidMaximumPushDataByteCount(maximumPartByteCount)
        }
        var script = try Script(bytes: [], maximumByteCount: maximumByteCount)
        try script.append(.zero, maximumScriptByteCount: maximumByteCount)
        try script.append(.return, maximumScriptByteCount: maximumByteCount)
        for part in parts {
            guard part.count <= maximumPartByteCount else {
                throw ScriptError.pushDataTooLarge(
                    actual: part.count,
                    maximum: maximumPartByteCount
                )
            }
            try script.appendPushData(part, maximumScriptByteCount: maximumByteCount)
        }
        return script
    }

    /// Validated SEC1 public key from an exact P2PK locking script.
    public var publicKey: PublicKey? {
        let keyBytes: [UInt8]
        switch storagePatternForPublicKey {
        case .some(let bytes): keyBytes = bytes
        case .none: return nil
        }
        return try? PublicKey(keyBytes)
    }

    public var isPayToPublicKey: Bool { publicKey != nil }

    /// Extracts BRC-18 data parts, or returns `nil` for another script form.
    public func falseReturnDataParts(
        maximumPushDataByteCount: Int
    ) throws -> [[UInt8]]? {
        let operations = try operations(maximumPushDataByteCount: maximumPushDataByteCount)
        guard operations.count >= 2,
              operations[0] == .opcode(.zero),
              operations[1] == .opcode(.return)
        else { return nil }

        var parts: [[UInt8]] = []
        parts.reserveCapacity(operations.count - 2)
        for (offset, operation) in operations.dropFirst(2).enumerated() {
            switch operation {
            case .push(_, let data):
                parts.append(data)
            case .opcode(.zero):
                parts.append([])
            case .opcode(let opcode):
                throw ScriptError.nonDataOperationInFalseReturn(index: offset, opcode)
            }
        }
        return parts
    }

    private var storagePatternForPublicKey: [UInt8]? {
        let bytes = self.bytes
        guard bytes.last == Opcode.checkSig.rawValue else { return nil }
        if bytes.count == 35, bytes[0] == 33 {
            return Array(bytes[1..<34])
        }
        if bytes.count == 67, bytes[0] == 65 {
            return Array(bytes[1..<66])
        }
        return nil
    }
}
