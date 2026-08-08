/// One byte in the Bitcoin Script instruction set.
///
/// This is a raw-value type instead of a closed enum so unknown and future
/// opcodes remain parseable and round-trip exactly.
public struct Opcode: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let zero = Self(rawValue: 0x00)
    public static let `false` = zero
    public static let pushData1 = Self(rawValue: 0x4c)
    public static let pushData2 = Self(rawValue: 0x4d)
    public static let pushData4 = Self(rawValue: 0x4e)
    public static let oneNegate = Self(rawValue: 0x4f)
    public static let reserved = Self(rawValue: 0x50)
    public static let one = Self(rawValue: 0x51)
    public static let `true` = one
    public static let two = Self(rawValue: 0x52)
    public static let three = Self(rawValue: 0x53)
    public static let four = Self(rawValue: 0x54)
    public static let five = Self(rawValue: 0x55)
    public static let six = Self(rawValue: 0x56)
    public static let seven = Self(rawValue: 0x57)
    public static let eight = Self(rawValue: 0x58)
    public static let nine = Self(rawValue: 0x59)
    public static let ten = Self(rawValue: 0x5a)
    public static let eleven = Self(rawValue: 0x5b)
    public static let twelve = Self(rawValue: 0x5c)
    public static let thirteen = Self(rawValue: 0x5d)
    public static let fourteen = Self(rawValue: 0x5e)
    public static let fifteen = Self(rawValue: 0x5f)
    public static let sixteen = Self(rawValue: 0x60)
    public static let nop = Self(rawValue: 0x61)
    public static let ver = Self(rawValue: 0x62)
    public static let `if` = Self(rawValue: 0x63)
    public static let notIf = Self(rawValue: 0x64)
    public static let verIf = Self(rawValue: 0x65)
    public static let verNotIf = Self(rawValue: 0x66)
    public static let `else` = Self(rawValue: 0x67)
    public static let endIf = Self(rawValue: 0x68)
    public static let verify = Self(rawValue: 0x69)
    public static let `return` = Self(rawValue: 0x6a)
    public static let toAltStack = Self(rawValue: 0x6b)
    public static let fromAltStack = Self(rawValue: 0x6c)
    public static let twoDrop = Self(rawValue: 0x6d)
    public static let twoDup = Self(rawValue: 0x6e)
    public static let threeDup = Self(rawValue: 0x6f)
    public static let twoOver = Self(rawValue: 0x70)
    public static let twoRot = Self(rawValue: 0x71)
    public static let twoSwap = Self(rawValue: 0x72)
    public static let ifDup = Self(rawValue: 0x73)
    public static let depth = Self(rawValue: 0x74)
    public static let drop = Self(rawValue: 0x75)
    public static let dup = Self(rawValue: 0x76)
    public static let nip = Self(rawValue: 0x77)
    public static let over = Self(rawValue: 0x78)
    public static let pick = Self(rawValue: 0x79)
    public static let roll = Self(rawValue: 0x7a)
    public static let rot = Self(rawValue: 0x7b)
    public static let swap = Self(rawValue: 0x7c)
    public static let tuck = Self(rawValue: 0x7d)
    public static let cat = Self(rawValue: 0x7e)
    public static let split = Self(rawValue: 0x7f)
    public static let num2bin = Self(rawValue: 0x80)
    public static let bin2num = Self(rawValue: 0x81)
    public static let size = Self(rawValue: 0x82)
    public static let invert = Self(rawValue: 0x83)
    public static let and = Self(rawValue: 0x84)
    public static let or = Self(rawValue: 0x85)
    public static let xor = Self(rawValue: 0x86)
    public static let equal = Self(rawValue: 0x87)
    public static let equalVerify = Self(rawValue: 0x88)
    public static let reserved1 = Self(rawValue: 0x89)
    public static let reserved2 = Self(rawValue: 0x8a)
    public static let oneAdd = Self(rawValue: 0x8b)
    public static let oneSub = Self(rawValue: 0x8c)
    public static let twoMul = Self(rawValue: 0x8d)
    public static let twoDiv = Self(rawValue: 0x8e)
    public static let negate = Self(rawValue: 0x8f)
    public static let abs = Self(rawValue: 0x90)
    public static let not = Self(rawValue: 0x91)
    public static let zeroNotEqual = Self(rawValue: 0x92)
    public static let add = Self(rawValue: 0x93)
    public static let sub = Self(rawValue: 0x94)
    public static let mul = Self(rawValue: 0x95)
    public static let div = Self(rawValue: 0x96)
    public static let mod = Self(rawValue: 0x97)
    public static let leftShift = Self(rawValue: 0x98)
    public static let rightShift = Self(rawValue: 0x99)
    public static let boolAnd = Self(rawValue: 0x9a)
    public static let boolOr = Self(rawValue: 0x9b)
    public static let numEqual = Self(rawValue: 0x9c)
    public static let numEqualVerify = Self(rawValue: 0x9d)
    public static let numNotEqual = Self(rawValue: 0x9e)
    public static let lessThan = Self(rawValue: 0x9f)
    public static let greaterThan = Self(rawValue: 0xa0)
    public static let lessThanOrEqual = Self(rawValue: 0xa1)
    public static let greaterThanOrEqual = Self(rawValue: 0xa2)
    public static let min = Self(rawValue: 0xa3)
    public static let max = Self(rawValue: 0xa4)
    public static let within = Self(rawValue: 0xa5)
    public static let ripemd160 = Self(rawValue: 0xa6)
    public static let sha1 = Self(rawValue: 0xa7)
    public static let sha256 = Self(rawValue: 0xa8)
    public static let hash160 = Self(rawValue: 0xa9)
    public static let hash256 = Self(rawValue: 0xaa)
    public static let codeSeparator = Self(rawValue: 0xab)
    public static let checkSig = Self(rawValue: 0xac)
    public static let checkSigVerify = Self(rawValue: 0xad)
    public static let checkMultiSig = Self(rawValue: 0xae)
    public static let checkMultiSigVerify = Self(rawValue: 0xaf)
    public static let nop1 = Self(rawValue: 0xb0)
    public static let checkLockTimeVerify = Self(rawValue: 0xb1)
    public static let checkSequenceVerify = Self(rawValue: 0xb2)
    public static let substring = Self(rawValue: 0xb3)
    public static let left = Self(rawValue: 0xb4)
    public static let right = Self(rawValue: 0xb5)
    public static let leftShiftNumber = Self(rawValue: 0xb6)
    public static let rightShiftNumber = Self(rawValue: 0xb7)
    public static let nop9 = Self(rawValue: 0xb8)
    public static let nop10 = Self(rawValue: 0xb9)

    /// `true` for the one-byte direct data-length opcodes 1...75.
    public var isDirectPush: Bool { (1...75).contains(rawValue) }

    /// `true` for direct pushes and OP_PUSHDATA1/2/4.
    public var isDataPush: Bool { (1...0x4e).contains(rawValue) }

    /// The direct data length, when this opcode itself contains that length.
    public var directPushByteCount: Int? {
        isDirectPush ? Int(rawValue) : nil
    }

    /// The integer represented by OP_0, OP_1NEGATE, or OP_1...OP_16.
    public var smallIntegerValue: Int? {
        return switch rawValue {
        case 0x00: 0
        case 0x4f: -1
        case 0x51...0x60: Int(rawValue - 0x50)
        default: nil
        }
    }

    /// Canonical ASM name for known opcodes, including unknown byte values.
    public var name: String {
        if isDirectPush { return "OP_DATA_\(rawValue)" }
        return switch rawValue {
        case 0x00: "OP_0"
        case 0x4c: "OP_PUSHDATA1"
        case 0x4d: "OP_PUSHDATA2"
        case 0x4e: "OP_PUSHDATA4"
        case 0x4f: "OP_1NEGATE"
        case 0x50: "OP_RESERVED"
        case 0x51...0x60: "OP_\(rawValue - 0x50)"
        case 0x61: "OP_NOP"
        case 0x62: "OP_VER"
        case 0x63: "OP_IF"
        case 0x64: "OP_NOTIF"
        case 0x65: "OP_VERIF"
        case 0x66: "OP_VERNOTIF"
        case 0x67: "OP_ELSE"
        case 0x68: "OP_ENDIF"
        case 0x69: "OP_VERIFY"
        case 0x6a: "OP_RETURN"
        case 0x6b: "OP_TOALTSTACK"
        case 0x6c: "OP_FROMALTSTACK"
        case 0x6d: "OP_2DROP"
        case 0x6e: "OP_2DUP"
        case 0x6f: "OP_3DUP"
        case 0x70: "OP_2OVER"
        case 0x71: "OP_2ROT"
        case 0x72: "OP_2SWAP"
        case 0x73: "OP_IFDUP"
        case 0x74: "OP_DEPTH"
        case 0x75: "OP_DROP"
        case 0x76: "OP_DUP"
        case 0x77: "OP_NIP"
        case 0x78: "OP_OVER"
        case 0x79: "OP_PICK"
        case 0x7a: "OP_ROLL"
        case 0x7b: "OP_ROT"
        case 0x7c: "OP_SWAP"
        case 0x7d: "OP_TUCK"
        case 0x7e: "OP_CAT"
        case 0x7f: "OP_SPLIT"
        case 0x80: "OP_NUM2BIN"
        case 0x81: "OP_BIN2NUM"
        case 0x82: "OP_SIZE"
        case 0x83: "OP_INVERT"
        case 0x84: "OP_AND"
        case 0x85: "OP_OR"
        case 0x86: "OP_XOR"
        case 0x87: "OP_EQUAL"
        case 0x88: "OP_EQUALVERIFY"
        case 0x89: "OP_RESERVED1"
        case 0x8a: "OP_RESERVED2"
        case 0x8b: "OP_1ADD"
        case 0x8c: "OP_1SUB"
        case 0x8d: "OP_2MUL"
        case 0x8e: "OP_2DIV"
        case 0x8f: "OP_NEGATE"
        case 0x90: "OP_ABS"
        case 0x91: "OP_NOT"
        case 0x92: "OP_0NOTEQUAL"
        case 0x93: "OP_ADD"
        case 0x94: "OP_SUB"
        case 0x95: "OP_MUL"
        case 0x96: "OP_DIV"
        case 0x97: "OP_MOD"
        case 0x98: "OP_LSHIFT"
        case 0x99: "OP_RSHIFT"
        case 0x9a: "OP_BOOLAND"
        case 0x9b: "OP_BOOLOR"
        case 0x9c: "OP_NUMEQUAL"
        case 0x9d: "OP_NUMEQUALVERIFY"
        case 0x9e: "OP_NUMNOTEQUAL"
        case 0x9f: "OP_LESSTHAN"
        case 0xa0: "OP_GREATERTHAN"
        case 0xa1: "OP_LESSTHANOREQUAL"
        case 0xa2: "OP_GREATERTHANOREQUAL"
        case 0xa3: "OP_MIN"
        case 0xa4: "OP_MAX"
        case 0xa5: "OP_WITHIN"
        case 0xa6: "OP_RIPEMD160"
        case 0xa7: "OP_SHA1"
        case 0xa8: "OP_SHA256"
        case 0xa9: "OP_HASH160"
        case 0xaa: "OP_HASH256"
        case 0xab: "OP_CODESEPARATOR"
        case 0xac: "OP_CHECKSIG"
        case 0xad: "OP_CHECKSIGVERIFY"
        case 0xae: "OP_CHECKMULTISIG"
        case 0xaf: "OP_CHECKMULTISIGVERIFY"
        case 0xb0: "OP_NOP1"
        case 0xb1: "OP_CHECKLOCKTIMEVERIFY"
        case 0xb2: "OP_CHECKSEQUENCEVERIFY"
        case 0xb3: "OP_SUBSTR"
        case 0xb4: "OP_LEFT"
        case 0xb5: "OP_RIGHT"
        case 0xb6: "OP_LSHIFTNUM"
        case 0xb7: "OP_RSHIFTNUM"
        case 0xb8: "OP_NOP9"
        case 0xb9: "OP_NOP10"
        default: "OP_UNKNOWN\(rawValue)"
        }
    }
}
