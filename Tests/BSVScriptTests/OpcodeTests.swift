import BSVScript
import Testing

@Suite("Bitcoin Script opcodes")
struct OpcodeTests {
    @Test("Every byte value round trips")
    func rawValues() {
        for raw in UInt8.min...UInt8.max {
            #expect(Opcode(rawValue: raw).rawValue == raw)
        }
    }

    @Test("Push and small-integer classification is exact")
    func classification() {
        #expect(!Opcode.zero.isDataPush)
        #expect(Opcode(rawValue: 1).isDirectPush)
        #expect(Opcode(rawValue: 75).isDirectPush)
        #expect(!Opcode.pushData1.isDirectPush)
        #expect(Opcode.pushData1.isDataPush)
        #expect(Opcode.pushData2.isDataPush)
        #expect(Opcode.pushData4.isDataPush)
        #expect(!Opcode.oneNegate.isDataPush)

        #expect(Opcode.zero.smallIntegerValue == 0)
        #expect(Opcode.oneNegate.smallIntegerValue == -1)
        for integer in 1...16 {
            #expect(Opcode(rawValue: UInt8(0x50 + integer)).smallIntegerValue == integer)
        }
        #expect(Opcode.nop.smallIntegerValue == nil)
    }

    @Test("Canonical names cover active and unknown opcodes")
    func names() {
        #expect(Opcode.zero.name == "OP_FALSE")
        #expect(Opcode.one.name == "OP_TRUE")
        #expect(Opcode(rawValue: 20).name == "OP_DATA_20")
        #expect(Opcode.dup.name == "OP_DUP")
        #expect(Opcode.hash160.name == "OP_HASH160")
        #expect(Opcode.checkSig.name == "OP_CHECKSIG")
        #expect(Opcode.substring.name == "OP_SUBSTR")
        #expect(Opcode(rawValue: 0xff).name == "OP_INVALIDOPCODE")
    }

    @Test("Canonical, compact, and compatibility names parse")
    func parsingNames() {
        #expect(Opcode(asmName: "OP_FALSE", dialect: .brc106) == .zero)
        #expect(Opcode(asmName: "OP_0", dialect: .brc106) == .zero)
        #expect(Opcode(asmName: "false", dialect: .brc106) == .zero)
        #expect(Opcode(asmName: "OP_TRUE", dialect: .brc106) == .one)
        #expect(Opcode(asmName: "OP_1", dialect: .brc106) == .one)
        #expect(Opcode(asmName: "dup", dialect: .brc106) == .dup)
        #expect(Opcode(asmName: "OP_NOP4", dialect: .brc106) == .leftShiftNumber)
        #expect(Opcode(asmName: "OP_NOP4", dialect: .goSDK) == .substring)
        #expect(Opcode(asmName: "OP_INVALIDOPCODE", dialect: .brc106) == Opcode(rawValue: 0xff))
        #expect(Opcode(rawValue: 0xb6).goSDKName == "OP_LSHIFTNUM")
        #expect(Opcode.ten.compactName == "OP_10")
        #expect(Opcode.sixteen.compactName == "OP_16")
        #expect(Opcode(asmName: "not-an-opcode", dialect: .brc106) == nil)
        #expect(Opcode(asmName: "FALSE", dialect: .brc106) == nil)
        #expect(Opcode(asmName: "op_false", dialect: .brc106) == nil)
    }
}
