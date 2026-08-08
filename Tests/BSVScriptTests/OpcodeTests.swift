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
        #expect(Opcode.zero.name == "OP_0")
        #expect(Opcode(rawValue: 20).name == "OP_DATA_20")
        #expect(Opcode.dup.name == "OP_DUP")
        #expect(Opcode.hash160.name == "OP_HASH160")
        #expect(Opcode.checkSig.name == "OP_CHECKSIG")
        #expect(Opcode.substring.name == "OP_SUBSTR")
        #expect(Opcode(rawValue: 0xff).name == "OP_UNKNOWN255")
    }
}
