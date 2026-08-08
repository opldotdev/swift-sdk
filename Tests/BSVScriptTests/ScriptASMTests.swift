import BSVCore
import BSVScript
import Testing

@Suite("Bitcoin Script ASM")
struct ScriptASMTests {
    private let p2pkhASM = "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG"

    @Test("BRC-106 ASM and compact SASM round trip")
    func canonicalAndCompact() throws {
        let script = try Script(
            asm: p2pkhASM,
            dialect: .brc106,
            maximumScriptByteCount: 25,
            maximumASMByteCount: 128
        )
        #expect(script.hex == "76a914000000000000000000000000000000000000000088ac")
        #expect(try script.asm(
            maximumPushDataByteCount: 20,
            maximumASMByteCount: 128
        ) == p2pkhASM)
        #expect(try script.asm(
            style: .compact,
            maximumPushDataByteCount: 20,
            maximumASMByteCount: 128
        ) == "dup hash160 0000000000000000000000000000000000000000 equalverify checksig")

        let compact = try Script(
            asm: "dup hash160 0000000000000000000000000000000000000000 equalverify checksig",
            dialect: .brc106,
            maximumScriptByteCount: 25,
            maximumASMByteCount: 128
        )
        #expect(compact == script)
    }

    @Test("Aliases and unknown opcodes use canonical output")
    func aliases() throws {
        let script = try Script(
            asm: "OP_0 OP_1 OP_NOP4 OP_INVALIDOPCODE",
            dialect: .brc106,
            maximumScriptByteCount: 4,
            maximumASMByteCount: 64
        )
        #expect(script.bytes == [0x00, 0x51, 0xb6, 0xff])
        #expect(try script.asm(
            maximumPushDataByteCount: 0,
            maximumASMByteCount: 64
        ) == "OP_FALSE OP_TRUE OP_NOP4 OP_INVALIDOPCODE")

        let goScript = try Script(
            asm: "OP_0 OP_1 OP_NOP4 OP_INVALIDOPCODE",
            dialect: .goSDK,
            maximumScriptByteCount: 4,
            maximumASMByteCount: 64
        )
        #expect(goScript.bytes == [0x00, 0x51, 0xb3, 0xff])
        #expect(try goScript.asm(
            style: .goSDK,
            maximumPushDataByteCount: 0,
            maximumASMByteCount: 64
        ) == "OP_FALSE OP_TRUE OP_SUBSTR OP_INVALIDOPCODE")
    }

    @Test("ASM normalizes non-minimal push forms")
    func pushNormalization() throws {
        let nonMinimal = try Script(bytes: [0x4c, 0x01, 0xaa], maximumByteCount: 3)
        let text = try nonMinimal.asm(
            maximumPushDataByteCount: 1,
            maximumASMByteCount: 2
        )
        #expect(text == "aa")
        let normalized = try Script(
            asm: text,
            dialect: .brc106,
            maximumScriptByteCount: 2,
            maximumASMByteCount: 2
        )
        #expect(normalized.bytes == [0x01, 0xaa])

        let emptyNonMinimal = try Script(bytes: [0x4c, 0x00], maximumByteCount: 2)
        #expect(try emptyNonMinimal.asm(
            maximumPushDataByteCount: 0,
            maximumASMByteCount: 8
        ) == "OP_FALSE")
    }

    @Test("bare 10 through 16 are data, never compact opcode names")
    func numericTokenCollision() throws {
        for byte in UInt8(0x10)...UInt8(0x16) {
            let token = Hex.encode([byte])
            for dialect in [ScriptASMDialect.brc106, .goSDK] {
                let script = try Script(
                    asm: token,
                    dialect: dialect,
                    maximumScriptByteCount: 2,
                    maximumASMByteCount: 2
                )
                #expect(script.bytes == [0x01, byte])
                let compact = try script.asm(
                    style: .compact,
                    maximumPushDataByteCount: 1,
                    maximumASMByteCount: 2
                )
                #expect(compact == token)
            }
        }

        let opTen = try Script(bytes: [Opcode.ten.rawValue], maximumByteCount: 1)
        #expect(try opTen.asm(
            style: .compact,
            maximumPushDataByteCount: 0,
            maximumASMByteCount: 5
        ) == "OP_10")
    }

    @Test("Malformed or oversized ASM fails with typed errors")
    func malformedAndBounded() throws {
        #expect(throws: ScriptError.invalidMaximumASMByteCount(-1)) {
            try Script(asm: "", dialect: .brc106, maximumScriptByteCount: 0, maximumASMByteCount: -1)
        }
        #expect(throws: ScriptError.asmTooLarge(observedAtLeast: 4, maximum: 3)) {
            try Script(asm: "OP_DUP", dialect: .brc106, maximumScriptByteCount: 1, maximumASMByteCount: 3)
        }
        #expect(throws: ScriptError.invalidASMSpacing(byteOffset: 0)) {
            try Script(asm: " OP_DUP", dialect: .brc106, maximumScriptByteCount: 1, maximumASMByteCount: 8)
        }
        #expect(throws: ScriptError.invalidASMSpacing(byteOffset: 7)) {
            try Script(asm: "OP_DUP  OP_HASH160", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 32)
        }
        #expect(throws: ScriptError.invalidASMSpacing(byteOffset: 6)) {
            try Script(asm: "OP_DUP\nOP_HASH160", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 32)
        }
        #expect(throws: ScriptError.invalidASMData(index: 0, .oddLength)) {
            try Script(asm: "abc", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 3)
        }
        #expect(throws: ScriptError.invalidASMToken(index: 0)) {
            try Script(asm: "wat", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 3)
        }
        #expect(throws: ScriptError.pushOpcodeRequiresData(.pushData1)) {
            try Script(asm: "OP_PUSHDATA1", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 12)
        }

        let malformed = try Script(bytes: [0x02, 0xaa], maximumByteCount: 2)
        #expect(throws: ScriptError.truncatedPushData(
            offset: 0,
            expected: 2,
            remaining: 1
        )) {
            try malformed.asm(maximumPushDataByteCount: 2, maximumASMByteCount: 8)
        }
        let dup = try Script(bytes: [Opcode.dup.rawValue], maximumByteCount: 1)
        #expect(throws: ScriptError.asmOutputTooLarge(actual: 6, maximum: 5)) {
            try dup.asm(maximumPushDataByteCount: 0, maximumASMByteCount: 5)
        }
    }
}
