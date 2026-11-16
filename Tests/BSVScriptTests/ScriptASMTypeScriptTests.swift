import BSVCore
import BSVScript
import Testing

/// ASM interop with @bsv/sdk 4.1.1 `src/script/Script.ts` and `src/script/OP.ts`,
/// plus the unmerged branches `cursor/script-op-return-asm-954d` and
/// `cursor/script-fromasm-empty-09e9`.
@Suite("Script ASM interoperates with @bsv/sdk")
struct ScriptASMTypeScriptTests {
    @Test("every byte prints the first name @bsv/sdk lists and parses back")
    func opcodeTable() throws {
        var firstNames: [UInt8: String] = [:]
        for (name, byte) in typeScriptOpcodeNames {
            if firstNames[byte] == nil { firstNames[byte] = name }
            #expect(Opcode(asmName: name, dialect: .typeScript)?.rawValue == byte, "\(name)")
        }
        for raw in UInt16(0)...UInt16(0xff) {
            let opcode = Opcode(rawValue: UInt8(raw))
            guard !opcode.isDirectPush else { continue }
            #expect(opcode.typeScriptName == firstNames[opcode.rawValue], "0x\(Hex.encode([opcode.rawValue]))")
        }
        #expect(Opcode(asmName: "0", dialect: .typeScript) == .zero)
        #expect(Opcode(asmName: "-1", dialect: .typeScript) == .oneNegate)
        #expect(Opcode(asmName: "OP_DATA_20", dialect: .typeScript) == nil)
        #expect(Opcode(asmName: "dup", dialect: .typeScript) == nil)
        #expect(Opcode(asmName: "OP_UNKNOWN186", dialect: .typeScript) == nil)
    }

    @Test("every non-push byte round trips through the default dialect")
    func defaultRoundTrip() throws {
        for raw in UInt16(0)...UInt16(0xff) where !(0x01...0x4e).contains(raw) {
            let script = try Script(bytes: [UInt8(raw)], maximumByteCount: 1)
            let text = try script.asm(maximumPushDataByteCount: 0, maximumASMByteCount: 64)
            let parsed = try Script(asm: text, maximumScriptByteCount: 1, maximumASMByteCount: 64)
            #expect(parsed == script, "\(text)")
        }
    }

    @Test("Chronicle and high NOP names keep their bytes across the SDKs")
    func chronicleNames() throws {
        // tx-script review T13: BRC-106 prints 0xb6 as OP_NOP4, which @bsv/sdk
        // reads as 0xb3; @bsv/sdk prints 0xb8 as OP_NOP9, which BRC-106 reads as 0xbb.
        let bytes: [UInt8] = [0x50, 0xb3, 0xb6, 0xb8, 0xb9, 0xba, 0xf8, 0xf9, 0xfc]
        let script = try Script(bytes: bytes, maximumByteCount: 9)
        let text = try script.asm(maximumPushDataByteCount: 0, maximumASMByteCount: 256)
        #expect(text == "OP_RESERVED OP_SUBSTR OP_LSHIFTNUM OP_NOP9 OP_NOP10 OP_NOP11 OP_NOP73 OP_SMALLDATA OP_NOP77")
        #expect(try Script(asm: text, maximumScriptByteCount: 9, maximumASMByteCount: 256) == script)
        #expect(try Script(
            asm: "OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP2 OP_NOP3",
            maximumScriptByteCount: 7,
            maximumASMByteCount: 64
        ).bytes == [0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb1, 0xb2])
        #expect(try Script(
            asm: "OP_NOP9",
            dialect: .brc106,
            maximumScriptByteCount: 1,
            maximumASMByteCount: 8
        ).bytes == [0xbb])
    }

    @Test("Script.test.ts fromASM and toASM vectors")
    func scriptTestVectors() throws {
        // Script.test.ts:228 and :245
        #expect(try roundTrip("OP_0 010203 OP_0") == "OP_0 010203 OP_0")
        #expect(try roundTrip("OP_0 3 010203 OP_0") == "OP_0 03 010203 OP_0")
        #expect(try parse("OP_0 3 010203 OP_0").hex == "0001030301020300")
        // Script.test.ts:246
        #expect(try roundTrip("") == "")
        // Script.test.ts:248
        let p2pkh = "OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG"
        #expect(try parse(p2pkh).hex == "76a914f4c03610e60ad15100929cc23da2f3a799af172588ac")
        #expect(try roundTrip(p2pkh) == p2pkh)
        // Script.test.ts:264
        #expect(try roundTrip("OP_RETURN 026d02 0568656c6c6f") == "OP_RETURN 026d02 0568656c6c6f")
        // Script.test.ts:271
        #expect(throws: ScriptError.invalidASMToken(index: 2)) {
            try parse("OP_RETURN 026d02 0568656c6c6fzz")
        }
        // Script.test.ts:282, :290 and :298
        for (count, opcode) in [(220, Opcode.pushData1), (1_024, .pushData2), (1 << 17, .pushData4)] {
            let text = "OP_RETURN " + String(repeating: "00", count: count)
            let script = try parse(text)
            #expect(script.bytes[1] == opcode.rawValue)
            #expect(try format(script) == text)
        }
        // Script.test.ts:307 and :316
        for alias in ["OP_FALSE", "OP_0", "0"] {
            #expect(try roundTrip(alias) == "OP_0")
        }
        for alias in ["OP_1NEGATE", "-1"] {
            #expect(try roundTrip(alias) == "OP_1NEGATE")
        }
        #expect(try roundTrip("OP_TRUE") == "OP_1")
        // Script.test.ts:211: OP_PUSHDATA4 with a three-byte payload.
        let pushData4 = try Script(hex: "004e0300000001020300", maximumByteCount: 10)
        #expect(try format(pushData4) == "OP_0 010203 OP_0")
    }

    @Test("OP_PUSHDATA1/2/4 <length> <hex> keeps its push opcode")
    func explicitPushData() throws {
        // Script.test.ts:335
        let script = try parse("OP_PUSHDATA1 5 1010101010")
        #expect(script.hex == "4c051010101010")
        #expect(try script.isPushOnly(maximumPushDataByteCount: 5))
        #expect(try format(script) == "1010101010")
        #expect(try parse("OP_PUSHDATA2 2 abcd").hex == "4d0200abcd")
        #expect(try parse("OP_PUSHDATA4 1 a OP_1").hex == "4e010000000a51")

        #expect(throws: ScriptError.invalidASMPushDataLength(index: 1)) {
            try parse("OP_PUSHDATA1 4 1010101010")
        }
        #expect(throws: ScriptError.invalidASMPushDataLength(index: 2)) {
            try parse("OP_1 OP_PUSHDATA1 0x05 1010101010")
        }
        // The length token is the plain decimal byte count: no leading zeros.
        #expect(throws: ScriptError.invalidASMPushDataLength(index: 1)) {
            try parse("OP_PUSHDATA1 05 1010101010")
        }
        // @bsv/sdk reads a missing data token as no data (Script.ts:108).
        #expect(try parse("OP_PUSHDATA1").hex == "4c00")
        #expect(try parse("OP_PUSHDATA1 0").hex == "4c00")
        #expect(try parse("OP_1 OP_PUSHDATA2").hex == "514d0000")
        // @bsv/sdk returns 4c00 here too; Swift keeps the length-token rule.
        #expect(throws: ScriptError.invalidASMPushDataLength(index: 1)) {
            try parse("OP_PUSHDATA1 5")
        }
        // The data token skips @bsv/sdk's raw-token check, so uppercase is read.
        #expect(try parse("OP_PUSHDATA1 2 ABCD").hex == "4c02abcd")
        #expect(throws: ScriptError.pushOpcodeRequiresData(.pushData1)) {
            try Script(asm: "OP_PUSHDATA1", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 12)
        }
        #expect(throws: ScriptError.dataTooLargeForPush(actual: 256)) {
            try parse("OP_PUSHDATA1 256 " + String(repeating: "00", count: 256))
        }
        #expect(throws: ScriptError.invalidASMToken(index: 2)) {
            try parse("OP_PUSHDATA1 1 zz")
        }
    }

    @Test("odd-length hexadecimal is left-padded and compact names are data or errors")
    func oddHexAndCompactNames() throws {
        #expect(try parse("3").hex == "0103")
        #expect(try parse("abc").hex == "020abc")
        // @bsv/sdk reads `1` as the byte 0x01, not OP_1.
        #expect(try parse("1").hex == "0101")
        // ...and `add` as the bytes 0x0add.
        #expect(try parse("add").hex == "020add")
        #expect(throws: ScriptError.invalidASMToken(index: 0)) { try parse("dup") }
        // @bsv/sdk re-encodes raw data and rejects uppercase (Script.ts:116).
        #expect(throws: ScriptError.invalidASMToken(index: 1)) { try parse("OP_1 ABCD") }
        #expect(throws: ScriptError.invalidASMToken(index: 0)) { try parse("abCd") }
        #expect(try Script(asm: "ABCD", dialect: .brc106, maximumScriptByteCount: 3, maximumASMByteCount: 4).hex == "02abcd")
        #expect(throws: ScriptError.invalidASMToken(index: 0)) { try parse("OP_UNKNOWN186") }
        // BRC-106 keeps rejecting odd-length data.
        #expect(throws: ScriptError.invalidASMData(index: 0, .oddLength)) {
            try Script(asm: "abc", dialect: .brc106, maximumScriptByteCount: 2, maximumASMByteCount: 3)
        }
    }

    @Test("a top-level OP_RETURN is named and the bytes after it are read leniently")
    func opReturn() throws {
        // cursor/script-op-return-asm-954d, Script.test.ts
        let cases = [
            ("6a0568656c6c6f", "OP_RETURN 68656c6c6f"),
            ("006a0568656c6c6f", "OP_0 OP_RETURN 68656c6c6f"),
            ("6a", "OP_RETURN"),
            ("006a", "OP_0 OP_RETURN"),
        ]
        for (hex, text) in cases {
            let script = try Script(hex: hex, maximumByteCount: 16)
            #expect(try format(script) == text)
            #expect(try parse(text).hex == hex)
        }
        #expect(try parse("OP_FALSE OP_RETURN 68656c6c6f").hex == "006a0568656c6c6f")

        // A truncated push after a top-level OP_RETURN prints the bytes left.
        let truncated = try Script(hex: "6a056869", maximumByteCount: 4)
        #expect(try format(truncated) == "OP_RETURN 6869")
        let missingLength = try Script(hex: "6a4d01", maximumByteCount: 3)
        #expect(try format(missingLength) == "OP_RETURN OP_0")
        let afterEndIf = try Script(hex: "6368" + "6a0268", maximumByteCount: 5)
        #expect(try format(afterEndIf) == "OP_IF OP_ENDIF OP_RETURN 68")

        // That text is lossy: it reads back as a well-formed push of the
        // bytes that remained. `style: .canonical` is the strict check.
        #expect(try parse(format(truncated)).hex == "6a026869")
        #expect(try parse(format(missingLength)).hex == "6a00")

        // Inside a conditional, and in the other styles, malformed pushes stay errors.
        let inBranch = try Script(hex: "636a0568", maximumByteCount: 4)
        #expect(throws: ScriptError.truncatedPushData(offset: 2, expected: 5, remaining: 1)) {
            try format(inBranch)
        }
        #expect(throws: ScriptError.truncatedPushData(offset: 1, expected: 5, remaining: 2)) {
            try truncated.asm(style: .canonical, maximumPushDataByteCount: 8, maximumASMByteCount: 64)
        }
        #expect(throws: ScriptError.truncatedPushData(offset: 0, expected: 5, remaining: 2)) {
            try Script(hex: "056869", maximumByteCount: 3).asm(maximumPushDataByteCount: 8, maximumASMByteCount: 64)
        }
        #expect(throws: ScriptError.pushDataTooLarge(actual: 2, maximum: 1)) {
            try truncated.asm(maximumPushDataByteCount: 1, maximumASMByteCount: 64)
        }
    }

    @Test("where @bsv/sdk 4.1.1 toASM cannot be read back, Swift writes the unmerged fixes' text")
    func differencesFromTypeScript411() throws {
        // @bsv/sdk 4.1.1 toASM: "OP_0 0568656c6c6f" (drops OP_RETURN; reads back as 00060568656c6c6f).
        let opReturn = try Script(hex: "006a0568656c6c6f", maximumByteCount: 8)
        #expect(try format(opReturn) == "OP_0 OP_RETURN 68656c6c6f")
        // @bsv/sdk 4.1.1 toASM: "" (empty string).
        #expect(try format(Script(hex: "6a", maximumByteCount: 1)) == "OP_RETURN")
        // @bsv/sdk 4.1.1 toASM: "" (a blank token).
        #expect(try format(Script(hex: "4c00", maximumByteCount: 2)) == "OP_0")
        // @bsv/sdk 4.1.1 toASM: "OP_0 OP_IF  OP_ENDIF OP_1" (two spaces).
        #expect(try format(Script(hex: "00634c006851", maximumByteCount: 6)) == "OP_0 OP_IF OP_0 OP_ENDIF OP_1")
        // @bsv/sdk 4.1.1 fromASM(""): script 00.
        #expect(try parse("").hex == "")
    }

    @Test("empty text, blank tokens, and zero-length pushes")
    func emptyForms() throws {
        // cursor/script-fromasm-empty-09e9, Script.test.ts
        #expect(try parse("").bytes.isEmpty)
        for text in ["OP_DUP  OP_HASH160", " OP_1", "OP_1 ", " ", "OP_1   OP_2", "OP_PUSHDATA1  01", "OP_PUSHDATA1 1 "] {
            #expect(throws: ScriptError.self, "\(text)") { try parse(text) }
        }
        #expect(try format(Script(hex: "4c00", maximumByteCount: 2)) == "OP_0")
        let insideBranch = try Script(hex: "00634c006851", maximumByteCount: 6)
        #expect(try format(insideBranch) == "OP_0 OP_IF OP_0 OP_ENDIF OP_1")
        #expect(try roundTrip("OP_0 OP_IF OP_0 OP_ENDIF OP_1") == "OP_0 OP_IF OP_0 OP_ENDIF OP_1")
    }
}

private func parse(_ text: String) throws -> Script {
    try Script(asm: text, maximumScriptByteCount: 1 << 20, maximumASMByteCount: 1 << 20)
}

private func format(_ script: Script) throws -> String {
    try script.asm(maximumPushDataByteCount: 1 << 20, maximumASMByteCount: 1 << 20)
}

private func roundTrip(_ text: String) throws -> String {
    try format(parse(text))
}
