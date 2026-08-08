import BSVCore
import BSVKeys
import BSVScript
import Testing

@Suite("Standard locking scripts")
struct StandardScriptsTests {
    private let generatorCompressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    @Test("P2PKH and P2SH constructors are exact")
    func hashTemplates() throws {
        let hash = try Hash160(Array(0..<UInt8(20)))
        let p2pkh = try Script.payToPublicKeyHash(hash, maximumByteCount: 25)
        #expect(p2pkh.hex == "76a914000102030405060708090a0b0c0d0e0f1011121388ac")
        #expect(p2pkh.isPayToPublicKeyHash)
        #expect(p2pkh.publicKeyHash == hash.bytes)

        let address = Address(publicKeyHash: hash, network: .mainnet)
        #expect(try Script.payToPublicKeyHash(address, maximumByteCount: 25) == p2pkh)

        let p2sh = try Script.payToScriptHash(hash, maximumByteCount: 23)
        #expect(p2sh.hex == "a914000102030405060708090a0b0c0d0e0f1011121387")
        #expect(p2sh.isPayToScriptHash)
        #expect(throws: ScriptError.scriptTooLarge(actual: 25, maximum: 24)) {
            try Script.payToPublicKeyHash(hash, maximumByteCount: 24)
        }
    }

    @Test("P2PK validates its SEC1 key")
    func publicKeyTemplate() throws {
        let publicKey = try PublicKey(
            Hex.decode(generatorCompressed, maximumDecodedByteCount: 33)
        )
        let compressed = try Script.payToPublicKey(
            publicKey,
            maximumByteCount: 35
        )
        #expect(compressed.hex == "21\(generatorCompressed)ac")
        #expect(compressed.isPayToPublicKey)
        #expect(compressed.publicKey == publicKey)

        let uncompressed = try Script.payToPublicKey(
            publicKey,
            format: .uncompressed,
            maximumByteCount: 67
        )
        #expect(uncompressed.byteCount == 67)
        #expect(uncompressed.isPayToPublicKey)

        var invalid = compressed.bytes
        invalid[1] = 0x05
        let invalidScript = try Script(bytes: invalid, maximumByteCount: 35)
        #expect(!invalidScript.isPayToPublicKey)
        #expect(invalidScript.publicKey == nil)
    }

    @Test("BRC-18 false-return preserves every data part")
    func falseReturn() throws {
        let parts: [[UInt8]] = [[], Array("hello".utf8), [0x01], Array(repeating: 0xaa, count: 76)]
        let script = try Script.falseReturn(
            parts,
            maximumByteCount: 89,
            maximumPartByteCount: 76
        )
        #expect(script.bytes.prefix(2) == [Opcode.zero.rawValue, Opcode.return.rawValue])
        #expect(script.isData)
        #expect(try script.falseReturnDataParts(maximumPushDataByteCount: 76) == parts)
        #expect(try Script(bytes: [Opcode.return.rawValue], maximumByteCount: 1)
            .falseReturnDataParts(maximumPushDataByteCount: 0) == nil)

        #expect(throws: ScriptError.pushDataTooLarge(actual: 76, maximum: 75)) {
            try Script.falseReturn(parts, maximumByteCount: 89, maximumPartByteCount: 75)
        }

        let opcodeAfterHeader = try Script(
            bytes: [Opcode.zero.rawValue, Opcode.return.rawValue, Opcode.dup.rawValue],
            maximumByteCount: 3
        )
        #expect(throws: ScriptError.nonDataOperationInFalseReturn(index: 0, .dup)) {
            try opcodeAfterHeader.falseReturnDataParts(maximumPushDataByteCount: 0)
        }
    }
}
