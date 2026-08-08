import BSVScript
import Testing

@Suite("Script ASM conformance", .serialized)
struct ScriptASMConformanceTests {
    @Test("pinned Go SDK agrees on canonical ASM and bytes")
    func goOracleDifferentials() throws {
        let cases = [
            "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG",
            "OP_0 OP_1 OP_NOP4 OP_INVALIDOPCODE",
            "OP_FALSE OP_RETURN 68656c6c6f 00ff",
            "OP_DUP aa OP_EQUALVERIFY OP_CHECKSIG",
            "10",
            "OP_NOP4",
            "OP_NOP5",
            "OP_NOP6",
            "OP_NOP7",
            "OP_NOP8",
        ]
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script ASM Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }

            let names = try client.request(
                id: "script-asm-all-names",
                operation: "script.asm.names",
                arguments: [:]
            )
            #expect(names.ok)
            #expect(names.result == .object([
                "names": .array((0...255).map {
                    .string(Opcode(rawValue: UInt8($0)).goSDKName)
                }),
            ]))

            for (index, text) in cases.enumerated() {
                let swiftScript = try Script(
                    asm: text,
                    dialect: .goSDK,
                    maximumScriptByteCount: 128,
                    maximumASMByteCount: 256
                )
                let swiftASM = try swiftScript.asm(
                    style: .goSDK,
                    maximumPushDataByteCount: 128,
                    maximumASMByteCount: 256
                )

                let decoded = try client.request(
                    id: "script-asm-decode-\(index)",
                    operation: "script.asm.decode",
                    arguments: ["text": .string(text)]
                )
                #expect(decoded.ok)
                #expect(decoded.result == .object(["bytes": .string(swiftScript.hex)]))

                let encoded = try client.request(
                    id: "script-asm-encode-\(index)",
                    operation: "script.asm.encode",
                    arguments: ["bytes": .string(swiftScript.hex)]
                )
                #expect(encoded.ok)
                #expect(encoded.result == .object(["text": .string(swiftASM)]))
            }

            let goArtifacts: [(String, String)] = [
                ("4c", ""),
                ("4c00", ""),
                ("4c01aa", "aa"),
            ]
            for (index, artifact) in goArtifacts.enumerated() {
                let response = try client.request(
                    id: "script-asm-artifact-\(index)",
                    operation: "script.asm.encode",
                    arguments: ["bytes": .string(artifact.0)]
                )
                #expect(response.ok)
                #expect(response.result == .object(["text": .string(artifact.1)]))
            }

            let ignoredPushOpcode = try client.request(
                id: "script-asm-ignored-push-opcode",
                operation: "script.asm.decode",
                arguments: ["text": .string("OP_PUSHDATA1")]
            )
            #expect(ignoredPushOpcode.ok)
            #expect(ignoredPushOpcode.result == .object(["bytes": .string("")]))

            let nonMinimal = try Script(bytes: [0x4c, 0x01, 0xaa], maximumByteCount: 3)
            #expect(try nonMinimal.asm(
                style: .goSDK,
                maximumPushDataByteCount: 1,
                maximumASMByteCount: 2
            ) == "aa")
            let emptyNonMinimal = try Script(bytes: [0x4c, 0x00], maximumByteCount: 2)
            #expect(try emptyNonMinimal.asm(
                style: .goSDK,
                maximumPushDataByteCount: 0,
                maximumASMByteCount: 8
            ) == "OP_FALSE")

            let malformed = try Script(bytes: [0x4c], maximumByteCount: 1)
            #expect(throws: ScriptError.truncatedPushDataLength(
                offset: 0,
                expected: 1,
                remaining: 0
            )) {
                try malformed.asm(
                    style: .goSDK,
                    maximumPushDataByteCount: 0,
                    maximumASMByteCount: 8
                )
            }
            #expect(throws: ScriptError.pushOpcodeRequiresData(.pushData1)) {
                try Script(
                    asm: "OP_PUSHDATA1",
                    dialect: .goSDK,
                    maximumScriptByteCount: 1,
                    maximumASMByteCount: 12
                )
            }
        }
    }
}
