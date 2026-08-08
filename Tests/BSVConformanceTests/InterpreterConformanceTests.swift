import BSVCore
import BSVInterpreter
import BSVScript
import BSVTransaction
import Testing

@Suite("Bitcoin Script interpreter differential conformance", .serialized)
struct InterpreterConformanceTests {
    private struct Case {
        let name: String
        let unlocking: String
        let locking: String
        let era: ScriptExecutionEra
        let flags: ScriptVerificationFlags
        let goFlags: [String]
    }

    @Test("foundation opcodes match pinned Go SDK stacks")
    func foundationDifferentials() throws {
        let cases = [
            Case(
                name: "equality",
                unlocking: "012a",
                locking: "7687",
                era: .legacy,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "conditional",
                unlocking: "",
                locking: "006300675168",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "stack duplication",
                unlocking: "",
                locking: "51526e51",
                era: .legacy,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "alternative stack",
                unlocking: "",
                locking: "516b6c",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "minimal conditional",
                unlocking: "",
                locking: "51635168",
                era: .genesis,
                flags: [.minimalIf],
                goFlags: ["minimalIf"]
            ),
            Case(
                name: "post genesis return tail",
                unlocking: "516a4c",
                locking: "51",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "post genesis return preserves alternative stack",
                unlocking: "516b6a",
                locking: "6c",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "hidden genesis version conditional",
                unlocking: "",
                locking: "0063656851",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "returned genesis version conditional",
                unlocking: "51",
                locking: "51636a6568",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "split cat",
                unlocking: "",
                locking: "0461626364527f7e046162636487",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "num2bin",
                unlocking: "",
                locking: "017f5280027f0087",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "bin2num",
                unlocking: "",
                locking: "020100815187",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "bitwise and",
                unlocking: "",
                locking: "020ff00233cc840203c087",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "hash family",
                unlocking: "",
                locking: "00a600a700a800a900aa51",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "arithmetic family",
                unlocking: "",
                locking: "528b539c5253944f9c5354955c9c575296539c51",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "wide arithmetic",
                unlocking: "",
                locking: "090000000000000000010900000000000000000193090000000000000000029c",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "byte shifts",
                unlocking: "",
                locking: "02123454980223408702123454990201238751",
                era: .genesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "chronicle arithmetic right shift",
                unlocking: "",
                locking: "538f51b701829c",
                era: .chronicle,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "legacy p2sh redeem",
                unlocking: "0151",
                locking: "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87",
                era: .legacy,
                flags: [.payToScriptHash],
                goFlags: ["p2sh"]
            ),
            Case(
                name: "legacy reenabled multiply",
                unlocking: "",
                locking: "525395569c",
                era: .legacy,
                flags: [],
                goFlags: []
            ),
        ]

        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, testCase) in cases.enumerated() {
                let local = try execute(testCase)
                let response = try client.request(
                    id: "script-foundation-\(index)-\(testCase.name)",
                    operation: "script.execute",
                    arguments: [
                        "unlockingScript": .string(testCase.unlocking),
                        "lockingScript": .string(testCase.locking),
                        "era": .string(testCase.era.rawValue),
                        "flags": .array(testCase.goFlags.map(GoOracleJSON.string)),
                    ]
                )
                #expect(response.ok)
                #expect(response.result == .object([
                    "stack": .array(local.stack.map { .string(Hex.encode($0)) }),
                    "valid": .bool(true),
                ]))
            }
        }
    }

    @Test("foundation failures use equivalent pinned Go categories")
    func failureDifferentials() throws {
        let cases: [(String, String, String, ScriptExecutionEra, ScriptExecutionError, String)] = [
            (
                "false",
                "",
                "00",
                .legacy,
                .consensus(.evaluatedFalse),
                "evaluatedFalse"
            ),
            (
                "empty",
                "",
                "",
                .legacy,
                .consensus(.emptyFinalStack),
                "evaluatedFalse"
            ),
            (
                "verify",
                "",
                "0069",
                .legacy,
                .consensus(.verifyFailed),
                "verifyFailed"
            ),
            (
                "unbalanced",
                "",
                "516351",
                .genesis,
                .consensus(.unbalancedConditional),
                "unbalancedConditional"
            ),
            (
                "legacy return",
                "",
                "6a",
                .legacy,
                .consensus(.earlyReturn),
                "earlyReturn"
            ),
            (
                "unknown 186",
                "",
                "ba",
                .chronicle,
                .consensus(.reservedOpcode(Opcode(rawValue: 0xba))),
                "reservedOpcode"
            ),
            (
                "unknown 189",
                "",
                "bd",
                .chronicle,
                .consensus(.reservedOpcode(Opcode(rawValue: 0xbd))),
                "reservedOpcode"
            ),
            (
                "unknown 254",
                "",
                "fe",
                .chronicle,
                .consensus(.reservedOpcode(Opcode(rawValue: 0xfe))),
                "reservedOpcode"
            ),
            (
                "chronicle version conditional empty stack",
                "",
                "65",
                .chronicle,
                .consensus(.unbalancedConditional),
                "unbalancedConditional"
            ),
        ]

        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, testCase) in cases.enumerated() {
                #expect(throws: testCase.4) {
                    try execute(Case(
                        name: testCase.0,
                        unlocking: testCase.1,
                        locking: testCase.2,
                        era: testCase.3,
                        flags: [],
                        goFlags: []
                    ))
                }
                let response = try client.request(
                    id: "script-failure-\(index)",
                    operation: "script.execute",
                    arguments: [
                        "unlockingScript": .string(testCase.1),
                        "lockingScript": .string(testCase.2),
                        "era": .string(testCase.3.rawValue),
                    ]
                )
                #expect(!response.ok)
                #expect(response.error?.category == testCase.5)
            }
        }
    }

    @Test("Chronicle version opcodes match the pinned Go SDK")
    func chronicleVersionDifferential() throws {
        let unlocking = try Script(hex: "", maximumByteCount: 1_000)
        let lockingHex = "6204020000008804020000006551675068"
        let locking = try Script(hex: lockingHex, maximumByteCount: 1_000)
        let transaction = Transaction(
            version: 2,
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(
                        wireBytes: Array(repeating: 0, count: 32)
                    ),
                    outputIndex: 0
                ),
                unlockingScript: unlocking
            )]
        )
        let local = try ScriptInterpreter.execute(
            unlockingScript: unlocking,
            lockingScript: locking,
            configuration: ScriptExecutionConfiguration(
                era: .chronicle,
                resourceLimits: .standard
            ),
            context: ScriptExecutionContext(
                transaction: transaction,
                inputIndex: 0,
                spentOutput: TransactionOutput(satoshis: 0, lockingScript: locking),
                transactionLimits: try TransactionLimits(
                    maximumTransactionByteCount: 1_000,
                    maximumInputCount: 1,
                    maximumOutputCount: 1,
                    maximumScriptByteCount: 1_000
                )
            )
        )

        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let response = try client.request(
                id: "script-chronicle-version",
                operation: "script.execute",
                arguments: [
                    "unlockingScript": .string(""),
                    "lockingScript": .string(lockingHex),
                    "era": .string("chronicle"),
                    "transactionVersion": .string("2"),
                ]
            )
            #expect(response.ok)
            #expect(response.result == .object([
                "stack": .array(local.stack.map { .string(Hex.encode($0)) }),
                "valid": .bool(true),
            ]))
        }
    }

    private func execute(_ testCase: Case) throws -> ScriptExecutionResult {
        let maximum = 32 * 1_024 * 1_024
        return try ScriptInterpreter.execute(
            unlockingScript: Script(
                hex: testCase.unlocking,
                maximumByteCount: maximum
            ),
            lockingScript: Script(
                hex: testCase.locking,
                maximumByteCount: maximum
            ),
            configuration: ScriptExecutionConfiguration(
                era: testCase.era,
                flags: testCase.flags,
                resourceLimits: .standard
            )
        )
    }
}
