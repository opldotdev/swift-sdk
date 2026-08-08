import BSVCore
import BSVCrypto
import BSVInterpreter
import BSVKeys
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
                era: .beforeGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "conditional",
                unlocking: "",
                locking: "006300675168",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "stack duplication",
                unlocking: "",
                locking: "51526e51",
                era: .beforeGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "alternative stack",
                unlocking: "",
                locking: "516b6c",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "minimal conditional",
                unlocking: "",
                locking: "51635168",
                era: .afterGenesis,
                flags: [.minimalIf],
                goFlags: ["minimalIf"]
            ),
            Case(
                name: "after-genesis return tail",
                unlocking: "516a4c",
                locking: "51",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "after-genesis return preserves alternative stack",
                unlocking: "516b6a",
                locking: "6c",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "hidden after-genesis version conditional",
                unlocking: "",
                locking: "0063656851",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "returned after-genesis version conditional",
                unlocking: "51",
                locking: "51636a6568",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "split cat",
                unlocking: "",
                locking: "0461626364527f7e046162636487",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "num2bin",
                unlocking: "",
                locking: "017f5280027f0087",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "bin2num",
                unlocking: "",
                locking: "020100815187",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "bitwise and",
                unlocking: "",
                locking: "020ff00233cc840203c087",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "hash family",
                unlocking: "",
                locking: "00a600a700a800a900aa51",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "arithmetic family",
                unlocking: "",
                locking: "528b539c5253944f9c5354955c9c575296539c51",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "wide arithmetic",
                unlocking: "",
                locking: "090000000000000000010900000000000000000193090000000000000000029c",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "byte shifts",
                unlocking: "",
                locking: "02123454980223408702123454990201238751",
                era: .afterGenesis,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "after-chronicle arithmetic right shift",
                unlocking: "",
                locking: "538f51b701829c",
                era: .afterChronicle,
                flags: [],
                goFlags: []
            ),
            Case(
                name: "before-genesis p2sh redeem",
                unlocking: "0151",
                locking: "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87",
                era: .beforeGenesis,
                flags: [.payToScriptHash],
                goFlags: ["p2sh"]
            ),
            Case(
                name: "before-genesis reenabled multiply",
                unlocking: "",
                locking: "525395569c",
                era: .beforeGenesis,
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
                        "era": .string(goOracleEraValue(for: testCase.era)),
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
                .beforeGenesis,
                .consensus(.evaluatedFalse),
                "evaluatedFalse"
            ),
            (
                "empty",
                "",
                "",
                .beforeGenesis,
                .consensus(.emptyFinalStack),
                "evaluatedFalse"
            ),
            (
                "verify",
                "",
                "0069",
                .beforeGenesis,
                .consensus(.verifyFailed),
                "verifyFailed"
            ),
            (
                "unbalanced",
                "",
                "516351",
                .afterGenesis,
                .consensus(.unbalancedConditional),
                "unbalancedConditional"
            ),
            (
                "before-genesis return",
                "",
                "6a",
                .beforeGenesis,
                .consensus(.earlyReturn),
                "earlyReturn"
            ),
            (
                "unknown 186",
                "",
                "ba",
                .afterChronicle,
                .consensus(.reservedOpcode(Opcode(rawValue: 0xba))),
                "reservedOpcode"
            ),
            (
                "unknown 189",
                "",
                "bd",
                .afterChronicle,
                .consensus(.reservedOpcode(Opcode(rawValue: 0xbd))),
                "reservedOpcode"
            ),
            (
                "unknown 254",
                "",
                "fe",
                .afterChronicle,
                .consensus(.reservedOpcode(Opcode(rawValue: 0xfe))),
                "reservedOpcode"
            ),
            (
                "after-chronicle version conditional empty stack",
                "",
                "65",
                .afterChronicle,
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
                        "era": .string(goOracleEraValue(for: testCase.3)),
                    ]
                )
                #expect(!response.ok)
                #expect(response.error?.category == testCase.5)
            }
        }
    }

    @Test("after-Chronicle version opcodes match the pinned Go SDK")
    func afterChronicleVersionDifferential() throws {
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
                era: .afterChronicle,
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
                id: "script-after-chronicle-version",
                operation: "script.execute",
                arguments: [
                    "unlockingScript": .string(""),
                    "lockingScript": .string(lockingHex),
                    "era": .string(goOracleEraValue(for: .afterChronicle)),
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

    @Test("legacy CHECKSIG and CHECKMULTISIG match complete pinned Go transaction execution")
    func legacySignatureDifferentials() throws {
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 10_000
        )
        let keys = try (1...3).map {
            try PrivateKey(Array(repeating: 0, count: 31) + [UInt8($0)])
        }

        let checkSignature = try Script.payToPublicKey(
            keys[0].publicKey,
            maximumByteCount: 10_000
        )
        var checkSignatureTransaction = try signatureTransaction(
            locking: checkSignature
        )
        let signatureDigest = try checkSignatureTransaction.legacySignatureHash(
            inputIndex: 0,
            scriptCode: checkSignature,
            limits: limits
        )
        checkSignatureTransaction.inputs[0].unlockingScript = try pushOnlyScript([
            try keys[0].sign(digest: signatureDigest).derBytes + [0x01],
        ])

        var checkMultiSignature = try Script(bytes: [], maximumByteCount: 10_000)
        try checkMultiSignature.append(.two, maximumScriptByteCount: 10_000)
        for key in keys {
            try checkMultiSignature.appendPushData(
                key.publicKey.compressedBytes,
                maximumScriptByteCount: 10_000
            )
        }
        try checkMultiSignature.append(.three, maximumScriptByteCount: 10_000)
        try checkMultiSignature.append(.checkMultiSig, maximumScriptByteCount: 10_000)
        var checkMultiSignatureTransaction = try signatureTransaction(
            locking: checkMultiSignature
        )
        let multiDigest = try checkMultiSignatureTransaction.legacySignatureHash(
            inputIndex: 0,
            scriptCode: checkMultiSignature,
            limits: limits
        )
        checkMultiSignatureTransaction.inputs[0].unlockingScript = try pushOnlyScript([
            [],
            try keys[0].sign(digest: multiDigest).derBytes + [0x01],
            try keys[2].sign(digest: multiDigest).derBytes + [0x01],
        ])

        var cleanedScriptCode = try Script(
            bytes: [Opcode.drop.rawValue],
            maximumByteCount: 10_000
        )
        try cleanedScriptCode.appendPushData(
            keys[1].publicKey.compressedBytes,
            maximumScriptByteCount: 10_000
        )
        try cleanedScriptCode.append(.checkSig, maximumScriptByteCount: 10_000)
        var cleanupTransaction = try signatureTransaction(locking: cleanedScriptCode)
        let cleanupDigest = try cleanupTransaction.legacySignatureHash(
            inputIndex: 0,
            scriptCode: cleanedScriptCode,
            limits: limits
        )
        let cleanupSignature = try keys[1].sign(digest: cleanupDigest).derBytes + [0x01]
        var cleanupLocking = try Script(
            bytes: [Opcode.codeSeparator.rawValue],
            maximumByteCount: 10_000
        )
        try cleanupLocking.appendPushData(
            cleanupSignature,
            maximumScriptByteCount: 10_000
        )
        try cleanupLocking.append(.drop, maximumScriptByteCount: 10_000)
        try cleanupLocking.appendPushData(
            keys[1].publicKey.compressedBytes,
            maximumScriptByteCount: 10_000
        )
        try cleanupLocking.append(.checkSig, maximumScriptByteCount: 10_000)
        cleanupTransaction.inputs[0].sourceOutput = TransactionOutput(
            satoshis: 20_000,
            lockingScript: cleanupLocking
        )
        cleanupTransaction.inputs[0].unlockingScript = try pushOnlyScript([
            cleanupSignature,
        ])

        let cases: [(String, Transaction, Script, [String], ScriptVerificationFlags)] = [
            (
                "checksig",
                checkSignatureTransaction,
                checkSignature,
                ["strictEncoding", "derSignatures", "lowS", "nullFail"],
                [.strictEncoding, .derSignatures, .lowS, .nullFail]
            ),
            (
                "checkmultisig",
                checkMultiSignatureTransaction,
                checkMultiSignature,
                [
                    "strictEncoding", "strictMultiSignatureDummy",
                    "derSignatures", "lowS", "nullFail",
                ],
                [
                    .strictEncoding, .strictMultiSignatureDummy,
                    .derSignatures, .lowS, .nullFail,
                ]
            ),
            (
                "signature-cleanup",
                cleanupTransaction,
                cleanupLocking,
                ["strictEncoding", "derSignatures", "lowS"],
                [.strictEncoding, .derSignatures, .lowS]
            ),
        ]

        let oracleConfiguration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: oracleConfiguration) {
        case .unavailable(let reason):
            #expect(!oracleConfiguration.required)
            print("Script signature Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for testCase in cases {
                let spentOutput = TransactionOutput(
                    satoshis: 20_000,
                    lockingScript: testCase.2
                )
                let local = try ScriptInterpreter.execute(
                    unlockingScript: testCase.1.inputs[0].unlockingScript,
                    lockingScript: testCase.2,
                    configuration: ScriptExecutionConfiguration(
                        era: .beforeGenesis,
                        flags: testCase.4,
                        resourceLimits: .standard
                    ),
                    context: ScriptExecutionContext(
                        transaction: testCase.1,
                        inputIndex: 0,
                        spentOutput: spentOutput,
                        transactionLimits: limits
                    )
                )
                let response = try client.request(
                    id: "script-signature-\(testCase.0)",
                    operation: "script.execute",
                    arguments: [
                        "unlockingScript": .string(testCase.1.inputs[0].unlockingScript.hex),
                        "lockingScript": .string(testCase.2.hex),
                        "era": .string(goOracleEraValue(for: .beforeGenesis)),
                        "flags": .array(testCase.3.map(GoOracleJSON.string)),
                        "transaction": .string(Hex.encode(try testCase.1.serialized(limits: limits))),
                        "inputIndex": .string("0"),
                        "sourceSatoshis": .string("20000"),
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

    private func signatureTransaction(locking: Script) throws -> Transaction {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        return Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(
                        wireBytes: Array(repeating: 0x55, count: 32)
                    ),
                    outputIndex: 1
                ),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: 20_000, lockingScript: locking)
            )],
            outputs: [TransactionOutput(
                satoshis: 19_000,
                lockingScript: try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
            )]
        )
    }

    private func pushOnlyScript(_ values: [[UInt8]]) throws -> Script {
        var script = try Script(bytes: [], maximumByteCount: 10_000)
        for value in values {
            try script.appendPushData(value, maximumScriptByteCount: 10_000)
        }
        return script
    }
}

/// The existing Go-oracle JSON protocol predates the Swift public API naming.
private func goOracleEraValue(for era: ScriptExecutionEra) -> String {
    switch era {
    case .beforeGenesis: "legacy"
    case .afterGenesis: "genesis"
    case .afterChronicle: "chronicle"
    }
}
