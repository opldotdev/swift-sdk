import BSVCore
import BSVCrypto
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import Foundation
import Testing

@Suite("InterpreterReference adversarial corpus", .serialized)
struct InterpreterReferenceCorpusTests {
    private static let fixturePath =
        "Permissive/BitcoinCore/InterpreterReference/script-tests-legacy-subset.json"

    @Test("Bitcoin Core source, license, selection, and local hashes are pinned")
    func manifestProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(manifest.groups.first {
            $0.id == "interpreter-reference-bitcoin-core-v0.15.0.1"
        })
        #expect(group.source.url == "https://github.com/bitcoin/bitcoin")
        #expect(group.source.revision == "fb7b5293844ea6adc5dcf5ad0a0c5890b4495939")
        #expect(group.license.identifier == "MIT")
        #expect(
            group.license.sha256
                == "93d633183b4715ff1d799dc26b30a6edae096a13fb35b062d0d69463f453644e"
        )
        let file = try #require(group.files.first)
        #expect(file.originalPath == "src/test/data/script_tests.json")
        #expect(file.localPath == Self.fixturePath)
        #expect(
            file.sha256
                == "6b95d199a560cabc64133024a6f6737e9dd5baf6c4e72d2ad8feeebde4591ab0"
        )

        let fixture = try loadFixture()
        #expect(
            fixture.sourceSHA256
                == "5e5b1d8f6e758929bbdf5fe7f4906523cae13de939ece1fcf681824ccfa2b4aa"
        )
        #expect(fixture.cases.count == 200)
        #expect(fixture.cases.filter { $0.expected == "OK" }.count == 140)
        #expect(fixture.cases.filter { $0.expected != "OK" }.count == 60)
        #expect(fixture.cases.map(\.sourceIndex) == fixture.cases.map(\.sourceIndex).sorted())
    }

    @Test("200 applicable Bitcoin Core before-Genesis cases conform")
    func bitcoinCoreBeforeGenesisCorpus() throws {
        let fixture = try loadFixture()
        for testCase in fixture.cases {
            let unlocking = try compileBitcoinCoreASM(testCase.unlocking)
            let locking = try compileBitcoinCoreASM(testCase.locking)
            do {
                _ = try execute(
                    unlocking: unlocking,
                    locking: locking,
                    era: .beforeGenesis,
                    flags: try verificationFlags(testCase.flags)
                )
                #expect(
                    testCase.expected == "OK",
                    "Bitcoin Core source row \(testCase.sourceIndex) unexpectedly succeeded"
                )
            } catch {
                let actual = referenceCategory(error)
                #expect(
                    actual == testCase.expected,
                    "Bitcoin Core source row \(testCase.sourceIndex): \(error)"
                )
            }
        }
    }

    @Test("all proper PUSHDATA1, PUSHDATA2, and PUSHDATA4 truncations are typed")
    func pushDataTruncationMatrix() throws {
        let encodings: [(Opcode, [UInt8])] = [
            (.pushData1, [5]),
            (.pushData2, [5, 0]),
            (.pushData4, [5, 0, 0, 0]),
        ]
        for (opcode, lengthBytes) in encodings {
            let header = [opcode.rawValue] + lengthBytes
            for prefixCount in 1..<header.count {
                let prefix = Array(header.prefix(prefixCount))
                #expect(throws: ScriptExecutionError.malformedScript(
                    phase: .locking,
                    offset: 0,
                    cause: .truncatedPushLength(
                        expected: lengthBytes.count,
                        remaining: prefixCount - 1
                    )
                )) {
                    try execute(unlocking: [], locking: prefix, era: .beforeGenesis)
                }
            }
            for presentDataCount in 0..<5 {
                let prefix = header + Array(repeating: 0x42, count: presentDataCount)
                #expect(throws: ScriptExecutionError.malformedScript(
                    phase: .locking,
                    offset: 0,
                    cause: .truncatedPushData(expected: 5, remaining: presentDataCount)
                )) {
                    try execute(unlocking: [], locking: prefix, era: .beforeGenesis)
                }
            }
        }
    }

    @Test("before-Genesis consensus limits accept exact boundaries and reject plus one")
    func beforeGenesisConsensusBoundaries() throws {
        let exactScript = repeatedPushScript(byteCount: 10_000)
        #expect(try execute(unlocking: [], locking: exactScript, era: .beforeGenesis).stack.last == [1])
        #expect(throws: ScriptExecutionError.consensus(
            .scriptTooLarge(actual: 10_001, maximum: 10_000)
        )) {
            try execute(unlocking: [], locking: exactScript + [Opcode.nop.rawValue], era: .beforeGenesis)
        }

        let exactPush = encodedPush(Array(repeating: 0x01, count: 520))
            + [Opcode.drop.rawValue, Opcode.one.rawValue]
        #expect(try execute(unlocking: [], locking: exactPush, era: .beforeGenesis).stack == [[1]])
        let oversizedPush = encodedPush(Array(repeating: 0x01, count: 521))
            + [Opcode.drop.rawValue, Opcode.one.rawValue]
        #expect(throws: ScriptExecutionError.consensus(
            .pushDataTooLarge(actual: 521, maximum: 520)
        )) {
            try execute(unlocking: [], locking: oversizedPush, era: .beforeGenesis)
        }

        let exactStack = Array(repeating: Opcode.one.rawValue, count: 1_000)
        #expect(try execute(unlocking: [], locking: exactStack, era: .beforeGenesis).stack.count == 1_000)
        #expect(throws: ScriptExecutionError.consensus(
            .tooManyStackItems(actual: 1_001, maximum: 1_000)
        )) {
            try execute(
                unlocking: [],
                locking: exactStack + [Opcode.one.rawValue],
                era: .beforeGenesis
            )
        }

        let exactOperations = Array(repeating: Opcode.nop.rawValue, count: 500)
            + [Opcode.one.rawValue]
        #expect(try execute(
            unlocking: [],
            locking: exactOperations,
            era: .beforeGenesis
        ).operationCount == 500)
        #expect(throws: ScriptExecutionError.consensus(
            .tooManyOperations(actual: 501, maximum: 500)
        )) {
            try execute(
                unlocking: [],
                locking: exactOperations + [Opcode.nop.rawValue],
                era: .beforeGenesis
            )
        }

        let exactNumber = encodedPush([0xff, 0xff, 0xff, 0x7f])
            + [Opcode.oneAdd.rawValue, Opcode.drop.rawValue, Opcode.one.rawValue]
        #expect(try execute(unlocking: [], locking: exactNumber, era: .beforeGenesis).stack == [[1]])
        let oversizedNumber = encodedPush([0xff, 0xff, 0xff, 0xff, 0x7f])
            + [Opcode.oneAdd.rawValue]
        #expect(throws: ScriptExecutionError.consensus(
            .numberTooLarge(actual: 5, maximum: 4)
        )) {
            try execute(unlocking: [], locking: oversizedNumber, era: .beforeGenesis)
        }
    }

    @Test("operational budgets stay distinct and consensus takes precedence when both fail")
    func resourceBudgetPrecedence() throws {
        let tight = ScriptResourceLimits(
            maximumScriptByteCount: 100,
            maximumPushDataByteCount: 4,
            maximumStackItemCount: 10,
            maximumStackMemoryByteCount: 100,
            maximumOperationCountPerScript: 10,
            maximumConditionalDepth: 10,
            maximumScriptNumberByteCount: 4
        )
        #expect(throws: ScriptExecutionError.resourceBudgetExceeded(
            .scriptByteCount(actual: 101, maximum: 100)
        )) {
            try execute(
                unlocking: [],
                locking: Array(repeating: Opcode.one.rawValue, count: 101),
                era: .beforeGenesis,
                limits: tight
            )
        }
        #expect(throws: ScriptExecutionError.consensus(
            .scriptTooLarge(actual: 10_001, maximum: 10_000)
        )) {
            try execute(
                unlocking: [],
                locking: Array(repeating: Opcode.one.rawValue, count: 10_001),
                era: .beforeGenesis,
                limits: tight
            )
        }
        #expect(throws: ScriptExecutionError.resourceBudgetExceeded(
            .pushDataByteCount(actual: 5, maximum: 4)
        )) {
            try execute(
                unlocking: [],
                locking: [Opcode.pushData1.rawValue, 5, 1],
                era: .beforeGenesis,
                limits: tight
            )
        }
        #expect(throws: ScriptExecutionError.consensus(
            .pushDataTooLarge(actual: 521, maximum: 520)
        )) {
            try execute(
                unlocking: [],
                locking: [Opcode.pushData2.rawValue, 9, 2],
                era: .beforeGenesis,
                limits: tight
            )
        }
    }

    @Test("policy flag edges and deterministic transaction contexts are enforced")
    func policyAndTransactionBoundaries() throws {
        #expect(throws: ScriptExecutionError.consensus(.nonMinimalPush)) {
            try execute(
                unlocking: [],
                locking: [Opcode.pushData1.rawValue, 1, 1],
                era: .beforeGenesis,
                flags: [.minimalData]
            )
        }
        #expect(throws: ScriptExecutionError.consensus(.minimalIf)) {
            try execute(
                unlocking: [],
                locking: [1, 2, Opcode.if.rawValue, Opcode.one.rawValue, Opcode.endIf.rawValue],
                era: .afterGenesis,
                flags: [.minimalIf]
            )
        }
        #expect(throws: ScriptExecutionError.consensus(
            .cleanStackViolation(actualItemCount: 2)
        )) {
            try execute(
                unlocking: [],
                locking: [Opcode.one.rawValue, Opcode.one.rawValue],
                era: .beforeGenesis,
                flags: [.payToScriptHash, .cleanStack]
            )
        }
        #expect(try execute(
            unlocking: [1, Opcode.one.rawValue],
            locking: try hexBytes("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"),
            era: .beforeGenesis,
            flags: [.payToScriptHash]
        ).stack == [[1]])

        let empty = try script([])
        let contextLimits = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 2,
            maximumOutputCount: 2,
            maximumScriptByteCount: 10_000
        )
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        let checkSignature = try Script.payToPublicKey(key.publicKey, maximumByteCount: 10_000)
        let spentOutput = TransactionOutput(satoshis: 20_000, lockingScript: checkSignature)
        let unsigned = Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(wireBytes: Array(repeating: 0x22, count: 32)),
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sequence: 10,
                sourceOutput: spentOutput
            )],
            outputs: [TransactionOutput(satoshis: 19_000, lockingScript: checkSignature)],
            lockTime: 100
        )
        let digest = try unsigned.legacySignatureHash(
            inputIndex: 0,
            scriptCode: checkSignature,
            limits: contextLimits
        )
        let lowSignature = try key.sign(digest: digest)

        var invalidDER = unsigned
        invalidDER.inputs[0].unlockingScript = try pushOnlyScript([[1]])
        #expect(throws: ScriptExecutionError.consensus(.invalidSignatureEncoding)) {
            try execute(
                transaction: invalidDER,
                spentOutput: spentOutput,
                limits: contextLimits,
                flags: [.derSignatures]
            )
        }

        let highSignature = try ECDSASignature(
            compactBytes: Array(lowSignature.compactBytes[..<32])
                + subtract(Array(lowSignature.compactBytes[32...]), from: curveOrder)
        )
        var highS = unsigned
        highS.inputs[0].unlockingScript = try pushOnlyScript([
            highSignature.derBytes + [0x01],
        ])
        #expect(throws: ScriptExecutionError.consensus(.invalidSignatureEncoding)) {
            try execute(
                transaction: highS,
                spentOutput: spentOutput,
                limits: contextLimits,
                flags: [.lowS]
            )
        }

        var wrongSignature = unsigned
        let wrongDigest = try Hash256(Array(repeating: 0x44, count: 32))
        wrongSignature.inputs[0].unlockingScript = try pushOnlyScript([
            try key.sign(digest: wrongDigest).derBytes + [0x01],
        ])
        #expect(throws: ScriptExecutionError.consensus(.nullFail)) {
            try execute(
                transaction: wrongSignature,
                spentOutput: spentOutput,
                limits: contextLimits,
                flags: [.derSignatures, .lowS, .nullFail]
            )
        }

        var multiLocking = try script([Opcode.one.rawValue])
        try multiLocking.appendPushData(
            key.publicKey.compressedBytes,
            maximumScriptByteCount: 10_000
        )
        try multiLocking.append(.one, maximumScriptByteCount: 10_000)
        try multiLocking.append(.checkMultiSig, maximumScriptByteCount: 10_000)
        let multiSpent = TransactionOutput(satoshis: 20_000, lockingScript: multiLocking)
        var validMulti = unsigned
        validMulti.inputs[0].sourceOutput = multiSpent
        let multiDigest = try validMulti.legacySignatureHash(
            inputIndex: 0,
            scriptCode: multiLocking,
            limits: contextLimits
        )
        let multiSignature = try key.sign(digest: multiDigest).derBytes + [0x01]
        validMulti.inputs[0].unlockingScript = try pushOnlyScript([[], multiSignature])
        #expect(try execute(
            transaction: validMulti,
            spentOutput: multiSpent,
            limits: contextLimits,
            flags: [.strictMultiSignatureDummy, .derSignatures, .lowS, .nullFail]
        ).stack == [[1]])
        var nonNullDummy = validMulti
        nonNullDummy.inputs[0].unlockingScript = try pushOnlyScript([[1], multiSignature])
        #expect(throws: ScriptExecutionError.consensus(.nullDummy)) {
            try execute(
                transaction: nonNullDummy,
                spentOutput: multiSpent,
                limits: contextLimits,
                flags: [.strictMultiSignatureDummy, .derSignatures, .lowS, .nullFail]
            )
        }

        let lockTransaction = Transaction(
            version: 2,
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(wireBytes: Array(repeating: 0x33, count: 32)),
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sequence: 10
            )],
            lockTime: 100
        )
        for (lockingBytes, flag) in [
            (
                [1, 100, Opcode.checkLockTimeVerify.rawValue, Opcode.drop.rawValue,
                 Opcode.one.rawValue],
                ScriptVerificationFlags.checkLockTimeVerify
            ),
            (
                [Opcode.five.rawValue, Opcode.checkSequenceVerify.rawValue,
                 Opcode.drop.rawValue, Opcode.one.rawValue],
                ScriptVerificationFlags.checkSequenceVerify
            ),
        ] {
            let locking = try script(lockingBytes)
            let output = TransactionOutput(satoshis: 1, lockingScript: locking)
            #expect(try ScriptInterpreter.execute(
                unlockingScript: empty,
                lockingScript: locking,
                configuration: ScriptExecutionConfiguration(
                    era: .beforeGenesis,
                    flags: flag,
                    resourceLimits: .standard
                ),
                context: ScriptExecutionContext(
                    transaction: lockTransaction,
                    inputIndex: 0,
                    spentOutput: output,
                    transactionLimits: contextLimits
                )
            ).stack == [[1]])
        }

        let p2pkh = try Script.payToPublicKeyHash(
            BSVHashing.hash160(key.publicKey.compressedBytes),
            maximumByteCount: 25
        )
        let forkSpent = TransactionOutput(satoshis: 12_345, lockingScript: p2pkh)
        var forkTransaction = Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(wireBytes: Array(repeating: 0x11, count: 32)),
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sourceOutput: forkSpent
            )],
            outputs: [TransactionOutput(satoshis: 12_000, lockingScript: p2pkh)]
        )
        try forkTransaction.signPayToPublicKeyHashInput(
            at: 0,
            with: key,
            limits: contextLimits
        )
        #expect(try execute(
            transaction: forkTransaction,
            spentOutput: forkSpent,
            limits: contextLimits,
            era: .afterGenesis,
            flags: [.enableForkID, .derSignatures, .lowS, .nullFail]
        ).stack == [[1]])
    }

    @Test("context indices, source scripts, and absent metadata fail closed")
    func contextAndMetadataFailures() throws {
        let empty = try script([])
        let locking = try script([Opcode.one.rawValue])
        let output = TransactionOutput(satoshis: 1, lockingScript: locking)
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 1_000,
            maximumInputCount: 2,
            maximumOutputCount: 2,
            maximumScriptByteCount: 1_000
        )
        let transaction = Transaction(inputs: [TransactionInput(
            previousOutput: try Outpoint(
                transactionID: TransactionID(wireBytes: Array(repeating: 0, count: 32)),
                outputIndex: 0
            ),
            unlockingScript: empty
        )])
        #expect(throws: ScriptExecutionError.invalidContext(
            .inputIndexOutOfBounds(index: 1, inputCount: 1)
        )) {
            try ScriptInterpreter.execute(
                unlockingScript: empty,
                lockingScript: locking,
                configuration: ScriptExecutionConfiguration(
                    era: .beforeGenesis,
                    resourceLimits: .standard
                ),
                context: ScriptExecutionContext(
                    transaction: transaction,
                    inputIndex: 1,
                    spentOutput: output,
                    transactionLimits: limits
                )
            )
        }
        #expect(throws: ScriptExecutionError.invalidContext(.unlockingScriptMismatch)) {
            try ScriptInterpreter.execute(
                unlockingScript: locking,
                lockingScript: locking,
                configuration: ScriptExecutionConfiguration(
                    era: .beforeGenesis,
                    resourceLimits: .standard
                ),
                context: ScriptExecutionContext(
                    transaction: transaction,
                    inputIndex: 0,
                    spentOutput: output,
                    transactionLimits: limits
                )
            )
        }
        #expect(throws: ScriptExecutionError.missingExecutionContext(opcode: .checkSig)) {
            try execute(
                unlocking: [],
                locking: [Opcode.zero.rawValue, Opcode.zero.rawValue, Opcode.checkSig.rawValue],
                era: .beforeGenesis
            )
        }
    }

    @Test("independently generated after-Genesis and after-Chronicle cases match one pinned Go process")
    func generatedEraDifferentials() throws {
        let cases = generatedDifferentialCases()
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("InterpreterReference Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, testCase) in cases.enumerated() {
                let local = try execute(
                    unlocking: [],
                    locking: testCase.locking,
                    era: testCase.era
                )
                let response = try client.request(
                    id: "interpreter-reference-generated-\(index)-\(testCase.name)",
                    operation: "script.execute",
                    arguments: [
                        "unlockingScript": .string(""),
                        "lockingScript": .string(Hex.encode(testCase.locking)),
                        "era": .string(interpreterReferenceGoOracleEraValue(for: testCase.era)),
                    ]
                )
                #expect(response.ok, "\(testCase.name): \(String(describing: response.error))")
                #expect(response.result == .object([
                    "stack": .array(local.stack.map { .string(Hex.encode($0)) }),
                    "valid": .bool(true),
                ]), "generated case \(testCase.name)")
            }
        }
    }
}

/// The existing Go-oracle JSON protocol predates the Swift public API naming.
private func interpreterReferenceGoOracleEraValue(for era: ScriptExecutionEra) -> String {
    switch era {
    case .beforeGenesis: "legacy"
    case .afterGenesis: "genesis"
    case .afterChronicle: "chronicle"
    }
}

private struct InterpreterReferenceFixture: Decodable {
    let schema: String
    let sourceSHA256: String
    let sourceCaseCount: Int
    let selection: String
    let cases: [InterpreterReferenceCase]
}

private struct InterpreterReferenceCase: Decodable {
    let sourceIndex: Int
    let unlocking: String
    let locking: String
    let flags: String
    let expected: String
    let comment: String

    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        sourceIndex = try container.decode(Int.self)
        unlocking = try container.decode(String.self)
        locking = try container.decode(String.self)
        flags = try container.decode(String.self)
        expected = try container.decode(String.self)
        comment = try container.decode(String.self)
        guard container.isAtEnd else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "reference case contains trailing fields"
            )
        }
    }
}

private struct InterpreterGeneratedCase {
    let name: String
    let locking: [UInt8]
    let era: ScriptExecutionEra
}

private enum InterpreterReferenceFixtureError: Error {
    case fixtureRootUnavailable
    case invalidASMToken(String)
    case invalidHex(String)
}

private func loadFixture() throws -> InterpreterReferenceFixture {
    guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw InterpreterReferenceFixtureError.fixtureRootUnavailable
    }
    let url = root.appendingPathComponent(
        "Permissive/BitcoinCore/InterpreterReference/script-tests-legacy-subset.json",
        isDirectory: false
    )
    let fixture = try JSONDecoder().decode(
        InterpreterReferenceFixture.self,
        from: Data(contentsOf: url, options: [.mappedIfSafe])
    )
    guard fixture.schema == "bitcoin-core-interpreter-reference/1" else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: [],
            debugDescription: "unsupported interpreter reference schema"
        ))
    }
    return fixture
}

private func compileBitcoinCoreASM(_ text: String) throws -> [UInt8] {
    var result: [UInt8] = []
    for token in text.split(whereSeparator: { $0.isWhitespace }).map(String.init) {
        if let value = Int64(token) {
            if value == 0 {
                result.append(Opcode.zero.rawValue)
            } else if value == -1 {
                result.append(Opcode.oneNegate.rawValue)
            } else if (1...16).contains(value) {
                result.append(Opcode.one.rawValue + UInt8(value - 1))
            } else {
                result += encodedPush(scriptNumberBytes(value))
            }
        } else if token.hasPrefix("0x") {
            result += try hexBytes(String(token.dropFirst(2)))
        } else if token.first == "'", token.last == "'", token.count >= 2 {
            result += encodedPush(Array(token.dropFirst().dropLast().utf8))
        } else {
            let name = token.hasPrefix("OP_") ? token : "OP_\(token)"
            guard let opcode = Opcode(asmName: name, dialect: .brc106) else {
                throw InterpreterReferenceFixtureError.invalidASMToken(token)
            }
            result.append(opcode.rawValue)
        }
    }
    return result
}

private func scriptNumberBytes(_ value: Int64) -> [UInt8] {
    guard value != 0 else { return [] }
    let negative = value < 0
    var magnitude = value.magnitude
    var result: [UInt8] = []
    while magnitude > 0 {
        result.append(UInt8(magnitude & 0xff))
        magnitude >>= 8
    }
    if result[result.count - 1] & 0x80 != 0 {
        result.append(negative ? 0x80 : 0)
    } else if negative {
        result[result.count - 1] |= 0x80
    }
    return result
}

private func encodedPush(_ data: [UInt8]) -> [UInt8] {
    switch data.count {
    case 0:
        return [Opcode.zero.rawValue]
    case 1...75:
        return [UInt8(data.count)] + data
    case 76...255:
        return [Opcode.pushData1.rawValue, UInt8(data.count)] + data
    case 256...65_535:
        return [
            Opcode.pushData2.rawValue,
            UInt8(data.count & 0xff),
            UInt8((data.count >> 8) & 0xff),
        ] + data
    default:
        return [
            Opcode.pushData4.rawValue,
            UInt8(data.count & 0xff),
            UInt8((data.count >> 8) & 0xff),
            UInt8((data.count >> 16) & 0xff),
            UInt8((data.count >> 24) & 0xff),
        ] + data
    }
}

private func hexBytes(_ text: String) throws -> [UInt8] {
    guard text.utf8.count.isMultiple(of: 2) else {
        throw InterpreterReferenceFixtureError.invalidHex(text)
    }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(text.utf8.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<end], radix: 16) else {
            throw InterpreterReferenceFixtureError.invalidHex(text)
        }
        bytes.append(byte)
        index = end
    }
    return bytes
}

private func verificationFlags(_ text: String) throws -> ScriptVerificationFlags {
    var result: ScriptVerificationFlags = []
    for flag in text.split(separator: ",").map(String.init) {
        switch flag {
        case "": break
        case "P2SH": result.insert(.payToScriptHash)
        case "STRICTENC": result.insert(.strictEncoding)
        case "MINIMALDATA": result.insert(.minimalData)
        default: throw InterpreterReferenceFixtureError.invalidASMToken(flag)
        }
    }
    return result
}

private func referenceCategory(_ error: Error) -> String {
    guard let executionError = error as? ScriptExecutionError else {
        return "UNEXPECTED:\(error)"
    }
    switch executionError {
    case .malformedScript:
        return "BAD_OPCODE"
    case .consensus(let failure):
        switch failure {
        case .evaluatedFalse, .emptyFinalStack: return "EVAL_FALSE"
        case .verifyFailed: return "VERIFY"
        case .equalVerifyFailed: return "EQUALVERIFY"
        case .earlyReturn: return "OP_RETURN"
        case .stackUnderflow, .invalidStackIndex: return "INVALID_STACK_OPERATION"
        case .altStackUnderflow: return "INVALID_ALTSTACK_OPERATION"
        case .unbalancedConditional: return "UNBALANCED_CONDITIONAL"
        case .reservedOpcode: return "BAD_OPCODE"
        case .disabledOpcode: return "DISABLED_OPCODE"
        case .nonMinimalPush, .nonMinimalNumber: return "MINIMALDATA"
        case .pushDataTooLarge: return "PUSH_SIZE"
        case .tooManyOperations: return "OP_COUNT"
        case .tooManyStackItems: return "STACK_SIZE"
        default: return "UNEXPECTED:\(failure)"
        }
    default:
        return "UNEXPECTED:\(executionError)"
    }
}

private func repeatedPushScript(byteCount: Int) -> [UInt8] {
    precondition(byteCount >= 1)
    var result: [UInt8] = []
    while result.count + 77 <= byteCount {
        result += encodedPush(Array(repeating: 1, count: 75))
    }
    let remainingBeforeTruth = byteCount - result.count - 1
    if remainingBeforeTruth > 0 {
        precondition(remainingBeforeTruth >= 2)
        result += encodedPush(Array(repeating: 1, count: remainingBeforeTruth - 1))
    }
    result.append(Opcode.one.rawValue)
    precondition(result.count == byteCount)
    return result
}

private func execute(
    unlocking: [UInt8],
    locking: [UInt8],
    era: ScriptExecutionEra,
    flags: ScriptVerificationFlags = [],
    limits: ScriptResourceLimits = .standard
) throws -> ScriptExecutionResult {
    try ScriptInterpreter.execute(
        unlockingScript: script(unlocking),
        lockingScript: script(locking),
        configuration: ScriptExecutionConfiguration(
            era: era,
            flags: flags,
            resourceLimits: limits
        )
    )
}

private func execute(
    transaction: Transaction,
    spentOutput: TransactionOutput,
    limits: TransactionLimits,
    era: ScriptExecutionEra = .beforeGenesis,
    flags: ScriptVerificationFlags
) throws -> ScriptExecutionResult {
    try ScriptInterpreter.execute(
        unlockingScript: transaction.inputs[0].unlockingScript,
        lockingScript: spentOutput.lockingScript,
        configuration: ScriptExecutionConfiguration(
            era: era,
            flags: flags,
            resourceLimits: .standard
        ),
        context: ScriptExecutionContext(
            transaction: transaction,
            inputIndex: 0,
            spentOutput: spentOutput,
            transactionLimits: limits
        )
    )
}

private func script(_ bytes: [UInt8]) throws -> Script {
    try Script(bytes: bytes, maximumByteCount: max(bytes.count, 1))
}

private func pushOnlyScript(_ values: [[UInt8]]) throws -> Script {
    try script(values.flatMap(encodedPush))
}

private func generatedDifferentialCases() -> [InterpreterGeneratedCase] {
    [
        .init(
            name: "cat",
            locking: [2, 0x61, 0x62, 1, 0x63, Opcode.cat.rawValue,
                      3, 0x61, 0x62, 0x63, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "split",
            locking: [4, 0x61, 0x62, 0x63, 0x64, Opcode.two.rawValue,
                      Opcode.split.rawValue, Opcode.cat.rawValue,
                      4, 0x61, 0x62, 0x63, 0x64, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "num2bin",
            locking: [1, 0x7f, Opcode.two.rawValue, Opcode.num2bin.rawValue,
                      2, 0x7f, 0, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "bin2num",
            locking: [2, 1, 0, Opcode.bin2num.rawValue, Opcode.one.rawValue,
                      Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "bitwise-and",
            locking: [2, 0x0f, 0xf0, 2, 0x33, 0xcc, Opcode.and.rawValue,
                      2, 0x03, 0xc0, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "bitwise-or",
            locking: [2, 0x0f, 0xf0, 2, 0x33, 0xcc, Opcode.or.rawValue,
                      2, 0x3f, 0xfc, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "bitwise-xor",
            locking: [2, 0x0f, 0xf0, 2, 0x33, 0xcc, Opcode.xor.rawValue,
                      2, 0x3c, 0x3c, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "mul-div-mod",
            locking: [Opcode.six.rawValue, Opcode.seven.rawValue, Opcode.mul.rawValue,
                      Opcode.six.rawValue, Opcode.div.rawValue, Opcode.seven.rawValue,
                      Opcode.equalVerify.rawValue, Opcode.seven.rawValue,
                      Opcode.three.rawValue, Opcode.mod.rawValue, Opcode.one.rawValue,
                      Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "byte-shifts",
            locking: [2, 0x12, 0x34, Opcode.four.rawValue, Opcode.leftShift.rawValue,
                      2, 0x23, 0x40, Opcode.equalVerify.rawValue,
                      2, 0x12, 0x34, Opcode.four.rawValue, Opcode.rightShift.rawValue,
                      2, 0x01, 0x23, Opcode.equal.rawValue],
            era: .afterGenesis
        ),
        .init(
            name: "after-chronicle-substring",
            locking: [4, 0x61, 0x62, 0x63, 0x64, Opcode.one.rawValue,
                      Opcode.two.rawValue, Opcode.substring.rawValue,
                      2, 0x62, 0x63, Opcode.equal.rawValue],
            era: .afterChronicle
        ),
        .init(
            name: "after-chronicle-left-right",
            locking: [4, 0x61, 0x62, 0x63, 0x64, Opcode.two.rawValue,
                      Opcode.left.rawValue, 2, 0x61, 0x62, Opcode.equalVerify.rawValue,
                      4, 0x61, 0x62, 0x63, 0x64, Opcode.two.rawValue,
                      Opcode.right.rawValue, 2, 0x63, 0x64, Opcode.equal.rawValue],
            era: .afterChronicle
        ),
        .init(
            name: "after-chronicle-arithmetic-right-shift",
            locking: [Opcode.three.rawValue, Opcode.negate.rawValue,
                      Opcode.one.rawValue, Opcode.rightShiftNumber.rawValue,
                      1, 0x82, Opcode.equal.rawValue],
            era: .afterChronicle
        ),
    ]
}

private let curveOrder: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]

private func subtract(_ value: [UInt8], from minuend: [UInt8]) -> [UInt8] {
    precondition(value.count == minuend.count)
    var result = Array(repeating: UInt8(0), count: value.count)
    var borrow = 0
    for index in value.indices.reversed() {
        var difference = Int(minuend[index]) - Int(value[index]) - borrow
        if difference < 0 {
            difference += 256
            borrow = 1
        } else {
            borrow = 0
        }
        result[index] = UInt8(difference)
    }
    precondition(borrow == 0)
    return result
}
