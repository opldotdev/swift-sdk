import BSVCore
import BSVScript
import BSVTransaction
import Testing

@Suite("Legacy signature-hash differential conformance", .serialized)
struct LegacySignatureHashConformanceTests {
    @Test("all canonical legacy modes match the pinned Go SDK")
    func canonicalModes() throws {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let scriptCode = try Script(
            hex: "76a914000000000000000000000000000000000000000088ac",
            maximumByteCount: 25
        )
        let sourceOutput = TransactionOutput(satoshis: 50_000, lockingScript: scriptCode)
        let transaction = Transaction(
            version: 2,
            inputs: [
                TransactionInput(
                    previousOutput: try Outpoint(
                        transactionID: TransactionID(
                            wireBytes: Array(repeating: 0x11, count: 32)
                        ),
                        outputIndex: 1
                    ),
                    unlockingScript: empty,
                    sequence: 0x11111111
                ),
                TransactionInput(
                    previousOutput: try Outpoint(
                        transactionID: TransactionID(
                            wireBytes: Array(repeating: 0x22, count: 32)
                        ),
                        outputIndex: 2
                    ),
                    unlockingScript: empty,
                    sequence: 0x22222222,
                    sourceOutput: sourceOutput
                ),
            ],
            outputs: [
                TransactionOutput(
                    satoshis: 10_000,
                    lockingScript: try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
                ),
                TransactionOutput(
                    satoshis: 20_000,
                    lockingScript: try Script(bytes: [Opcode.two.rawValue], maximumByteCount: 1)
                ),
            ],
            lockTime: 7
        )
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        let wireBytes = try transaction.serialized(limits: limits)
        let hashTypes = [
            LegacySignatureHashType.all,
            .none,
            .single,
            LegacySignatureHashType(outputs: .all, anyoneCanPay: true),
            LegacySignatureHashType(outputs: .none, anyoneCanPay: true),
            LegacySignatureHashType(outputs: .single, anyoneCanPay: true),
        ]

        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Legacy sighash Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for hashType in hashTypes {
                let preimage = try transaction.legacySignaturePreimage(
                    inputIndex: 1,
                    hashType: hashType,
                    scriptCode: scriptCode,
                    limits: limits
                )
                let digest = try transaction.legacySignatureHash(
                    inputIndex: 1,
                    hashType: hashType,
                    scriptCode: scriptCode,
                    limits: limits
                )
                let response = try client.request(
                    id: "legacy-sighash-\(hashType.rawValue)",
                    operation: "transaction.sighash",
                    arguments: [
                        "bytes": .string(Hex.encode(wireBytes)),
                        "inputIndex": .string("1"),
                        "sourceSatoshis": .string("50000"),
                        "sourceScript": .string(scriptCode.hex),
                        "signatureHash": .string(String(hashType.rawValue)),
                    ]
                )
                #expect(response.ok)
                #expect(response.result == .object([
                    "digest": .string(Hex.encode(digest.bytes)),
                    "preimage": .string(Hex.encode(preimage)),
                ]))
            }
        }
    }
}
