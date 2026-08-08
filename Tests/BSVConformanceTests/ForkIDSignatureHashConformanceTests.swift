import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@Suite("ForkID signature-hash conformance", .serialized)
struct ForkIDSignatureHashConformanceTests {
    @Test("all six ForkID modes agree with the pinned Go SDK")
    func goOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("ForkID signature-hash Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let limits = try TransactionLimits(
                maximumTransactionByteCount: 10_000,
                maximumInputCount: 10,
                maximumOutputCount: 10,
                maximumScriptByteCount: 1_000
            )
            let sourceScript = try Script(
                hex: "76a91400112233445566778899aabbccddeeff0011223388ac",
                maximumByteCount: 25
            )
            var transaction = try conformanceTransaction()
            transaction.inputs[1].sourceOutput = TransactionOutput(
                satoshis: 9_876_543_210,
                lockingScript: sourceScript
            )
            let transactionHex = try transaction.hex(limits: limits)

            var caseIndex = 0
            for outputs in SignatureHashOutputs.allCases {
                for anyoneCanPay in [false, true] {
                    let hashType = ForkIDSignatureHashType(
                        outputs: outputs,
                        anyoneCanPay: anyoneCanPay
                    )
                    let response = try client.request(
                        id: "forkid-sighash-\(caseIndex)",
                        operation: "transaction.sighash",
                        arguments: [
                            "bytes": .string(transactionHex),
                            "inputIndex": .string("1"),
                            "sourceSatoshis": .string("9876543210"),
                            "sourceScript": .string(sourceScript.hex),
                            "signatureHash": .string(String(hashType.rawValue)),
                        ]
                    )
                    let preimage = try transaction.forkIDSignaturePreimage(
                        inputIndex: 1,
                        hashType: hashType,
                        limits: limits
                    )
                    let digest = try transaction.forkIDSignatureHash(
                        inputIndex: 1,
                        hashType: hashType,
                        limits: limits
                    )
                    #expect(response.ok)
                    #expect(response.result == .object([
                        "digest": .string(Hex.encode(digest.bytes)),
                        "preimage": .string(Hex.encode(preimage)),
                    ]))
                    caseIndex += 1
                }
            }
        }
    }

    @Test("compressed P2PKH signing matches the pinned Go SDK byte for byte")
    func p2pkhSigningDifferential() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("P2PKH signing Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let limits = try TransactionLimits(
                maximumTransactionByteCount: 10_000,
                maximumInputCount: 10,
                maximumOutputCount: 10,
                maximumScriptByteCount: 1_000
            )
            let privateKeyBytes = [UInt8](repeating: 0, count: 31) + [1]
            let privateKey = try PrivateKey(privateKeyBytes)
            let sourceScript = try Script.payToPublicKeyHash(
                BSVHashing.hash160(privateKey.publicKey.compressedBytes),
                maximumByteCount: 25
            )
            var transaction = try conformanceTransaction()
            transaction.inputs[1].sourceOutput = TransactionOutput(
                satoshis: 9_876_543_210,
                lockingScript: sourceScript
            )
            let unsignedHex = try transaction.hex(limits: limits)
            let response = try client.request(
                id: "p2pkh-sign",
                operation: "transaction.p2pkh.sign",
                arguments: [
                    "bytes": .string(unsignedHex),
                    "inputIndex": .string("1"),
                    "sourceSatoshis": .string("9876543210"),
                    "sourceScript": .string(sourceScript.hex),
                    "signatureHash": .string("65"),
                    "privateKey": .string(Hex.encode(privateKeyBytes)),
                ]
            )
            try transaction.signPayToPublicKeyHashInput(
                at: 1,
                with: privateKey,
                limits: limits
            )
            #expect(response.ok)
            #expect(response.result == .object([
                "unlockingScript": .string(transaction.inputs[1].unlockingScript.hex),
            ]))
        }
    }
}

private func conformanceTransaction() throws -> Transaction {
    let empty = try Script(bytes: [], maximumByteCount: 0)
    func outpoint(_ byte: UInt8, _ index: UInt32) throws -> Outpoint {
        Outpoint(
            transactionID: try TransactionID(
                wireBytes: [UInt8](repeating: byte, count: 32)
            ),
            outputIndex: index
        )
    }
    return Transaction(
        version: 2,
        inputs: [
            TransactionInput(
                previousOutput: try outpoint(0x11, 3),
                unlockingScript: empty,
                sequence: 0x1234_5678
            ),
            TransactionInput(
                previousOutput: try outpoint(0x22, 4),
                unlockingScript: empty,
                sequence: 0x8765_4321
            ),
        ],
        outputs: [
            TransactionOutput(satoshis: 100, lockingScript: empty),
            TransactionOutput(satoshis: 200, lockingScript: empty),
            TransactionOutput(satoshis: 300, lockingScript: empty),
        ],
        lockTime: 42
    )
}
