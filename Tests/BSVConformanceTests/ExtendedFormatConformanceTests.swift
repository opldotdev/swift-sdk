import BSVCore
import BSVScript
import BSVTransaction
import Testing

@Suite("Extended Format Go conformance", .serialized)
struct ExtendedFormatConformanceTests {
    @Test("Swift EF encoding is decoded identically by pinned Go")
    func swiftToGo() throws {
        try withOracle { client in
            let transaction = try knownAnswerTransaction()
            let limits = try extendedLimits()
            let extendedHex = try transaction.hex(format: .extended, limits: limits)
            let rawHex = try transaction.hex(limits: limits)
            let txid = try transaction.transactionID(limits: limits).displayHex
            let response = try client.request(
                id: "extended-swift-to-go",
                operation: "transaction.ef.decode",
                arguments: ["bytes": .string(extendedHex)]
            )

            #expect(response.ok)
            #expect(response.result == .object([
                "bytes": .string(extendedHex),
                "rawBytes": .string(rawHex),
                "txid": .string(txid),
                "version": .string(String(transaction.version)),
                "inputs": .string("1"),
                "outputs": .string("1"),
                "lockTime": .string(String(transaction.lockTime)),
                "sources": .array([.object([
                    "satoshis": .string("72623859790382856"),
                    "lockingScript": .string("5100ac"),
                ])]),
            ]))
        }
    }

    @Test("pinned Go EF encoding round trips byte-identically through Swift")
    func goToSwift() throws {
        try withOracle { client in
            let transaction = try knownAnswerTransaction()
            let limits = try extendedLimits()
            let rawHex = try transaction.hex(limits: limits)
            let extendedHex = try transaction.hex(format: .extended, limits: limits)
            let txid = try transaction.transactionID(limits: limits).displayHex
            let response = try client.request(
                id: "extended-go-to-swift",
                operation: "transaction.ef.encode",
                arguments: [
                    "bytes": .string(rawHex),
                    "sources": .array([.object([
                        "satoshis": .string("72623859790382856"),
                        "lockingScript": .string("5100ac"),
                    ])]),
                ]
            )

            #expect(response.ok)
            #expect(response.result == .object([
                "bytes": .string(extendedHex),
                "rawBytes": .string(rawHex),
                "txid": .string(txid),
            ]))

            guard case .object(let fields) = response.result,
                  case .string(let goExtendedHex) = fields["bytes"]
            else {
                Issue.record("oracle omitted Extended Format bytes")
                return
            }
            let decoded = try Transaction(
                hex: goExtendedHex,
                format: .extended,
                limits: limits
            )
            #expect(try decoded.hex(format: .extended, limits: limits) == goExtendedHex)
            #expect(decoded == transaction)
            #expect(decoded.inputs[0].sourceOutput?.satoshis == 0x0102_0304_0506_0708)
        }
    }
}

private func withOracle(_ operation: (GoOracleClient) throws -> Void) throws {
    let configuration = GoOracleConfiguration.default()
    switch try GoOracleClient.connect(configuration: configuration) {
    case .unavailable(let reason):
        #expect(!configuration.required)
        print("Extended Format Go oracle unavailable: \(reason)")
    case .available(let client):
        defer { client.close() }
        try operation(client)
    }
}

private func knownAnswerTransaction() throws -> Transaction {
    Transaction(
        version: 0x7856_3412,
        inputs: [TransactionInput(
            previousOutput: Outpoint(
                transactionID: try TransactionID(wireBytes: (0..<32).map(UInt8.init)),
                outputIndex: 0x4433_2211
            ),
            unlockingScript: try Script(bytes: [0xaa, 0xbb], maximumByteCount: 2),
            sequence: 0xd4c3_b2a1,
            sourceOutput: TransactionOutput(
                satoshis: 0x0102_0304_0506_0708,
                lockingScript: try Script(bytes: [0x51, 0x00, 0xac], maximumByteCount: 3)
            )
        )],
        outputs: [TransactionOutput(
            satoshis: 9,
            lockingScript: try Script(bytes: [0x6a, 0x00], maximumByteCount: 2)
        )],
        lockTime: 0x0d0c_0b0a
    )
}

private func extendedLimits() throws -> TransactionLimits {
    try TransactionLimits(
        maximumTransactionByteCount: 1_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 100
    )
}
