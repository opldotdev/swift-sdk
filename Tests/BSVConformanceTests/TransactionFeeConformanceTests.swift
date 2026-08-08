import BSVCore
import BSVScript
import BSVTransaction
import Testing

@Suite("Transaction fee conformance", .serialized)
struct TransactionFeeConformanceTests {
    @Test("pinned Go SDK agrees on actual and projected transaction sizes")
    func goOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Transaction fee Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let limits = try TransactionLimits(
                maximumTransactionByteCount: 10_000,
                maximumInputCount: 10,
                maximumOutputCount: 10,
                maximumScriptByteCount: 1_000
            )
            let empty = try Script(bytes: [], maximumByteCount: 0)
            let actualScript = try Script(bytes: [0x01], maximumByteCount: 1)
            let outpoint = Outpoint(
                transactionID: try TransactionID(
                    wireBytes: [UInt8](repeating: 0x11, count: 32)
                ),
                outputIndex: 3
            )

            let cases: [(name: String, transaction: Transaction, rate: UInt64)] = [
                (
                    "actual",
                    Transaction(inputs: [TransactionInput(
                        previousOutput: outpoint,
                        unlockingScript: actualScript,
                        estimatedUnlockingScriptByteCount: 900
                    )]),
                    1_000
                ),
                (
                    "projected",
                    Transaction(inputs: [TransactionInput(
                        previousOutput: outpoint,
                        unlockingScript: empty,
                        estimatedUnlockingScriptByteCount: 106
                    )]),
                    500
                ),
                ("empty", Transaction(), 1),
            ]

            for testCase in cases {
                let estimates: [GoOracleJSON] = testCase.transaction.inputs.map { input in
                    guard input.unlockingScript.byteCount == 0,
                          let estimate = input.estimatedUnlockingScriptByteCount
                    else { return .null }
                    return .string(String(estimate))
                }
                let response = try client.request(
                    id: "transaction-fee-\(testCase.name)",
                    operation: "transaction.fee",
                    arguments: [
                        "bytes": .string(try testCase.transaction.hex(limits: limits)),
                        "satoshisPerKilobyte": .string(String(testCase.rate)),
                        "unlockingByteCounts": .array(estimates),
                    ]
                )
                let swiftFee = try SatoshisPerKilobyteFeeModel(
                    satoshisPerKilobyte: testCase.rate
                ).fee(for: testCase.transaction, limits: limits)
                #expect(response.result == .object(["fee": .string(String(swiftFee))]))
            }
        }
    }
}
