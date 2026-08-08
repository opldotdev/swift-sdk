import BSVCore
import BSVTransaction
import Foundation
import Testing

@Suite("Transaction wire conformance", .serialized)
struct TransactionWireConformanceTests {
    @Test("BTCD transaction fixture provenance and hashes verify")
    func manifestVerification() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "transaction-wire-btcd-v0.24.2" }
        )
        #expect(group.source.url == "https://github.com/btcsuite/btcd")
        #expect(group.source.revision == "v0.24.2")
        #expect(group.license.identifier == "ISC")
        let file = try #require(group.files.first)
        #expect(file.originalPath == "wire/msgtx_test.go")
        #expect(file.localPath == "Permissive/BTCD/Transaction/transaction-wire.json")
        #expect(
            file.sha256
                == "27ed949b7d7e74cf96cb56910a0ec697ffb8a534701614fc3a68847a712c8ff1"
        )
    }

    @Test("permissive BTCD wire images round trip through the public API")
    func staticVectors() throws {
        let fixture = try loadTransactionFixture()
        let maximumBytes = try #require(
            fixture.cases.map(\.hex.utf8.count).max().map { $0 / 2 }
        )
        let limits = try TransactionLimits(
            maximumTransactionByteCount: maximumBytes,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: UInt64(maximumBytes)
        )

        for testCase in fixture.cases {
            let transaction = try Transaction(hex: testCase.hex, limits: limits)
            #expect(transaction.version == testCase.version)
            #expect(transaction.inputs.count == testCase.inputCount)
            #expect(transaction.outputs.count == testCase.outputCount)
            #expect(transaction.lockTime == testCase.lockTime)
            #expect(try transaction.hex(limits: limits) == testCase.hex)
            if let expectedID = testCase.txid {
                #expect(try transaction.transactionID(limits: limits).displayHex == expectedID)
            }
        }
    }

    @Test("pinned Go SDK agrees on canonical wire fields and transaction IDs")
    func goOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Transaction Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, testCase) in try loadTransactionFixture().cases.enumerated() {
                let response = try client.request(
                    id: "transaction-decode-\(index)",
                    operation: "transaction.decode",
                    arguments: ["bytes": .string(testCase.hex)]
                )
                let transaction = try Transaction(
                    hex: testCase.hex,
                    limits: TransactionLimits(
                        maximumTransactionByteCount: testCase.hex.utf8.count / 2,
                        maximumInputCount: 10,
                        maximumOutputCount: 10,
                        maximumScriptByteCount: UInt64(testCase.hex.utf8.count / 2)
                    )
                )
                let txid = try transaction.transactionID(limits: TransactionLimits(
                    maximumTransactionByteCount: testCase.hex.utf8.count / 2,
                    maximumInputCount: 10,
                    maximumOutputCount: 10,
                    maximumScriptByteCount: UInt64(testCase.hex.utf8.count / 2)
                )).displayHex
                #expect(response.ok)
                #expect(response.result == .object([
                    "bytes": .string(testCase.hex),
                    "inputs": .string(String(testCase.inputCount)),
                    "lockTime": .string(String(testCase.lockTime)),
                    "outputs": .string(String(testCase.outputCount)),
                    "txid": .string(txid),
                    "version": .string(String(testCase.version)),
                ]))
            }
        }
    }
}

private struct TransactionFixture: Decodable {
    let schema: String
    let cases: [TransactionFixtureCase]
}

private struct TransactionFixtureCase: Decodable {
    let name: String
    let hex: String
    let version: UInt32
    let inputCount: Int
    let outputCount: Int
    let lockTime: UInt32
    let txid: String?
}

private enum TransactionFixtureError: Error {
    case rootUnavailable
    case invalidSchema(String)
}

private func loadTransactionFixture() throws -> TransactionFixture {
    guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw TransactionFixtureError.rootUnavailable
    }
    let url = root.appendingPathComponent(
        "Permissive/BTCD/Transaction/transaction-wire.json",
        isDirectory: false
    )
    let fixture = try JSONDecoder().decode(
        TransactionFixture.self,
        from: Data(contentsOf: url, options: [.mappedIfSafe])
    )
    guard fixture.schema == "bsv-transaction-wire-fixtures/1" else {
        throw TransactionFixtureError.invalidSchema(fixture.schema)
    }
    return fixture
}
