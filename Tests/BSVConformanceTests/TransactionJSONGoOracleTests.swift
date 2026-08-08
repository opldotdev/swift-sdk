import BSVCore
import BSVScript
import BSVTransaction
import Foundation
import Testing

@Suite("Transaction JSON pinned-Go conformance", .serialized)
struct TransactionJSONGoOracleTests {
    private let rawHex = "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a20100000000ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000"

    @Test("canonical transaction JSON agrees in both directions")
    func transactionParity() throws {
        try withOracle { client in
            let limits = try makeLimits()
            let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
            let swiftDocument = try transaction.jsonBytes(limits: limits)

            let marshal = try client.request(
                id: "transaction-json-marshal",
                operation: "transaction.json.marshal",
                arguments: ["bytes": .string(rawHex)]
            )
            #expect(marshal.ok)
            let goDocument = try decodeDocument(marshal, maximum: limits.maximumJSONByteCount)
            #expect(goDocument == swiftDocument)
            #expect(try Transaction(jsonBytes: goDocument, limits: limits) == transaction)

            let unmarshal = try client.request(
                id: "transaction-json-unmarshal",
                operation: "transaction.json.unmarshal",
                arguments: ["json": .string(Hex.encode(swiftDocument))]
            )
            #expect(unmarshal.ok)
            #expect(unmarshal.result?.objectString(for: "bytes") == rawHex)

            let empty = Transaction()
            let swiftEmptyDocument = try empty.jsonBytes(limits: limits)
            let emptyMarshal = try client.request(
                id: "transaction-json-empty-marshal",
                operation: "transaction.json.marshal",
                arguments: ["bytes": .string("01000000000000000000")]
            )
            #expect(emptyMarshal.ok)
            let goEmptyDocument = try decodeDocument(
                emptyMarshal,
                maximum: limits.maximumJSONByteCount
            )
            #expect(goEmptyDocument == swiftEmptyDocument)
            #expect(String(decoding: goEmptyDocument, as: UTF8.self).contains("\"inputs\":null,\"outputs\":null"))
            #expect(try Transaction(jsonBytes: goEmptyDocument, limits: limits) == empty)
        }
    }

    @Test("input and output JSON methods agree in both directions")
    func componentParity() throws {
        try withOracle { client in
            let limits = try makeLimits()
            let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
            let input = transaction.inputs[0]
            let inputMarshal = try client.request(
                id: "transaction-input-json-marshal",
                operation: "transaction.input.json.marshal",
                arguments: [
                    "unlockingScript": .string(input.unlockingScript.hex),
                    "txid": .string(input.previousOutput.transactionID.displayHex),
                    "vout": .string(String(input.previousOutput.outputIndex)),
                    "sequence": .string(String(input.sequence)),
                ]
            )
            #expect(inputMarshal.ok)
            let inputDocument = try decodeDocument(inputMarshal, maximum: limits.maximumJSONByteCount)
            let swiftInputDocument = try input.jsonBytes(limits: limits)
            #expect(inputDocument == swiftInputDocument)
            #expect(try TransactionInput(jsonBytes: inputDocument, limits: limits) == input)
            let inputUnmarshal = try client.request(
                id: "transaction-input-json-unmarshal",
                operation: "transaction.input.json.unmarshal",
                arguments: ["json": .string(Hex.encode(inputDocument))]
            )
            #expect(inputUnmarshal.ok)
            #expect(inputUnmarshal.result?.objectString(for: "txid") == input.previousOutput.transactionID.displayHex)
            #expect(inputUnmarshal.result?.objectString(for: "vout") == String(input.previousOutput.outputIndex))
            #expect(inputUnmarshal.result?.objectString(for: "sequence") == String(input.sequence))
            #expect(inputUnmarshal.result?.objectString(for: "unlockingScript") == input.unlockingScript.hex)

            let output = transaction.outputs[1]
            let outputMarshal = try client.request(
                id: "transaction-output-json-marshal",
                operation: "transaction.output.json.marshal",
                arguments: [
                    "satoshis": .string(String(output.satoshis)),
                    "lockingScript": .string(output.lockingScript.hex),
                ]
            )
            #expect(outputMarshal.ok)
            let outputDocument = try decodeDocument(outputMarshal, maximum: limits.maximumJSONByteCount)
            let swiftOutputDocument = try output.jsonBytes(limits: limits)
            #expect(outputDocument == swiftOutputDocument)
            #expect(try TransactionOutput(jsonBytes: outputDocument, limits: limits) == output)
            let outputUnmarshal = try client.request(
                id: "transaction-output-json-unmarshal",
                operation: "transaction.output.json.unmarshal",
                arguments: ["json": .string(Hex.encode(outputDocument))]
            )
            #expect(outputUnmarshal.ok)
            #expect(outputUnmarshal.result?.objectString(for: "satoshis") == String(output.satoshis))
            #expect(outputUnmarshal.result?.objectString(for: "lockingScript") == output.lockingScript.hex)
        }
    }

    @Test("Swift rejects pinned Go lossy transaction JSON artifacts")
    func strictSwiftDifferences() throws {
        try withOracle { client in
            let limits = try makeLimits()
            let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
            let canonical = String(decoding: try transaction.jsonBytes(limits: limits), as: UTF8.self)
            let transactionID = try transaction.transactionID(limits: limits.transactionLimits).displayHex
            let values: [(name: String, document: String, goBytes: String)] = [
                ("partial without hex", "{\"version\":2,\"lockTime\":3,\"inputs\":[{\"vout\":7}]}", "02000000000003000000"),
                ("unknown and inconsistent", "{\"hex\":\"\(rawHex)\",\"version\":9,\"lockTime\":8,\"unknown\":true}", rawHex),
                ("duplicate", canonical.replacingOccurrences(of: "{\"txid\":", with: "{\"txid\":\"\(transactionID)\",\"txid\":"), rawHex),
            ]
            for (index, value) in values.enumerated() {
                let response = try client.request(
                    id: "transaction-json-go-artifact-\(index)",
                    operation: "transaction.json.unmarshal",
                    arguments: ["json": .string(Hex.encode(Array(value.document.utf8)))]
                )
                #expect(response.ok, "Pinned Go rejected \(value.name)")
                #expect(response.result?.objectString(for: "bytes") == value.goBytes)
                #expect(throws: (any Error).self, "Swift accepted \(value.name)") {
                    try Transaction(jsonBytes: Array(value.document.utf8), limits: limits)
                }
            }

            let unsafeMarshal = try client.request(
                id: "transaction-output-json-unsafe-number",
                operation: "transaction.output.json.marshal",
                arguments: ["satoshis": .string("9007199254740992"), "lockingScript": .string("")]
            )
            #expect(unsafeMarshal.ok)
            let unsafeDocument = try decodeDocument(unsafeMarshal, maximum: 128)
            #expect(String(decoding: unsafeDocument, as: UTF8.self).contains("9007199254740992"))
            #expect(throws: TransactionJSONError.unsafeJSONNumber(field: "satoshis", value: 9_007_199_254_740_992)) {
                try TransactionOutput(jsonBytes: unsafeDocument, limits: limits)
            }

            let shortUppercaseInput = Array("{\"unlockingScript\":\"\",\"txid\":\"ABCD\",\"vout\":1,\"sequence\":2}".utf8)
            let lossyInput = try client.request(
                id: "transaction-input-json-short-uppercase",
                operation: "transaction.input.json.unmarshal",
                arguments: ["json": .string(Hex.encode(shortUppercaseInput))]
            )
            #expect(lossyInput.ok)
            #expect(lossyInput.result?.objectString(for: "txid") == String(repeating: "0", count: 60) + "abcd")
            #expect(throws: TransactionJSONError.nonCanonicalHex(field: "txid")) {
                try TransactionInput(jsonBytes: shortUppercaseInput, limits: limits)
            }

            let emptyOutputDocument = Array("{}".utf8)
            let lossyOutput = try client.request(
                id: "transaction-output-json-empty",
                operation: "transaction.output.json.unmarshal",
                arguments: ["json": .string(Hex.encode(emptyOutputDocument))]
            )
            #expect(lossyOutput.ok)
            #expect(lossyOutput.result?.objectString(for: "satoshis") == "0")
            #expect(lossyOutput.result?.objectString(for: "lockingScript") == "")
            #expect(throws: TransactionJSONError.missingKey("satoshis")) {
                try TransactionOutput(jsonBytes: emptyOutputDocument, limits: limits)
            }
        }
    }

    @Test("oracle rejects values beyond its fixed operation envelope")
    func oracleBounds() throws {
        try withOracle { client in
            let transactionOverflow = try client.request(
                id: "transaction-json-transaction-limit",
                operation: "transaction.json.marshal",
                arguments: ["bytes": .string(String(repeating: "00", count: 64 * 1_024 + 1))]
            )
            #expect(!transactionOverflow.ok)
            #expect(transactionOverflow.error?.category == "resourceLimit")

            let documentOverflow = try client.request(
                id: "transaction-json-document-limit",
                operation: "transaction.json.unmarshal",
                arguments: ["json": .string(String(repeating: "00", count: 384 * 1_024 + 1))]
            )
            #expect(!documentOverflow.ok)
            #expect(documentOverflow.error?.category == "resourceLimit")
        }
    }

    private func makeLimits() throws -> TransactionJSONLimits {
        try TransactionJSONLimits(
            maximumJSONByteCount: 16_384,
            transactionLimits: TransactionLimits(
                maximumTransactionByteCount: 1_024,
                maximumInputCount: 8,
                maximumOutputCount: 8,
                maximumScriptByteCount: 256
            )
        )
    }

    private func decodeDocument(
        _ response: GoOracleResponse,
        maximum: Int
    ) throws -> [UInt8] {
        try Hex.decode(
            #require(response.result?.objectString(for: "json")),
            maximumDecodedByteCount: maximum
        )
    }

    private func withOracle(_ body: (GoOracleClient) throws -> Void) throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Transaction JSON Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            try body(client)
        }
    }
}

private extension GoOracleJSON {
    func objectString(for key: String) -> String? {
        guard case .object(let object) = self,
              case .string(let value)? = object[key] else { return nil }
        return value
    }
}
