import BSVCore
import BSVScript
import Testing

@Suite("Script JSON pinned-Go conformance", .serialized)
struct ScriptJSONGoOracleTests {
    @Test("canonical lowercase JSON agrees in both directions")
    func canonicalParity() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script JSON Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let cases: [[UInt8]] = [
                [],
                [0x00, 0xff, 0x51, 0xac],
                (UInt8.min...UInt8.max).map { $0 },
            ]
            for (index, bytes) in cases.enumerated() {
                let script = try Script(bytes: bytes, maximumByteCount: bytes.count)
                let limits = try ScriptJSONLimits(
                    maximumJSONByteCount: bytes.count * 2 + 2,
                    maximumScriptByteCount: bytes.count
                )
                let swiftJSON = try script.jsonBytes(limits: limits)

                let unmarshal = try client.request(
                    id: "script-json-unmarshal-\(index)",
                    operation: "script.json.unmarshal",
                    arguments: ["json": .string(Hex.encode(swiftJSON))]
                )
                #expect(unmarshal.ok)
                #expect(unmarshal.result == .object(["bytes": .string(script.hex)]))

                let marshal = try client.request(
                    id: "script-json-marshal-\(index)",
                    operation: "script.json.marshal",
                    arguments: ["bytes": .string(script.hex)]
                )
                #expect(marshal.ok)
                let goJSONHex = try #require(marshal.result?.objectString(for: "json"))
                let goJSON = try Hex.decode(
                    goJSONHex,
                    maximumDecodedByteCount: limits.maximumJSONByteCount
                )
                #expect(goJSON == swiftJSON)
                #expect(try Script(jsonBytes: goJSON, limits: limits) == script)
            }
        }
    }

    @Test("Swift rejects the pinned Go JSON token artifacts")
    func strictSwiftDifferences() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script JSON Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let limits = try ScriptJSONLimits(
                maximumJSONByteCount: 32,
                maximumScriptByteCount: 8
            )
            let acceptedByGo: [(name: String, document: [UInt8])] = [
                ("uppercase", [0x22, 0x41, 0x41, 0x22]),
                ("non-string", [0x61, 0x61]),
                ("trailing quote", [0x22, 0x61, 0x61, 0x22, 0x22]),
            ]
            for (index, value) in acceptedByGo.enumerated() {
                let response = try client.request(
                    id: "script-json-go-artifact-\(index)",
                    operation: "script.json.unmarshal",
                    arguments: ["json": .string(Hex.encode(value.document))]
                )
                #expect(response.ok, "Pinned Go rejected \(value.name)")
                #expect(response.result == .object(["bytes": .string("aa")]))
                #expect(throws: ScriptError.invalidJSON, "Swift accepted \(value.name)") {
                    try Script(jsonBytes: value.document, limits: limits)
                }
            }

            let escaped = Array(#""\u0061\u0061""#.utf8)
            let escapedResponse = try client.request(
                id: "script-json-go-escaped",
                operation: "script.json.unmarshal",
                arguments: ["json": .string(Hex.encode(escaped))]
            )
            #expect(!escapedResponse.ok)
            #expect(escapedResponse.error?.category == "invalidCharacter")
            #expect(throws: ScriptError.invalidJSON) {
                try Script(jsonBytes: escaped, limits: limits)
            }
        }
    }

    @Test("oracle limits stop oversized Script JSON values")
    func oracleBounds() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script JSON Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let exactScript = String(repeating: "00", count: 128 * 1024)
            let exactMarshal = try client.request(
                id: "script-json-exact-script-limit",
                operation: "script.json.marshal",
                arguments: ["bytes": .string(exactScript)]
            )
            #expect(exactMarshal.ok)
            let exactDocument = try #require(exactMarshal.result?.objectString(for: "json"))
            #expect(exactDocument.count == (256 * 1024 + 2) * 2)

            let exactUnmarshal = try client.request(
                id: "script-json-exact-document-limit",
                operation: "script.json.unmarshal",
                arguments: ["json": .string(exactDocument)]
            )
            #expect(exactUnmarshal.ok)
            #expect(exactUnmarshal.result?.objectString(for: "bytes") == exactScript)

            let scriptOverflow = try client.request(
                id: "script-json-script-limit",
                operation: "script.json.marshal",
                arguments: ["bytes": .string(String(repeating: "00", count: 128 * 1024 + 1))]
            )
            #expect(!scriptOverflow.ok)
            #expect(scriptOverflow.error?.category == "resourceLimit")

            let documentOverflow = try client.request(
                id: "script-json-document-limit",
                operation: "script.json.unmarshal",
                arguments: ["json": .string(String(repeating: "00", count: 256 * 1024 + 3))]
            )
            #expect(!documentOverflow.ok)
            #expect(documentOverflow.error?.category == "resourceLimit")
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
