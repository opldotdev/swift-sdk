import BSVScript
import Foundation
import Testing

@Suite("ScriptNumberConformance", .serialized)
struct ScriptNumberConformanceTests {
    @Test("BTCD provenance and content hashes verify")
    func manifestVerification() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "script-number-btcd-v0.24.2" }
        )
        #expect(group.source.url == "https://github.com/btcsuite/btcd")
        #expect(group.source.revision == "v0.24.2")
        #expect(group.license.identifier == "ISC")
        #expect(group.license.file == "Licenses/btcd-isc.txt")
        #expect(
            group.license.sha256
                == "73b368e7df1c52ce72711298096da6dd1509a9e261b53f864d721992b3da3eb7"
        )
        let file = try #require(group.files.first)
        #expect(file.originalPath == "txscript/scriptnum_test.go")
        #expect(file.localPath == "Permissive/BTCD/ScriptNumber/script-number.json")
        #expect(
            file.sha256
                == "7e9de04d60ed17c6af36c574c15d146955748f98828d885807b1e3a948ac9986"
        )
    }

    @Test("Permissive BTCD vectors match the public Swift API")
    func staticVectors() throws {
        let fixture = try loadScriptNumberFixture()
        for testCase in fixture.canonical {
            let integer = try #require(Int64(testCase.value))
            let image = try scriptNumberHex(testCase.hex)
            let value = try ScriptNumber(
                encoded: image,
                maximumByteCount: image.count,
                requireMinimal: true
            )
            #expect(value.int64Clamped() == integer)
            #expect(try value.serialized(maximumByteCount: image.count) == image)
        }

        for testCase in fixture.nonMinimal {
            let integer = try #require(Int64(testCase.value))
            let image = try scriptNumberHex(testCase.hex)
            let canonical = try scriptNumberHex(testCase.canonicalHex)
            #expect(throws: ScriptNumberError.nonMinimalEncoding) {
                try ScriptNumber(
                    encoded: image,
                    maximumByteCount: image.count,
                    requireMinimal: true
                )
            }
            let value = try ScriptNumber(
                encoded: image,
                maximumByteCount: image.count,
                requireMinimal: false
            )
            #expect(value.int64Clamped() == integer)
            #expect(try value.serialized(maximumByteCount: canonical.count) == canonical)
        }
    }

    @Test("Pinned Go oracle agrees on encode, strict decode, and permissive decode")
    func goOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Script number Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let fixture = try loadScriptNumberFixture()
            var sequence = 0

            for testCase in fixture.canonical {
                sequence += 1
                let encode = try client.request(
                    id: "script-number-encode-\(sequence)",
                    operation: "scriptnum.encode",
                    arguments: [
                        "value": .string(testCase.value),
                        "era": .string("postGenesis"),
                    ]
                )
                #expect(encode.ok)
                #expect(encode.result == .object(["bytes": .string(testCase.hex)]))

                let decode = try client.request(
                    id: "script-number-decode-\(sequence)",
                    operation: "scriptnum.decode",
                    arguments: [
                        "bytes": .string(testCase.hex),
                        "era": .string("postGenesis"),
                        "minimal": .bool(true),
                        "maxBytes": .string(String(max(1, testCase.hex.count / 2))),
                    ]
                )
                #expect(decode.ok)
                #expect(decode.result == .object(["value": .string(testCase.value)]))
            }

            for testCase in fixture.nonMinimal {
                sequence += 1
                let decode = try client.request(
                    id: "script-number-permissive-\(sequence)",
                    operation: "scriptnum.decode",
                    arguments: [
                        "bytes": .string(testCase.hex),
                        "era": .string("postGenesis"),
                        "minimal": .bool(false),
                        "maxBytes": .string(String(testCase.hex.count / 2)),
                    ]
                )
                #expect(decode.ok)
                #expect(decode.result == .object(["value": .string(testCase.value)]))
            }
        }
    }
}

private struct ScriptNumberFixture: Decodable {
    let canonical: [ScriptNumberFixtureCase]
    let nonMinimal: [NonMinimalScriptNumberFixtureCase]
}

private struct ScriptNumberFixtureCase: Decodable {
    let value: String
    let hex: String
}

private struct NonMinimalScriptNumberFixtureCase: Decodable {
    let value: String
    let hex: String
    let canonicalHex: String
}

private enum ScriptNumberFixtureError: Error {
    case fixtureRootUnavailable
    case invalidHex(String)
}

private func loadScriptNumberFixture() throws -> ScriptNumberFixture {
    guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw ScriptNumberFixtureError.fixtureRootUnavailable
    }
    let url = root.appendingPathComponent(
        "Permissive/BTCD/ScriptNumber/script-number.json",
        isDirectory: false
    )
    return try JSONDecoder().decode(
        ScriptNumberFixture.self,
        from: Data(contentsOf: url, options: [.mappedIfSafe])
    )
}

private func scriptNumberHex(_ text: String) throws -> [UInt8] {
    guard text.utf8.count.isMultiple(of: 2) else {
        throw ScriptNumberFixtureError.invalidHex(text)
    }
    var result: [UInt8] = []
    result.reserveCapacity(text.utf8.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<end], radix: 16) else {
            throw ScriptNumberFixtureError.invalidHex(text)
        }
        result.append(byte)
        index = end
    }
    return result
}
