import BSVCore
import Foundation
import Testing

@Suite("EncodingConformance", .serialized)
struct EncodingConformanceTests {
    @Test("permissive fixture manifests and selected vectors verify")
    func permissiveFixtures() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let groups = Dictionary(uniqueKeysWithValues: manifest.groups.map { ($0.id, $0) })
        #expect(groups["go-stdlib-encoding-go1.24.3"]?.source.revision == "go1.24.3")
        #expect(groups["go-stdlib-encoding-go1.24.3"]?.license.identifier == "BSD-3-Clause")
        #expect(
            groups["bsvutil-base58-1d77cf353ea9"]?.source.revision
                == "v0.0.0-20181216182056-1d77cf353ea9"
        )
        #expect(groups["bsvutil-base58-1d77cf353ea9"]?.license.identifier == "ISC")

        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        let decoder = JSONDecoder()

        let hexVectors = try decoder.decode(
            [HexFixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/GoStdlib/Encoding/hex.json"
                )
            )
        )
        for vector in hexVectors {
            let bytes = try Hex.decode(
                vector.bytes,
                maximumDecodedByteCount: vector.bytes.utf8.count / 2
            )
            #expect(Hex.encode(bytes) == vector.encoded.lowercased())
            #expect(
                try Hex.decode(vector.encoded, maximumDecodedByteCount: bytes.count) == bytes
            )
        }

        let base64Vectors = try decoder.decode(
            [Base64Fixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/GoStdlib/Encoding/base64.json"
                )
            )
        )
        for vector in base64Vectors {
            let bytes = try Hex.decode(
                vector.bytes,
                maximumDecodedByteCount: vector.bytes.utf8.count / 2
            )
            #expect(Base64Encoding.encode(bytes) == vector.standard)
            #expect(Base64Encoding.encode(bytes, alphabet: .urlSafe) == vector.urlSafe)
            #expect(Base64Encoding.encode(bytes, padding: .omitted) == vector.rawStandard)
            #expect(
                Base64Encoding.encode(bytes, alphabet: .urlSafe, padding: .omitted)
                    == vector.rawURLSafe
            )
            #expect(
                try Base64Encoding.decode(
                    vector.standard,
                    maximumDecodedByteCount: bytes.count
                ) == bytes
            )
            #expect(
                try Base64Encoding.decode(
                    vector.urlSafe,
                    alphabet: .urlSafe,
                    maximumDecodedByteCount: bytes.count
                ) == bytes
            )
            #expect(
                try Base64Encoding.decode(
                    vector.rawStandard,
                    padding: .omitted,
                    maximumDecodedByteCount: bytes.count
                ) == bytes
            )
            #expect(
                try Base64Encoding.decode(
                    vector.rawURLSafe,
                    alphabet: .urlSafe,
                    padding: .omitted,
                    maximumDecodedByteCount: bytes.count
                ) == bytes
            )
        }

        let base58Vectors = try decoder.decode(
            [Base58Fixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/BSVUtil/Base58/base58.json"
                )
            )
        )
        for vector in base58Vectors {
            let bytes = try Hex.decode(
                vector.bytes,
                maximumDecodedByteCount: vector.bytes.utf8.count / 2
            )
            #expect(Base58.encode(bytes) == vector.encoded)
            #expect(
                try Base58.decode(vector.encoded, maximumDecodedByteCount: bytes.count) == bytes
            )
        }
    }

    @Test("persistent Go oracle: hex, strict standard-padded Base64, and raw Base58")
    func strictStandardPaddedGoOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        let availability = try GoOracleClient.connect(configuration: configuration)
        let client: GoOracleClient
        switch availability {
        case .available(let availableClient):
            client = availableClient
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        let cases: [[UInt8]] = [
            [],
            [0],
            [0, 1],
            [0xfb, 0xff, 0xfe],
            Array("strict standard padded differential".utf8),
            (0..<32).map { UInt8(truncatingIfNeeded: $0 * 29 + 7) },
        ]
        var sequence = 0
        func request(
            _ operation: String,
            _ arguments: [String: GoOracleJSON]
        ) throws -> GoOracleJSON {
            sequence += 1
            let response = try client.request(
                id: "encoding-\(sequence)",
                operation: operation,
                arguments: arguments
            )
            #expect(response.ok)
            return try #require(response.result)
        }

        for bytes in cases {
            let hexadecimal = Hex.encode(bytes)
            let base64 = Base64Encoding.encode(
                bytes,
                alphabet: .standard,
                padding: .included
            )
            let base58 = Base58.encode(bytes)

            #expect(
                try request("hex.encode", ["bytes": .string(hexadecimal)])
                    == .object(["text": .string(hexadecimal)])
            )
            #expect(
                try request("hex.decode", ["text": .string(hexadecimal.uppercased())])
                    == .object(["bytes": .string(hexadecimal)])
            )
            #expect(
                try request("base64.encode", ["bytes": .string(hexadecimal)])
                    == .object(["text": .string(base64)])
            )
            #expect(
                try request("base64.decode", ["text": .string(base64)])
                    == .object(["bytes": .string(hexadecimal)])
            )
            #expect(
                try request("base58.encode", ["bytes": .string(hexadecimal)])
                    == .object(["text": .string(base58)])
            )
            #expect(
                try request("base58.decode", ["text": .string(base58)])
                    == .object(["bytes": .string(hexadecimal)])
            )
        }
    }

    @Test("strict Swift negative policy differs explicitly from pinned Go SDK decoding")
    func strictSwiftNegativeGoSDKDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        let availability = try GoOracleClient.connect(configuration: configuration)
        let client: GoOracleClient
        switch availability {
        case .available(let availableClient):
            client = availableClient
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        #expect(throws: TextEncodingError.invalidCharacter(index: 2)) {
            try Base64Encoding.decode("Zm\n9v", maximumDecodedByteCount: 3)
        }
        let newlineResponse = try client.request(
            id: "encoding-negative-1",
            operation: "base64.decode",
            arguments: ["text": .string("Zm\n9v"), "policy": .string("goSDK")]
        )
        #expect(newlineResponse.ok)
        #expect(newlineResponse.result == .object(["bytes": .string("666f6f")]))

        #expect(throws: TextEncodingError.nonCanonicalEncoding) {
            try Base64Encoding.decode("Zh==", maximumDecodedByteCount: 1)
        }
        let discardedBitsResponse = try client.request(
            id: "encoding-negative-2",
            operation: "base64.decode",
            arguments: ["text": .string("Zh=="), "policy": .string("goSDK")]
        )
        #expect(discardedBitsResponse.ok)
        #expect(discardedBitsResponse.result == .object(["bytes": .string("66")]))

        #expect(throws: TextEncodingError.invalidCharacter(index: 1)) {
            try Base58.decode("20", maximumDecodedByteCount: 2)
        }
        let base58Response = try client.request(
            id: "encoding-negative-3",
            operation: "base58.decode",
            arguments: ["text": .string("20")]
        )
        #expect(!base58Response.ok)
        #expect(base58Response.error?.category == "invalidCharacter")
    }
}

private struct HexFixture: Decodable {
    let encoded: String
    let bytes: String
}

private struct Base64Fixture: Decodable {
    let bytes: String
    let standard: String
    let urlSafe: String
    let rawStandard: String
    let rawURLSafe: String
}

private struct Base58Fixture: Decodable {
    let bytes: String
    let encoded: String
}
