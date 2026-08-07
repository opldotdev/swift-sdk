import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("Base58CheckConformance", .serialized)
struct Base58CheckConformanceTests {
    @Test("direct bsvutil Base58Check vectors verify through their strict manifest")
    func permissiveFixtures() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "bsvutil-base58check-1d77cf353ea9" }
        )
        #expect(group.source.revision == "v0.0.0-20181216182056-1d77cf353ea9")
        #expect(group.license.identifier == "ISC")
        #expect(group.license.file == "Licenses/bsvutil-isc.txt")

        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        let vectors = try JSONDecoder().decode(
            [Base58CheckFixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/BSVUtil/Base58Check/base58check.json"
                )
            )
        )
        #expect(vectors.count == 11)

        for vector in vectors {
            let payloadBytes = try Hex.decode(
                vector.payload,
                maximumDecodedByteCount: vector.payload.utf8.count / 2
            )
            let payload = [vector.version] + payloadBytes
            #expect(Base58Check.encode(payload) == vector.encoded)
            #expect(
                try Base58Check.decode(
                    vector.encoded,
                    maximumPayloadByteCount: payload.count
                ) == payload
            )
        }
    }

    @Test("persistent Go oracle covers success, negative decoding, and size policy")
    func persistentGoOracleDifferentials() throws {
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

        var sequence = 0
        func request(
            _ operation: String,
            _ arguments: [String: GoOracleJSON]
        ) throws -> GoOracleResponse {
            sequence += 1
            return try client.request(
                id: "base58check-\(sequence)",
                operation: operation,
                arguments: arguments
            )
        }

        let cases: [[UInt8]] = [
            [0],
            [0] + [UInt8](repeating: 0, count: 20),
            [20, 0x61, 0x62, 0x63],
            [0xff, 0x00, 0x80, 0x01, 0xfe],
            [111] + (0..<32).map { UInt8(truncatingIfNeeded: $0 * 37 + 11) },
        ]

        for payload in cases {
            let version = payload[0]
            let body = Array(payload.dropFirst())
            let text = Base58Check.encode(payload)
            let encoded = try request(
                "base58check.encode",
                [
                    "payload": .string(Hex.encode(body)),
                    "version": .string(String(version)),
                ]
            )
            #expect(encoded.ok)
            #expect(encoded.result == .object(["text": .string(text)]))

            let decoded = try request(
                "base58check.decode",
                ["text": .string(text)]
            )
            #expect(decoded.ok)
            #expect(
                decoded.result == .object([
                    "payload": .string(Hex.encode(body)),
                    "version": .string(String(version)),
                ])
            )
            #expect(
                try Base58Check.decode(
                    text,
                    maximumPayloadByteCount: payload.count
                ) == payload
            )
        }

        let validPayload: [UInt8] = [20, 0x61, 0x62, 0x63]
        let validText = Base58Check.encode(validPayload)
        var corruptBytes = try Base58.decode(
            validText,
            maximumDecodedByteCount: validPayload.count + 4
        )
        corruptBytes[corruptBytes.count - 1] ^= 1
        let corruptText = Base58.encode(corruptBytes)
        #expect(throws: Base58CheckError.checksumMismatch) {
            try Base58Check.decode(
                corruptText,
                maximumPayloadByteCount: validPayload.count
            )
        }
        let checksumResponse = try request(
            "base58check.decode",
            ["text": .string(corruptText)]
        )
        #expect(!checksumResponse.ok)
        #expect(checksumResponse.error?.category == "checksum")

        #expect(
            throws: Base58CheckError.invalidEncoding(
                .invalidCharacter(index: 2)
            )
        ) {
            try Base58Check.decode("12O3", maximumPayloadByteCount: 8)
        }
        let alphabetResponse = try request(
            "base58check.decode",
            ["text": .string("12O3")]
        )
        #expect(!alphabetResponse.ok)
        #expect(alphabetResponse.error?.category == "invalidCharacter")

        #expect(
            throws: Base58CheckError.payloadSizeLimitExceeded(
                maximum: validPayload.count - 1
            )
        ) {
            try Base58Check.decode(
                validText,
                maximumPayloadByteCount: validPayload.count - 1
            )
        }
        let unboundedOracleResponse = try request(
            "base58check.decode",
            ["text": .string(validText)]
        )
        #expect(unboundedOracleResponse.ok)
    }
}

private struct Base58CheckFixture: Decodable {
    let version: UInt8
    let payload: String
    let encoded: String
}
