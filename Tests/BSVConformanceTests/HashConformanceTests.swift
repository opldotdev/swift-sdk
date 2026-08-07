import BSVCore
import BSVCrypto
import Foundation
import Testing

@Suite("HashConformance", .serialized)
struct HashConformanceTests {
    @Test("pinned permissive hashing fixtures and manifests verify")
    func permissiveFixtures() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let groups = Dictionary(uniqueKeysWithValues: manifest.groups.map { ($0.id, $0) })

        let swiftCrypto = try #require(groups["swift-crypto-hashing-4.5.1"])
        #expect(swiftCrypto.source.revision == "47d3869a7291f085c1fb9fb1e6d3b97a793f45c6")
        #expect(swiftCrypto.license.identifier == "Apache-2.0")
        #expect(
            swiftCrypto.license.sha256
                == "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
        )

        let xcrypto = try #require(groups["xcrypto-ripemd160-v0.54.0"])
        #expect(xcrypto.source.revision == "v0.54.0")
        #expect(xcrypto.license.identifier == "BSD-3-Clause")
        #expect(
            xcrypto.license.sha256
                == "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
        )

        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        let decoder = JSONDecoder()

        let sha2 = try decoder.decode(
            [SHA2Fixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/SwiftCrypto/Hashing/sha2.json"
                )
            )
        )
        #expect(sha2.count == 2)
        for vector in sha2 {
            let message = Array(vector.messageUTF8.utf8)
            #expect(Hex.encode(BSVHashing.sha256(message).bytes) == vector.sha256)
            #expect(Hex.encode(BSVHashing.sha512(message).bytes) == vector.sha512)
        }

        let hmac = try decoder.decode(
            [HMACFixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/SwiftCrypto/Hashing/hmac-rfc4231.json"
                )
            )
        )
        #expect(hmac.count == 4)
        for vector in hmac {
            let key = try vector.keyBytes()
            let message = Array(vector.messageUTF8.utf8)
            #expect(Hex.encode(BSVHashing.hmacSHA256(message, key: key).bytes) == vector.sha256)
            #expect(Hex.encode(BSVHashing.hmacSHA512(message, key: key).bytes) == vector.sha512)
        }

        let ripemd160 = try decoder.decode(
            [RIPEMD160Fixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/XCrypto/RIPEMD160/vectors.json"
                )
            )
        )
        #expect(ripemd160.count == 9)
        for vector in ripemd160 {
            let message = vector.messageBytes()
            #expect(Hex.encode(BSVHashing.ripemd160(message).bytes) == vector.digest)
        }
    }

    @Test("persistent Go oracle differentials for every hash and HMAC operation")
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
            operation: String,
            arguments: [String: GoOracleJSON],
            expectedBytes: [UInt8]
        ) throws {
            sequence += 1
            let response = try client.request(
                id: "hashing-\(sequence)",
                operation: operation,
                arguments: arguments
            )
            #expect(response.ok)
            #expect(
                response.result == .object(["bytes": .string(Hex.encode(expectedBytes))])
            )
        }

        let hashCases: [[UInt8]] = [
            [],
            [0],
            Array("abc".utf8),
            deterministicBytes(count: 63),
            deterministicBytes(count: 64),
            deterministicBytes(count: 65),
            deterministicBytes(count: 127),
            deterministicBytes(count: 128),
            deterministicBytes(count: 129),
            deterministicBytes(count: 257),
        ]
        for message in hashCases {
            let arguments = ["bytes": GoOracleJSON.string(Hex.encode(message))]
            try request(
                operation: "hash.sha256",
                arguments: arguments,
                expectedBytes: BSVHashing.sha256(message).bytes
            )
            try request(
                operation: "hash.sha256d",
                arguments: arguments,
                expectedBytes: BSVHashing.sha256d(message).bytes
            )
            try request(
                operation: "hash.sha512",
                arguments: arguments,
                expectedBytes: BSVHashing.sha512(message).bytes
            )
            try request(
                operation: "hash.ripemd160",
                arguments: arguments,
                expectedBytes: BSVHashing.ripemd160(message).bytes
            )
            try request(
                operation: "hash.hash160",
                arguments: arguments,
                expectedBytes: BSVHashing.hash160(message).bytes
            )
        }

        let hmacCases: [(key: [UInt8], message: [UInt8])] = [
            ([], []),
            ([], Array("message with empty key".utf8)),
            (Array("key".utf8), []),
            (deterministicBytes(count: 63), deterministicBytes(count: 65)),
            (deterministicBytes(count: 64), deterministicBytes(count: 128)),
            (deterministicBytes(count: 65), deterministicBytes(count: 129)),
            (deterministicBytes(count: 127), deterministicBytes(count: 127)),
            (deterministicBytes(count: 128), deterministicBytes(count: 128)),
            (deterministicBytes(count: 131), deterministicBytes(count: 257)),
        ]
        for testCase in hmacCases {
            let arguments = [
                "key": GoOracleJSON.string(Hex.encode(testCase.key)),
                "message": GoOracleJSON.string(Hex.encode(testCase.message)),
            ]
            try request(
                operation: "hmac.sha256",
                arguments: arguments,
                expectedBytes: BSVHashing.hmacSHA256(testCase.message, key: testCase.key).bytes
            )
            try request(
                operation: "hmac.sha512",
                arguments: arguments,
                expectedBytes: BSVHashing.hmacSHA512(testCase.message, key: testCase.key).bytes
            )
        }
    }
}

private struct SHA2Fixture: Decodable {
    let messageUTF8: String
    let sha256: String
    let sha512: String
}

private struct HMACFixture: Decodable {
    let keyByte: String?
    let keyCount: Int?
    let keyUTF8: String?
    let messageUTF8: String
    let sha256: String
    let sha512: String

    func keyBytes() throws -> [UInt8] {
        let hasRepeatedByteEncoding = keyByte != nil || keyCount != nil
        if keyUTF8 != nil, hasRepeatedByteEncoding {
            Issue.record("HMAC fixture must define exactly one key encoding")
            throw FixtureShapeError.ambiguousHMACKey
        }
        if let keyUTF8 {
            return Array(keyUTF8.utf8)
        }
        guard keyByte != nil, keyCount != nil else {
            Issue.record("HMAC fixture is missing its key encoding")
            throw FixtureShapeError.missingHMACKey
        }
        let encodedByte = try #require(keyByte)
        let count = try #require(keyCount)
        let decoded = try Hex.decode(encodedByte, maximumDecodedByteCount: 1)
        let byte = try #require(decoded.first)
        return Array(repeating: byte, count: count)
    }
}

private enum FixtureShapeError: Error {
    case ambiguousHMACKey
    case missingHMACKey
}

private struct RIPEMD160Fixture: Decodable {
    let messageUTF8: String
    let repeatCount: Int
    let digest: String

    private enum CodingKeys: String, CodingKey {
        case messageUTF8
        case repeatCount = "repeat"
        case digest
    }

    func messageBytes() -> [UInt8] {
        let unit = Array(messageUTF8.utf8)
        if repeatCount == 1 { return unit }
        if unit.count == 1, let byte = unit.first {
            return Array(repeating: byte, count: repeatCount)
        }
        var result: [UInt8] = []
        for _ in 0..<repeatCount {
            result.append(contentsOf: unit)
        }
        return result
    }
}

private func deterministicBytes(count: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ 7) }
}
