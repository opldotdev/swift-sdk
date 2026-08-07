import BSVCore
import BSVCrypto
import Foundation
import Testing

@Suite("HMACDRBGConformance", .serialized)
struct HMACDRBGConformanceTests {
    @Test("official NIST CAVP HMAC-DRBG SHA-256 case verifies through its manifest")
    func nistCAVPFixture() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first {
                $0.id == "nist-cavs14.3-hmac-drbg-sha256-no-reseed"
            }
        )
        #expect(group.source.url.contains("csrc.nist.gov"))
        #expect(group.source.revision.contains("CAVS 14.3"))
        #expect(group.license.identifier == "LicenseRef-NIST-Public-Domain")

        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        let vectors = try JSONDecoder().decode(
            [NISTHMACDRBGFixture].self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/NIST/HMACDRBG/hmac-drbg-sha256.json"
                )
            )
        )

        for vector in vectors {
            #expect(vector.count == 0)
            let entropy = try decodeHex(vector.entropy)
            let nonce = try decodeHex(vector.nonce)
            let expected = try decodeHex(vector.returnedBits)
            var generator = try HMACDRBG(entropy: entropy, nonce: nonce)
            _ = try generator.generate(count: vector.firstGenerateByteCount)
            #expect(
                try generator.generate(count: vector.secondGenerateByteCount)
                    == expected
            )
        }
    }

    @Test("one persistent Go oracle covers sequences, boundaries, reseed, errors, and deterministic differentials")
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
        func request(_ arguments: [String: GoOracleJSON]) throws -> GoOracleResponse {
            sequence += 1
            return try client.request(
                id: "hmac-drbg-\(sequence)",
                operation: "drbg.generate",
                arguments: arguments
            )
        }
        func generateAction(_ count: Int) -> GoOracleJSON {
            .object([
                "type": .string("generate"),
                "count": .string(String(count)),
            ])
        }
        func reseedAction(_ entropy: [UInt8]) -> GoOracleJSON {
            .object([
                "type": .string("reseed"),
                "entropy": .string(Hex.encode(entropy)),
            ])
        }

        let entropy = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 17 + 3) }
        let nonce: [UInt8] = [0xa0, 0xa1, 0xa2, 0xa3]
        let reseedEntropy = (0..<32).map {
            UInt8(truncatingIfNeeded: $0 * 29 + 7)
        }
        let actions = [
            generateAction(16),
            generateAction(0),
            generateAction(937),
            reseedAction(reseedEntropy),
            generateAction(64),
        ]

        var swift = try HMACDRBG(entropy: entropy, nonce: nonce)
        let swiftOutputs = [
            try swift.generate(count: 16),
            try swift.generate(count: 0),
            try swift.generate(count: 937),
        ]
        try swift.reseed(entropy: reseedEntropy)
        let allSwiftOutputs = swiftOutputs + [try swift.generate(count: 64)]

        let primaryResponse = try request([
            "entropy": .string(Hex.encode(entropy)),
            "nonce": .string(Hex.encode(nonce)),
            "actions": .array(actions),
        ])
        #expect(primaryResponse.ok)
        #expect(
            primaryResponse.result == .object([
                "outputs": .array(
                    allSwiftOutputs.map { .string(Hex.encode($0)) }
                ),
                "reseedCounter": .string(String(swift.reseedCounter)),
            ])
        )

        var state: UInt64 = 0x6a09_e667_f3bc_c909
        for caseIndex in 0..<12 {
            func nextByte() -> UInt8 {
                state = state &* 2_862_933_555_777_941_757 &+ 3_037_000_493
                return UInt8(truncatingIfNeeded: state >> 21)
            }
            let caseEntropy = (0..<(32 + caseIndex % 2)).map { _ in nextByte() }
            let caseNonce = (0..<(caseIndex % 7)).map { _ in nextByte() }
            let counts = [caseIndex, 31 + caseIndex, 64 + caseIndex * 3]
            var local = try HMACDRBG(entropy: caseEntropy, nonce: caseNonce)
            var expectedOutputs: [[UInt8]] = []
            var caseActions: [GoOracleJSON] = []
            for count in counts {
                expectedOutputs.append(try local.generate(count: count))
                caseActions.append(generateAction(count))
            }
            if caseIndex.isMultiple(of: 3) {
                let freshEntropy = (0..<32).map { _ in nextByte() }
                try local.reseed(entropy: freshEntropy)
                caseActions.append(reseedAction(freshEntropy))
                expectedOutputs.append(try local.generate(count: 33))
                caseActions.append(generateAction(33))
            }

            let response = try request([
                "entropy": .string(Hex.encode(caseEntropy)),
                "nonce": .string(Hex.encode(caseNonce)),
                "actions": .array(caseActions),
            ])
            #expect(response.ok)
            #expect(
                response.result == .object([
                    "outputs": .array(
                        expectedOutputs.map { .string(Hex.encode($0)) }
                    ),
                    "reseedCounter": .string(String(local.reseedCounter)),
                ])
            )
        }

        let shortEntropy = [UInt8](repeating: 0, count: 31)
        let shortInitialization = try request([
            "entropy": .string(Hex.encode(shortEntropy)),
            "nonce": .string(""),
            "actions": .array([]),
        ])
        #expect(!shortInitialization.ok)
        #expect(shortInitialization.error?.category == "insufficientEntropy")

        let negative = try request([
            "entropy": .string(Hex.encode(entropy)),
            "nonce": .string(""),
            "actions": .array([generateAction(-1)]),
        ])
        #expect(!negative.ok)
        #expect(negative.error?.category == "invalidRequestedByteCount")

        let oversized = try request([
            "entropy": .string(Hex.encode(entropy)),
            "nonce": .string(""),
            "actions": .array([generateAction(938)]),
        ])
        #expect(!oversized.ok)
        #expect(oversized.error?.category == "requestTooLarge")

        let shortReseed = try request([
            "entropy": .string(Hex.encode(entropy)),
            "nonce": .string(""),
            "actions": .array([reseedAction(shortEntropy)]),
        ])
        #expect(!shortReseed.ok)
        #expect(shortReseed.error?.category == "insufficientEntropy")

        let tooManyActions = (0...HMACDRBG.maximumRequestsBeforeReseed).map {
            _ in generateAction(0)
        }
        let reseedRequired = try request([
            "entropy": .string(Hex.encode(entropy)),
            "nonce": .string(""),
            "actions": .array(tooManyActions),
        ])
        #expect(!reseedRequired.ok)
        #expect(reseedRequired.error?.category == "reseedRequired")
    }
}

private struct NISTHMACDRBGFixture: Decodable {
    let count: Int
    let entropy: String
    let nonce: String
    let firstGenerateByteCount: Int
    let secondGenerateByteCount: Int
    let returnedBits: String
}

private func decodeHex(_ text: String) throws -> [UInt8] {
    try Hex.decode(text, maximumDecodedByteCount: text.utf8.count / 2)
}
