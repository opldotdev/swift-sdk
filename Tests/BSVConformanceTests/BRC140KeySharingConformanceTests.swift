import BSVCore
import BSVCrypto
import BSVKeys
import Foundation
import Testing

@Suite("BRC140KeySharingConformance", .serialized)
struct BRC140KeySharingConformanceTests {
    @Test("public canonical text round-trips and recovers")
    func publicRoundTrip() throws {
        let privateKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [42])
        let shares = try KeySharing.split(
            privateKey,
            threshold: 3,
            shareCount: 5,
            using: BRC140DeterministicRandomSource(seed: 140)
        )

        let reparsed = try shares.map { try KeyShare($0.backupString) }
        #expect(reparsed.map(\.backupString) == shares.map(\.backupString))
        #expect(reparsed.allSatisfy { $0.description == "<redacted key share>" })
        #expect(reparsed.allSatisfy { String(reflecting: $0) == "<redacted key share>" })
        #expect(try KeySharing.recover([reparsed[0], reparsed[2], reparsed[4]]) == privateKey)
    }

    @Test("Swift and fresh pinned-Go shares recover bidirectionally")
    func pinnedGoDifferential() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let availableClient):
            client = availableClient
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BRC-140 Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        let configurations = [
            (threshold: 2, shareCount: 3, scalar: UInt8(42)),
            (threshold: 3, shareCount: 5, scalar: UInt8(43)),
            (threshold: 5, shareCount: 10, scalar: UInt8(44)),
        ]

        for (caseIndex, item) in configurations.enumerated() {
            let privateKey = try PrivateKey(scalar(item.scalar))
            let swiftShares = try KeySharing.split(
                privateKey,
                threshold: item.threshold,
                shareCount: item.shareCount,
                using: BRC140DeterministicRandomSource(seed: UInt64(1_400 + caseIndex))
            )
            let goRecovery = try client.request(
                id: "brc140-swift-recover-\(caseIndex)",
                operation: "keyshares.recover",
                arguments: [
                    "shares": .array(swiftShares.map { .string($0.backupString) }),
                ]
            )
            #expect(
                try oracleString(goRecovery.result, field: "privateKey")
                    == Hex.encode(privateKey.bytes)
            )

            let goSplit = try client.request(
                id: "brc140-go-split-\(caseIndex)",
                operation: "keyshares.split",
                arguments: [
                    "privateKey": .string(Hex.encode(privateKey.bytes)),
                    "threshold": .string(String(item.threshold)),
                    "shareCount": .string(String(item.shareCount)),
                ]
            )
            let goShareStrings = try oracleStrings(goSplit.result, field: "shares")
            #expect(goShareStrings.count == item.shareCount)
            let goShares = try goShareStrings.map(KeyShare.init)
            #expect(goShares.map(\.backupString) == goShareStrings)

            for (subsetIndex, indexes) in subsetIndexes(
                threshold: item.threshold,
                shareCount: item.shareCount
            ).enumerated() {
                let subset = indexes.map { goShares[$0] }
                #expect(try KeySharing.recover(subset) == privateKey)

                let goSubsetRecovery = try client.request(
                    id: "brc140-go-subset-\(caseIndex)-\(subsetIndex)",
                    operation: "keyshares.recover",
                    arguments: [
                        "shares": .array(subset.map { .string($0.backupString) }),
                    ]
                )
                #expect(
                    try oracleString(goSubsetRecovery.result, field: "privateKey")
                        == Hex.encode(privateKey.bytes)
                )
            }
        }

        let corruptionKey = try PrivateKey(scalar(51))
        let splitResponse = try client.request(
            id: "brc140-corruption-split",
            operation: "keyshares.split",
            arguments: [
                "privateKey": .string(Hex.encode(corruptionKey.bytes)),
                "threshold": .string("2"),
                "shareCount": .string("3"),
            ]
        )
        let validShares = try oracleStrings(splitResponse.result, field: "shares")
        var fields = validShares[0].split(separator: ".").map(String.init)
        fields[0] = "0"
        let corruptShare = fields.joined(separator: ".")
        #expect(throws: KeyShareError.invalidCoordinateEncoding) {
            try KeyShare(corruptShare)
        }

        let rejected = try client.request(
            id: "brc140-corruption-recover",
            operation: "keyshares.recover",
            arguments: [
                "shares": .array([.string(corruptShare), .string(validShares[1])]),
            ]
        )
        #expect(!rejected.ok)
        #expect(rejected.error?.category == "invalidEncoding")
    }

    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }

    private func subsetIndexes(threshold: Int, shareCount: Int) -> [[Int]] {
        let first = Array(0..<threshold)
        let last = Array((shareCount - threshold)..<shareCount)
        let spread = (0..<threshold).map { index in
            index * (shareCount - 1) / (threshold - 1)
        }
        return first == last ? [first] : [first, last, spread]
    }

    private func oracleStrings(_ result: GoOracleJSON?, field: String) throws -> [String] {
        guard case .object(let fields) = result,
              case .array(let values) = fields[field]
        else {
            throw BRC140OracleConformanceError.unexpectedResult
        }
        return try values.map { value in
            guard case .string(let text) = value else {
                throw BRC140OracleConformanceError.unexpectedResult
            }
            return text
        }
    }

    private func oracleString(_ result: GoOracleJSON?, field: String) throws -> String {
        guard case .object(let fields) = result,
              case .string(let text) = fields[field]
        else {
            throw BRC140OracleConformanceError.unexpectedResult
        }
        return text
    }
}

private enum BRC140OracleConformanceError: Error {
    case unexpectedResult
}

private final class BRC140DeterministicRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    func randomBytes(count: Int) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)
        for _ in 0..<count {
            state = state &* 2_862_933_555_777_941_757 &+ 3_037_000_493
            bytes.append(UInt8(truncatingIfNeeded: state >> 56))
        }
        return bytes
    }
}
