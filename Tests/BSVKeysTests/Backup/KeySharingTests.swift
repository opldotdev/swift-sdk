import BSVCore
import BSVCrypto
@testable import BSVKeys
import Foundation
import Testing

@Suite("BRC-140 key sharing", .serialized)
struct KeySharingTests {
    @Test("2/2, 2/3, and 3/5 recover from every threshold-sized subset")
    func everySmallThresholdSubsetRecovers() throws {
        let key = try PrivateKey(scalar(42))
        for (threshold, shareCount) in [(2, 2), (2, 3), (3, 5)] {
            let shares = try KeySharing.split(
                key,
                threshold: threshold,
                shareCount: shareCount,
                using: DeterministicRandomSource(seed: UInt64(threshold * 100 + shareCount))
            )
            let subsets = combinations(shares, choosing: threshold)
            #expect(!subsets.isEmpty)
            for subset in subsets {
                #expect(try KeySharing.recover(subset) == key)
            }
        }
    }

    @Test("5/10 recovery accepts separated threshold shares")
    func fiveOfTenRecovers() throws {
        let key = try PrivateKey(scalar(99))
        let shares = try KeySharing.split(
            key,
            threshold: 5,
            shareCount: 10,
            using: DeterministicRandomSource(seed: 510)
        )
        #expect(try KeySharing.recover([shares[0], shares[2], shares[5], shares[7], shares[9]]) == key)
    }

    @Test("injected randomness is deterministic and requests exact lengths")
    func deterministicRandomnessAndExactDrawLengths() throws {
        let key = try PrivateKey(scalar(7))
        let firstSource = DeterministicRandomSource(seed: 0x1234_5678)
        let secondSource = DeterministicRandomSource(seed: 0x1234_5678)

        let first = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: 3,
            using: firstSource
        )
        let second = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: 3,
            using: secondSource
        )

        #expect(first == second)
        #expect(first.map(\.backupString) == second.map(\.backupString))
        #expect(firstSource.requestedCounts == [32, 32, 64, 32, 32, 32])
    }

    @Test("four-byte big-endian index and attempt derivation is locked")
    func bigEndianCounterDerivation() throws {
        #expect(try KeySharing.uint32BigEndian(0) == [0, 0, 0, 0])
        #expect(try KeySharing.uint32BigEndian(1) == [0, 0, 0, 1])
        #expect(try KeySharing.uint32BigEndian(0x0102_0304) == [1, 2, 3, 4])
        let key = try PrivateKey(scalar(7))
        let shares = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: 3,
            using: DeterministicRandomSource(seed: 0x1234_5678)
        )

        // SDK-owned deterministic regression value. This locks HMAC input as
        // uint32BE(index) || uint32BE(attempt) || random32, beginning at zero.
        #expect(
            shares[0].backupString
                == "kkSQeCUEahNtz7mYUk8naNP2rvbRJAqqJRzaX6aKoGs.9KUyCB65TBrp4k5iRLWXjN1HP7VKqwircCYYYZYfbSmp.2.5dedfbf9"
        )
    }

    @Test("random source failures, wrong lengths, and retry exhaustion are typed")
    func randomFailures() throws {
        let key = try PrivateKey(scalar(1))
        #expect(throws: KeyShareError.randomSourceFailure) {
            try KeySharing.split(
                key,
                threshold: 2,
                shareCount: 2,
                using: ThrowingRandomSource()
            )
        }
        #expect(throws: KeyShareError.invalidRandomByteCount(expected: 32, actual: 31)) {
            try KeySharing.split(
                key,
                threshold: 2,
                shareCount: 2,
                using: WrongCountRandomSource()
            )
        }
        #expect(throws: KeyShareError.coordinateGenerationExhausted) {
            try KeySharing.split(
                key,
                threshold: 2,
                shareCount: 2,
                using: ZeroRandomSource()
            )
        }
    }

    @Test("threshold and count bounds are exact in split and recover")
    func bounds() throws {
        let key = try PrivateKey(scalar(3))
        for (threshold, count) in [(1, 2), (2, 1), (3, 2), (0, 0), (-1, 2)] {
            #expect(
                throws: KeyShareError.invalidShareConfiguration(
                    threshold: threshold,
                    shareCount: count
                )
            ) {
                try KeySharing.split(
                    key,
                    threshold: threshold,
                    shareCount: count,
                    using: DeterministicRandomSource(seed: 1)
                )
            }
        }

        let limit = KeySharing.maximumShareCount
        let maximumShares = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: limit,
            using: DeterministicRandomSource(seed: 20)
        )
        #expect(maximumShares.count == limit)
        #expect(try KeySharing.recover(Array(maximumShares.prefix(2))) == key)
        #expect(throws: KeyShareError.shareCountExceedsMaximum(limit + 1)) {
            try KeySharing.split(
                key,
                threshold: 2,
                shareCount: limit + 1,
                using: DeterministicRandomSource(seed: 21)
            )
        }
        #expect(throws: KeyShareError.shareCountExceedsMaximum(limit + 1)) {
            try KeySharing.recover(
                Array(repeating: maximumShares[0], count: limit + 1)
            )
        }
    }

    @Test("parser accepts only canonical bounded share text")
    func strictParser() throws {
        let key = try PrivateKey(scalar(5))
        let share = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: 2,
            using: DeterministicRandomSource(seed: 22)
        )[0]
        #expect(try KeyShare(share.backupString) == share)
        #expect(try KeyShare(share.backupString).backupString == share.backupString)
        let secretFragment = String(share.backupString.split(separator: ".")[1])
        let described = String(describing: share)
        let reflected = String(reflecting: share)
        var dumped = ""
        dump(share, to: &dumped)
        #expect(described == "<redacted key share>")
        #expect(reflected == "<redacted key share>")
        #expect(dumped.contains("<redacted key share>"))
        #expect(Mirror(reflecting: share).children.isEmpty)
        for diagnostic in [described, reflected, dumped] {
            #expect(!diagnostic.contains(secretFragment))
            #expect(!diagnostic.contains(share.backupString))
        }

        for malformed in [
            "", ".", "2.3.2", "2.3.2.00000000.extra",
            ".3.2.00000000", "2..2.00000000", "2.3..00000000", "2.3.2.",
            String(repeating: "2", count: 102),
            String(repeating: "2", count: 1_000_000),
        ] {
            #expect(throws: KeyShareError.invalidFormat) {
                try KeyShare(malformed)
            }
        }
        #expect(throws: KeyShareError.invalidCoordinateEncoding) {
            try KeyShare("0.2.2.00000000")
        }
        #expect(throws: KeyShareError.nonCanonicalCoordinate) {
            try KeyShare("12.2.2.00000000")
        }
        #expect(throws: KeyShareError.invalidCoordinateEncoding) {
            try KeyShare("\(String(repeating: "z", count: 45)).2.2.00000000")
        }

        let fieldPrime = try Hex.decode(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            maximumDecodedByteCount: 32
        )
        #expect(throws: KeyShareError.coordinateOutOfRange) {
            try KeyShare("\(Base58.encode(fieldPrime)).2.2.00000000")
        }
        for threshold in ["0", "1", "02", "+2", "21", "999", "２"] {
            #expect(throws: KeyShareError.invalidThreshold) {
                try KeyShare("2.3.\(threshold).00000000")
            }
        }
        for integrity in ["0000000", "000000000", "ABCDEF12", "abcdefg0", "dead bee"] {
            #expect(throws: KeyShareError.invalidIntegrity) {
                try KeyShare("2.3.2.\(integrity)")
            }
        }
    }

    @Test("recovery rejects insufficient, duplicate, and incoherent shares")
    func recoveryValidation() throws {
        let key = try PrivateKey(scalar(11))
        let shares = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: 3,
            using: DeterministicRandomSource(seed: 23)
        )

        #expect(throws: KeyShareError.noShares) {
            try KeySharing.recover([])
        }
        #expect(throws: KeyShareError.insufficientShares(required: 2, actual: 1)) {
            try KeySharing.recover([shares[0]])
        }
        #expect(throws: KeyShareError.duplicateXCoordinate) {
            try KeySharing.recover([shares[0], shares[0]])
        }

        let thresholdFields = shares[1].backupString.split(separator: ".").map(String.init)
        let mixedThreshold = try KeyShare(
            "\(thresholdFields[0]).\(thresholdFields[1]).3.\(thresholdFields[3])"
        )
        #expect(throws: KeyShareError.mixedThresholds) {
            try KeySharing.recover([shares[0], mixedThreshold])
        }

        let integrityFields = shares[1].backupString.split(separator: ".").map(String.init)
        let replacementIntegrity = integrityFields[3] == "00000000" ? "00000001" : "00000000"
        let mixedIntegrity = try KeyShare(
            "\(integrityFields[0]).\(integrityFields[1]).2.\(replacementIntegrity)"
        )
        #expect(throws: KeyShareError.mixedIntegrity) {
            try KeySharing.recover([shares[0], mixedIntegrity])
        }
    }

    @Test("recovery rejects invalid scalars and conflicting extra shares")
    func invalidScalarAndConflictingExtra() throws {
        // The line through (1,1) and (2,2) evaluates to zero at x=0.
        let zeroSecretShares = [
            try KeyShare("2.2.2.00000000"),
            try KeyShare("3.3.2.00000000"),
        ]
        #expect(throws: KeyShareError.invalidRecoveredPrivateKey) {
            try KeySharing.recover(zeroSecretShares)
        }

        // This line evaluates to the secp256k1 scalar order at x=0.
        var orderPlusOne = try Hex.decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            maximumDecodedByteCount: 32
        )
        orderPlusOne[31] += 1
        var orderPlusTwo = orderPlusOne
        orderPlusTwo[31] += 1
        let orderSecretShares = [
            try KeyShare("2.\(Base58.encode(orderPlusOne)).2.00000000"),
            try KeyShare("3.\(Base58.encode(orderPlusTwo)).2.00000000"),
        ]
        #expect(throws: KeyShareError.invalidRecoveredPrivateKey) {
            try KeySharing.recover(orderSecretShares)
        }

        let key = try PrivateKey(scalar(13))
        let shares = try KeySharing.split(
            key,
            threshold: 2,
            shareCount: 3,
            using: DeterministicRandomSource(seed: 24)
        )
        let fields = shares[2].backupString.split(separator: ".").map(String.init)
        let replacementY = fields[1] == "2" ? "3" : "2"
        let conflicting = try KeyShare(
            "\(fields[0]).\(replacementY).\(fields[2]).\(fields[3])"
        )
        #expect(throws: KeyShareError.inconsistentShare) {
            try KeySharing.recover([shares[0], shares[1], conflicting])
        }

        let wrongIntegrity = try shares.prefix(2).map { share in
            let shareFields = share.backupString.split(separator: ".").map(String.init)
            let replacement = shareFields[3] == "00000000" ? "00000001" : "00000000"
            return try KeyShare(
                "\(shareFields[0]).\(shareFields[1]).\(shareFields[2]).\(replacement)"
            )
        }
        #expect(throws: KeyShareError.recoveredIntegrityMismatch) {
            try KeySharing.recover(wrongIntegrity)
        }
    }

    @Test("deterministic private keys recover across a threshold matrix")
    func propertyMatrix() throws {
        let scalars: [[UInt8]] = [
            scalar(1), scalar(2), scalar(42),
            try Hex.decode(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                maximumDecodedByteCount: 32
            ),
        ]
        let configurations = [(2, 2), (2, 3), (3, 5), (5, 10)]

        for (keyIndex, bytes) in scalars.enumerated() {
            let key = try PrivateKey(bytes)
            for (configurationIndex, configuration) in configurations.enumerated() {
                let shares = try KeySharing.split(
                    key,
                    threshold: configuration.0,
                    shareCount: configuration.1,
                    using: DeterministicRandomSource(
                        seed: UInt64(1_000 + keyIndex * 100 + configurationIndex)
                    )
                )
                #expect(try KeySharing.recover(Array(shares.prefix(configuration.0))) == key)
            }
        }
    }

    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }

    private func combinations<T>(_ values: [T], choosing count: Int) -> [[T]] {
        guard count > 0 else { return [[]] }
        guard count <= values.count else { return [] }
        if count == values.count { return [values] }
        guard let first = values.first else { return [] }
        let tail = Array(values.dropFirst())
        return combinations(tail, choosing: count - 1).map { [first] + $0 }
            + combinations(tail, choosing: count)
    }
}

private final class DeterministicRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var state: UInt64
    private var counts: [Int] = []

    init(seed: UInt64) {
        state = seed
    }

    func randomBytes(count: Int) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        counts.append(count)
        var result: [UInt8] = []
        result.reserveCapacity(count)
        for _ in 0..<count {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            result.append(UInt8(truncatingIfNeeded: state >> 56))
        }
        return result
    }

    var requestedCounts: [Int] {
        lock.lock()
        defer { lock.unlock() }
        return counts
    }
}

private struct ThrowingRandomSource: SecureRandomSource {
    private enum Failure: Error { case failed }

    func randomBytes(count _: Int) throws -> [UInt8] {
        throw Failure.failed
    }
}

private struct WrongCountRandomSource: SecureRandomSource {
    func randomBytes(count: Int) throws -> [UInt8] {
        [UInt8](repeating: 1, count: max(0, count - 1))
    }
}

private struct ZeroRandomSource: SecureRandomSource {
    func randomBytes(count: Int) throws -> [UInt8] {
        [UInt8](repeating: 0, count: count)
    }
}
