import BSVBigNum
import BSVCore
import BSVCrypto

/// Errors produced while parsing, splitting, or recovering BRC-140 key shares.
public enum KeyShareError: Error, Equatable, Sendable {
    case invalidFormat
    case invalidCoordinateEncoding
    case nonCanonicalCoordinate
    case coordinateOutOfRange
    case invalidThreshold
    case invalidIntegrity
    case invalidShareConfiguration(threshold: Int, shareCount: Int)
    case shareCountExceedsMaximum(Int)
    case randomSourceFailure
    case invalidRandomByteCount(expected: Int, actual: Int)
    case coordinateGenerationExhausted
    case noShares
    case insufficientShares(required: Int, actual: Int)
    case mixedThresholds
    case mixedIntegrity
    case duplicateXCoordinate
    case inconsistentShare
    case arithmeticFailure
    case invalidRecoveredPrivateKey
    case recoveredIntegrityMismatch
}

/// A strict, canonical BRC-140 private-key share.
public struct KeyShare:
    Hashable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    /// The number of coherent shares required to recover the private key.
    public let threshold: Int

    /// The first eight lowercase hexadecimal characters of the recovered key's
    /// compressed-public-key HASH160.
    public let integrity: String

    private let x: BigMagnitude
    private let y: BigMagnitude
    private let xText: String
    private let yText: String

    /// Parses an exact canonical BRC-140 share string.
    public init(_ text: String) throws {
        // 44 + 44 Base58 digits, two threshold digits, eight integrity digits,
        // and three separators is the largest accepted representation.
        guard text.utf8.prefix(102).count <= 101 else {
            throw KeyShareError.invalidFormat
        }
        let fields = text.split(separator: ".", omittingEmptySubsequences: false)
        guard fields.count == 4, fields.allSatisfy({ !$0.isEmpty }) else {
            throw KeyShareError.invalidFormat
        }

        let parsedX = try Self.parseCoordinate(String(fields[0]))
        let parsedY = try Self.parseCoordinate(String(fields[1]))
        let parsedThreshold = try Self.parseThreshold(String(fields[2]))
        let parsedIntegrity = String(fields[3])
        guard Self.isCanonicalIntegrity(parsedIntegrity) else {
            throw KeyShareError.invalidIntegrity
        }

        x = parsedX
        y = parsedY
        xText = String(fields[0])
        yText = String(fields[1])
        threshold = parsedThreshold
        integrity = parsedIntegrity
    }

    fileprivate init(
        x: BigMagnitude,
        y: BigMagnitude,
        threshold: Int,
        integrity: String
    ) throws {
        do {
            xText = Base58.encode(try x.bigEndianBytes(maximumByteCount: 32))
            yText = Base58.encode(try y.bigEndianBytes(maximumByteCount: 32))
        } catch {
            throw KeyShareError.arithmeticFailure
        }
        self.x = x
        self.y = y
        self.threshold = threshold
        self.integrity = integrity
    }

    /// The exact canonical backup string.
    ///
    /// This value contains secret-bearing share material. Store and transmit it
    /// with the same protections as a private key, and do not log it.
    public var backupString: String {
        "\(xText).\(yText).\(threshold).\(integrity)"
    }

    /// A redacted description suitable for interpolation and diagnostic logging.
    public var description: String { "<redacted key share>" }

    /// A redacted debug description that never reveals the backup string.
    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(reflecting: description) }

    private static func parseCoordinate(_ text: String) throws -> BigMagnitude {
        // Any canonical positive 256-bit integer occupies at most 44 Base58 digits.
        guard text.utf8.count <= 44 else {
            throw KeyShareError.invalidCoordinateEncoding
        }

        let bytes: [UInt8]
        do {
            bytes = try Base58.decode(text, maximumDecodedByteCount: 32)
        } catch {
            throw KeyShareError.invalidCoordinateEncoding
        }
        guard !bytes.isEmpty else {
            throw KeyShareError.invalidCoordinateEncoding
        }
        guard bytes[0] != 0, Base58.encode(bytes) == text else {
            throw KeyShareError.nonCanonicalCoordinate
        }

        do {
            let coordinate = try BigMagnitude(bigEndian: bytes, maximumByteCount: 32)
            let prime = try KeySharing.fieldPrime()
            guard !coordinate.isZero, coordinate.compared(to: prime) < 0 else {
                throw KeyShareError.coordinateOutOfRange
            }
            return coordinate
        } catch let error as KeyShareError {
            throw error
        } catch {
            throw KeyShareError.arithmeticFailure
        }
    }

    private static func parseThreshold(_ text: String) throws -> Int {
        let bytes = Array(text.utf8)
        guard !bytes.isEmpty,
              bytes.count <= 3,
              bytes[0] != 48,
              bytes.allSatisfy({ (48...57).contains($0) }),
              let value = Int(text),
              (2...KeySharing.maximumShareCount).contains(value)
        else {
            throw KeyShareError.invalidThreshold
        }
        return value
    }

    private static func isCanonicalIntegrity(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        return bytes.count == 8 && bytes.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    fileprivate var coordinateX: BigMagnitude { x }
    fileprivate var coordinateY: BigMagnitude { y }
}

/// Bounded BRC-140 key splitting and recovery.
///
/// Field interpolation uses variable-time big-integer arithmetic. These APIs are
/// intended for offline backup workflows, not attacker-observable online use.
public enum KeySharing {
    /// The maximum supported share count and threshold.
    ///
    /// This conservative SDK bound caps the quadratic interpolation work. It is
    /// intentionally stricter than the unbounded pinned compatibility API.
    public static let maximumShareCount = 20

    private static let coordinateByteCount = 32
    private static let seedByteCount = 64
    private static let maximumCoordinateAttempts = 16
    private static let fieldPrimeBytes: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
    ]

    /// Splits a validated secp256k1 private key into canonical BRC-140 shares.
    public static func split(
        _ privateKey: PrivateKey,
        threshold: Int,
        shareCount: Int,
        using randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws -> [KeyShare] {
        guard threshold >= 2, shareCount >= 2, threshold <= shareCount else {
            throw KeyShareError.invalidShareConfiguration(
                threshold: threshold,
                shareCount: shareCount
            )
        }
        guard shareCount <= maximumShareCount else {
            throw KeyShareError.shareCountExceedsMaximum(shareCount)
        }

        let prime = try fieldPrime()
        let budget = try arithmeticBudget()
        let secret: BigMagnitude
        do {
            secret = try BigMagnitude(
                bigEndian: privateKey.bytes,
                maximumByteCount: coordinateByteCount
            )
        } catch {
            throw KeyShareError.arithmeticFailure
        }

        var definingPoints: [(x: BigMagnitude, y: BigMagnitude)] = [(.zero, secret)]
        definingPoints.reserveCapacity(threshold)
        var definingX: Set<BigMagnitude> = [.zero]
        var definingY: Set<BigMagnitude> = [secret]

        for _ in 1..<threshold {
            let x = try randomFieldCoordinate(
                using: randomSource,
                excluding: definingX,
                prime: prime,
                budget: budget
            )
            let y = try randomFieldCoordinate(
                using: randomSource,
                excluding: definingY,
                prime: prime,
                budget: budget
            )
            definingX.insert(x)
            definingY.insert(y)
            definingPoints.append((x, y))
        }

        let seed = try exactRandomBytes(count: seedByteCount, using: randomSource)
        let integrity = integrityString(for: privateKey)
        var shares: [KeyShare] = []
        shares.reserveCapacity(shareCount)
        var shareX: Set<BigMagnitude> = []

        for index in 0..<shareCount {
            var generatedShare: KeyShare?
            for attempt in 0..<maximumCoordinateAttempts {
                let random = try exactRandomBytes(
                    count: coordinateByteCount,
                    using: randomSource
                )
                // BRC-140's Go convention is exactly two unsigned four-byte,
                // big-endian counters followed by the fresh 32-byte draw.
                let message = try uint32BigEndian(index)
                    + uint32BigEndian(attempt)
                    + random
                let digest = BSVHashing.hmacSHA512(message, key: seed).bytes
                let candidate = try reduced(
                    try magnitude(digest, maximumByteCount: seedByteCount),
                    modulo: prime,
                    budget: budget
                )
                guard !candidate.isZero, !shareX.contains(candidate) else {
                    continue
                }

                let y = try evaluate(
                    definingPoints,
                    at: candidate,
                    prime: prime,
                    budget: budget
                )
                guard !y.isZero else { continue }

                generatedShare = try KeyShare(
                    x: candidate,
                    y: y,
                    threshold: threshold,
                    integrity: integrity
                )
                shareX.insert(candidate)
                break
            }
            guard let generatedShare else {
                throw KeyShareError.coordinateGenerationExhausted
            }
            shares.append(generatedShare)
        }

        return shares
    }

    /// Recovers a private key from a coherent set of canonical BRC-140 shares.
    public static func recover(_ shares: [KeyShare]) throws -> PrivateKey {
        guard shares.count <= maximumShareCount else {
            throw KeyShareError.shareCountExceedsMaximum(shares.count)
        }
        guard let first = shares.first else {
            throw KeyShareError.noShares
        }
        guard shares.allSatisfy({ $0.threshold == first.threshold }) else {
            throw KeyShareError.mixedThresholds
        }
        guard shares.allSatisfy({ $0.integrity == first.integrity }) else {
            throw KeyShareError.mixedIntegrity
        }
        guard shares.count >= first.threshold else {
            throw KeyShareError.insufficientShares(
                required: first.threshold,
                actual: shares.count
            )
        }

        var xCoordinates: Set<BigMagnitude> = []
        xCoordinates.reserveCapacity(shares.count)
        for share in shares {
            guard xCoordinates.insert(share.coordinateX).inserted else {
                throw KeyShareError.duplicateXCoordinate
            }
        }

        let prime = try fieldPrime()
        let budget = try arithmeticBudget()
        let basis = shares.prefix(first.threshold).map {
            (x: $0.coordinateX, y: $0.coordinateY)
        }

        // Do not silently ignore coherent-looking extras. Every extra point must
        // lie on the polynomial defined by the threshold-sized basis.
        for share in shares.dropFirst(first.threshold) {
            let expected = try evaluate(
                basis,
                at: share.coordinateX,
                prime: prime,
                budget: budget
            )
            guard expected == share.coordinateY else {
                throw KeyShareError.inconsistentShare
            }
        }

        let recovered = try evaluate(
            basis,
            at: .zero,
            prime: prime,
            budget: budget
        )
        let order: BigMagnitude
        do {
            order = try BigMagnitude(
                bigEndian: secp256k1Order,
                maximumByteCount: coordinateByteCount
            )
        } catch {
            throw KeyShareError.arithmeticFailure
        }
        guard !recovered.isZero, recovered.compared(to: order) < 0 else {
            throw KeyShareError.invalidRecoveredPrivateKey
        }

        let unpadded: [UInt8]
        do {
            unpadded = try recovered.bigEndianBytes(maximumByteCount: coordinateByteCount)
        } catch {
            throw KeyShareError.arithmeticFailure
        }
        let paddingCount = coordinateByteCount - unpadded.count
        let scalar = [UInt8](repeating: 0, count: paddingCount) + unpadded
        let privateKey: PrivateKey
        do {
            privateKey = try PrivateKey(scalar)
        } catch {
            throw KeyShareError.invalidRecoveredPrivateKey
        }
        guard integrityString(for: privateKey) == first.integrity else {
            throw KeyShareError.recoveredIntegrityMismatch
        }
        return privateKey
    }

    fileprivate static func fieldPrime() throws -> BigMagnitude {
        do {
            return try BigMagnitude(
                bigEndian: fieldPrimeBytes,
                maximumByteCount: coordinateByteCount
            )
        } catch {
            throw KeyShareError.arithmeticFailure
        }
    }

    private static func arithmeticBudget() throws -> BigNumOperationBudget {
        do {
            return try BigNumOperationBudget(
                maximumOperandByteCount: 64,
                maximumResultByteCount: 64,
                maximumShiftBitCount: 256
            )
        } catch {
            throw KeyShareError.arithmeticFailure
        }
    }

    private static func magnitude(
        _ bytes: [UInt8],
        maximumByteCount: Int
    ) throws -> BigMagnitude {
        do {
            return try BigMagnitude(
                bigEndian: bytes,
                maximumByteCount: maximumByteCount
            )
        } catch {
            throw KeyShareError.arithmeticFailure
        }
    }

    private static func exactRandomBytes(
        count: Int,
        using randomSource: any SecureRandomSource
    ) throws -> [UInt8] {
        let bytes: [UInt8]
        do {
            bytes = try randomSource.randomBytes(count: count)
        } catch {
            throw KeyShareError.randomSourceFailure
        }
        guard bytes.count == count else {
            throw KeyShareError.invalidRandomByteCount(
                expected: count,
                actual: bytes.count
            )
        }
        return bytes
    }

    private static func randomFieldCoordinate(
        using randomSource: any SecureRandomSource,
        excluding excluded: Set<BigMagnitude>,
        prime: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        for _ in 0..<maximumCoordinateAttempts {
            let bytes = try exactRandomBytes(
                count: coordinateByteCount,
                using: randomSource
            )
            let value = try reduced(
                try magnitude(bytes, maximumByteCount: coordinateByteCount),
                modulo: prime,
                budget: budget
            )
            guard !value.isZero, !excluded.contains(value) else { continue }
            return value
        }
        throw KeyShareError.coordinateGenerationExhausted
    }

    private static func evaluate(
        _ points: [(x: BigMagnitude, y: BigMagnitude)],
        at x: BigMagnitude,
        prime: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        var result = BigMagnitude.zero
        do {
            for (index, point) in points.enumerated() {
                var term = point.y
                for (otherIndex, other) in points.enumerated() where otherIndex != index {
                    let numerator = try subtractMod(x, other.x, prime: prime, budget: budget)
                    let denominator = try subtractMod(
                        point.x,
                        other.x,
                        prime: prime,
                        budget: budget
                    )
                    guard !denominator.isZero else {
                        throw KeyShareError.duplicateXCoordinate
                    }
                    let inverse: BigMagnitude
                    do {
                        inverse = try denominator.inverse(modulo: prime, budget: budget)
                    } catch {
                        throw KeyShareError.arithmeticFailure
                    }
                    term = try multiplyMod(term, numerator, prime: prime, budget: budget)
                    term = try multiplyMod(term, inverse, prime: prime, budget: budget)
                }
                result = try addMod(result, term, prime: prime, budget: budget)
            }
            return result
        } catch let error as KeyShareError {
            throw error
        } catch {
            throw KeyShareError.arithmeticFailure
        }
    }

    private static func reduced(
        _ value: BigMagnitude,
        modulo prime: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        do {
            return try value.quotientAndRemainder(dividingBy: prime, budget: budget).remainder
        } catch {
            throw KeyShareError.arithmeticFailure
        }
    }

    private static func addMod(
        _ lhs: BigMagnitude,
        _ rhs: BigMagnitude,
        prime: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        try reduced(lhs.adding(rhs, budget: budget), modulo: prime, budget: budget)
    }

    private static func subtractMod(
        _ lhs: BigMagnitude,
        _ rhs: BigMagnitude,
        prime: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        if lhs.compared(to: rhs) >= 0 {
            return try lhs.subtracting(rhs, budget: budget)
        }
        return try prime.subtracting(
            rhs.subtracting(lhs, budget: budget),
            budget: budget
        )
    }

    private static func multiplyMod(
        _ lhs: BigMagnitude,
        _ rhs: BigMagnitude,
        prime: BigMagnitude,
        budget: BigNumOperationBudget
    ) throws -> BigMagnitude {
        try reduced(lhs.multiplied(by: rhs, budget: budget), modulo: prime, budget: budget)
    }

    static func uint32BigEndian(_ value: Int) throws -> [UInt8] {
        guard let value = UInt32(exactly: value) else {
            throw KeyShareError.arithmeticFailure
        }
        return [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ]
    }

    private static func integrityString(for privateKey: PrivateKey) -> String {
        let digest = BSVHashing.hash160(privateKey.publicKey.compressedBytes).bytes
        return Hex.encode(Array(digest.prefix(4)))
    }
}
