/// A stable error reported by the deterministic HMAC-DRBG state machine.
public enum HMACDRBGError: Error, Equatable, Sendable {
    /// The supplied entropy does not meet the 256-bit minimum.
    case insufficientEntropy(minimumByteCount: Int, actualByteCount: Int)
    /// The requested output count is negative.
    case invalidRequestedByteCount(Int)
    /// One generation request exceeds the supported byte limit.
    case requestTooLarge(maximumByteCount: Int, actualByteCount: Int)
    /// The state has served its maximum number of requests and must be reseeded.
    case reseedRequired
}

/// Deterministic HMAC-SHA256 state initialized from caller-supplied entropy.
///
/// This type does not gather randomness. Callers remain responsible for supplying
/// cryptographically secure entropy when initializing or reseeding it.
/// Copying the value forks its deterministic state and repeats the same future
/// output sequence. Its internal arrays are not guaranteed to be zeroized.
public struct HMACDRBG:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    /// The Go SDK compatibility profile requires at least 256 bits of entropy.
    public static let minimumEntropyByteCount = 32
    /// The Go SDK compatibility profile permits at most 937 bytes per request.
    public static let maximumBytesPerGenerate = 937
    /// The Go SDK compatibility profile requires reseeding after 10,000 requests.
    public static let maximumRequestsBeforeReseed = 10_000

    private var key: [UInt8]
    private var value: [UInt8]

    /// The next generation request number for the current seed.
    public private(set) var reseedCounter: Int

    /// A redacted description suitable for diagnostic logging.
    public var description: String { "<redacted HMAC-DRBG>" }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(reflecting: description) }

    /// Creates deterministic state from entropy followed directly by an optional nonce.
    public init(entropy: [UInt8], nonce: [UInt8] = []) throws {
        guard entropy.count >= Self.minimumEntropyByteCount else {
            throw HMACDRBGError.insufficientEntropy(
                minimumByteCount: Self.minimumEntropyByteCount,
                actualByteCount: entropy.count
            )
        }

        key = [UInt8](repeating: 0, count: 32)
        value = [UInt8](repeating: 1, count: 32)
        reseedCounter = 1

        var seedMaterial = entropy
        seedMaterial.append(contentsOf: nonce)
        update(providedData: seedMaterial)
    }

    /// Generates the requested number of deterministic bytes and advances the state.
    public mutating func generate(count: Int) throws -> [UInt8] {
        guard count >= 0 else {
            throw HMACDRBGError.invalidRequestedByteCount(count)
        }
        guard reseedCounter <= Self.maximumRequestsBeforeReseed else {
            throw HMACDRBGError.reseedRequired
        }
        guard count <= Self.maximumBytesPerGenerate else {
            throw HMACDRBGError.requestTooLarge(
                maximumByteCount: Self.maximumBytesPerGenerate,
                actualByteCount: count
            )
        }

        var output: [UInt8] = []
        output.reserveCapacity(count)
        while output.count < count {
            value = BSVHashing.hmacSHA256(value, key: key).bytes
            output.append(contentsOf: value.prefix(count - output.count))
        }

        update(providedData: nil)
        reseedCounter += 1
        return output
    }

    /// Mixes fresh caller-supplied entropy into the state and resets the request counter.
    public mutating func reseed(entropy: [UInt8]) throws {
        guard entropy.count >= Self.minimumEntropyByteCount else {
            throw HMACDRBGError.insufficientEntropy(
                minimumByteCount: Self.minimumEntropyByteCount,
                actualByteCount: entropy.count
            )
        }

        update(providedData: entropy)
        reseedCounter = 1
    }

    private mutating func update(providedData: [UInt8]?) {
        var message = value
        message.append(0)
        if let providedData {
            message.append(contentsOf: providedData)
        }
        key = BSVHashing.hmacSHA256(message, key: key).bytes
        value = BSVHashing.hmacSHA256(value, key: key).bytes

        guard let providedData, !providedData.isEmpty else {
            return
        }

        message = value
        message.append(1)
        message.append(contentsOf: providedData)
        key = BSVHashing.hmacSHA256(message, key: key).bytes
        value = BSVHashing.hmacSHA256(value, key: key).bytes
    }
}
