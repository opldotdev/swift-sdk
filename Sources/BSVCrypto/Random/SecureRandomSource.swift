/// Supplies cryptographically secure random bytes to SDK primitives.
///
/// Production APIs default to ``SystemSecureRandomSource``. Inject a dedicated
/// implementation when a protocol needs deterministic vectors or controlled
/// failure testing; injected sources must still return exactly the requested
/// number of bytes.
public protocol SecureRandomSource: Sendable {
    func randomBytes(count: Int) throws -> [UInt8]
}

/// Validation errors emitted by the system-backed secure-random source.
public enum SecureRandomSourceError: Error, Equatable, Sendable {
    case invalidByteCount(Int)
}

/// Secure randomness backed by Swift's operating-system random-number generator.
public struct SystemSecureRandomSource: SecureRandomSource, Sendable {
    public init() {}

    public func randomBytes(count: Int) throws -> [UInt8] {
        guard count >= 0 else {
            throw SecureRandomSourceError.invalidByteCount(count)
        }
        guard count > 0 else { return [] }

        var bytes = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: .min ... .max, using: &generator)
        }
        return bytes
    }
}
