import Foundation

/// Resource and retry bounds for a network request.
public struct NetworkRequestPolicy: Hashable, Sendable {
    public let requestTimeout: Duration
    public let resourceTimeout: Duration
    public let maximumResponseBodyByteCount: Int
    public let maximumAttempts: Int
    public let initialBackoff: Duration
    public let maximumBackoff: Duration

    public init(
        requestTimeout: Duration,
        resourceTimeout: Duration,
        maximumResponseBodyByteCount: Int,
        maximumAttempts: Int,
        initialBackoff: Duration,
        maximumBackoff: Duration
    ) throws {
        guard requestTimeout > .zero,
              resourceTimeout > .zero,
              maximumResponseBodyByteCount > 0,
              maximumAttempts > 0,
              initialBackoff >= .zero,
              maximumBackoff >= initialBackoff,
              requestTimeout.finiteTimeInterval != nil,
              resourceTimeout.finiteTimeInterval != nil
        else {
            throw NetworkServiceError.invalidConfiguration
        }

        self.requestTimeout = requestTimeout
        self.resourceTimeout = resourceTimeout
        self.maximumResponseBodyByteCount = maximumResponseBodyByteCount
        self.maximumAttempts = maximumAttempts
        self.initialBackoff = initialBackoff
        self.maximumBackoff = maximumBackoff
    }

    public static let chainLookup: Self = {
        do {
            return try Self(
                requestTimeout: .seconds(10),
                resourceTimeout: .seconds(30),
                maximumResponseBodyByteCount: 64 * 1_024,
                maximumAttempts: 3,
                initialBackoff: .milliseconds(350),
                maximumBackoff: .seconds(2)
            )
        } catch {
            preconditionFailure("The built-in chain lookup policy must be valid")
        }
    }()

    /// Bounds for a transaction broadcast, which is never automatically retried.
    public static let broadcast: Self = {
        do {
            return try Self(
                requestTimeout: .seconds(15),
                resourceTimeout: .seconds(30),
                maximumResponseBodyByteCount: 64 * 1_024,
                maximumAttempts: 1,
                initialBackoff: .zero,
                maximumBackoff: .zero
            )
        } catch {
            preconditionFailure("The built-in broadcast policy must be valid")
        }
    }()
}

extension Duration {
    fileprivate var finiteTimeInterval: TimeInterval? {
        let parts = components
        let value = Double(parts.seconds)
            + Double(parts.attoseconds) / 1_000_000_000_000_000_000
        return value.isFinite && value > 0 ? value : nil
    }

    package var networkTimeInterval: TimeInterval {
        let parts = components
        return Double(parts.seconds)
            + Double(parts.attoseconds) / 1_000_000_000_000_000_000
    }
}
