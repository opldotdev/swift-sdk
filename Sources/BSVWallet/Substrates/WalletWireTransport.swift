/// A transport-neutral request/response boundary for BRC-100 wallet-wire bytes.
///
/// Implementations can use an in-process processor, IPC, or another bounded
/// transport. This protocol does not provide HTTP, WebSocket, or persistence.
public protocol WalletWireTransport: Sendable {
    /// Transmit one request. The implementation must enforce
    /// `maximumResponseByteCount` before it buffers or copies a larger response.
    func transmit(
        _ request: [UInt8],
        maximumResponseByteCount: Int
    ) async throws -> [UInt8]
}

/// Checks the caller originator before a processor invokes a wallet capability.
public protocol WalletWireOriginatorAuthorizing: Sendable {
    func authorize(originator: String, call: WalletCall) async throws
}

/// Converts wallet or authorization failures to bounded remote failures.
public protocol WalletWireFailureMapping: Sendable {
    func remoteError(for error: any Error, call: WalletCall) -> WalletWireRemoteError
}

/// A closure-backed originator authorization boundary.
public struct WalletWireOriginatorAuthorizer:
    WalletWireOriginatorAuthorizing,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let authorizeBody: @Sendable (String, WalletCall) async throws -> Void

    public init(
        _ authorize: @escaping @Sendable (String, WalletCall) async throws -> Void
    ) {
        authorizeBody = authorize
    }

    public func authorize(originator: String, call: WalletCall) async throws {
        try await authorizeBody(originator, call)
    }

    public var description: String { "<wallet-wire originator authorizer>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// A failure mapper that preserves an existing wire error and redacts all
/// other failures to one caller-supplied bounded error.
public struct WalletWireRedactingFailureMapper:
    WalletWireFailureMapping,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let fallback: WalletWireRemoteError

    public init(
        code: UInt8 = 1,
        message: String = "wallet operation failed",
        stack: String = "",
        limits: WalletWireLimits
    ) throws {
        fallback = try WalletWireRemoteError(
            code: code,
            message: message,
            stack: stack,
            limits: limits
        )
    }

    public func remoteError(for error: any Error, call: WalletCall) -> WalletWireRemoteError {
        if let remote = error as? WalletWireRemoteError {
            return remote
        }
        return fallback
    }

    public var description: String { "<wallet-wire redacting failure mapper>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// Transport failures and impossible call/result mismatches. These cases do
/// not retain request bytes, result bytes, originators, or error text.
public enum WalletWireSubstrateError:
    Error,
    Equatable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    case transportFailure
    case unexpectedResult(expected: WalletCall, actual: WalletCall)

    public var description: String {
        switch self {
        case .transportFailure:
            "WalletWireSubstrateError.transportFailure"
        case .unexpectedResult(let expected, let actual):
            "WalletWireSubstrateError.unexpectedResult(expected: \(expected.rawValue), actual: \(actual.rawValue))"
        }
    }

    public var debugDescription: String { description }
    public var customMirror: Mirror {
        switch self {
        case .transportFailure:
            Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
        case .unexpectedResult(let expected, let actual):
            Mirror(self, children: ["expected": expected.rawValue, "actual": actual.rawValue])
        }
    }
}
