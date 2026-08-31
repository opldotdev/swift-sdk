/// Transport metadata accompanying one decoded wallet request.
///
/// `rawOriginator` preserves the transport-provided value exactly. A transport
/// or policy handler remains responsible for establishing trust in that value;
/// this type only enforces the BRC-100 wallet-wire size bound.
public struct WalletRequestContext:
    Hashable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public static let maximumRawOriginatorUTF8ByteCount = 255

    public let rawOriginator: String

    public init(rawOriginator: String) throws {
        let count = rawOriginator.utf8.count
        guard count <= Self.maximumRawOriginatorUTF8ByteCount else {
            throw WalletRequestContextError.originatorTooLong(
                actualUTF8ByteCount: count,
                maximumUTF8ByteCount: Self.maximumRawOriginatorUTF8ByteCount
            )
        }
        self.rawOriginator = rawOriginator
    }

    public var description: String { "<wallet request context>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

public enum WalletRequestContextError: Error, Equatable, Sendable {
    case originatorTooLong(actualUTF8ByteCount: Int, maximumUTF8ByteCount: Int)
}

/// The permission-seeking semantics of a decoded BRC-100 request.
///
/// `rawValue` preserves the caller's tri-state input. `effectiveValue` applies
/// the operation-specific BRC-100 default, or is `nil` when the operation does
/// not define `seekPermission`.
public struct WalletSeekPermissionMetadata: Equatable, Sendable {
    public let rawValue: Bool?
    public let effectiveValue: Bool?

    public init(rawValue: Bool?, effectiveValue: Bool?) {
        self.rawValue = rawValue
        self.effectiveValue = effectiveValue
    }
}

/// A decoded request from any of the 28 BRC-100 wallet operations.
public enum WalletRequest:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case action(WalletWireActionRequest)
    case certificate(WalletWireCertificateRequest)
    case keyQuery(WalletWireKeyQueryRequest)

    public var call: WalletCall {
        switch self {
        case .action(let request): request.call
        case .certificate(let request): request.call
        case .keyQuery(let request): request.call
        }
    }

    /// Permission-seeking metadata for transport or host policy.
    public var seekPermissionMetadata: WalletSeekPermissionMetadata {
        switch self {
        case .action(.listActions(let value)):
            return makeSeekPermissionMetadata(rawValue: value.seekPermission, defaultValue: true)
        case .action(.internalizeAction(let value)):
            return makeSeekPermissionMetadata(rawValue: value.seekPermission, defaultValue: true)
        case .action(.listOutputs(let value)):
            return makeSeekPermissionMetadata(rawValue: value.seekPermission, defaultValue: true)
        case .certificate(.discoverByIdentityKey(let value)):
            return makeSeekPermissionMetadata(rawValue: value.seekPermission, defaultValue: false)
        case .certificate(.discoverByAttributes(let value)):
            return makeSeekPermissionMetadata(rawValue: value.seekPermission, defaultValue: false)
        case .keyQuery(.getPublicKey(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .keyQuery(.encrypt(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .keyQuery(.decrypt(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .keyQuery(.createHMAC(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .keyQuery(.verifyHMAC(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .keyQuery(.createSignature(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .keyQuery(.verifySignature(let value)):
            return makeSeekPermissionMetadata(rawValue: value.access.seekPermission, defaultValue: true)
        case .action(.createAction),
             .action(.signAction),
             .action(.abortAction),
             .action(.relinquishOutput),
             .certificate(.revealCounterpartyKeyLinkage),
             .certificate(.revealSpecificKeyLinkage),
             .certificate(.acquireCertificate),
             .certificate(.listCertificates),
             .certificate(.proveCertificate),
             .certificate(.relinquishCertificate),
             .keyQuery(.isAuthenticated),
             .keyQuery(.waitForAuthentication),
             .keyQuery(.getHeight),
             .keyQuery(.getHeaderForHeight),
             .keyQuery(.getNetwork),
             .keyQuery(.getVersion):
            return WalletSeekPermissionMetadata(rawValue: nil, effectiveValue: nil)
        }
    }

    /// The caller-provided value without applying an operation default.
    public var rawSeekPermission: Bool? { seekPermissionMetadata.rawValue }

    /// The operation's effective value after applying its BRC-100 default.
    public var effectiveSeekPermission: Bool? { seekPermissionMetadata.effectiveValue }

    public var description: String { "<redacted wallet request call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

private func makeSeekPermissionMetadata(
    rawValue: Bool?,
    defaultValue: Bool
) -> WalletSeekPermissionMetadata {
    WalletSeekPermissionMetadata(
        rawValue: rawValue,
        effectiveValue: rawValue ?? defaultValue
    )
}

/// A typed result from any of the 28 BRC-100 wallet operations.
public enum WalletResult:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case action(WalletWireActionResult)
    case certificate(WalletWireCertificateResult)
    case keyQuery(WalletWireKeyQueryResult)

    public var call: WalletCall {
        switch self {
        case .action(let result): result.call
        case .certificate(let result): result.call
        case .keyQuery(let result): result.call
        }
    }

    public var description: String { "<redacted wallet result call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

/// A transport-neutral policy and dispatch boundary for decoded wallet calls.
///
/// Permission-aware handlers can inspect both the full typed request and its
/// originator before forwarding to a wallet. The returned result must have the
/// same `call` as the request.
public protocol WalletRequestHandling: Sendable {
    func handle(
        _ request: WalletRequest,
        context: WalletRequestContext
    ) async throws -> WalletResult
}

/// Adapts a trusted, in-process `WalletInterface` to request handling.
///
/// This adapter intentionally does not authorize the originator. Use a policy
/// handler in front of it for requests that cross a trust boundary.
public struct WalletInterfaceRequestHandler:
    WalletRequestHandling,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let wallet: any WalletInterface

    public init(wallet: any WalletInterface) {
        self.wallet = wallet
    }

    public func handle(
        _ request: WalletRequest,
        context: WalletRequestContext
    ) async throws -> WalletResult {
        switch request {
        case .action(let request):
            return .action(try await handle(request))
        case .certificate(let request):
            return .certificate(try await handle(request))
        case .keyQuery(let request):
            return .keyQuery(try await handle(request))
        }
    }

    private func handle(_ request: WalletWireActionRequest) async throws -> WalletWireActionResult {
        switch request {
        case .createAction(let value):
            .createAction(try await wallet.createAction(value))
        case .signAction(let value):
            .signAction(try await wallet.signAction(value))
        case .abortAction(let value):
            .abortAction(try await wallet.abortAction(value))
        case .listActions(let value):
            .listActions(try await wallet.listActions(value))
        case .internalizeAction(let value):
            .internalizeAction(try await wallet.internalizeAction(value))
        case .listOutputs(let value):
            .listOutputs(try await wallet.listOutputs(value))
        case .relinquishOutput(let value):
            .relinquishOutput(try await wallet.relinquishOutput(value))
        }
    }

    private func handle(
        _ request: WalletWireCertificateRequest
    ) async throws -> WalletWireCertificateResult {
        switch request {
        case .revealCounterpartyKeyLinkage(let value):
            .revealCounterpartyKeyLinkage(try await wallet.revealCounterpartyKeyLinkage(value))
        case .revealSpecificKeyLinkage(let value):
            .revealSpecificKeyLinkage(try await wallet.revealSpecificKeyLinkage(value))
        case .acquireCertificate(let value):
            .acquireCertificate(try await wallet.acquireCertificate(value))
        case .listCertificates(let value):
            .listCertificates(try await wallet.listCertificates(value))
        case .proveCertificate(let value):
            .proveCertificate(try await wallet.proveCertificate(value))
        case .relinquishCertificate(let value):
            .relinquishCertificate(try await wallet.relinquishCertificate(value))
        case .discoverByIdentityKey(let value):
            .discoverByIdentityKey(try await wallet.discoverByIdentityKey(value))
        case .discoverByAttributes(let value):
            .discoverByAttributes(try await wallet.discoverByAttributes(value))
        }
    }

    private func handle(
        _ request: WalletWireKeyQueryRequest
    ) async throws -> WalletWireKeyQueryResult {
        switch request {
        case .getPublicKey(let value):
            .getPublicKey(try await wallet.getPublicKey(value))
        case .encrypt(let value):
            .encrypt(try await wallet.encrypt(value))
        case .decrypt(let value):
            .decrypt(try await wallet.decrypt(value))
        case .createHMAC(let value):
            .createHMAC(try await wallet.createHMAC(value))
        case .verifyHMAC(let value):
            .verifyHMAC(try await wallet.verifyHMAC(value))
        case .createSignature(let value):
            .createSignature(try await wallet.createSignature(value))
        case .verifySignature(let value):
            .verifySignature(try await wallet.verifySignature(value))
        case .isAuthenticated(let value):
            .isAuthenticated(try await wallet.isAuthenticated(value))
        case .waitForAuthentication(let value):
            .waitForAuthentication(try await wallet.waitForAuthentication(value))
        case .getHeight(let value):
            .getHeight(try await wallet.getHeight(value))
        case .getHeaderForHeight(let value):
            .getHeaderForHeight(try await wallet.getHeaderForHeight(value))
        case .getNetwork(let value):
            .getNetwork(try await wallet.getNetwork(value))
        case .getVersion(let value):
            .getVersion(try await wallet.getVersion(value))
        }
    }

    public var description: String { "<wallet interface request handler>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
