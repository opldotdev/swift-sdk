/// No-argument request for an authentication-status query.
public struct WalletIsAuthenticatedRequest: Equatable, Sendable { public init() {} }
/// No-argument request to wait for authentication.
public struct WalletWaitForAuthenticationRequest: Equatable, Sendable { public init() {} }
/// No-argument request for the current chain height.
public struct WalletGetHeightRequest: Equatable, Sendable { public init() {} }
/// No-argument request for the configured network.
public struct WalletGetNetworkRequest: Equatable, Sendable { public init() {} }
/// No-argument request for the wallet implementation version.
public struct WalletGetVersionRequest: Equatable, Sendable { public init() {} }

public struct WalletAuthenticatedResult: Equatable, Sendable {
    public let authenticated: Bool
    public init(authenticated: Bool) { self.authenticated = authenticated }
}

public struct WalletGetHeightResult: Equatable, Sendable {
    public let height: UInt32
    public init(height: UInt32) { self.height = height }
}

public struct WalletGetHeaderRequest: Equatable, Sendable {
    public let height: UInt32
    public init(height: UInt32) { self.height = height }
}

public struct WalletGetHeaderResult: Equatable, Sendable {
    public static let byteCount = 80
    public let header: [UInt8]
    public init(header: [UInt8]) throws {
        guard header.count == Self.byteCount else {
            throw WalletABIError.invalidFieldRelation("a block header must contain exactly 80 bytes")
        }
        self.header = header
    }
}

public struct WalletGetNetworkResult: Equatable, Sendable {
    public let network: WalletNetwork
    public init(network: WalletNetwork) { self.network = network }
}

public struct WalletGetVersionResult: Equatable, Sendable {
    public let version: String
    public init(version: String, limits: WalletABILimits = .standard) throws {
        try walletABIRequireText(version, kind: "wallet version", limits: limits)
        self.version = version
    }
}

/// Transaction creation, completion, inspection, and internalization capabilities.
public protocol WalletActionOperations: Sendable {
    func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult
    func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult
    func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult
    func listActions(_ request: WalletListActionsRequest) async throws -> WalletListActionsResult
    func internalizeAction(
        _ request: WalletInternalizeActionRequest
    ) async throws -> WalletInternalizeActionResult
}

/// Spendable-output query and relinquishment capabilities.
public protocol WalletOutputOperations: Sendable {
    func listOutputs(_ request: WalletListOutputsRequest) async throws -> WalletListOutputsResult
    func relinquishOutput(
        _ request: WalletRelinquishOutputRequest
    ) async throws -> WalletRelinquishOutputResult
}

/// Certificate lifecycle capabilities. Conformance makes no persistence claim.
public protocol WalletCertificateOperations: Sendable {
    func acquireCertificate(_ request: WalletAcquireCertificateRequest) async throws -> Certificate
    func listCertificates(
        _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult
    func proveCertificate(
        _ request: WalletProveCertificateRequest
    ) async throws -> WalletProveCertificateResult
    func relinquishCertificate(
        _ request: WalletRelinquishCertificateRequest
    ) async throws -> WalletRelinquishCertificateResult
}

/// Key-linkage revelation capability contracts; no proof generation is supplied here.
public protocol WalletLinkageOperations: Sendable {
    func revealCounterpartyKeyLinkage(
        _ request: WalletRevealCounterpartyKeyLinkageRequest
    ) async throws -> WalletRevealCounterpartyKeyLinkageResult
    func revealSpecificKeyLinkage(
        _ request: WalletRevealSpecificKeyLinkageRequest
    ) async throws -> WalletRevealSpecificKeyLinkageResult
}

/// Identity-certificate discovery capability contracts.
public protocol WalletDiscoveryOperations: Sendable {
    func discoverByIdentityKey(
        _ request: WalletDiscoverByIdentityKeyRequest
    ) async throws -> WalletDiscoverCertificatesResult
    func discoverByAttributes(
        _ request: WalletDiscoverByAttributesRequest
    ) async throws -> WalletDiscoverCertificatesResult
}

/// Authentication state capabilities.
public protocol WalletAuthenticationOperations: Sendable {
    func isAuthenticated(
        _ request: WalletIsAuthenticatedRequest
    ) async throws -> WalletAuthenticatedResult
    func waitForAuthentication(
        _ request: WalletWaitForAuthenticationRequest
    ) async throws -> WalletAuthenticatedResult
}

/// Read-only chain and wallet implementation information.
public protocol WalletChainInformation: Sendable {
    func getHeight(_ request: WalletGetHeightRequest) async throws -> WalletGetHeightResult
    func getHeaderForHeight(_ request: WalletGetHeaderRequest) async throws -> WalletGetHeaderResult
    func getNetwork(_ request: WalletGetNetworkRequest) async throws -> WalletGetNetworkResult
    func getVersion(_ request: WalletGetVersionRequest) async throws -> WalletGetVersionResult
}

/// The complete typed BRC-100 wallet ABI contract.
///
/// Conformance describes capabilities only. It does not imply persistence,
/// transport, permission prompting, or successful behavior for any operation.
public protocol WalletInterface:
    WalletKeyOperations,
    WalletActionOperations,
    WalletOutputOperations,
    WalletCertificateOperations,
    WalletLinkageOperations,
    WalletDiscoveryOperations,
    WalletAuthenticationOperations,
    WalletChainInformation {}
