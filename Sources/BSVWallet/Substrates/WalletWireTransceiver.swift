import BSVTransaction

/// A transport-neutral `WalletInterface` client for all 28 wallet-wire calls.
///
/// One instance is bound to one validated originator. It has no HTTP,
/// WebSocket, authentication, retry, or persistence behavior.
public struct WalletWireTransceiver:
    WalletInterface,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let transport: any WalletWireTransport
    private let originator: String
    private let beefLimits: BEEFLimits
    private let certificateLimits: CertificateLimits
    private let wireLimits: WalletWireLimits

    public init(
        transport: any WalletWireTransport,
        originator: String,
        beefLimits: BEEFLimits,
        certificateLimits: CertificateLimits,
        wireLimits: WalletWireLimits
    ) throws {
        let count = originator.utf8.count
        let maximum = min(
            wireLimits.maximumOriginatorUTF8ByteCount,
            WalletWireLimits.hardMaximumOriginatorUTF8ByteCount
        )
        guard count <= maximum else {
            throw WalletWireError.byteLimitExceeded(
                kind: "originator",
                actual: count,
                maximum: maximum
            )
        }
        self.transport = transport
        self.originator = originator
        self.beefLimits = try BEEFLimits(
            maximumByteCount: min(
                beefLimits.maximumByteCount,
                wireLimits.maximumPayloadByteCount
            ),
            maximumMerklePathCount: beefLimits.maximumMerklePathCount,
            maximumTransactionCount: beefLimits.maximumTransactionCount,
            transactionLimits: beefLimits.transactionLimits,
            merklePathLimits: beefLimits.merklePathLimits
        )
        self.certificateLimits = certificateLimits
        self.wireLimits = wireLimits
    }

    public func createAction(
        _ request: WalletCreateActionRequest
    ) async throws -> WalletCreateActionResult {
        switch try await action(.createAction(request)) {
        case .createAction(let result): return result
        case let result: throw mismatch(.createAction, result.call)
        }
    }

    public func signAction(
        _ request: WalletSignActionRequest
    ) async throws -> WalletSignActionResult {
        switch try await action(.signAction(request)) {
        case .signAction(let result): return result
        case let result: throw mismatch(.signAction, result.call)
        }
    }

    public func abortAction(
        _ request: WalletAbortActionRequest
    ) async throws -> WalletAbortActionResult {
        switch try await action(.abortAction(request)) {
        case .abortAction(let result): return result
        case let result: throw mismatch(.abortAction, result.call)
        }
    }

    public func listActions(
        _ request: WalletListActionsRequest
    ) async throws -> WalletListActionsResult {
        switch try await action(.listActions(request)) {
        case .listActions(let result): return result
        case let result: throw mismatch(.listActions, result.call)
        }
    }

    public func internalizeAction(
        _ request: WalletInternalizeActionRequest
    ) async throws -> WalletInternalizeActionResult {
        switch try await action(.internalizeAction(request)) {
        case .internalizeAction(let result): return result
        case let result: throw mismatch(.internalizeAction, result.call)
        }
    }

    public func listOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        switch try await action(.listOutputs(request)) {
        case .listOutputs(let result): return result
        case let result: throw mismatch(.listOutputs, result.call)
        }
    }

    public func relinquishOutput(
        _ request: WalletRelinquishOutputRequest
    ) async throws -> WalletRelinquishOutputResult {
        switch try await action(.relinquishOutput(request)) {
        case .relinquishOutput(let result): return result
        case let result: throw mismatch(.relinquishOutput, result.call)
        }
    }

    public func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        switch try await keyQuery(.getPublicKey(request)) {
        case .getPublicKey(let result): return result
        case let result: throw mismatch(.getPublicKey, result.call)
        }
    }

    public func revealCounterpartyKeyLinkage(
        _ request: WalletRevealCounterpartyKeyLinkageRequest
    ) async throws -> WalletRevealCounterpartyKeyLinkageResult {
        switch try await certificate(.revealCounterpartyKeyLinkage(request)) {
        case .revealCounterpartyKeyLinkage(let result): return result
        case let result: throw mismatch(.revealCounterpartyKeyLinkage, result.call)
        }
    }

    public func revealSpecificKeyLinkage(
        _ request: WalletRevealSpecificKeyLinkageRequest
    ) async throws -> WalletRevealSpecificKeyLinkageResult {
        switch try await certificate(.revealSpecificKeyLinkage(request)) {
        case .revealSpecificKeyLinkage(let result): return result
        case let result: throw mismatch(.revealSpecificKeyLinkage, result.call)
        }
    }

    public func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        switch try await keyQuery(.encrypt(request)) {
        case .encrypt(let result): return result
        case let result: throw mismatch(.encrypt, result.call)
        }
    }

    public func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        switch try await keyQuery(.decrypt(request)) {
        case .decrypt(let result): return result
        case let result: throw mismatch(.decrypt, result.call)
        }
    }

    public func createHMAC(
        _ request: WalletCreateHMACRequest
    ) async throws -> WalletCreateHMACResult {
        switch try await keyQuery(.createHMAC(request)) {
        case .createHMAC(let result): return result
        case let result: throw mismatch(.createHMAC, result.call)
        }
    }

    public func verifyHMAC(
        _ request: WalletVerifyHMACRequest
    ) async throws -> WalletVerifyHMACResult {
        switch try await keyQuery(.verifyHMAC(request)) {
        case .verifyHMAC(let result): return result
        case let result: throw mismatch(.verifyHMAC, result.call)
        }
    }

    public func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        switch try await keyQuery(.createSignature(request)) {
        case .createSignature(let result): return result
        case let result: throw mismatch(.createSignature, result.call)
        }
    }

    public func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        switch try await keyQuery(.verifySignature(request)) {
        case .verifySignature(let result): return result
        case let result: throw mismatch(.verifySignature, result.call)
        }
    }

    public func acquireCertificate(
        _ request: WalletAcquireCertificateRequest
    ) async throws -> Certificate {
        switch try await certificate(.acquireCertificate(request)) {
        case .acquireCertificate(let result): return result
        case let result: throw mismatch(.acquireCertificate, result.call)
        }
    }

    public func listCertificates(
        _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        switch try await certificate(.listCertificates(request)) {
        case .listCertificates(let result): return result
        case let result: throw mismatch(.listCertificates, result.call)
        }
    }

    public func proveCertificate(
        _ request: WalletProveCertificateRequest
    ) async throws -> WalletProveCertificateResult {
        switch try await certificate(.proveCertificate(request)) {
        case .proveCertificate(let result): return result
        case let result: throw mismatch(.proveCertificate, result.call)
        }
    }

    public func relinquishCertificate(
        _ request: WalletRelinquishCertificateRequest
    ) async throws -> WalletRelinquishCertificateResult {
        switch try await certificate(.relinquishCertificate(request)) {
        case .relinquishCertificate(let result): return result
        case let result: throw mismatch(.relinquishCertificate, result.call)
        }
    }

    public func discoverByIdentityKey(
        _ request: WalletDiscoverByIdentityKeyRequest
    ) async throws -> WalletDiscoverCertificatesResult {
        switch try await certificate(.discoverByIdentityKey(request)) {
        case .discoverByIdentityKey(let result): return result
        case let result: throw mismatch(.discoverByIdentityKey, result.call)
        }
    }

    public func discoverByAttributes(
        _ request: WalletDiscoverByAttributesRequest
    ) async throws -> WalletDiscoverCertificatesResult {
        switch try await certificate(.discoverByAttributes(request)) {
        case .discoverByAttributes(let result): return result
        case let result: throw mismatch(.discoverByAttributes, result.call)
        }
    }

    public func isAuthenticated(
        _ request: WalletIsAuthenticatedRequest
    ) async throws -> WalletAuthenticatedResult {
        switch try await keyQuery(.isAuthenticated(request)) {
        case .isAuthenticated(let result): return result
        case let result: throw mismatch(.isAuthenticated, result.call)
        }
    }

    public func waitForAuthentication(
        _ request: WalletWaitForAuthenticationRequest
    ) async throws -> WalletAuthenticatedResult {
        switch try await keyQuery(.waitForAuthentication(request)) {
        case .waitForAuthentication(let result): return result
        case let result: throw mismatch(.waitForAuthentication, result.call)
        }
    }

    public func getHeight(
        _ request: WalletGetHeightRequest
    ) async throws -> WalletGetHeightResult {
        switch try await keyQuery(.getHeight(request)) {
        case .getHeight(let result): return result
        case let result: throw mismatch(.getHeight, result.call)
        }
    }

    public func getHeaderForHeight(
        _ request: WalletGetHeaderRequest
    ) async throws -> WalletGetHeaderResult {
        switch try await keyQuery(.getHeaderForHeight(request)) {
        case .getHeaderForHeight(let result): return result
        case let result: throw mismatch(.getHeaderForHeight, result.call)
        }
    }

    public func getNetwork(
        _ request: WalletGetNetworkRequest
    ) async throws -> WalletGetNetworkResult {
        switch try await keyQuery(.getNetwork(request)) {
        case .getNetwork(let result): return result
        case let result: throw mismatch(.getNetwork, result.call)
        }
    }

    public func getVersion(
        _ request: WalletGetVersionRequest
    ) async throws -> WalletGetVersionResult {
        switch try await keyQuery(.getVersion(request)) {
        case .getVersion(let result): return result
        case let result: throw mismatch(.getVersion, result.call)
        }
    }

    private func action(_ request: WalletWireActionRequest) async throws -> WalletWireActionResult {
        let frame = try WalletWireCodec.encodeActionRequest(
            request,
            originator: originator,
            beefLimits: beefLimits,
            limits: wireLimits
        )
        let response = try await send(frame)
        return try WalletWireCodec.decodeActionResult(
            response,
            expectedCall: request.call,
            beefLimits: beefLimits,
            limits: wireLimits
        )
    }

    private func certificate(
        _ request: WalletWireCertificateRequest
    ) async throws -> WalletWireCertificateResult {
        let frame = try WalletWireCodec.encodeCertificateRequest(
            request,
            originator: originator,
            certificateLimits: certificateLimits,
            limits: wireLimits
        )
        let response = try await send(frame)
        return try WalletWireCodec.decodeCertificateResult(
            response,
            expectedCall: request.call,
            certificateLimits: certificateLimits,
            limits: wireLimits
        )
    }

    private func keyQuery(
        _ request: WalletWireKeyQueryRequest
    ) async throws -> WalletWireKeyQueryResult {
        let frame = try WalletWireCodec.encodeKeyQueryRequest(
            request,
            originator: originator,
            limits: wireLimits
        )
        let response = try await send(frame)
        return try WalletWireCodec.decodeKeyQueryResult(
            response,
            expectedCall: request.call,
            limits: wireLimits
        )
    }

    private func send(_ frame: [UInt8]) async throws -> [UInt8] {
        try Task.checkCancellation()
        do {
            let response = try await transport.transmit(
                frame,
                maximumResponseByteCount: wireLimits.maximumFrameByteCount
            )
            try Task.checkCancellation()
            guard response.count <= wireLimits.maximumFrameByteCount else {
                throw WalletWireError.byteLimitExceeded(
                    kind: "transport response",
                    actual: response.count,
                    maximum: wireLimits.maximumFrameByteCount
                )
            }
            return response
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as WalletWireError {
            throw error
        } catch let error as WalletWireRemoteError {
            throw error
        } catch let error as WalletWireSubstrateError {
            throw error
        } catch {
            throw WalletWireSubstrateError.transportFailure
        }
    }

    private func mismatch(_ expected: WalletCall, _ actual: WalletCall) -> WalletWireSubstrateError {
        .unexpectedResult(expected: expected, actual: actual)
    }

    public var description: String { "<wallet-wire transceiver>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
