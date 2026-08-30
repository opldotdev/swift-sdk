import BSVTransaction

/// A bounded in-process server for all 28 BRC-100 wallet-wire calls.
public struct WalletWireProcessor:
    WalletWireTransport,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let handler: any WalletRequestHandling
    private let failureMapper: any WalletWireFailureMapping
    private let beefLimits: BEEFLimits
    private let certificateLimits: CertificateLimits
    private let wireLimits: WalletWireLimits

    public init(
        wallet: any WalletInterface,
        authorizer: any WalletWireOriginatorAuthorizing,
        failureMapper: any WalletWireFailureMapping,
        beefLimits: BEEFLimits,
        certificateLimits: CertificateLimits,
        wireLimits: WalletWireLimits
    ) {
        self.handler = WalletCoarselyAuthorizedRequestHandler(
            wallet: wallet,
            authorizer: authorizer
        )
        self.failureMapper = failureMapper
        self.beefLimits = beefLimits
        self.certificateLimits = certificateLimits
        self.wireLimits = wireLimits
    }

    /// Creates a processor whose decoded calls pass through a transport-neutral
    /// policy and dispatch handler.
    public init(
        handler: any WalletRequestHandling,
        failureMapper: any WalletWireFailureMapping,
        beefLimits: BEEFLimits,
        certificateLimits: CertificateLimits,
        wireLimits: WalletWireLimits
    ) {
        self.handler = handler
        self.failureMapper = failureMapper
        self.beefLimits = beefLimits
        self.certificateLimits = certificateLimits
        self.wireLimits = wireLimits
    }

    public func transmit(
        _ request: [UInt8],
        maximumResponseByteCount: Int
    ) async throws -> [UInt8] {
        guard maximumResponseByteCount >= 0 else {
            throw WalletWireError.invalidLimit(
                name: "maximumResponseByteCount",
                value: maximumResponseByteCount
            )
        }
        let responseLimits = try limitedResponseLimits(maximumResponseByteCount)
        try Task.checkCancellation()
        let frame = try WalletWireCodec.decodeRequestFrame(request, limits: wireLimits)

        let response: [UInt8]
        switch frame.call {
        case .createAction, .signAction, .abortAction, .listActions,
             .internalizeAction, .listOutputs, .relinquishOutput:
            response = try await processAction(request, responseLimits: responseLimits)
        case .revealCounterpartyKeyLinkage, .revealSpecificKeyLinkage,
             .acquireCertificate, .listCertificates, .proveCertificate,
             .relinquishCertificate, .discoverByIdentityKey, .discoverByAttributes:
            response = try await processCertificate(request, responseLimits: responseLimits)
        case .getPublicKey, .encrypt, .decrypt, .createHMAC, .verifyHMAC,
             .createSignature, .verifySignature, .isAuthenticated,
             .waitForAuthentication, .getHeight, .getHeaderForHeight,
             .getNetwork, .getVersion:
            response = try await processKeyQuery(request, responseLimits: responseLimits)
        }
        guard response.count <= maximumResponseByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "transport response",
                actual: response.count,
                maximum: maximumResponseByteCount
            )
        }
        return response
    }

    private func processAction(
        _ bytes: [UInt8],
        responseLimits: WalletWireLimits
    ) async throws -> [UInt8] {
        let decoded = try WalletWireCodec.decodeActionRequest(
            bytes,
            beefLimits: beefLimits,
            limits: wireLimits
        )
        try Task.checkCancellation()
        let result: WalletWireActionResult
        do {
            let request = WalletRequest.action(decoded.request)
            let handled = try await handler.handle(
                request,
                context: try WalletRequestContext(rawOriginator: decoded.originator)
            )
            guard handled.call == request.call else {
                throw WalletWireSubstrateError.unexpectedResult(
                    expected: request.call,
                    actual: handled.call
                )
            }
            guard case .action(let actionResult) = handled else {
                throw WalletWireSubstrateError.unexpectedResult(
                    expected: request.call,
                    actual: handled.call
                )
            }
            result = actionResult
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return try encodeFailure(error, call: decoded.request.call, limits: responseLimits)
        }
        try Task.checkCancellation()
        let responseBEEFLimits = try limitedBEEFLimits(responseLimits.maximumPayloadByteCount)
        return try WalletWireCodec.encodeActionResult(
            result,
            beefLimits: responseBEEFLimits,
            limits: responseLimits
        )
    }

    private func processCertificate(
        _ bytes: [UInt8],
        responseLimits: WalletWireLimits
    ) async throws -> [UInt8] {
        let decoded = try WalletWireCodec.decodeCertificateRequest(
            bytes,
            certificateLimits: certificateLimits,
            limits: wireLimits
        )
        try Task.checkCancellation()
        let result: WalletWireCertificateResult
        do {
            let request = WalletRequest.certificate(decoded.request)
            let handled = try await handler.handle(
                request,
                context: try WalletRequestContext(rawOriginator: decoded.originator)
            )
            guard handled.call == request.call else {
                throw WalletWireSubstrateError.unexpectedResult(
                    expected: request.call,
                    actual: handled.call
                )
            }
            guard case .certificate(let certificateResult) = handled else {
                throw WalletWireSubstrateError.unexpectedResult(
                    expected: request.call,
                    actual: handled.call
                )
            }
            result = certificateResult
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return try encodeFailure(error, call: decoded.request.call, limits: responseLimits)
        }
        try Task.checkCancellation()
        return try WalletWireCodec.encodeCertificateResult(
            result,
            certificateLimits: certificateLimits,
            limits: responseLimits
        )
    }

    private func processKeyQuery(
        _ bytes: [UInt8],
        responseLimits: WalletWireLimits
    ) async throws -> [UInt8] {
        let decoded = try WalletWireCodec.decodeKeyQueryRequest(bytes, limits: wireLimits)
        try Task.checkCancellation()
        let result: WalletWireKeyQueryResult
        do {
            let request = WalletRequest.keyQuery(decoded.request)
            let handled = try await handler.handle(
                request,
                context: try WalletRequestContext(rawOriginator: decoded.originator)
            )
            guard handled.call == request.call else {
                throw WalletWireSubstrateError.unexpectedResult(
                    expected: request.call,
                    actual: handled.call
                )
            }
            guard case .keyQuery(let keyQueryResult) = handled else {
                throw WalletWireSubstrateError.unexpectedResult(
                    expected: request.call,
                    actual: handled.call
                )
            }
            result = keyQueryResult
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return try encodeFailure(error, call: decoded.request.call, limits: responseLimits)
        }
        try Task.checkCancellation()
        return try WalletWireCodec.encodeKeyQueryResult(result, limits: responseLimits)
    }

    private func encodeFailure(
        _ error: any Error,
        call: WalletCall,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        let remote = failureMapper.remoteError(for: error, call: call)
        return try WalletWireCodec.encodeResultFrame(.failure(remote), limits: limits)
    }

    private func limitedResponseLimits(_ maximum: Int) throws -> WalletWireLimits {
        let frameMaximum = min(maximum, wireLimits.maximumFrameByteCount)
        return try WalletWireLimits(
            maximumFrameByteCount: frameMaximum,
            maximumOriginatorUTF8ByteCount: min(
                wireLimits.maximumOriginatorUTF8ByteCount,
                frameMaximum
            ),
            maximumPayloadByteCount: min(wireLimits.maximumPayloadByteCount, frameMaximum),
            maximumTextUTF8ByteCount: min(wireLimits.maximumTextUTF8ByteCount, frameMaximum),
            maximumRemoteMessageUTF8ByteCount: min(
                wireLimits.maximumRemoteMessageUTF8ByteCount,
                frameMaximum
            ),
            maximumRemoteStackUTF8ByteCount: min(
                wireLimits.maximumRemoteStackUTF8ByteCount,
                frameMaximum
            ),
            abiLimits: wireLimits.abiLimits,
            cryptoLimits: wireLimits.cryptoLimits
        )
    }

    private func limitedBEEFLimits(_ maximum: Int) throws -> BEEFLimits {
        try BEEFLimits(
            maximumByteCount: min(beefLimits.maximumByteCount, maximum),
            maximumMerklePathCount: beefLimits.maximumMerklePathCount,
            maximumTransactionCount: beefLimits.maximumTransactionCount,
            transactionLimits: beefLimits.transactionLimits,
            merklePathLimits: beefLimits.merklePathLimits
        )
    }

    public var description: String { "<wallet-wire processor>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

private struct WalletCoarselyAuthorizedRequestHandler: WalletRequestHandling {
    let adapter: WalletInterfaceRequestHandler
    let authorizer: any WalletWireOriginatorAuthorizing

    init(wallet: any WalletInterface, authorizer: any WalletWireOriginatorAuthorizing) {
        adapter = WalletInterfaceRequestHandler(wallet: wallet)
        self.authorizer = authorizer
    }

    func handle(
        _ request: WalletRequest,
        context: WalletRequestContext
    ) async throws -> WalletResult {
        try await authorizer.authorize(
            originator: context.rawOriginator,
            call: request.call
        )
        try Task.checkCancellation()
        return try await adapter.handle(request, context: context)
    }
}
