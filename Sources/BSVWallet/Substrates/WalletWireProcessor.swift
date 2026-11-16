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

    /// Answers one request frame.
    ///
    /// Every malformed or unsupported request gets an in-band error frame, as a
    /// `@bsv/sdk` 4.1.1 processor sends: code 1 and a short message, with an
    /// empty stack. Only a bad `maximumResponseByteCount`, cancellation, or a
    /// response larger than the caller allows throw out of band.
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
        let call = request.first.flatMap(WalletCall.init(rawValue:))
        let response: [UInt8]
        do {
            response = try await process(request, responseLimits: responseLimits)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            WalletLog.failure("Wallet wire request decode", call: call, underlying: error)
            response = try failureFrame(
                code: WalletWireErrorCode.unknownError,
                message: walletWireRequestFailureMessage(error, call: call),
                limits: responseLimits
            )
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

    private func process(
        _ request: [UInt8],
        responseLimits: WalletWireLimits
    ) async throws -> [UInt8] {
        // Call 29 is the @bsv/sdk 4.1 certificate compatibility profile. This
        // processor answers it as an older processor does, with exactly the
        // error a TypeScript transceiver downgrades on (see COMP-050).
        try walletWireRejectCompatibilityProfile(request)
        let frame = try WalletWireCodec.decodeRequestFrame(request, limits: wireLimits)
        switch frame.call {
        case .createAction, .signAction, .abortAction, .listActions,
             .internalizeAction, .listOutputs, .relinquishOutput:
            return try await processAction(request, responseLimits: responseLimits)
        case .revealCounterpartyKeyLinkage, .revealSpecificKeyLinkage,
             .acquireCertificate, .listCertificates, .proveCertificate,
             .relinquishCertificate, .discoverByIdentityKey, .discoverByAttributes:
            return try await processCertificate(request, responseLimits: responseLimits)
        case .getPublicKey, .encrypt, .decrypt, .createHMAC, .verifyHMAC,
             .createSignature, .verifySignature, .isAuthenticated,
             .waitForAuthentication, .getHeight, .getHeaderForHeight,
             .getNetwork, .getVersion:
            return try await processKeyQuery(request, responseLimits: responseLimits)
        }
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
        return try encodeResult(call: decoded.request.call, limits: responseLimits) {
            try WalletWireCodec.encodeActionResult(
                result,
                request: decoded.request,
                listOutputsEncoding: decoded.listOutputsEncoding,
                beefLimits: responseBEEFLimits,
                limits: responseLimits
            )
        }
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
        return try encodeResult(call: decoded.request.call, limits: responseLimits) {
            try WalletWireCodec.encodeCertificateResult(
                result,
                request: decoded.request,
                certificateLimits: certificateLimits,
                limits: responseLimits
            )
        }
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
        return try encodeResult(call: decoded.request.call, limits: responseLimits) {
            try WalletWireCodec.encodeKeyQueryResult(result, limits: responseLimits)
        }
    }

    /// Encodes a wallet result, answering in-band when it has no wire encoding.
    private func encodeResult(
        call: WalletCall,
        limits: WalletWireLimits,
        _ encode: () throws -> [UInt8]
    ) throws -> [UInt8] {
        do {
            return try encode()
        } catch let rejection as WalletWireResultRejection {
            WalletLog.failure("Wallet wire result", call: call, underlying: rejection)
            return try failureFrame(
                code: WalletWireErrorCode.clamped(rejection.code),
                message: rejection.message,
                limits: limits
            )
        } catch {
            WalletLog.failure("Wallet wire result encode", call: call, underlying: error)
            return try failureFrame(
                code: WalletWireErrorCode.unknownError,
                message: walletWireResultFailureMessage(error, call: call),
                limits: limits
            )
        }
    }

    private func encodeFailure(
        _ error: any Error,
        call: WalletCall,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        let remote = failureMapper.remoteError(for: error, call: call)
        return try failureFrame(
            code: WalletWireErrorCode.clamped(remote.code),
            message: remote.message,
            limits: limits
        )
    }

    /// An error frame with an empty stack: stacks disclose implementation details.
    private func failureFrame(
        code: UInt8,
        message: String,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        let remote = try WalletWireRemoteError(
            code: code,
            message: walletWireTruncatedMessage(
                message,
                maximum: limits.maximumRemoteMessageUTF8ByteCount
            ),
            stack: "",
            limits: limits
        )
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
