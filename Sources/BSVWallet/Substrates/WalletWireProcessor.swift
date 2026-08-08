import BSVTransaction

/// A bounded in-process server for all 28 BRC-100 wallet-wire calls.
public struct WalletWireProcessor:
    WalletWireTransport,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let wallet: any WalletInterface
    private let authorizer: any WalletWireOriginatorAuthorizing
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
        self.wallet = wallet
        self.authorizer = authorizer
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

    private func authorize(
        originator: String,
        call: WalletCall,
        responseLimits: WalletWireLimits
    ) async throws -> [UInt8]? {
        do {
            try await authorizer.authorize(originator: originator, call: call)
            return nil
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return try encodeFailure(error, call: call, limits: responseLimits)
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
        if let failure = try await authorize(
            originator: decoded.originator,
            call: decoded.request.call,
            responseLimits: responseLimits
        ) {
            return failure
        }
        try Task.checkCancellation()
        let result: WalletWireActionResult
        do {
            switch decoded.request {
            case .createAction(let request):
                result = .createAction(try await wallet.createAction(request))
            case .signAction(let request):
                result = .signAction(try await wallet.signAction(request))
            case .abortAction(let request):
                result = .abortAction(try await wallet.abortAction(request))
            case .listActions(let request):
                result = .listActions(try await wallet.listActions(request))
            case .internalizeAction(let request):
                result = .internalizeAction(try await wallet.internalizeAction(request))
            case .listOutputs(let request):
                result = .listOutputs(try await wallet.listOutputs(request))
            case .relinquishOutput(let request):
                result = .relinquishOutput(try await wallet.relinquishOutput(request))
            }
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
        if let failure = try await authorize(
            originator: decoded.originator,
            call: decoded.request.call,
            responseLimits: responseLimits
        ) {
            return failure
        }
        try Task.checkCancellation()
        let result: WalletWireCertificateResult
        do {
            switch decoded.request {
            case .revealCounterpartyKeyLinkage(let request):
                result = .revealCounterpartyKeyLinkage(
                    try await wallet.revealCounterpartyKeyLinkage(request)
                )
            case .revealSpecificKeyLinkage(let request):
                result = .revealSpecificKeyLinkage(
                    try await wallet.revealSpecificKeyLinkage(request)
                )
            case .acquireCertificate(let request):
                result = .acquireCertificate(try await wallet.acquireCertificate(request))
            case .listCertificates(let request):
                result = .listCertificates(try await wallet.listCertificates(request))
            case .proveCertificate(let request):
                result = .proveCertificate(try await wallet.proveCertificate(request))
            case .relinquishCertificate(let request):
                result = .relinquishCertificate(
                    try await wallet.relinquishCertificate(request)
                )
            case .discoverByIdentityKey(let request):
                result = .discoverByIdentityKey(try await wallet.discoverByIdentityKey(request))
            case .discoverByAttributes(let request):
                result = .discoverByAttributes(try await wallet.discoverByAttributes(request))
            }
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
        if let failure = try await authorize(
            originator: decoded.originator,
            call: decoded.request.call,
            responseLimits: responseLimits
        ) {
            return failure
        }
        try Task.checkCancellation()
        let result: WalletWireKeyQueryResult
        do {
            switch decoded.request {
            case .getPublicKey(let request):
                result = .getPublicKey(try await wallet.getPublicKey(request))
            case .encrypt(let request):
                result = .encrypt(try await wallet.encrypt(request))
            case .decrypt(let request):
                result = .decrypt(try await wallet.decrypt(request))
            case .createHMAC(let request):
                result = .createHMAC(try await wallet.createHMAC(request))
            case .verifyHMAC(let request):
                result = .verifyHMAC(try await wallet.verifyHMAC(request))
            case .createSignature(let request):
                result = .createSignature(try await wallet.createSignature(request))
            case .verifySignature(let request):
                result = .verifySignature(try await wallet.verifySignature(request))
            case .isAuthenticated(let request):
                result = .isAuthenticated(try await wallet.isAuthenticated(request))
            case .waitForAuthentication(let request):
                result = .waitForAuthentication(try await wallet.waitForAuthentication(request))
            case .getHeight(let request):
                result = .getHeight(try await wallet.getHeight(request))
            case .getHeaderForHeight(let request):
                result = .getHeaderForHeight(try await wallet.getHeaderForHeight(request))
            case .getNetwork(let request):
                result = .getNetwork(try await wallet.getNetwork(request))
            case .getVersion(let request):
                result = .getVersion(try await wallet.getVersion(request))
            }
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
