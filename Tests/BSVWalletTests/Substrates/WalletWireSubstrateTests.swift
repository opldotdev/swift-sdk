import BSVTransaction
import BSVWallet
import Testing

@Suite("Wallet-wire transport-neutral substrates")
struct WalletWireSubstrateTests {
    @Test("all call groups round-trip and authorize the bound originator")
    func allGroupsRoundTrip() async throws {
        let recorder = OriginatorRecorder()
        let limits = WalletWireLimits.standard
        let processor = WalletWireProcessor(
            wallet: SubstrateWallet(),
            authorizer: recorder,
            failureMapper: try WalletWireRedactingFailureMapper(limits: limits),
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let client = try WalletWireTransceiver(
            transport: processor,
            originator: "example.com",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        #expect(!String(reflecting: client).contains("example.com"))
        #expect(Array(Mirror(reflecting: client).children).isEmpty)
        #expect(Array(Mirror(reflecting: processor).children).isEmpty)

        let aborted = try await client.abortAction(WalletAbortActionRequest(
            reference: try WalletBase64Data([1, 2, 3])
        ))
        #expect(aborted.aborted)

        let certificates = try await client.listCertificates(
            try WalletListCertificatesRequest(certifiers: [], types: [])
        )
        #expect(certificates.totalCertificates == 0)
        #expect(certificates.certificates.isEmpty)

        let height = try await client.getHeight(WalletGetHeightRequest())
        #expect(height.height == 321)

        let calls = await recorder.snapshot()
        #expect(calls == [
            OriginatorCall(originator: "example.com", call: .abortAction),
            OriginatorCall(originator: "example.com", call: .listCertificates),
            OriginatorCall(originator: "example.com", call: .getHeight),
        ])
        #expect(WalletCall.allCases.count == 28)
    }

    @Test("strict parameter decoding happens before originator authorization")
    func rejectsMalformedParametersBeforeAuthorization() async throws {
        let recorder = OriginatorRecorder()
        let limits = WalletWireLimits.standard
        let processor = WalletWireProcessor(
            wallet: SubstrateWallet(),
            authorizer: recorder,
            failureMapper: try WalletWireRedactingFailureMapper(limits: limits),
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let malformed = try WalletWireCodec.encodeRequestFrame(
            WalletWireRequestFrame(
                call: .getHeight,
                originator: "untrusted.example",
                parameters: [0]
            ),
            limits: limits
        )

        await #expect(throws: WalletWireError.trailingBytes) {
            try await processor.transmit(
                malformed,
                maximumResponseByteCount: limits.maximumFrameByteCount
            )
        }
        #expect(await recorder.snapshot().isEmpty)
    }

    @Test("wallet failures cross the wire as bounded redacted remote errors")
    func remoteFailuresAreBoundedAndRedacted() async throws {
        let limits = WalletWireLimits.standard
        let mapper = try WalletWireRedactingFailureMapper(
            code: 7,
            message: "request denied",
            stack: "",
            limits: limits
        )
        let processor = WalletWireProcessor(
            wallet: SubstrateWallet(failVersion: true),
            authorizer: WalletWireOriginatorAuthorizer { _, _ in },
            failureMapper: mapper,
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let client = try WalletWireTransceiver(
            transport: processor,
            originator: "example.com",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )

        do {
            _ = try await client.getVersion(WalletGetVersionRequest())
            Issue.record("expected a remote failure")
        } catch let error as WalletWireRemoteError {
            #expect(error.code == 7)
            #expect(error.message == "request denied")
            #expect(error.stack.isEmpty)
            #expect(!error.description.contains("request denied"))
            #expect(!String(reflecting: error).contains("secret-wallet-detail"))
        }
    }

    @Test("transport failures are redacted and cancellation stays cancellation")
    func transportFailureAndCancellation() async throws {
        let limits = WalletWireLimits.standard
        let failed = try WalletWireTransceiver(
            transport: FailingTransport(),
            originator: "example.com",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        await #expect(throws: WalletWireSubstrateError.transportFailure) {
            try await failed.getHeight(WalletGetHeightRequest())
        }

        let blocking = try WalletWireTransceiver(
            transport: BlockingTransport(),
            originator: "example.com",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let task = Task { try await blocking.getHeight(WalletGetHeightRequest()) }
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("originator and response bounds are enforced at the client boundary")
    func clientBounds() async throws {
        let limits = try WalletWireLimits(maximumOriginatorUTF8ByteCount: 3)
        #expect(throws: WalletWireError.self) {
            _ = try WalletWireTransceiver(
                transport: FailingTransport(),
                originator: "four",
                beefLimits: try substrateBEEFLimits(),
                certificateLimits: .standard,
                wireLimits: limits
            )
        }

        let malformed = try WalletWireTransceiver(
            transport: FixedTransport(response: [0, 1, 2]),
            originator: "app",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        await #expect(throws: WalletWireError.trailingBytes) {
            try await malformed.getHeight(WalletGetHeightRequest())
        }

        let tiny = try WalletWireLimits(
            maximumFrameByteCount: 8,
            maximumOriginatorUTF8ByteCount: 3,
            maximumPayloadByteCount: 7,
            maximumTextUTF8ByteCount: 7,
            maximumRemoteMessageUTF8ByteCount: 7,
            maximumRemoteStackUTF8ByteCount: 7
        )
        let hostile = OversizedTransport()
        let bounded = try WalletWireTransceiver(
            transport: hostile,
            originator: "app",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: tiny
        )
        await #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "transport response",
            actual: 9,
            maximum: 8
        )) {
            try await bounded.getHeight(WalletGetHeightRequest())
        }
        #expect(await hostile.requestedMaximum() == 8)
    }

    @Test("key/query writers reject payload max plus one during append")
    func keyQueryWritersAreBounded() throws {
        let request = WalletWireKeyQueryRequest.encrypt(WalletEncryptRequest(
            protocolID: try walletTestProtocol("substrate bound"),
            keyID: try walletTestKeyID("key"),
            plaintext: [UInt8](repeating: 1, count: 16)
        ))
        let baseline = try WalletWireCodec.encodeKeyQueryRequest(
            request,
            originator: ""
        )
        let payloadCount = try WalletWireCodec.decodeRequestFrame(baseline).parameters.count
        let exactRequestLimits = try substrateWireLimits(maximumPayload: payloadCount)
        _ = try WalletWireCodec.encodeKeyQueryRequest(
            request,
            originator: "",
            limits: exactRequestLimits
        )
        let shortRequestLimits = try substrateWireLimits(maximumPayload: payloadCount - 1)
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "request parameters",
            actual: payloadCount,
            maximum: payloadCount - 1
        )) {
            try WalletWireCodec.encodeKeyQueryRequest(
                request,
                originator: "",
                limits: shortRequestLimits
            )
        }

        let exactResultLimits = try substrateWireLimits(maximumPayload: 16)
        _ = try WalletWireCodec.encodeKeyQueryResult(
            .encrypt(WalletEncryptResult(ciphertext: [UInt8](repeating: 2, count: 16))),
            limits: exactResultLimits
        )
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "result payload",
            actual: 17,
            maximum: 16
        )) {
            try WalletWireCodec.encodeKeyQueryResult(
                .encrypt(WalletEncryptResult(ciphertext: [UInt8](repeating: 2, count: 17))),
                limits: exactResultLimits
            )
        }
    }
}

private struct OriginatorCall: Equatable, Sendable {
    let originator: String
    let call: WalletCall
}

private func substrateBEEFLimits() throws -> BEEFLimits {
    try BEEFLimits(
        maximumByteCount: 1_000_000,
        maximumMerklePathCount: 100,
        maximumTransactionCount: 1_000,
        transactionLimits: try TransactionLimits(
            maximumTransactionByteCount: 100_000,
            maximumInputCount: 100,
            maximumOutputCount: 100,
            maximumScriptByteCount: 10_000
        ),
        merklePathLimits: try MerklePathLimits(
            maximumByteCount: 100_000,
            maximumLeavesPerLevel: 100,
            maximumTotalLeaves: 1_000
        )
    )
}

private func substrateWireLimits(maximumPayload: Int) throws -> WalletWireLimits {
    try WalletWireLimits(
        maximumFrameByteCount: maximumPayload + 256,
        maximumOriginatorUTF8ByteCount: 32,
        maximumPayloadByteCount: maximumPayload,
        maximumTextUTF8ByteCount: maximumPayload,
        maximumRemoteMessageUTF8ByteCount: maximumPayload,
        maximumRemoteStackUTF8ByteCount: maximumPayload,
        cryptoLimits: try WalletCryptoLimits(maximumPayloadByteCount: 1_000)
    )
}

private actor OriginatorRecorder: WalletWireOriginatorAuthorizing {
    private var calls: [OriginatorCall] = []

    func authorize(originator: String, call: WalletCall) {
        calls.append(OriginatorCall(originator: originator, call: call))
    }

    func snapshot() -> [OriginatorCall] { calls }
}

private struct FixedTransport: WalletWireTransport {
    let response: [UInt8]
    func transmit(
        _ request: [UInt8],
        maximumResponseByteCount: Int
    ) async throws -> [UInt8] { response }
}

private struct FailingTransport: WalletWireTransport {
    func transmit(
        _ request: [UInt8],
        maximumResponseByteCount: Int
    ) async throws -> [UInt8] {
        throw TestFailure.secret("secret-transport-detail")
    }
}

private struct BlockingTransport: WalletWireTransport {
    func transmit(
        _ request: [UInt8],
        maximumResponseByteCount: Int
    ) async throws -> [UInt8] {
        try await Task.sleep(for: .seconds(60))
        return []
    }
}

private actor OversizedTransport: WalletWireTransport {
    private var maximum: Int?

    func transmit(
        _ request: [UInt8],
        maximumResponseByteCount: Int
    ) async throws -> [UInt8] {
        maximum = maximumResponseByteCount
        return Array(repeating: 0, count: maximumResponseByteCount + 1)
    }

    func requestedMaximum() -> Int? { maximum }
}

private enum TestFailure: Error {
    case unexpectedCall
    case secret(String)
}

private struct SubstrateWallet: WalletInterface {
    let failVersion: Bool
    init(failVersion: Bool = false) { self.failVersion = failVersion }

    func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult {
        WalletAbortActionResult(aborted: true)
    }

    func listCertificates(
        _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        try WalletListCertificatesResult(totalCertificates: 0, certificates: [])
    }

    func getHeight(_ request: WalletGetHeightRequest) async throws -> WalletGetHeightResult {
        WalletGetHeightResult(height: 321)
    }

    func getVersion(_ request: WalletGetVersionRequest) async throws -> WalletGetVersionResult {
        if failVersion { throw TestFailure.secret("secret-wallet-detail") }
        return try WalletGetVersionResult(version: "test")
    }
}

private extension WalletActionOperations {
    func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult { throw TestFailure.unexpectedCall }
    func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult { throw TestFailure.unexpectedCall }
    func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult { throw TestFailure.unexpectedCall }
    func listActions(_ request: WalletListActionsRequest) async throws -> WalletListActionsResult { throw TestFailure.unexpectedCall }
    func internalizeAction(_ request: WalletInternalizeActionRequest) async throws -> WalletInternalizeActionResult { throw TestFailure.unexpectedCall }
}

private extension WalletOutputOperations {
    func listOutputs(_ request: WalletListOutputsRequest) async throws -> WalletListOutputsResult { throw TestFailure.unexpectedCall }
    func relinquishOutput(_ request: WalletRelinquishOutputRequest) async throws -> WalletRelinquishOutputResult { throw TestFailure.unexpectedCall }
}

private extension WalletCertificateOperations {
    func acquireCertificate(_ request: WalletAcquireCertificateRequest) async throws -> Certificate { throw TestFailure.unexpectedCall }
    func listCertificates(_ request: WalletListCertificatesRequest) async throws -> WalletListCertificatesResult { throw TestFailure.unexpectedCall }
    func proveCertificate(_ request: WalletProveCertificateRequest) async throws -> WalletProveCertificateResult { throw TestFailure.unexpectedCall }
    func relinquishCertificate(_ request: WalletRelinquishCertificateRequest) async throws -> WalletRelinquishCertificateResult { throw TestFailure.unexpectedCall }
}

private extension WalletLinkageOperations {
    func revealCounterpartyKeyLinkage(_ request: WalletRevealCounterpartyKeyLinkageRequest) async throws -> WalletRevealCounterpartyKeyLinkageResult { throw TestFailure.unexpectedCall }
    func revealSpecificKeyLinkage(_ request: WalletRevealSpecificKeyLinkageRequest) async throws -> WalletRevealSpecificKeyLinkageResult { throw TestFailure.unexpectedCall }
}

private extension WalletDiscoveryOperations {
    func discoverByIdentityKey(_ request: WalletDiscoverByIdentityKeyRequest) async throws -> WalletDiscoverCertificatesResult { throw TestFailure.unexpectedCall }
    func discoverByAttributes(_ request: WalletDiscoverByAttributesRequest) async throws -> WalletDiscoverCertificatesResult { throw TestFailure.unexpectedCall }
}

private extension WalletAuthenticationOperations {
    func isAuthenticated(_ request: WalletIsAuthenticatedRequest) async throws -> WalletAuthenticatedResult { throw TestFailure.unexpectedCall }
    func waitForAuthentication(_ request: WalletWaitForAuthenticationRequest) async throws -> WalletAuthenticatedResult { throw TestFailure.unexpectedCall }
}

private extension WalletChainInformation {
    func getHeight(_ request: WalletGetHeightRequest) async throws -> WalletGetHeightResult { throw TestFailure.unexpectedCall }
    func getHeaderForHeight(_ request: WalletGetHeaderRequest) async throws -> WalletGetHeaderResult { throw TestFailure.unexpectedCall }
    func getNetwork(_ request: WalletGetNetworkRequest) async throws -> WalletGetNetworkResult { throw TestFailure.unexpectedCall }
    func getVersion(_ request: WalletGetVersionRequest) async throws -> WalletGetVersionResult { throw TestFailure.unexpectedCall }
}

private extension WalletKeyOperations {
    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult { throw TestFailure.unexpectedCall }
    func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult { throw TestFailure.unexpectedCall }
    func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult { throw TestFailure.unexpectedCall }
    func createHMAC(_ request: WalletCreateHMACRequest) async throws -> WalletCreateHMACResult { throw TestFailure.unexpectedCall }
    func verifyHMAC(_ request: WalletVerifyHMACRequest) async throws -> WalletVerifyHMACResult { throw TestFailure.unexpectedCall }
    func createSignature(_ request: WalletCreateSignatureRequest) async throws -> WalletCreateSignatureResult { throw TestFailure.unexpectedCall }
    func verifySignature(_ request: WalletVerifySignatureRequest) async throws -> WalletVerifySignatureResult { throw TestFailure.unexpectedCall }
}
