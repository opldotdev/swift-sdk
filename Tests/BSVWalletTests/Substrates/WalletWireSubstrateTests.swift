import BSVCore
import BSVCrypto
import BSVKeys
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

    /// The wallet wire carries the largest payload the wallet's own
    /// cryptography accepts, `WalletCryptoLimits.defaultPayloadByteCount`
    /// (16 MiB plus 512 KiB, the BRC-103 general-message bound), with the
    /// longest originator, protocol name and key ID, in a request and in an
    /// encrypt result 48 bytes longer. Frames were capped at 16 MiB before.
    @Test("a maximum-size payload is signed, encrypted and HMACed over the wire, and one byte more is not")
    func maximumPayloadOverWire() async throws {
        let limits = WalletWireLimits.standard
        #expect(
            limits.maximumFrameByteCount
                == WalletCryptoLimits.defaultPayloadByteCount + WalletWireLimits.frameOverheadByteCount)
        #expect(limits.maximumPayloadByteCount == limits.maximumFrameByteCount)
        #expect(limits.abiLimits.maximumAggregatePayloadByteCount == limits.maximumFrameByteCount)
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [9])
        let processor = WalletWireProcessor(
            wallet: CryptoWallet(crypto: ProtoWallet(rootKey: key)),
            authorizer: OriginatorRecorder(),
            failureMapper: try WalletWireRedactingFailureMapper(limits: limits),
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let client = try WalletWireTransceiver(
            transport: processor,
            originator: String(repeating: "o", count: WalletWireLimits.hardMaximumOriginatorUTF8ByteCount),
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let protocolID = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: String(repeating: "p", count: WalletProtocolID.maximumNameUTF8ByteCount))
        let keyID = try WalletKeyID(String(repeating: "k", count: WalletKeyID.maximumUTF8ByteCount))
        var payload = [UInt8](repeating: 0x5A, count: WalletCryptoLimits.defaultPayloadByteCount)
        payload[0] = 1
        payload[payload.count - 1] = 2

        let signed = try await client.createSignature(WalletCreateSignatureRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .anyone, payload: .data(payload)))
        let verified = try await client.verifySignature(WalletVerifySignatureRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .anyone, payload: .data(payload),
            signature: signed.signature, forSelf: true))
        #expect(verified.valid)

        let encrypted = try await client.encrypt(WalletEncryptRequest(
            protocolID: protocolID, keyID: keyID, plaintext: payload))
        #expect(encrypted.ciphertext.count == payload.count + 48)
        let decrypted = try await client.decrypt(WalletDecryptRequest(
            protocolID: protocolID, keyID: keyID, ciphertext: encrypted.ciphertext))
        #expect(decrypted.plaintext == payload)

        let hmac = try await client.createHMAC(WalletCreateHMACRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .anyone, data: payload))
        let hmacVerified = try await client.verifyHMAC(WalletVerifyHMACRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .anyone, data: payload,
            hmac: hmac.hmac))
        #expect(hmacVerified.valid)

        // One payload byte more is refused by the transceiver before anything is sent.
        let over = WalletCryptoLimits.defaultPayloadByteCount + 1
        await #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "signature data", actual: over, maximum: WalletCryptoLimits.defaultPayloadByteCount)
        ) {
            try await client.createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID, keyID: keyID, counterparty: .anyone,
                payload: .data(payload + [0])))
        }
        await #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "HMAC data", actual: over, maximum: WalletCryptoLimits.defaultPayloadByteCount)
        ) {
            try await client.createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID, keyID: keyID, counterparty: .anyone, data: payload + [0]))
        }

        // The frame bound itself: a frame of exactly the limit is read, one
        // byte more is refused as a request frame and answered in band.
        let frameMaximum = limits.maximumFrameByteCount
        var frame = [WalletCall.getHeight.rawValue, 0]
        frame += [UInt8](repeating: 0, count: frameMaximum - frame.count)
        #expect(try WalletWireCodec.decodeRequestFrame(frame, limits: limits).parameters.count
            == frameMaximum - 2)
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "request frame", actual: frameMaximum + 1, maximum: frameMaximum)
        ) {
            try WalletWireCodec.decodeRequestFrame(frame + [0], limits: limits)
        }
        let answer = try WalletWireCodec.decodeResultFrame(
            try await processor.transmit(frame + [0], maximumResponseByteCount: frameMaximum),
            limits: limits)
        guard case .failure(let remote) = answer else {
            Issue.record("an oversized frame was not answered with an error frame")
            return
        }
        #expect(remote.code == 1)
        #expect(remote.message.contains(
            "request frame is \(frameMaximum + 1) bytes, above the limit of \(frameMaximum)"))
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

        // `@bsv/sdk` 4.1.1 answers a malformed request in-band:
        // WalletWireProcessor.ts:2478 throws, its catch writes code 1 with
        // "Wallet Wire getHeight request contains trailing data".
        let response = try await processor.transmit(
            malformed,
            maximumResponseByteCount: limits.maximumFrameByteCount
        )
        let message = "Wallet Wire getHeight request contains trailing data"
        #expect(response == [1, UInt8(message.utf8.count)] + Array(message.utf8) + [0])
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

    @Test("handler receives originator and full protocol and basket scopes")
    func handlerReceivesScopedRequests() async throws {
        let limits = WalletWireLimits.standard
        let handler = ScopedRequestRecorder()
        let processor = WalletWireProcessor(
            handler: handler,
            failureMapper: try WalletWireRedactingFailureMapper(limits: limits),
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let firstClient = try WalletWireTransceiver(
            transport: processor,
            originator: "first.example",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        let secondClient = try WalletWireTransceiver(
            transport: processor,
            originator: "second.example",
            beefLimits: try substrateBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )

        _ = try await firstClient.listOutputs(try WalletListOutputsRequest(basket: "alpha basket"))
        _ = try await secondClient.listOutputs(try WalletListOutputsRequest(basket: "beta basket"))
        _ = try await firstClient.encrypt(WalletEncryptRequest(
            protocolID: try walletTestProtocol("alpha scope"),
            keyID: try walletTestKeyID("key"),
            plaintext: []
        ))
        _ = try await secondClient.encrypt(WalletEncryptRequest(
            protocolID: try walletTestProtocol("beta scope"),
            keyID: try walletTestKeyID("key"),
            plaintext: []
        ))

        #expect(await handler.snapshot() == [
            ScopedCall(
                originator: "first.example", call: .listOutputs, scope: "alpha basket",
                rawSeekPermission: nil, effectiveSeekPermission: true
            ),
            ScopedCall(
                originator: "second.example", call: .listOutputs, scope: "beta basket",
                rawSeekPermission: nil, effectiveSeekPermission: true
            ),
            ScopedCall(
                originator: "first.example", call: .encrypt, scope: "alpha scope",
                rawSeekPermission: nil, effectiveSeekPermission: true
            ),
            ScopedCall(
                originator: "second.example", call: .encrypt, scope: "beta scope",
                rawSeekPermission: nil, effectiveSeekPermission: true
            ),
        ])
    }

    @Test("request context preserves bounded raw originator")
    func requestContextValidation() throws {
        let raw = " HTTPS://Example.COM:443 "
        let context = try WalletRequestContext(rawOriginator: raw)
        #expect(context.rawOriginator == raw)
        #expect(!context.description.contains(raw))
        #expect(Array(Mirror(reflecting: context).children).isEmpty)

        let tooLong = String(
            repeating: "a",
            count: WalletRequestContext.maximumRawOriginatorUTF8ByteCount + 1
        )
        #expect(throws: WalletRequestContextError.originatorTooLong(
            actualUTF8ByteCount: 256,
            maximumUTF8ByteCount: 255
        )) {
            try WalletRequestContext(rawOriginator: tooLong)
        }
    }

    @Test("request metadata applies BRC-100 permission defaults without losing raw input")
    func seekPermissionMetadata() throws {
        let protocolID = try walletTestProtocol("permission metadata")
        let keyID = try walletTestKeyID("key")
        let hmac = try WalletHMAC(bytes: [UInt8](repeating: 0, count: 32))
        let signature = try walletTestPrivateKey(3).sign(digest: BSVHashing.sha256([1]))
        let defaultAccess = WalletKeyAccess.standard

        let defaultTrueRequests: [WalletRequest] = [
            .action(.listActions(try WalletListActionsRequest(labels: []))),
            .action(.internalizeAction(try WalletInternalizeActionRequest(
                transaction: actionAtomicBEEF(),
                description: "internalize",
                outputs: []
            ))),
            .action(.listOutputs(try WalletListOutputsRequest(basket: "default"))),
            .keyQuery(.getPublicKey(WalletGetPublicKeyRequest(
                selection: .identity,
                access: defaultAccess
            ))),
            .keyQuery(.encrypt(WalletEncryptRequest(
                protocolID: protocolID, keyID: keyID, plaintext: [], access: defaultAccess
            ))),
            .keyQuery(.decrypt(WalletDecryptRequest(
                protocolID: protocolID, keyID: keyID, ciphertext: [], access: defaultAccess
            ))),
            .keyQuery(.createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID, keyID: keyID, data: [], access: defaultAccess
            ))),
            .keyQuery(.verifyHMAC(WalletVerifyHMACRequest(
                protocolID: protocolID, keyID: keyID, data: [], hmac: hmac, access: defaultAccess
            ))),
            .keyQuery(.createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .data([]), access: defaultAccess
            ))),
            .keyQuery(.verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .data([1]),
                signature: signature, access: defaultAccess
            ))),
        ]

        for request in defaultTrueRequests {
            #expect(request.seekPermissionMetadata == WalletSeekPermissionMetadata(
                rawValue: nil,
                effectiveValue: true
            ), "call \(request.call.rawValue)")
        }

        let explicitFalse = WalletRequest.keyQuery(.encrypt(WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            plaintext: [],
            access: try WalletKeyAccess(seekPermission: false)
        )))
        #expect(explicitFalse.rawSeekPermission == false)
        #expect(explicitFalse.effectiveSeekPermission == false)

        let identityKey = try walletTestPrivateKey(4).publicKey
        let defaultDiscovery = WalletRequest.certificate(.discoverByIdentityKey(.init(
            identityKey: identityKey
        )))
        // BRC-100 discovery defaults seekPermission to true, as every other
        // call does (packages/sdk/src/wallet/Wallet.interfaces.ts:1021 and
        // :1041 declare `seekPermission?: BooleanDefaultTrue`; W8).
        #expect(defaultDiscovery.rawSeekPermission == nil)
        #expect(defaultDiscovery.effectiveSeekPermission == true)

        let explicitDiscovery = WalletRequest.certificate(.discoverByAttributes(try .init(
            attributes: [:],
            seekPermission: false
        )))
        #expect(explicitDiscovery.rawSeekPermission == false)
        #expect(explicitDiscovery.effectiveSeekPermission == false)

        let notApplicable: [WalletRequest] = [
            .action(.abortAction(WalletAbortActionRequest(
                reference: try WalletBase64Data([1])
            ))),
            .certificate(.revealCounterpartyKeyLinkage(.init(
                counterparty: identityKey,
                verifier: identityKey
            ))),
            .keyQuery(.getHeight(WalletGetHeightRequest())),
        ]
        for request in notApplicable {
            #expect(request.seekPermissionMetadata == WalletSeekPermissionMetadata(
                rawValue: nil,
                effectiveValue: nil
            ), "call \(request.call.rawValue)")
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

private struct ScopedCall: Equatable, Sendable {
    let originator: String
    let call: WalletCall
    let scope: String
    let rawSeekPermission: Bool?
    let effectiveSeekPermission: Bool?
}

private actor ScopedRequestRecorder: WalletRequestHandling {
    private var calls: [ScopedCall] = []

    func handle(
        _ request: WalletRequest,
        context: WalletRequestContext
    ) async throws -> WalletResult {
        switch request {
        case .action(.listOutputs(let value)):
            calls.append(ScopedCall(
                originator: context.rawOriginator,
                call: request.call,
                scope: value.basket,
                rawSeekPermission: request.rawSeekPermission,
                effectiveSeekPermission: request.effectiveSeekPermission
            ))
            return .action(.listOutputs(try WalletListOutputsResult(
                totalOutputs: 0,
                outputs: []
            )))
        case .keyQuery(.encrypt(let value)):
            calls.append(ScopedCall(
                originator: context.rawOriginator,
                call: request.call,
                scope: value.protocolID.name,
                rawSeekPermission: request.rawSeekPermission,
                effectiveSeekPermission: request.effectiveSeekPermission
            ))
            return .keyQuery(.encrypt(WalletEncryptResult(ciphertext: [1, 2, 3])))
        default:
            throw TestFailure.unexpectedCall
        }
    }

    func snapshot() -> [ScopedCall] { calls }
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

/// A wallet whose key operations are a `ProtoWallet`'s.
private struct CryptoWallet: WalletInterface {
    let crypto: ProtoWallet

    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        try await crypto.getPublicKey(request)
    }
    func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        try await crypto.encrypt(request)
    }
    func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        try await crypto.decrypt(request)
    }
    func createSignature(_ request: WalletCreateSignatureRequest) async throws -> WalletCreateSignatureResult {
        try await crypto.createSignature(request)
    }
    func verifySignature(_ request: WalletVerifySignatureRequest) async throws -> WalletVerifySignatureResult {
        try await crypto.verifySignature(request)
    }
    func createHMAC(_ request: WalletCreateHMACRequest) async throws -> WalletCreateHMACResult {
        try await crypto.createHMAC(request)
    }
    func verifyHMAC(_ request: WalletVerifyHMACRequest) async throws -> WalletVerifyHMACResult {
        try await crypto.verifyHMAC(request)
    }
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
