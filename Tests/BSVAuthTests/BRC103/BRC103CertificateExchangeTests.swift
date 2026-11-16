import BSVAuth
import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
import BSVWallet
import Foundation
import Testing

@Suite("BRC-103 certificate exchange")
struct BRC103CertificateExchangeTests {
    @Test("strict message JSON round-trips requests and verifiable certificates")
    func messageCodec() throws {
        let requester = try key(3)
        let peer = try key(7)
        let certifier = try key(11)
        let type = try CertificateTypeID([UInt8](repeating: 0x21, count: 32))
        let field = try CertificateFieldName("email")
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifier.publicKey],
            certificateTypes: [type: [field]]
        )
        let nonce = Base64Encoding.encode([UInt8](repeating: 4, count: 32))
        let sessionNonce = Base64Encoding.encode([UInt8](repeating: 5, count: 48))
        let signature = try fixtureSignature().derBytes

        let requestMessage = AuthMessage(
            messageType: .certificateRequest,
            identityKey: requester.publicKey,
            nonce: nonce,
            initialNonce: sessionNonce,
            yourNonce: nonce,
            signature: signature,
            requestedCertificates: request
        )
        let requestJSON = try AuthMessageCodec.encode(requestMessage)
        #expect(try AuthMessageCodec.decode(requestJSON) == requestMessage)
        // The wire spelling is lowercase, matching the TypeScript and Go SDKs and the servers
        // that run them. A capitalised key is not this protocol and is refused.
        let noncanonicalRequest = String(decoding: requestJSON, as: UTF8.self)
            .replacingOccurrences(of: #""certifiers""#, with: #""Certifiers""#)
        #expect(throws: AuthError.invalidCertificateRequest) {
            try AuthMessageCodec.decode(Array(noncanonicalRequest.utf8))
        }

        let certificate = try fixtureCertificate(
            subject: peer.publicKey,
            certifier: certifier.publicKey,
            type: type,
            field: field
        )
        let responseMessage = AuthMessage(
            messageType: .certificateResponse,
            identityKey: peer.publicKey,
            nonce: nonce,
            initialNonce: sessionNonce,
            yourNonce: nonce,
            signature: signature,
            certificates: [certificate]
        )
        let responseJSON = try AuthMessageCodec.encode(responseMessage)
        #expect(try AuthMessageCodec.decode(responseJSON) == responseMessage)
        let extraCertificateMember = String(decoding: responseJSON, as: UTF8.self)
            .replacingOccurrences(
                of: #""keyring":"#,
                with: #""decryptedFields":{},"keyring":"#
            )
        #expect(throws: AuthError.certificateValidationFailed) {
            try AuthMessageCodec.decode(Array(extraCertificateMember.utf8))
        }

        // Certificate messages carry the sender's session nonce
        // (`AuthMessageValidation.ts:404`, `:415`).
        let withoutInitialNonce = String(decoding: requestJSON, as: UTF8.self)
            .replacingOccurrences(of: #""initialNonce":"\#(sessionNonce)","#, with: "")
        #expect(throws: AuthError.self) {
            try AuthMessageCodec.decode(Array(withoutInitialNonce.utf8))
        }
    }

    @Test("request validation rejects duplicate and over-limit values")
    func requestBounds() throws {
        let certifier = try key(11).publicKey
        let type = try CertificateTypeID([UInt8](repeating: 1, count: 32))
        let field = try CertificateFieldName("name")
        // `@bsv/sdk` 4.1.1 sends and accepts a set with no certifiers
        // (`AuthMessageValidation.ts:134-136`); it asks for nothing.
        #expect(
            try AuthRequestedCertificateSet(certifiers: [], certificateTypes: [type: [field]])
                .certifiers.isEmpty)
        #expect(throws: AuthError.resourceLimit) {
            try AuthLimits(
                maximumCertificateCount: AuthLimits.maximumAllowedCertificateCount + 1
            )
        }
        #expect(throws: AuthError.resourceLimit) {
            try AuthLimits(maximumJSONBytes: AuthLimits.maximumAllowedJSONBytes + 1)
        }
        #expect(throws: AuthError.invalidCertificateRequest) {
            try AuthRequestedCertificateSet(
                certifiers: [certifier, certifier],
                certificateTypes: [type: [field]]
            )
        }
        #expect(throws: AuthError.invalidCertificateRequest) {
            try AuthRequestedCertificateSet(
                certifiers: [certifier],
                certificateTypes: [type: [field, field]]
            )
        }
        #expect(throws: AuthError.invalidCertificateRequest) {
            try AuthRequestedCertificateSet(
                certifiers: [certifier],
                certificateTypes: [type: [field]],
                limits: AuthLimits(maximumCertificateFieldCount: 0)
            )
        }
    }

    @Test("authenticated peers exchange signed certificate requests and responses")
    func signedSessionExchange() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let type = try CertificateTypeID([UInt8](repeating: 0x31, count: 32))
        let field = try CertificateFieldName("name")
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [type: [field]]
        )

        let requestMessage = try sent(
            try await requester.makeCertificateRequest(request, using: session.requester)
        )
        let requestActions = try await peer.receive(requestMessage)
        guard case .certificateRequest(let receivedRequest) = requestActions.first else {
            Issue.record("missing certificate request")
            return
        }
        #expect(receivedRequest.request == request)
        #expect(receivedRequest.peer == requesterKey.publicKey)

        let wrongCertificate = try fixtureCertificate(
            subject: peerKey.publicKey,
            certifier: certifierKey.publicKey,
            type: type,
            field: try CertificateFieldName("other")
        )
        await #expect(throws: AuthError.certificateValidationFailed) {
            try await peer.makeCertificateResponse(
                [wrongCertificate],
                using: receivedRequest.sessionID
            )
        }

        let certificate = try fixtureCertificate(
            subject: peerKey.publicKey,
            certifier: certifierKey.publicKey,
            type: type,
            field: field
        )
        let responseMessage = try sent(
            try await peer.makeCertificateResponse([certificate], using: receivedRequest.sessionID)
        )
        let requestSignature = try #require(requestMessage.signature)
        let tamperedResponse = AuthMessage(
            messageType: responseMessage.messageType,
            identityKey: responseMessage.identityKey,
            nonce: responseMessage.nonce,
            initialNonce: responseMessage.initialNonce,
            yourNonce: responseMessage.yourNonce,
            signature: requestSignature,
            certificates: responseMessage.certificates
        )
        await #expect(throws: AuthError.invalidSignature) {
            try await requester.receive(tamperedResponse)
        }
        let responseActions = try await requester.receive(responseMessage)
        guard case .certificateResponse(let receivedResponse) = responseActions.first else {
            Issue.record("missing certificate response")
            return
        }
        #expect(receivedResponse.requested == request)
        #expect(receivedResponse.certificates == [certificate])
        await #expect(throws: AuthError.replay) {
            try await requester.receive(responseMessage)
        }
    }

    @Test("several certificate requests may be open at once, as in Peer.ts")
    func severalOpenRequests() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let nameType = try CertificateTypeID([UInt8](repeating: 0x31, count: 32))
        let ageType = try CertificateTypeID([UInt8](repeating: 0x32, count: 32))
        let name = try CertificateFieldName("name")
        let age = try CertificateFieldName("age")
        let first = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [nameType: [name]])
        let second = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [ageType: [age]])

        // `Peer.ts:474-478` keys each request by nonce; neither replaces the other.
        for request in [first, second] {
            let message = try sent(
                try await requester.makeCertificateRequest(request, using: session.requester))
            guard case .certificateRequest(let received) = try await peer.receive(message).first
            else {
                Issue.record("missing certificate request")
                return
            }
            #expect(received.request == request)
        }

        // Answered out of order: each response settles the request it fits
        // (`Peer.ts:1236-1240`).
        let ageCertificate = try fixtureCertificate(
            subject: peerKey.publicKey, certifier: certifierKey.publicKey, type: ageType,
            field: age)
        let nameCertificate = try fixtureCertificate(
            subject: peerKey.publicKey, certifier: certifierKey.publicKey, type: nameType,
            field: name)
        let ageResponse = try sent(
            try await peer.makeCertificateResponse([ageCertificate], using: session.peer))
        let nameResponse = try sent(
            try await peer.makeCertificateResponse([nameCertificate], using: session.peer))
        guard case .certificateResponse(let ageAnswer) = try await requester.receive(ageResponse).first,
            case .certificateResponse(let nameAnswer) = try await requester.receive(nameResponse).first
        else {
            Issue.record("missing certificate response")
            return
        }
        #expect(ageAnswer.requested == second)
        #expect(nameAnswer.requested == first)

        // Both are settled, so nothing more is awaited on either side.
        await #expect(throws: AuthError.notAuthenticated) {
            try await peer.makeCertificateResponse([], using: session.peer)
        }
        let late = try sent(
            try await requester.makeCertificateRequest(first, using: session.requester))
        _ = try await peer.receive(late)
        let decline = try sent(try await peer.makeCertificateResponse([], using: session.peer))
        guard case .certificateResponse(let declined) = try await requester.receive(decline).first
        else {
            Issue.record("missing certificate response")
            return
        }
        #expect(declined.requested == first)
    }

    @Test("an empty answer declines the oldest open request; at most 16 are open")
    func openRequestOrderAndLimit() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        var requests: [AuthRequestedCertificateSet] = []
        for index in 0..<16 {
            let request = try AuthRequestedCertificateSet(
                certifiers: [certifierKey.publicKey],
                certificateTypes: [
                    try CertificateTypeID([UInt8](repeating: UInt8(0x40 + index), count: 32)):
                        [try CertificateFieldName("name")]
                ])
            requests.append(request)
            _ = try await peer.receive(
                try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        }
        await #expect(throws: AuthError.resourceLimit) {
            try await requester.makeCertificateRequest(requests[0], using: session.requester)
        }

        let decline = try sent(try await peer.makeCertificateResponse([], using: session.peer))
        guard case .certificateResponse(let declined) = try await requester.receive(decline).first
        else {
            Issue.record("missing certificate response")
            return
        }
        #expect(declined.requested == requests[0])
        #expect(declined.certificates.isEmpty)
        // One slot is free again.
        _ = try await requester.makeCertificateRequest(requests[0], using: session.requester)
    }

    @Test("a response can name the request it answers")
    func answeringNamedRequest() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let type = try CertificateTypeID([UInt8](repeating: 0x31, count: 32))
        let other = try CertificateTypeID([UInt8](repeating: 0x32, count: 32))
        let name = try CertificateFieldName("name")
        let first = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [type: [name]])
        let second = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [other: [name], type: [name]])
        for request in [first, second] {
            _ = try await peer.receive(
                try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        }
        let certificate = try fixtureCertificate(
            subject: peerKey.publicKey, certifier: certifierKey.publicKey, type: type, field: name)
        let unasked = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [other: [name]])
        await #expect(throws: AuthError.unexpectedMessage) {
            try await peer.makeCertificateResponse(
                [certificate], using: session.peer, answering: unasked)
        }
        // The certificate fits both; `answering` settles the second.
        _ = try await peer.makeCertificateResponse(
            [certificate], using: session.peer, answering: second)
        let left = try sent(try await peer.makeCertificateResponse([certificate], using: session.peer))
        guard case .certificateResponse(let received) = try await requester.receive(left).first
        else {
            Issue.record("missing certificate response")
            return
        }
        #expect(received.requested == first)
    }

    @Test("wallet preparation and validation are exact and all-or-nothing")
    func walletPreparationAndValidation() async throws {
        let certifierKey = try key(13)
        let subjectKey = try key(17)
        let verifierKey = try key(19)
        let certifier = ProtoWallet(rootKey: certifierKey)
        let subject = ProtoWallet(rootKey: subjectKey)
        let verifier = ProtoWallet(rootKey: verifierKey)
        let type = try CertificateTypeID([UInt8](repeating: 0x41, count: 32))
        let serial = try CertificateSerialNumber([UInt8](repeating: 0x42, count: 32))
        let field = try CertificateFieldName("email")
        let master = try await CertificateEngine.issue(
            type: type,
            serialNumber: serial,
            subject: .publicKey(subjectKey.publicKey),
            plaintextFields: [field: "alice@example.test"],
            using: certifier
        )
        let projected = try await CertificateEngine.project(
            master,
            fields: [field],
            to: verifierKey.publicKey,
            using: subject
        )
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [type: [field]]
        )
        let source = CertificateOperationStub(
            certificate: master.certificate,
            keyring: projected.keyring.entries
        )
        let prepared = try await AuthCertificateExchange.prepare(
            request,
            for: verifierKey.publicKey,
            using: source
        )
        #expect(prepared == [projected])
        let validated = try await AuthCertificateExchange.validate(
            prepared,
            from: subjectKey.publicKey,
            requested: request,
            using: verifier
        )
        #expect(validated.count == 1)
        #expect(validated[0].disclosedFields == [field: "alice@example.test"])

        let wrongRequest = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [type: [try CertificateFieldName("other")]]
        )
        await #expect(throws: AuthError.certificateValidationFailed) {
            try await AuthCertificateExchange.validate(
                prepared,
                from: subjectKey.publicKey,
                requested: wrongRequest,
                using: verifier
            )
        }
    }

    @Test("certificate exchange values redact diagnostic output")
    func redaction() throws {
        let certifier = try key(23).publicKey
        let type = try CertificateTypeID([UInt8](repeating: 0x51, count: 32))
        let field = try CertificateFieldName("secret-field")
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifier],
            certificateTypes: [type: [field]]
        )
        var output = ""
        dump(request, to: &output)
        #expect(!output.contains("secret-field"))
        #expect(Mirror(reflecting: request).children.isEmpty)
    }

    private func authenticate(
        _ requester: PeerAuthenticator,
        _ peer: PeerAuthenticator,
        peerKey: PublicKey
    ) async throws -> (requester: AuthSessionID, peer: AuthSessionID) {
        let start = try await requester.beginAuthentication(with: peerKey)
        let initialRequest = try sent(start.actions[0])
        let response = try sent(try await peer.receive(initialRequest)[0])
        _ = try await requester.receive(response)
        let proof = try sent(
            try await requester.makeGeneralMessage(payload: [1], using: start.sessionID)
        )
        let proofActions = try await peer.receive(proof)
        guard case .deliver(let received) = proofActions.first else {
            throw AuthError.invalidMessage
        }
        return (start.sessionID, received.sessionID)
    }

    private func fixtureCertificate(
        subject: PublicKey,
        certifier: PublicKey,
        type: CertificateTypeID,
        field: CertificateFieldName
    ) throws -> VerifiableCertificate {
        let ciphertext = try CertificateCiphertext([1, 2, 3])
        let certificate = try Certificate(
            type: type,
            serialNumber: CertificateSerialNumber([UInt8](repeating: 0x61, count: 32)),
            subject: subject,
            certifier: certifier,
            revocationOutpoint: CertificateEngine.disabledRevocationOutpoint,
            fields: [field: ciphertext],
            signature: fixtureSignature()
        )
        return try VerifiableCertificate(
            certificate: certificate,
            keyring: CertificateKeyring([field: ciphertext])
        )
    }

    private func fixtureSignature() throws -> ECDSASignature {
        try ECDSASignature(derBytes: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = scalar
        return try PrivateKey(bytes)
    }

    private func sent(_ action: AuthPeerAction) throws -> AuthMessage {
        guard case .send(let message) = action else { throw AuthError.invalidMessage }
        return message
    }
}

private actor CertificateOperationStub: WalletCertificateOperations {
    let certificate: Certificate
    let keyring: [CertificateFieldName: CertificateCiphertext]

    init(
        certificate: Certificate,
        keyring: [CertificateFieldName: CertificateCiphertext]
    ) {
        self.certificate = certificate
        self.keyring = keyring
    }

    func acquireCertificate(_ request: WalletAcquireCertificateRequest) async throws -> Certificate
    {
        throw AuthError.unexpectedMessage
    }

    func listCertificates(
        _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        try WalletListCertificatesResult(
            totalCertificates: 1,
            certificates: [
                try WalletCertificateResult(
                    certificate: certificate,
                    keyring: nil,
                    verifier: []
                )
            ]
        )
    }

    func proveCertificate(
        _ request: WalletProveCertificateRequest
    ) async throws -> WalletProveCertificateResult {
        try WalletProveCertificateResult(keyringForVerifier: keyring)
    }

    func relinquishCertificate(
        _ request: WalletRelinquishCertificateRequest
    ) async throws -> WalletRelinquishCertificateResult {
        throw AuthError.unexpectedMessage
    }
}
