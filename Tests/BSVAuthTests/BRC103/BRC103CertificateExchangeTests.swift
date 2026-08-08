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
        let signature = try fixtureSignature().derBytes

        let requestMessage = AuthMessage(
            messageType: .certificateRequest,
            identityKey: requester.publicKey,
            nonce: nonce,
            yourNonce: nonce,
            signature: signature,
            requestedCertificates: request
        )
        let requestJSON = try AuthMessageCodec.encode(requestMessage)
        #expect(try AuthMessageCodec.decode(requestJSON) == requestMessage)
        let noncanonicalRequest = String(decoding: requestJSON, as: UTF8.self)
            .replacingOccurrences(of: #""Certifiers""#, with: #""certifiers""#)
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
    }

    @Test("request validation rejects empty, duplicate, and over-limit values")
    func requestBounds() throws {
        let certifier = try key(11).publicKey
        let type = try CertificateTypeID([UInt8](repeating: 1, count: 32))
        let field = try CertificateFieldName("name")
        #expect(throws: AuthError.invalidCertificateRequest) {
            try AuthRequestedCertificateSet(certifiers: [], certificateTypes: [type: [field]])
        }
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
