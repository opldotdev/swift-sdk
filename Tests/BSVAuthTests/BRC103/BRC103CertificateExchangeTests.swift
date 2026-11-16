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
        // (`Peer.ts:1236-1241`).
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

    @Test("a response fitting a certificateRequest and the handshake policy settles both, as in Peer.ts")
    func requestBeforeHandshakePolicy() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let type = try CertificateTypeID([UInt8](repeating: 0x31, count: 32))
        let name = try CertificateFieldName("name")
        let age = try CertificateFieldName("age")
        let policy = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [type: [name]])
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [type: [name, age]])
        let requester = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: requesterKey), certificatesToRequest: policy)
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        _ = try await peer.receive(
            try sent(try await requester.makeCertificateRequest(request, using: session.requester)))

        // The certificate fits both. `Peer.ts:1240` validates it against
        // the certificateRequest, `:1245` settles that request and `:1247`
        // counts the handshake policy as answered too.
        let certificate = try fixtureCertificate(
            subject: peerKey.publicKey, certifier: certifierKey.publicKey, type: type, field: name)
        let answer = try sent(
            try await peer.makeCertificateResponse([certificate], using: session.peer))
        let actions = try await requester.receive(answer)
        let settled = actions.compactMap { action -> AuthRequestedCertificateSet? in
            guard case .certificateResponse(let response) = action else { return nil }
            #expect(response.certificates == [certificate])
            return response.requested
        }
        #expect(settled == [request, policy])

        // Nothing is open on either side now.
        await #expect(throws: AuthError.notAuthenticated) {
            try await peer.makeCertificateResponse([], using: session.peer)
        }
    }

    @Test("an empty response settles one request, not the handshake policy as well")
    func emptyResponseSettlesOne() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let type = try CertificateTypeID([UInt8](repeating: 0x31, count: 32))
        let name = try CertificateFieldName("name")
        let policy = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [type: [name]])
        let requester = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: requesterKey), certificatesToRequest: policy)
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [type: [name, try CertificateFieldName("age")]])
        _ = try await peer.receive(
            try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        // `Peer.ts:1229` looks at a response only when it carries certificates.
        let decline = try sent(try await peer.makeCertificateResponse([], using: session.peer))
        let first = try await requester.receive(decline)
        #expect(first.count == 1)
        guard case .certificateResponse(let declined) = first.first else {
            Issue.record("missing certificate response")
            return
        }
        #expect(declined.requested == request)
        // The handshake policy is still open on both sides.
        let second = try await requester.receive(
            try sent(try await peer.makeCertificateResponse([], using: session.peer)))
        guard case .certificateResponse(let declinedPolicy) = second.first else {
            Issue.record("missing certificate response")
            return
        }
        #expect(declinedPolicy.requested == policy)
    }

    @Test("open received requests share one byte budget, and a repeat is refused")
    func receivedRequestBudget() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        // Each request below is charged 33 + 32 + 4 = 69 bytes.
        let peer = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: peerKey),
            limits: try AuthLimits(maximumCertificateAggregateBytes: 200))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        func request(_ byte: UInt8) throws -> AuthRequestedCertificateSet {
            try AuthRequestedCertificateSet(
                certifiers: [certifierKey.publicKey],
                certificateTypes: [
                    try CertificateTypeID([UInt8](repeating: byte, count: 32)):
                        [try CertificateFieldName("name")]
                ])
        }
        func ask(_ set: AuthRequestedCertificateSet) async throws -> [AuthPeerAction] {
            try await peer.receive(
                try sent(try await requester.makeCertificateRequest(set, using: session.requester)))
        }
        _ = try await ask(try request(0x50))
        let log = AuthLogLines()
        await log.record {
            await #expect(throws: AuthError.unexpectedMessage) {
                try await ask(try request(0x50))
            }
        }
        #expect(log.lines.contains { $0.contains("an identical request is already open") })
        _ = try await ask(try request(0x51))
        await #expect(throws: AuthError.resourceLimit) {
            try await ask(try request(0x52))
        }
        // The session stays usable; answering one frees its share.
        #expect((await peer.session(session.peer))?.state == .authenticated)
        _ = try await peer.makeCertificateResponse([], using: session.peer)
        _ = try await ask(try request(0x52))
    }

    @Test("a response's signature is checked before it is matched")
    func signatureBeforeMatching() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let type = try CertificateTypeID([UInt8](repeating: 0x31, count: 32))
        let name = try CertificateFieldName("name")
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [type: [name]])
        _ = try await peer.receive(
            try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        let response = try sent(try await peer.makeCertificateResponse([], using: session.peer))
        // Certificates that fit no request, under a signature over none.
        let unfitting = try fixtureCertificate(
            subject: peerKey.publicKey, certifier: certifierKey.publicKey,
            type: try CertificateTypeID([UInt8](repeating: 0x39, count: 32)), field: name)
        let forged = AuthMessage(
            messageType: response.messageType, identityKey: response.identityKey,
            nonce: response.nonce, initialNonce: response.initialNonce,
            yourNonce: response.yourNonce, signature: response.signature,
            certificates: [unfitting])
        let log = AuthLogLines()
        await log.record {
            await #expect(throws: AuthError.invalidSignature) {
                try await requester.receive(forged)
            }
        }
        #expect(log.lines.isEmpty)
    }

    @Test("an unsolicited response is checked for its signature before it is refused")
    func unsolicitedResponseSignatureFirst() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [
                try CertificateTypeID([UInt8](repeating: 0x31, count: 32)):
                    [try CertificateFieldName("name")]
            ])
        _ = try await peer.receive(
            try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        let response = try sent(try await peer.makeCertificateResponse([], using: session.peer))
        _ = try await requester.receive(response)
        // Nothing is open now. `Peer.ts:1202-1217` checks the signature first.
        let forged = AuthMessage(
            messageType: .certificateResponse, identityKey: response.identityKey,
            nonce: Base64Encoding.encode([UInt8](repeating: 0x77, count: 32)),
            initialNonce: response.initialNonce, yourNonce: response.yourNonce,
            signature: response.signature, certificates: [])
        await #expect(throws: AuthError.invalidSignature) {
            try await requester.receive(forged)
        }
    }

    @Test("a refused certificateRequest uses up its nonce")
    func refusedRequestCannotBeReplayed() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [
                try CertificateTypeID([UInt8](repeating: 0x31, count: 32)):
                    [try CertificateFieldName("name")]
            ])
        _ = try await peer.receive(
            try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        let repeated = try sent(
            try await requester.makeCertificateRequest(request, using: session.requester))
        let log = AuthLogLines()
        await log.record {
            await #expect(throws: AuthError.unexpectedMessage) {
                try await peer.receive(repeated)
            }
            // `Peer.ts:1088-1092` claims the nonce before acting on the request.
            await #expect(throws: AuthError.replay) {
                try await peer.receive(repeated)
            }
            // Even once the first request is answered and the repeat would fit.
            _ = try? await peer.makeCertificateResponse([], using: session.peer)
            await #expect(throws: AuthError.replay) {
                try await peer.receive(repeated)
            }
        }
        #expect(log.lines.count == 1)
    }

    @Test("a sender can stop waiting for a request the peer refused")
    func withdrawRefusedRequest() async throws {
        let requesterKey = try key(3)
        let peerKey = try key(7)
        let certifierKey = try key(11)
        let requester = PeerAuthenticator(wallet: ProtoWallet(rootKey: requesterKey))
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: peerKey))
        let session = try await authenticate(requester, peer, peerKey: peerKey.publicKey)
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [
                try CertificateTypeID([UInt8](repeating: 0x31, count: 32)):
                    [try CertificateFieldName("name")]
            ])
        _ = try await peer.receive(
            try sent(try await requester.makeCertificateRequest(request, using: session.requester)))
        await #expect(throws: AuthError.unexpectedMessage) {
            try await peer.receive(
                try self.sent(
                    try await requester.makeCertificateRequest(request, using: session.requester)))
        }
        #expect(await requester.withdrawCertificateRequest(request, using: session.requester))
        // One answer settles the one request still open on each side.
        _ = try await requester.receive(
            try sent(try await peer.makeCertificateResponse([], using: session.peer)))
        #expect(await requester.withdrawCertificateRequest(request, using: session.requester) == false)
    }

    @Test("only errors this SDK defines are logged in clear")
    func logPrivacy() async throws {
        #expect(AuthLog.isSDKError(AuthError.invalidSignature))
        #expect(AuthLog.isSDKError(BRC104Error.invalidMethod))
        #expect(!AuthLog.isSDKError(WalletFailure(secret: "x")))
        #expect(!AuthLog.isSDKError(CocoaError(.fileNoSuchFile)))

        // Through a real call path: a caller's wallet fails while a
        // certificate field is decrypted.
        let certifierKey = try key(13)
        let subjectKey = try key(17)
        let verifierKey = try key(19)
        let type = try CertificateTypeID([UInt8](repeating: 0x41, count: 32))
        let field = try CertificateFieldName("email")
        let master = try await CertificateEngine.issue(
            type: type, subject: .publicKey(subjectKey.publicKey),
            plaintextFields: [field: "alice@example.test"],
            using: ProtoWallet(rootKey: certifierKey))
        let projected = try await CertificateEngine.project(
            master, fields: [field], to: verifierKey.publicKey,
            using: ProtoWallet(rootKey: subjectKey))
        let request = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey], certificateTypes: [type: [field]])
        let failing = FailingDecryptWallet(
            base: ProtoWallet(rootKey: verifierKey), secret: "wallet secret 1234")
        let entries = AuthLogEntries()
        await entries.record {
            await #expect(throws: AuthError.certificateValidationFailed) {
                try await AuthCertificateExchange.validate(
                    [projected], from: subjectKey.publicKey, requested: request, using: failing)
            }
        }
        let walletEntry = try #require(
            entries.entries.first { $0.detail.contains("wallet secret 1234") })
        #expect(walletEntry.detailIsPrivate)
        #expect(walletEntry.prefix.hasPrefix("CertificateEngine field key decryption: WalletFailure"))
        #expect(entries.entries.allSatisfy { !$0.publicText.contains("wallet secret 1234") })
        // The SDK's own errors along the same path are public.
        #expect(entries.entries.contains { !$0.detailIsPrivate })
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

private struct WalletFailure: Error {
    let secret: String
}

/// A caller's wallet that fails to decrypt with an error holding a secret.
private struct FailingDecryptWallet: CertificateWallet {
    let base: ProtoWallet
    let secret: String

    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        try await base.getPublicKey(request)
    }
    func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        try await base.createSignature(request)
    }
    func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        try await base.verifySignature(request)
    }
    func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        try await base.encrypt(request)
    }
    func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        throw WalletFailure(secret: secret)
    }
}

/// Collects `AuthLog` entries about underlying errors while a test runs.
private final class AuthLogEntries: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [AuthLog.Entry] = []

    var entries: [AuthLog.Entry] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func record(_ body: () async throws -> Void) async rethrows {
        try await AuthLog.$entryObserver.withValue({ [self] entry in
            lock.lock()
            stored.append(entry)
            lock.unlock()
        }) {
            try await body()
        }
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
