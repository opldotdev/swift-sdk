import BSVAuth
import BSVCrypto
import BSVKeys
import BSVWallet
import Testing

@Suite("BRC-103 peer authenticator")
struct PeerAuthenticatorTests {
    @Test("initial response is verified and first signed general proof authenticates responder")
    func handshake() async throws {
        var aBytes = [UInt8](repeating: 0, count: 32)
        aBytes[31] = 3
        var bBytes = [UInt8](repeating: 0, count: 32)
        bBytes[31] = 7
        let aWallet = ProtoWallet(rootKey: try PrivateKey(aBytes))
        let bWallet = ProtoWallet(rootKey: try PrivateKey(bBytes))
        let a = PeerAuthenticator(wallet: aWallet)
        let b = PeerAuthenticator(wallet: bWallet)
        let start = try await a.beginAuthentication(with: try PrivateKey(bBytes).publicKey)
        guard case .send(let request) = start.actions[0] else {
            Issue.record("missing request")
            return
        }
        let responseActions = try await b.receive(request)
        guard case .send(let response) = responseActions[0] else {
            Issue.record("missing response")
            return
        }
        _ = try await a.receive(response)
        let proof = try await a.makeGeneralMessage(
            payload: Array("proof".utf8), using: start.sessionID)
        guard case .send(let general) = proof else {
            Issue.record("missing proof")
            return
        }
        let delivered = try await b.receive(general)
        guard case .deliver(let value) = delivered[0] else {
            Issue.record("missing delivery")
            return
        }
        #expect(value.payload == Array("proof".utf8))
        #expect((await b.session(value.sessionID))?.state == .authenticated)
    }

    @Test("rejects a response from a different expected peer")
    func expectedPeerBinding() async throws {
        let aKey = try privateKey(3)
        let bKey = try privateKey(7)
        let cKey = try privateKey(11)
        let a = PeerAuthenticator(wallet: ProtoWallet(rootKey: aKey))
        let c = PeerAuthenticator(wallet: ProtoWallet(rootKey: cKey))
        let start = try await a.beginAuthentication(with: bKey.publicKey)
        let request = try sentMessage(start.actions)
        let response = try sentMessage(try await c.receive(request))
        await #expect(throws: AuthError.peerMismatch) {
            try await a.receive(response)
        }
        #expect((await a.session(start.sessionID))?.state == .challengeSent)
    }

    @Test("rejects replay and closes a session at the message limit")
    func replayAndMessageLimit() async throws {
        let limits = try AuthLimits(maximumMessages: 1)
        let a = PeerAuthenticator(wallet: ProtoWallet(rootKey: try privateKey(3)), limits: limits)
        let b = PeerAuthenticator(wallet: ProtoWallet(rootKey: try privateKey(7)), limits: limits)
        let start = try await a.beginAuthentication(with: try privateKey(7).publicKey)
        let request = try sentMessage(start.actions)
        let response = try sentMessage(try await b.receive(request))
        _ = try await a.receive(response)
        let proof = try sentMessage([
            try await a.makeGeneralMessage(payload: [1], using: start.sessionID)
        ])
        let delivered = try await b.receive(proof)
        guard case .deliver(let received) = delivered.first else {
            Issue.record("missing delivered message")
            return
        }
        await #expect(throws: AuthError.replay) {
            try await b.receive(proof)
        }
        await #expect(throws: AuthError.resourceLimit) {
            try await a.makeGeneralMessage(payload: [2], using: start.sessionID)
        }
        #expect(await a.session(start.sessionID) == nil)
        #expect((await b.session(received.sessionID))?.state == .authenticated)
    }

    @Test("rejects invalid random output and expires pending sessions")
    func randomAndTimeoutLimits() async throws {
        let wallet = ProtoWallet(rootKey: try privateKey(3))
        let invalidRandom = PeerAuthenticator(
            wallet: wallet,
            randomSource: FixedRandomSource(bytes: [1])
        )
        await #expect(throws: AuthError.randomGenerationFailed) {
            try await invalidRandom.beginAuthentication()
        }

        let expiring = PeerAuthenticator(
            wallet: wallet,
            limits: try AuthLimits(handshakeTimeout: .nanoseconds(1))
        )
        let start = try await expiring.beginAuthentication()
        await #expect(throws: AuthError.notAuthenticated) {
            try await expiring.makeGeneralMessage(payload: [], using: start.sessionID)
        }
        #expect(await expiring.session(start.sessionID) == nil)
    }

    @Test("redacts authentication values")
    func redaction() async throws {
        let peer = PeerAuthenticator(wallet: ProtoWallet(rootKey: try privateKey(3)))
        let start = try await peer.beginAuthentication()
        let message = try sentMessage(start.actions)
        let snapshot = try #require(await peer.session(start.sessionID))
        let values: [Any] = [message, snapshot, start.actions[0]]
        for value in values {
            var dumped = ""
            dump(value, to: &dumped)
            #expect(!dumped.contains(snapshot.sessionNonce))
            #expect(Mirror(reflecting: value).children.isEmpty)
        }
    }

    private func privateKey(_ scalar: UInt8) throws -> PrivateKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = scalar
        return try PrivateKey(bytes)
    }

    private func sentMessage(_ actions: [AuthPeerAction]) throws -> AuthMessage {
        guard case .send(let message) = actions.first else {
            throw AuthError.invalidMessage
        }
        return message
    }
}

private struct FixedRandomSource: SecureRandomSource {
    let bytes: [UInt8]

    func randomBytes(count: Int) throws -> [UInt8] {
        bytes
    }
}
