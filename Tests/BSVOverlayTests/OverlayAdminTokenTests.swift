import BSVCrypto
import BSVKeys
import BSVOverlay
import BSVScript
import Testing

@Suite("Overlay administration token verification")
struct OverlayAdminTokenTests {
    @Test("verifies a signed SHIP administration token")
    func verifiesSHIPToken() throws {
        let identityKey = try privateKey(2)
        let lockingKey = try privateKey(3)
        let script = try signedScript(
            protocolText: "SHIP",
            identityKey: identityKey.publicKey,
            host: "overlay.example",
            subject: "tm_payments",
            lockingKey: lockingKey
        )

        let token = try OverlayAdminTokenCodec.decode(script)
        #expect(token.overlayProtocol == .ship)
        #expect(token.identityPublicKey == identityKey.publicKey)
        #expect(token.lockingPublicKey == lockingKey.publicKey)
        #expect(token.host.rawValue == "overlay.example")
        #expect(token.subject == .ship(try OverlayTopic(rawValue: "tm_payments")))
    }

    @Test("verifies a signed SLAP administration token")
    func verifiesSLAPToken() throws {
        let identityKey = try privateKey(4)
        let lockingKey = try privateKey(5)
        let script = try signedScript(
            protocolText: "SLAP",
            identityKey: identityKey.publicKey,
            host: "lookup.example",
            subject: "ls_ship",
            lockingKey: lockingKey
        )

        let token = try OverlayAdminTokenCodec.decode(script)
        #expect(token.overlayProtocol == .slap)
        #expect(token.subject == .slap(try OverlayService(rawValue: "ls_ship")))
    }

    @Test("rejects malformed token structure and fields")
    func rejectsMalformedFields() throws {
        let identityKey = try privateKey(6)
        let lockingKey = try privateKey(7)
        let fields = baseFields(
            protocolText: "SHIP",
            identityKey: identityKey.publicKey,
            host: "overlay.example",
            subject: "tm_test"
        )
        let unsigned = try PushDrop.lockingScript(
            fields: fields,
            publicKey: lockingKey.publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: OverlayAdminTokenError.unexpectedFieldCount(actual: 4, expected: 5)) {
            _ = try OverlayAdminTokenCodec.decode(unsigned)
        }

        let signed = try signedScript(fields: fields, lockingKey: lockingKey)
        let decodedSigned = try PushDrop.decode(signed, lockPosition: .beforeCompatibility)
        let surplus = try PushDrop.lockingScript(
            fields: decodedSigned.fields + [[0]],
            publicKey: lockingKey.publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: OverlayAdminTokenError.invalidPushDrop) {
            _ = try OverlayAdminTokenCodec.decode(surplus)
        }

        #expect(throws: OverlayAdminTokenError.invalidProtocol) {
            _ = try OverlayAdminTokenCodec.decode(
                try signedScript(
                    protocolText: "OTHER",
                    identityKey: identityKey.publicKey,
                    host: "overlay.example",
                    subject: "tm_test",
                    lockingKey: lockingKey
                ))
        }

        var invalidIdentity = fields
        invalidIdentity[1] = Array(repeating: 0, count: 33)
        #expect(throws: OverlayAdminTokenError.invalidIdentityKey) {
            _ = try OverlayAdminTokenCodec.decode(
                try signedScript(fields: invalidIdentity, lockingKey: lockingKey))
        }

        #expect(throws: OverlayAdminTokenError.invalidSubject) {
            _ = try OverlayAdminTokenCodec.decode(
                try signedScript(
                    protocolText: "SHIP",
                    identityKey: identityKey.publicKey,
                    host: "overlay.example",
                    subject: "ls_ship",
                    lockingKey: lockingKey
                ))
        }

        #expect(throws: OverlayAdminTokenError.invalidHost) {
            _ = try OverlayAdminTokenCodec.decode(
                try signedScript(
                    protocolText: "SLAP",
                    identityKey: identityKey.publicKey,
                    host: "bad host",
                    subject: "ls_ship",
                    lockingKey: lockingKey
                ))
        }
    }

    @Test("rejects invalid and mismatched signatures")
    func rejectsInvalidSignatures() throws {
        let identityKey = try privateKey(8)
        let lockingKey = try privateKey(9)
        let fields = baseFields(
            protocolText: "SHIP",
            identityKey: identityKey.publicKey,
            host: "overlay.example",
            subject: "tm_test"
        )

        let invalidDER = try PushDrop.lockingScript(
            fields: fields + [[0]],
            publicKey: lockingKey.publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: OverlayAdminTokenError.invalidSignature) {
            _ = try OverlayAdminTokenCodec.decode(invalidDER)
        }

        let otherKey = try privateKey(10)
        let mismatched = try signedScript(fields: fields, lockingKey: otherKey)
        #expect(throws: OverlayAdminTokenError.invalidSignature) {
            _ = try OverlayAdminTokenCodec.decode(
                replacingLockingKey(
                    in: mismatched,
                    with: lockingKey.publicKey
                ))
        }
    }

    @Test("limits are applied by PushDrop before administration fields are indexed")
    func appliesLimitsBeforeFieldIndexing() throws {
        let identityKey = try privateKey(11)
        let lockingKey = try privateKey(12)
        let script = try signedScript(
            protocolText: "SHIP",
            identityKey: identityKey.publicKey,
            host: "overlay.example",
            subject: "tm_test",
            lockingKey: lockingKey
        )
        let limits = try OverlayAdminTokenLimits(
            maximumScriptByteCount: 64 * 1_024,
            maximumFieldByteCount: 2
        )
        #expect(throws: OverlayAdminTokenError.invalidPushDrop) {
            _ = try OverlayAdminTokenCodec.decode(script, limits: limits)
        }
    }

    @Test("diagnostics and reflection redact token values")
    func redactsDiagnostics() throws {
        let identityKey = try privateKey(13)
        let lockingKey = try privateKey(14)
        let token = try OverlayAdminTokenCodec.decode(
            try signedScript(
                protocolText: "SHIP",
                identityKey: identityKey.publicKey,
                host: "private-overlay-173.example",
                subject: "tm_test",
                lockingKey: lockingKey
            ))
        #expect(!token.description.contains("173"))
        #expect(!token.debugDescription.contains("173"))
        #expect(token.customMirror.children.isEmpty)
        acceptSendable(token)
        acceptSendable(OverlayAdminTokenLimits.standard)
    }

    private func privateKey(_ value: UInt8) throws -> PrivateKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [value])
    }

    private func baseFields(
        protocolText: String,
        identityKey: PublicKey,
        host: String,
        subject: String
    ) -> [[UInt8]] {
        [
            Array(protocolText.utf8),
            identityKey.compressedBytes,
            Array(host.utf8),
            Array(subject.utf8),
        ]
    }

    private func signedScript(
        protocolText: String,
        identityKey: PublicKey,
        host: String,
        subject: String,
        lockingKey: PrivateKey
    ) throws -> Script {
        try signedScript(
            fields: baseFields(
                protocolText: protocolText,
                identityKey: identityKey,
                host: host,
                subject: subject
            ),
            lockingKey: lockingKey
        )
    }

    private func signedScript(
        fields: [[UInt8]],
        lockingKey: PrivateKey
    ) throws -> Script {
        let payload = fields.flatMap { $0 }
        let signature = try lockingKey.sign(digest: BSVHashing.sha256(payload))
        return try PushDrop.lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: lockingKey.publicKey,
            lockPosition: .beforeCompatibility
        )
    }

    private func replacingLockingKey(in script: Script, with publicKey: PublicKey) throws -> Script
    {
        let decoded = try PushDrop.decode(script, lockPosition: .beforeCompatibility)
        return try PushDrop.lockingScript(
            fields: decoded.fields,
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
    }

    private func acceptSendable<T: Sendable>(_ value: T) {}
}
