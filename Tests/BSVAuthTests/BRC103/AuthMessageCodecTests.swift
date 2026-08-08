import BSVAuth
import BSVCore
import BSVKeys
import BSVWallet
import Testing

@Suite("BRC-103 authentication message codec")
struct AuthMessageCodecTests {
    @Test("accepts canonical 32-byte and Go-style 48-byte session nonces")
    func nonceWidths() throws {
        let identity = try fixtureIdentity()
        for byteCount in [32, 48] {
            let nonce = Base64Encoding.encode(
                [UInt8](repeating: UInt8(byteCount), count: byteCount))
            let message = AuthMessage(
                messageType: .initialRequest,
                identityKey: identity,
                initialNonce: nonce
            )
            let encoded = try AuthMessageCodec.encode(message)
            let decoded = try AuthMessageCodec.decode(encoded)
            #expect(decoded == message)
        }
    }

    @Test("rejects duplicate, escaped, unknown, and malformed object keys")
    func strictObjectKeys() throws {
        let identity = try fixtureIdentity()
        let key = Hex.encode(identity.compressedBytes)
        let nonce = Base64Encoding.encode([UInt8](repeating: 1, count: 32))
        let base =
            #"{"version":"0.1","messageType":"initialRequest","identityKey":"\#(key)","initialNonce":"\#(nonce)"}"#
        let cases = [
            base.replacingOccurrences(
                of: #""version":"0.1""#,
                with: #""version":"0.1","version":"0.1""#
            ),
            base.replacingOccurrences(
                of: #""version":"0.1""#,
                with: #""vers\u0069on":"0.1","version":"0.1""#
            ),
            base.replacingOccurrences(
                of: #""initialNonce":"\#(nonce)""#,
                with: #""initialNonce":"\#(nonce)","unknown":0"#
            ),
            String(base.dropLast()),
        ]
        for document in cases {
            #expect(throws: AuthError.invalidMessage) {
                try AuthMessageCodec.decode(Array(document.utf8))
            }
        }
    }

    @Test("rejects duplicate nested request keys and nonintegral byte values")
    func strictNestedValues() throws {
        let identity = try fixtureIdentity()
        let key = Hex.encode(identity.compressedBytes)
        let nonce = Base64Encoding.encode([UInt8](repeating: 2, count: 32))
        let duplicateNested =
            #"{"version":"0.1","messageType":"initialRequest","identityKey":"\#(key)","initialNonce":"\#(nonce)","requestedCertificates":{"Certifiers":[],"Certifiers":[],"CertificateTypes":{}}}"#
        #expect(throws: AuthError.invalidMessage) {
            try AuthMessageCodec.decode(Array(duplicateNested.utf8))
        }

        let invalidPayloads = ["[true]", "[1.5]", "[-1]", "[256]"]
        for payload in invalidPayloads {
            let document =
                #"{"version":"0.1","messageType":"general","identityKey":"\#(key)","nonce":"\#(nonce)","yourNonce":"\#(nonce)","payload":\#(payload),"signature":[48,6,2,1,1,2,1,1]}"#
            #expect(throws: AuthError.self) {
                try AuthMessageCodec.decode(Array(document.utf8))
            }
        }
    }

    @Test("checks the JSON byte limit before parsing or encoding")
    func jsonLimit() throws {
        let identity = try fixtureIdentity()
        let nonce = Base64Encoding.encode([UInt8](repeating: 3, count: 32))
        let message = AuthMessage(
            messageType: .initialRequest,
            identityKey: identity,
            initialNonce: nonce
        )
        let encoded = try AuthMessageCodec.encode(message)
        let exact = try AuthLimits(maximumJSONBytes: encoded.count)
        #expect(try AuthMessageCodec.decode(encoded, limits: exact) == message)
        #expect(throws: AuthError.resourceLimit) {
            try AuthMessageCodec.encode(
                message,
                limits: AuthLimits(maximumJSONBytes: encoded.count - 1)
            )
        }
        #expect(throws: AuthError.resourceLimit) {
            try AuthMessageCodec.decode(
                encoded,
                limits: AuthLimits(maximumJSONBytes: encoded.count - 1)
            )
        }
    }

    @Test("certificate data is accepted only in signed certificate messages")
    func certificateMessageBoundary() throws {
        let identity = try fixtureIdentity()
        let nonce = Base64Encoding.encode([UInt8](repeating: 3, count: 32))
        let type = try CertificateTypeID([UInt8](repeating: 4, count: 32))
        let request = try AuthRequestedCertificateSet(
            certifiers: [identity],
            certificateTypes: [type: [try CertificateFieldName("name")]]
        )
        #expect(throws: AuthError.invalidMessage) {
            try AuthMessageCodec.encode(
                AuthMessage(
                    messageType: .initialRequest,
                    identityKey: identity,
                    initialNonce: nonce,
                    requestedCertificates: request
                )
            )
        }
        #expect(throws: AuthError.invalidMessage) {
            try AuthMessageCodec.encode(
                AuthMessage(
                    messageType: .general,
                    identityKey: identity,
                    nonce: nonce,
                    yourNonce: nonce,
                    payload: [1],
                    signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
                    requestedCertificates: request
                )
            )
        }
    }

    @Test("rejects excessive JSON nesting before Foundation parsing")
    func nestingLimit() {
        let document =
            String(repeating: "[", count: 66) + "0"
            + String(repeating: "]", count: 66)
        #expect(throws: AuthError.invalidMessage) {
            try AuthMessageCodec.decode(Array(document.utf8))
        }
    }

    private func fixtureIdentity() throws -> PublicKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = 9
        return try PrivateKey(bytes).publicKey
    }
}
