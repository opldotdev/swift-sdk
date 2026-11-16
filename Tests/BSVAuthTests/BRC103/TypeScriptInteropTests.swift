import BSVAuth
import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet
import Foundation
import Testing

/// Replays wire messages produced by `@bsv/sdk` 4.1.1 (`TypeScriptAuthVectors`)
/// against this SDK, in both directions of a session.
@Suite("BRC-103/104 TypeScript 4.1.1 interoperability")
struct TypeScriptInteropTests {
    // MARK: Swift client, TypeScript `Peer` responder

    @Test("Swift initiator completes the handshake and certificate exchange with a TS peer")
    func swiftClientWithTypeScriptPeer() async throws {
        let typeScript = try key(3).publicKey
        let certifier = try key(11).publicKey
        let swiftWallet = ProtoWallet(rootKey: try key(7))
        let client = PeerAuthenticator(
            wallet: swiftWallet, randomSource: CountingRandomSource(seed: 0x40))

        let start = try await client.beginAuthentication(with: typeScript)
        let request = try sent(start.actions)
        #expect(request.initialNonce == Base64Encoding.encode([UInt8](repeating: 0x41, count: 48)))

        // `Peer.ts:866-875` sends its handshake certificate policy in
        // initialResponse; `Peer.ts:1326-1328` holds general messages until it
        // is answered.
        let initialResponse = try decode(TypeScriptAuthVectors.initialResponse)
        let responseActions = try await client.receive(initialResponse)
        #expect(responseActions.count == 1)
        guard case .certificateRequest(let handshake) = responseActions.first else {
            Issue.record("initialResponse requestedCertificates were not surfaced")
            return
        }
        #expect(handshake.peer == typeScript)
        #expect(handshake.request.certifiers == [certifier])
        let handshakeType = try CertificateTypeID([UInt8](repeating: 0x51, count: 32))
        #expect(handshake.request.certificateTypes == [handshakeType: [try field("email")]])
        #expect((await client.session(start.sessionID))?.state == .authenticated)

        // An empty response is valid (`AuthMessageValidation.ts:417`, `Peer.ts:1117`).
        let empty = try sent([try await client.makeCertificateResponse([], using: start.sessionID)])
        #expect(empty.certificates == [])
        #expect(empty.initialNonce == request.initialNonce)
        let emptyWire = try String(decoding: AuthMessageCodec.encode(empty), as: UTF8.self)
        #expect(emptyWire.contains(#""certificates":[]"#))

        let requested = try AuthRequestedCertificateSet(
            certifiers: [certifier],
            certificateTypes: [
                try CertificateTypeID(TypeScriptAuthVectors.certificateType): [
                    try field("userName"), try field("profilePhoto"), try field("a&b<c>"),
                ]
            ])
        let certificateRequest = try sent([
            try await client.makeCertificateRequest(requested, using: start.sessionID)
        ])
        // TS requires initialNonce on certificate messages (`AuthMessageValidation.ts:404`).
        #expect(certificateRequest.initialNonce == request.initialNonce)
        #expect(
            certificateRequest.nonce
                == Base64Encoding.encode([UInt8](repeating: 0x43, count: 32)))

        // `Peer.ts:1142` signs the certificates in issue order for `fields` and
        // reveal order for `keyring`, neither byte-sorted.
        let tsResponse = try decode(TypeScriptAuthVectors.certificateResponse)
        let responseResult = try await client.receive(tsResponse)
        guard case .certificateResponse(let received) = responseResult.first else {
            Issue.record("missing certificate response")
            return
        }
        #expect(received.requested == requested)
        let validated = try await AuthCertificateExchange.validate(
            received.certificates, from: typeScript, requested: requested, using: swiftWallet)
        #expect(validated.count == 1)
        var expected: [CertificateFieldName: String] = [:]
        for item in TypeScriptAuthVectors.certificateFields {
            expected[try field(item.name)] = item.value
        }
        #expect(validated.first?.disclosedFields == expected)

        // `Peer.ts:453` signs the policy in insertion order: 0x02… before 0x01….
        let tsRequest = try decode(TypeScriptAuthVectors.certificateRequest)
        let requestResult = try await client.receive(tsRequest)
        guard case .certificateRequest(let peerRequest) = requestResult.first else {
            Issue.record("missing certificate request")
            return
        }
        #expect(
            peerRequest.request.certificateTypes == [
                try CertificateTypeID([UInt8](repeating: 0x02, count: 32)): [
                    try field("name"), try field("email"),
                ],
                try CertificateTypeID([UInt8](repeating: 0x01, count: 32)): [try field("x")],
            ])
    }

    @Test("a TS certificate message with the wrong initialNonce is rejected")
    func certificateInitialNonceBinding() async throws {
        let client = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x40))
        let start = try await client.beginAuthentication(with: try key(3).publicKey)
        _ = try await client.receive(try decode(TypeScriptAuthVectors.initialResponse))
        _ = try await client.makeCertificateResponse([], using: start.sessionID)

        let tsInitialNonce = try #require(
            try decode(TypeScriptAuthVectors.initialResponse).initialNonce)
        let wrong = Base64Encoding.encode([UInt8](repeating: 0x7e, count: 48))
        let tampered = TypeScriptAuthVectors.certificateRequest.replacingOccurrences(
            of: #""initialNonce":"\#(tsInitialNonce)""#, with: #""initialNonce":"\#(wrong)""#)
        #expect(tampered != TypeScriptAuthVectors.certificateRequest)
        await #expect(throws: AuthError.invalidNonce) {
            try await client.receive(try decode(tampered))
        }

        let missing = TypeScriptAuthVectors.certificateRequest.replacingOccurrences(
            of: #""initialNonce":"\#(tsInitialNonce)","#, with: "")
        #expect(throws: AuthError.self) { try decode(missing) }
    }

    @Test("a TS peer answers a Swift handshake policy with certificates in initialResponse")
    func handshakeCertificatesInInitialResponse() async throws {
        let typeScript = try key(3).publicKey
        let certifier = try key(11).publicKey
        let swiftWallet = ProtoWallet(rootKey: try key(7))
        let type = try CertificateTypeID(TypeScriptAuthVectors.handshakeCertificateType)
        let requested = try AuthRequestedCertificateSet(
            certifiers: [certifier],
            certificateTypes: [type: try TypeScriptAuthVectors.handshakeRequestedFields.map(field)])
        let client = PeerAuthenticator(
            wallet: swiftWallet, randomSource: CountingRandomSource(seed: 0x40))
        let start = try await client.beginAuthentication(with: typeScript, requesting: requested)
        let initialRequest = try sent(start.actions)
        #expect(initialRequest.requestedCertificates == requested)
        #expect(initialRequest.initialNonce == Base64Encoding.encode([UInt8](repeating: 0x41, count: 48)))
        #expect(try decode(String(decoding: AuthMessageCodec.encode(initialRequest), as: UTF8.self)) == initialRequest)

        // `Peer.ts:960-982`: the initiator validates initialResponse certificates
        // against its own policy.
        let actions = try await client.receive(
            try decode(TypeScriptAuthVectors.initialResponseWithCertificates))
        #expect(actions.count == 1)
        guard case .certificateResponse(let received) = actions.first else {
            Issue.record("initialResponse certificates were not surfaced")
            return
        }
        #expect(received.sessionID == start.sessionID)
        #expect(received.peer == typeScript)
        #expect(received.requested == requested)
        #expect((await client.session(start.sessionID))?.state == .authenticated)
        let validated = try await AuthCertificateExchange.validate(
            received.certificates, from: typeScript, requested: requested, using: swiftWallet)
        var expected: [CertificateFieldName: String] = [:]
        for item in TypeScriptAuthVectors.handshakeFields
        where TypeScriptAuthVectors.handshakeRequestedFields.contains(item.name) {
            expected[try field(item.name)] = item.value
        }
        #expect(validated.first?.disclosedFields == expected)

        // The policy was answered, so a later certificate request may be sent.
        _ = try await client.makeCertificateRequest(requested, using: start.sessionID)
    }

    @Test("initialResponse certificates are ignored unless requested and must match the policy")
    func handshakeCertificatesPolicy() async throws {
        let typeScript = try key(3).publicKey
        let vector = try decode(TypeScriptAuthVectors.initialResponseWithCertificates)

        // Not requested: ignored, as `Peer.ts:960-967` does.
        let plain = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x40))
        let plainStart = try await plain.beginAuthentication(with: typeScript)
        #expect(try await plain.receive(vector).isEmpty)
        #expect((await plain.session(plainStart.sessionID))?.state == .authenticated)

        // A narrower policy than the certificates reveal is refused before the
        // session changes.
        let narrow = try AuthRequestedCertificateSet(
            certifiers: [try key(11).publicKey],
            certificateTypes: [
                try CertificateTypeID(TypeScriptAuthVectors.handshakeCertificateType): [
                    try field("Zip")
                ]
            ])
        let strict = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x40))
        let strictStart = try await strict.beginAuthentication(with: typeScript, requesting: narrow)
        await #expect(throws: AuthError.self) { try await strict.receive(vector) }
        #expect((await strict.session(strictStart.sessionID))?.state == .challengeSent)
    }

    @Test("a TS certificateRequest with no certifiers authenticates and asks for nothing")
    func emptyCertifierRequest() async throws {
        let server = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x60))
        let initialRequest = try decode(TypeScriptAuthVectors.emptyRequestInitialRequest)
        // `Peer.ts:644-650` always sends a policy; this one asks for nothing.
        #expect(initialRequest.requestedCertificates?.certifiers == [])
        let actions = try await server.receive(initialRequest)
        #expect(actions.count == 1)
        let response = try sent(actions)
        #expect(response.initialNonce == Base64Encoding.encode([UInt8](repeating: 0x61, count: 48)))

        let request = try decode(TypeScriptAuthVectors.emptyCertificateRequest)
        #expect(request.requestedCertificates?.certifiers == [])
        #expect(request.requestedCertificates?.certificateTypes == [:])
        // `Peer.ts:1085-1119` verifies it and authenticates the sender, with no callback.
        #expect(try await server.receive(request).isEmpty)

        // A replay is still refused.
        await #expect(throws: AuthError.self) { try await server.receive(request) }
    }

    @Test("Swift sends a certificateRequest with no certifiers without awaiting an answer")
    func swiftEmptyCertifierRequest() async throws {
        let client = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x40))
        let start = try await client.beginAuthentication(with: try key(3).publicKey)
        _ = try await client.receive(try decode(TypeScriptAuthVectors.initialResponse))
        _ = try await client.makeCertificateResponse([], using: start.sessionID)
        let empty = try AuthRequestedCertificateSet(certifiers: [], certificateTypes: [:])
        let message = try sent([try await client.makeCertificateRequest(empty, using: start.sessionID)])
        let wire = try String(decoding: AuthMessageCodec.encode(message), as: UTF8.self)
        #expect(wire.contains(#""requestedCertificates":{"certifiers":[],"types":{}}"#))
        // Nothing is pending, so another request may follow.
        _ = try await client.makeCertificateRequest(empty, using: start.sessionID)
    }

    // MARK: TypeScript `AuthFetch` client, Swift server

    @Test("Swift server answers a TS AuthFetch handshake and verifies its GET request")
    func typeScriptAuthFetchWithSwiftServer() async throws {
        let server = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x60))

        let initialRequest = try decode(TypeScriptAuthVectors.authFetchInitialRequest)
        let actions = try await server.receive(initialRequest)
        // AuthFetch sends `requestedCertificates: {certifiers: [], types: {}}`.
        #expect(actions.count == 1)
        let response = try sent(actions)
        // `AuthMessageValidation.ts:394` requires exactly 48 bytes.
        let responderNonce = try #require(response.initialNonce)
        #expect(responderNonce.utf8.count == 64)
        #expect(
            try Base64Encoding.decode(responderNonce, maximumDecodedByteCount: 64)
                == [UInt8](repeating: 0x61, count: 48))
        #expect(response.yourNonce == initialRequest.initialNonce)

        // `SimplifiedFetchTransport.ts:189-194`: six headers, no message type,
        // no body for a GET.
        let frame = try BRC104HTTPRequestFrame(
            method: TypeScriptAuthVectors.authFetchMethod,
            path: TypeScriptAuthVectors.authFetchPath,
            headers: TypeScriptAuthVectors.authFetchHeaders.map {
                BRC104Header(name: $0.name, value: $0.value)
            },
            body: nil)
        let general = try BRC104HTTPFrameCodec.decodeRequest(frame)
        #expect(general.messageType == .general)
        let delivered = try await server.receive(general)
        guard case .deliver(let message) = delivered.first else {
            Issue.record("missing delivered request")
            return
        }
        let request = try BRC104Codec.decodeRequest(message.payload)
        #expect(request.method == "GET")
        #expect(request.path == "/a")
        #expect(request.body == nil)
        #expect((await server.session(message.sessionID))?.state == .authenticated)

        // A transport that hands over an empty array for the absent body signs
        // the same -1 (`authMiddlewareHelpers.ts:155-185`).
        let emptyFrame = try BRC104HTTPRequestFrame(
            method: frame.method, path: frame.path, headers: frame.headers, body: [])
        #expect(try BRC104HTTPFrameCodec.decodeRequest(emptyFrame).payload == general.payload)
    }

    // MARK: BRC-104 payload vectors

    @Test("request payloads equal AuthFetch.serializeRequest output")
    func requestPayloadVectors() throws {
        let id = [UInt8](repeating: 0x07, count: 32)
        let json = BRC104Header(name: "content-type", value: "application/json")
        let cases: [(BRC104Request, String)] = [
            (
                // `AuthFetch.ts:740` sorts signed headers with `localeCompare`.
                try BRC104Request(
                    requestID: id, method: "POST", path: "/h",
                    headers: [
                        .init(name: "x-bsv-zeta", value: "1"), .init(name: "x-bsv-ab", value: "2"),
                        .init(name: "x-bsv-a-b", value: "3"), .init(name: "x-bsv-a_b", value: "4"),
                        .init(name: "x-bsv-a.b", value: "5"), .init(name: "x-bsv-upper", value: "6"),
                        json,
                    ],
                    body: Array("{}".utf8)),
                TypeScriptAuthVectors.serializedHeaderOrder
            ),
            (
                try BRC104Request(requestID: id, method: "GET", path: "/a"),
                TypeScriptAuthVectors.serializedGetNoBody
            ),
            (
                try BRC104Request(
                    requestID: id, method: "POST", path: "/v1/items", headers: [json]),
                TypeScriptAuthVectors.serializedPostJsonDefault
            ),
            (
                try BRC104Request(
                    requestID: id, method: "POST", path: "/v1/items", headers: [json], body: []),
                TypeScriptAuthVectors.serializedPostEmptyString
            ),
            (
                try BRC104Request(
                    requestID: id, method: "POST", path: "/v1/items", query: "?x=1",
                    headers: [.init(name: "content-type", value: "application/json ; charset=utf-8")],
                    body: Array(#"{"a":1}"#.utf8)),
                TypeScriptAuthVectors.serializedContentTypeSpaces
            ),
            (
                try BRC104Request(
                    requestID: id, method: "POST", path: "/upload",
                    headers: [
                        .init(name: "content-type", value: "multipart/form-data; boundary=abc123")
                    ],
                    body: Array("part".utf8)),
                TypeScriptAuthVectors.serializedMultipart
            ),
        ]
        for (request, hex) in cases {
            #expect(Hex.encode(try BRC104Codec.encode(request)) == hex)
        }
    }

    @Test("bodyless responses sign -1 whether the body is nil or empty")
    func emptyResponseBodies() throws {
        // `SimplifiedFetchTransport.ts:314-321` and
        // `auth-express-middleware/src/index.ts:2112-2117`.
        let id = [UInt8](repeating: 0x07, count: 32)
        let minusOne = [UInt8](repeating: 0xff, count: 9)
        for body in [nil, [UInt8]()] as [[UInt8]?] {
            let noContent = try BRC104Response(requestID: id, status: 204, body: body)
            #expect(try BRC104Codec.encode(noContent) == id + [0xcc, 0x00] + minusOne)
            let notFound = try BRC104Response(requestID: id, status: 404, body: body)
            #expect(try BRC104Codec.encode(notFound) == id + [0xfd, 0x94, 0x01, 0x00] + minusOne)
        }
    }

    @Test("default limits accept TS-sized messages and payment headers")
    func typeScriptLimits() throws {
        // `AuthMessageValidation.ts:8-14`, `SimplifiedFetchTransport.ts:25-28`,
        // `SimplifiedFetchTransport.ts:655-661`, `clients/AuthFetch.ts:147`.
        #expect(AuthLimits.standard.maximumJSONBytes == 16 << 20)
        #expect(AuthLimits.standard.maximumPayloadBytes == (16 << 20) + (512 << 10))
        #expect(AuthLimits.standard.maximumCertificateCount == 100)
        #expect(BRC104Limits.standard.maximumHeaders == 512)
        #expect(BRC104Limits.standard.maximumHeaderValueBytes == 32 << 10)

        let id = [UInt8](repeating: 0x07, count: 32)
        let payment = String(repeating: "A", count: 200 << 10)
        let request = try BRC104Request(
            requestID: id, method: "POST", path: "/pay",
            headers: [.init(name: "x-bsv-payment", value: payment)])
        #expect(request.headers.first?.value == payment)
        #expect(throws: BRC104Error.invalidHeader) {
            try BRC104Request(
                requestID: id, method: "POST", path: "/pay",
                headers: [.init(name: "x-bsv-other", value: String(repeating: "A", count: 33 << 10))])
        }
        #expect(throws: BRC104Error.invalidHeader) {
            try BRC104Response(
                requestID: id, status: 200,
                headers: [.init(name: "x-bsv-payment", value: payment)])
        }
    }

    // MARK: Certificate JSON preimage

    @Test("Foundation sortedKeys order is not UTF-8 byte order on this platform")
    func foundationSortedKeysOrder() throws {
        // The old encoder wrote the wire JSON with `.sortedKeys` but signed
        // byte-sorted text. Two base64 type IDs that start "Z2dn" (0x67…) and
        // "aWlp" (0x69…) sort differently under the two rules.
        let upper = Base64Encoding.encode([UInt8](repeating: 0x67, count: 32))
        let lower = Base64Encoding.encode([UInt8](repeating: 0x69, count: 32))
        #expect(Array(upper.utf8).lexicographicallyPrecedes(Array(lower.utf8)))
        let data = try JSONSerialization.data(
            withJSONObject: [upper: 1, lower: 2], options: [.sortedKeys])
        let text = String(decoding: data, as: UTF8.self)
        let upperIndex = try #require(text.range(of: upper)).lowerBound
        let lowerIndex = try #require(text.range(of: lower)).lowerBound
        #expect(lowerIndex < upperIndex, "Foundation sortedKeys: \(text)")

        // The encoder now writes exactly the bytes it signs.
        let requested = try AuthRequestedCertificateSet(
            certifiers: [try key(11).publicKey],
            certificateTypes: [
                try CertificateTypeID([UInt8](repeating: 0x67, count: 32)): [try field("Zip")],
                try CertificateTypeID([UInt8](repeating: 0x69, count: 32)): [try field("age")],
            ])
        let message = AuthMessage(
            messageType: .certificateRequest, identityKey: try key(7).publicKey,
            nonce: Base64Encoding.encode([UInt8](repeating: 1, count: 32)),
            initialNonce: Base64Encoding.encode([UInt8](repeating: 2, count: 48)),
            yourNonce: Base64Encoding.encode([UInt8](repeating: 3, count: 48)),
            signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            requestedCertificates: requested)
        let wire = String(decoding: try AuthMessageCodec.encode(message), as: UTF8.self)
        let signed = String(
            decoding: try AuthMessageCodec.certificateRequestSigningBytes(requested, limits: .standard),
            as: UTF8.self)
        #expect(wire.contains(#""requestedCertificates":\#(signed)"#))
        #expect(signed.range(of: upper)!.lowerBound < signed.range(of: lower)!.lowerBound)
        #expect(try AuthMessageCodec.decode(Array(wire.utf8)) == message)
    }

    @Test("certificate JSON escapes exactly as JSON.stringify does")
    func certificateJSONEscaping() throws {
        let requested = try AuthRequestedCertificateSet(
            certifiers: [try key(11).publicKey],
            certificateTypes: [
                try CertificateTypeID([UInt8](repeating: 0x01, count: 32)): [
                    try field("R&D"), try field("a<b>\u{2028}"), try field("q\"\\\t\u{01}"),
                ]
            ])
        let signed = String(
            decoding: try AuthMessageCodec.certificateRequestSigningBytes(requested, limits: .standard),
            as: UTF8.self)
        #expect(signed.hasSuffix(#":["R&D","a<b>\#u{2028}","q\"\\\t\u0001"]}}"#))
    }

    // MARK: Swift messages for a TypeScript verifier

    /// Writes the messages this SDK sends in the two vector sessions, for the
    /// verifier in `Documentation/Compatibility/TypeScriptAuthVectors.md`,
    /// which feeds them to a live `@bsv/sdk` `Peer` and `AuthFetch`. Runs only
    /// when `BSV_TS_INTEROP_DUMP` names the output file.
    @Test("writes Swift messages for the TypeScript verifier")
    func swiftMessagesForTypeScript() async throws {
        guard let path = ProcessInfo.processInfo.environment["BSV_TS_INTEROP_DUMP"] else { return }
        var output: [String: Any] = [:]

        // Swift server answering the AuthFetch session.
        let server = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: try key(7)), randomSource: CountingRandomSource(seed: 0x60))
        let initialResponse = try sent(
            try await server.receive(try decode(TypeScriptAuthVectors.authFetchInitialRequest)))
        output["serverInitialResponse"] = try wire(initialResponse)
        let frame = try BRC104HTTPRequestFrame(
            method: TypeScriptAuthVectors.authFetchMethod,
            path: TypeScriptAuthVectors.authFetchPath,
            headers: TypeScriptAuthVectors.authFetchHeaders.map {
                BRC104Header(name: $0.name, value: $0.value)
            })
        guard
            case .deliver(let delivered) = try await server.receive(
                try BRC104HTTPFrameCodec.decodeRequest(frame)
            ).first
        else { throw AuthError.invalidMessage }
        let request = try BRC104Codec.decodeRequest(delivered.payload)
        let payload = try BRC104Codec.encode(
            try BRC104Response(requestID: request.requestID, status: 204, body: []))
        let general = try sent([
            try await server.makeGeneralMessage(payload: payload, using: delivered.sessionID)
        ])
        let responseFrame = try BRC104HTTPFrameCodec.encodeResponse(general)
        var headers: [String: String] = [:]
        for header in responseFrame.headers { headers[header.name] = header.value }
        output["serverResponse"] = ["status": responseFrame.status, "headers": headers]

        // Swift client in the `Peer` session: answers the handshake policy with
        // a certificate, then requests the TypeScript certificate and sends a
        // general message. `Zip` and `age` sort differently in `localeCompare`
        // order, which TypeScript verifies the certificate in (`Certificate.ts:290`).
        let typeScript = try key(3).publicKey
        let certifierKey = try key(11)
        let swiftWallet = ProtoWallet(rootKey: try key(7))
        let client = PeerAuthenticator(
            wallet: swiftWallet, randomSource: CountingRandomSource(seed: 0x40))
        let start = try await client.beginAuthentication(with: typeScript)
        guard
            case .certificateRequest(let handshake) = try await client.receive(
                try decode(TypeScriptAuthVectors.initialResponse)
            ).first
        else { throw AuthError.invalidMessage }
        let handshakeType = try CertificateTypeID([UInt8](repeating: 0x51, count: 32))
        let master = try await CertificateEngine.issue(
            type: handshakeType,
            serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x52, count: 32)),
            subject: .publicKey(try key(7).publicKey),
            plaintextFields: [
                try field("email"): "swift@example.test", try field("Zip"): "R&D <1>",
                try field("age"): "30", try field("a&b<c>"): "\u{2028}",
            ],
            using: ProtoWallet(rootKey: certifierKey))
        let revealed = try await CertificateEngine.project(
            master, fields: try #require(handshake.request.certificateTypes[handshakeType]),
            to: typeScript, using: swiftWallet)
        output["clientCertificateResponse"] = try wire(
            try sent([try await client.makeCertificateResponse([revealed], using: start.sessionID)]))
        let requested = try AuthRequestedCertificateSet(
            certifiers: [certifierKey.publicKey],
            certificateTypes: [
                try CertificateTypeID(TypeScriptAuthVectors.certificateType): [
                    try field("userName"), try field("profilePhoto"), try field("a&b<c>"),
                ],
                try CertificateTypeID([UInt8](repeating: 0x67, count: 32)): [try field("Zip")],
                try CertificateTypeID([UInt8](repeating: 0x69, count: 32)): [try field("age")],
            ])
        output["clientCertificateRequest"] = try wire(
            try sent([try await client.makeCertificateRequest(requested, using: start.sessionID)]))
        output["clientGeneral"] = try wire(
            try sent([
                try await client.makeGeneralMessage(
                    payload: Array("hello from swift".utf8), using: start.sessionID)
            ]))

        let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
        try data.write(to: URL(fileURLWithPath: path))
    }

    private func wire(_ message: AuthMessage) throws -> String {
        String(decoding: try AuthMessageCodec.encode(message), as: UTF8.self)
    }

    // MARK: Helpers

    private func decode(_ text: String) throws -> AuthMessage {
        try AuthMessageCodec.decode(Array(text.utf8))
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = scalar
        return try PrivateKey(bytes)
    }

    private func field(_ name: String) throws -> CertificateFieldName {
        try CertificateFieldName(name)
    }

    private func sent(_ actions: [AuthPeerAction]) throws -> AuthMessage {
        guard case .send(let message) = actions.first else { throw AuthError.invalidMessage }
        return message
    }
}

/// Call `k` (from 1) returns `count` bytes of `seed + k`, matching the inputs
/// the TypeScript generator assumed for the Swift peer.
private final class CountingRandomSource: SecureRandomSource, @unchecked Sendable {
    private let seed: UInt8
    private let lock = NSLock()
    private var calls: UInt8 = 0

    init(seed: UInt8) { self.seed = seed }

    func randomBytes(count: Int) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        calls += 1
        return [UInt8](repeating: seed &+ calls, count: count)
    }
}
