import BSVAuth
import BSVCore
import BSVKeys
import BSVWallet
import Testing

@Suite("BRC-104 authenticated HTTP framing")
struct BRC104HTTPFramingTests {
    @Test("general request and response messages round-trip through HTTP frames")
    func roundTrips() async throws {
        let fixture = try await makeHTTPFixture()

        let requestFrame = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        #expect(try BRC104HTTPFrameCodec.decodeRequest(requestFrame) == fixture.requestMessage)
        #expect(requestFrame.method == "POST")
        #expect(requestFrame.path == "/v1/items")
        #expect(requestFrame.query == "?a=b")

        let responseFrame = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)
        #expect(
            try BRC104HTTPFrameCodec.decodeResponse(
                responseFrame,
                expectedRequestID: fixture.requestID
            ) == fixture.responseMessage
        )
        #expect(responseFrame.status == 201)
    }

    @Test("authentication headers use exact canonical names and values")
    func exactAuthenticationHeaders() async throws {
        let fixture = try await makeHTTPFixture()
        let frame = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        let headers = Dictionary(uniqueKeysWithValues: frame.headers.map { ($0.name, $0.value) })

        #expect(headers[BRC104HTTPHeaderName.version] == "0.1")
        #expect(headers[BRC104HTTPHeaderName.messageType] == "general")
        #expect(
            headers[BRC104HTTPHeaderName.identityKey]
                == Hex.encode(fixture.requestMessage.identityKey.compressedBytes)
        )
        #expect(headers[BRC104HTTPHeaderName.nonce] == fixture.requestMessage.nonce)
        #expect(headers[BRC104HTTPHeaderName.yourNonce] == fixture.requestMessage.yourNonce)
        #expect(
            headers[BRC104HTTPHeaderName.signature]
                == Hex.encode(try #require(fixture.requestMessage.signature))
        )
        #expect(
            headers[BRC104HTTPHeaderName.requestID]
                == Base64Encoding.encode(fixture.requestID)
        )
        #expect(BRC104HTTPHeaderName.handshakePath == "/.well-known/auth")
    }

    @Test("known authentication headers are case-insensitive and fail closed")
    func strictAuthenticationHeaders() async throws {
        let fixture = try await makeHTTPFixture()
        let frame = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        let mixedCase = try requestFrame(
            basedOn: frame,
            headers: frame.headers.map {
                $0.name.hasPrefix(BRC104HTTPHeaderName.authenticationPrefix)
                    ? BRC104Header(name: $0.name.uppercased(), value: $0.value)
                    : $0
            }
        )
        #expect(try BRC104HTTPFrameCodec.decodeRequest(mixedCase) == fixture.requestMessage)

        let duplicate = try requestFrame(
            basedOn: frame, headers: frame.headers + [frame.headers[0]])
        #expect(throws: BRC104HTTPFramingError.duplicateAuthenticationHeader) {
            try BRC104HTTPFrameCodec.decodeRequest(duplicate)
        }

        let missing = try requestFrame(
            basedOn: frame,
            headers: frame.headers.filter { $0.name != BRC104HTTPHeaderName.requestID }
        )
        #expect(throws: BRC104HTTPFramingError.missingAuthenticationHeader) {
            try BRC104HTTPFrameCodec.decodeRequest(missing)
        }

        let unknown = try requestFrame(
            basedOn: frame,
            headers: frame.headers + [.init(name: "x-bsv-auth-extra", value: "1")]
        )
        #expect(throws: BRC104HTTPFramingError.unknownAuthenticationHeader) {
            try BRC104HTTPFrameCodec.decodeRequest(unknown)
        }

        let certificateRequest = try requestFrame(
            basedOn: frame,
            headers: frame.headers + [
                .init(name: BRC104HTTPHeaderName.requestedCertificates, value: "{}")
            ]
        )
        // `{}` is not a requested set; `@bsv/sdk` rejects it too
        // (`AuthMessageValidation.ts:134-136`).
        #expect(throws: BRC104HTTPFramingError.invalidAuthenticationHeader) {
            try BRC104HTTPFrameCodec.decodeRequest(certificateRequest)
        }

        let response = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)
        let responseCertificateRequest = try responseFrame(
            basedOn: response,
            headers: response.headers + [
                .init(name: BRC104HTTPHeaderName.requestedCertificates, value: "{}")
            ]
        )
        #expect(throws: BRC104HTTPFramingError.invalidAuthenticationHeader) {
            try BRC104HTTPFrameCodec.decodeResponse(
                responseCertificateRequest,
                expectedRequestID: fixture.requestID
            )
        }
    }

    @Test("response request identifiers must correlate exactly")
    func responseCorrelation() async throws {
        let fixture = try await makeHTTPFixture()
        let frame = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)

        #expect(throws: BRC104HTTPFramingError.requestIDMismatch) {
            try BRC104HTTPFrameCodec.decodeResponse(
                frame,
                expectedRequestID: [UInt8](repeating: 9, count: 32)
            )
        }

        let altered = try responseFrame(
            basedOn: frame,
            headers: frame.headers.map {
                $0.name == BRC104HTTPHeaderName.requestID
                    ? .init(
                        name: $0.name,
                        value: Base64Encoding.encode([UInt8](repeating: 8, count: 32))
                    )
                    : $0
            }
        )
        #expect(throws: BRC104HTTPFramingError.requestIDMismatch) {
            try BRC104HTTPFrameCodec.decodeResponse(
                altered,
                expectedRequestID: fixture.requestID
            )
        }
    }

    @Test("frame limits apply at exact and maximum plus one boundaries")
    func resourceLimits() async throws {
        let fixture = try await makeHTTPFixture()
        let frame = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        let exact = try BRC104HTTPFramingLimits(maximumHeaderCount: frame.headers.count)
        #expect(
            try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage, limits: exact) == frame)

        let oneFewer = try BRC104HTTPFramingLimits(maximumHeaderCount: frame.headers.count - 1)
        #expect(throws: BRC104HTTPFramingError.resourceLimit) {
            try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage, limits: oneFewer)
        }

        let exactMethod = try BRC104HTTPFramingLimits(
            maximumMethodByteCount: frame.method.utf8.count)
        #expect(
            try BRC104HTTPFrameCodec.decodeRequest(frame, limits: exactMethod)
                == fixture.requestMessage)
        let shortMethod = try BRC104HTTPFramingLimits(
            maximumMethodByteCount: frame.method.utf8.count - 1
        )
        #expect(throws: BRC104HTTPFramingError.resourceLimit) {
            try BRC104HTTPFrameCodec.decodeRequest(frame, limits: shortMethod)
        }
    }

    @Test("x-bsv-auth-requested-certificates carries a requested set on general messages")
    func requestedCertificatesHeader() async throws {
        let fixture = try await makeHTTPFixture()
        let certifier = try httpPrivateKey(11).publicKey
        let type = try CertificateTypeID([UInt8](repeating: 0x05, count: 32))
        let requested = try AuthRequestedCertificateSet(
            certifiers: [certifier], certificateTypes: [type: [try CertificateFieldName("Zip")]])
        let request = withRequestedCertificates(fixture.requestMessage, requested)
        let response = withRequestedCertificates(fixture.responseMessage, requested)
        // The middleware writes the set as JSON (`index.ts:985-988`) and the
        // client reads it back with `JSON.parse` (`SimplifiedFetchTransport.ts:234-258`).
        let expected =
            #"{"certifiers":[""# + Hex.encode(certifier.compressedBytes)
            + #""],"types":{""# + Base64Encoding.encode(type.bytes) + #"":["Zip"]}}"#

        let requestFrame = try BRC104HTTPFrameCodec.encodeRequest(request)
        #expect(header(BRC104HTTPHeaderName.requestedCertificates, in: requestFrame.headers) == expected)
        #expect(try BRC104HTTPFrameCodec.decodeRequest(requestFrame) == request)
        let encodedResponse = try BRC104HTTPFrameCodec.encodeResponse(response)
        #expect(header(BRC104HTTPHeaderName.requestedCertificates, in: encodedResponse.headers) == expected)
        #expect(
            try BRC104HTTPFrameCodec.decodeResponse(
                encodedResponse, expectedRequestID: fixture.requestID) == response)
        #expect(
            header(
                BRC104HTTPHeaderName.requestedCertificates,
                in: try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage).headers) == nil)

        // The set `@bsv/sdk` sends when it asks for nothing.
        let plain = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)
        let empty = try responseFrame(
            basedOn: plain,
            headers: plain.headers + [
                .init(name: "X-BSV-Auth-Requested-Certificates", value: #"{"certifiers":[],"types":{}}"#)
            ])
        let decoded = try BRC104HTTPFrameCodec.decodeResponse(
            empty, expectedRequestID: fixture.requestID)
        #expect(decoded.requestedCertificates?.certifiers.isEmpty == true)
        #expect(decoded.requestedCertificates?.certificateTypes.isEmpty == true)

        for malformed in ["not json", "[]", #"{"certifiers":["zz"],"types":{}}"#, #"{"certifiers":[]}"#] {
            let frame = try responseFrame(
                basedOn: plain,
                headers: plain.headers + [
                    .init(name: BRC104HTTPHeaderName.requestedCertificates, value: malformed)
                ])
            #expect(throws: BRC104HTTPFramingError.invalidAuthenticationHeader) {
                try BRC104HTTPFrameCodec.decodeResponse(frame, expectedRequestID: fixture.requestID)
            }
        }
        // `MAX_REQUESTED_CERTIFICATES_HEADER_BYTES` (`SimplifiedFetchTransport.ts:30`).
        let oversized = #"{"certifiers":[],"types":{}}"#
            + String(repeating: " ", count: (256 << 10) - 27)
        #expect(oversized.utf8.count == (256 << 10) + 1)
        #expect(throws: BRC104HTTPFramingError.resourceLimit) {
            try BRC104HTTPFrameCodec.decodeResponse(
                try responseFrame(
                    basedOn: plain,
                    headers: plain.headers + [
                        .init(name: BRC104HTTPHeaderName.requestedCertificates, value: oversized)
                    ]),
                expectedRequestID: fixture.requestID)
        }
    }

    @Test("a general message with a requested set is delivered and the set ignored")
    func requestedCertificatesOnGeneralMessagesAreIgnored() async throws {
        let client = PeerAuthenticator(wallet: ProtoWallet(rootKey: try httpPrivateKey(3)))
        let server = PeerAuthenticator(wallet: ProtoWallet(rootKey: try httpPrivateKey(7)))
        let start = try await client.beginAuthentication(with: try httpPrivateKey(7).publicKey)
        _ = try await client.receive(
            try sentHTTPMessage(try await server.receive(try sentHTTPMessage(start.actions))))
        let request = try BRC104Request(
            requestID: [UInt8](repeating: 9, count: 32), method: "GET", path: "/")
        let message = try sentHTTPMessage([
            try await client.makeGeneralMessage(
                payload: try BRC104Codec.encode(request), using: start.sessionID)
        ])
        let requested = try AuthRequestedCertificateSet(
            certifiers: [try httpPrivateKey(11).publicKey],
            certificateTypes: [
                try CertificateTypeID([UInt8](repeating: 0x05, count: 32)): [
                    try CertificateFieldName("name")
                ]
            ])
        // `Peer.processGeneralMessage` does not act on the header's set
        // (`Peer.ts:1272-1340`); it is not covered by the signature.
        let actions = try await server.receive(
            try BRC104HTTPFrameCodec.decodeRequest(
                try BRC104HTTPFrameCodec.encodeRequest(withRequestedCertificates(message, requested))))
        #expect(actions.count == 1)
        guard case .deliver(let delivered) = actions.first else {
            Issue.record("general message was not delivered")
            return
        }
        #expect(try BRC104Codec.decodeRequest(delivered.payload) == request)
    }

    @Test("frames refuse statuses, methods and request targets that @bsv/sdk rejects")
    func typeScriptFrameLimits() async throws {
        let fixture = try await makeHTTPFixture()
        for status in [100, 199, 600] {
            #expect(throws: BRC104HTTPFramingError.invalidFrame) {
                try BRC104HTTPResponseFrame(status: status)
            }
        }
        #expect(try BRC104HTTPResponseFrame(status: 200).status == 200)
        let frame = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        for method in ["post", "M1", "G E T"] {
            #expect(throws: BRC104HTTPFramingError.invalidFrame) {
                try BRC104HTTPRequestFrame(method: method, path: "/", headers: frame.headers)
            }
        }
        let path = "/" + String(repeating: "p", count: 4_095)
        let query = "?" + String(repeating: "q", count: 4_096)
        #expect(throws: BRC104HTTPFramingError.resourceLimit) {
            try BRC104HTTPRequestFrame(method: "GET", path: path, query: query)
        }
        #expect(
            try BRC104HTTPRequestFrame(method: "GET", path: path, query: String(query.dropLast()))
                .path == path)
    }

    @Test("a framing error keeps the detailed cause in the log")
    func detailedCauseIsLogged() async throws {
        let fixture = try await makeHTTPFixture()
        let message = fixture.requestMessage
        let malformed = AuthMessage(
            messageType: .general, identityKey: message.identityKey, nonce: message.nonce,
            yourNonce: message.yourNonce, payload: [1, 2, 3], signature: message.signature)
        let log = AuthLogLines()
        await log.record {
            #expect(throws: BRC104HTTPFramingError.invalidFrame) {
                try BRC104HTTPFrameCodec.encodeRequest(malformed)
            }
        }
        let line = try #require(log.lines.first)
        #expect(line.hasPrefix("BRC104HTTPFrameCodec.encodeRequest: BRC104Error: "))
        #expect(line.hasSuffix("reported as BSVAuth.BRC104HTTPFramingError.invalidFrame"))

        let plain = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)
        let headerLog = AuthLogLines()
        await headerLog.record {
            #expect(throws: BRC104HTTPFramingError.invalidAuthenticationHeader) {
                try BRC104HTTPFrameCodec.decodeResponse(
                    try responseFrame(
                        basedOn: plain,
                        headers: plain.headers + [
                            .init(name: BRC104HTTPHeaderName.requestedCertificates, value: "[]")
                        ]),
                    expectedRequestID: fixture.requestID)
            }
        }
        #expect(
            headerLog.lines.first?.hasPrefix(
                "BRC104HTTPFrameCodec.parseRequestedCertificates: AuthError: ") == true)
    }

    @Test("frames and messages do not disclose HTTP or authentication data")
    func redaction() async throws {
        let fixture = try await makeHTTPFixture()
        let request = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        let response = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)

        for value in [request as Any, response as Any, fixture.requestMessage as Any] {
            var output = ""
            dump(value, to: &output)
            #expect(!output.contains("/v1/items"))
            #expect(!output.contains("secret"))
            #expect(Mirror(reflecting: value).children.isEmpty)
        }
        assertHTTPFramingSendable(BRC104HTTPFramingLimits.self)
        assertHTTPFramingSendable(BRC104HTTPRequestFrame.self)
        assertHTTPFramingSendable(BRC104HTTPResponseFrame.self)
    }

    private func requestFrame(
        basedOn frame: BRC104HTTPRequestFrame,
        headers: [BRC104Header]
    ) throws -> BRC104HTTPRequestFrame {
        try BRC104HTTPRequestFrame(
            method: frame.method,
            path: frame.path,
            query: frame.query,
            headers: headers,
            body: frame.body
        )
    }

    private func responseFrame(
        basedOn frame: BRC104HTTPResponseFrame,
        headers: [BRC104Header]
    ) throws -> BRC104HTTPResponseFrame {
        try BRC104HTTPResponseFrame(status: frame.status, headers: headers, body: frame.body)
    }
}

private struct HTTPAuthFixture {
    let requestID: [UInt8]
    let requestMessage: AuthMessage
    let responseMessage: AuthMessage
}

private func makeHTTPFixture() async throws -> HTTPAuthFixture {
    let client = PeerAuthenticator(wallet: ProtoWallet(rootKey: try httpPrivateKey(3)))
    let server = PeerAuthenticator(wallet: ProtoWallet(rootKey: try httpPrivateKey(7)))
    let start = try await client.beginAuthentication(with: try httpPrivateKey(7).publicKey)
    let initialRequest = try sentHTTPMessage(start.actions)
    let initialResponse = try sentHTTPMessage(try await server.receive(initialRequest))
    _ = try await client.receive(initialResponse)

    let requestID = [UInt8](repeating: 7, count: 32)
    let request = try BRC104Request(
        requestID: requestID,
        method: "POST",
        path: "/v1/items",
        query: "?a=b",
        headers: [
            .init(name: "content-type", value: "application/json"),
            .init(name: "x-bsv-trace", value: "1"),
        ],
        body: Array(#"{"secret":true}"#.utf8)
    )
    let requestMessage = try sentHTTPMessage([
        try await client.makeGeneralMessage(
            payload: BRC104Codec.encode(request),
            using: start.sessionID
        )
    ])
    let delivered = try await server.receive(requestMessage)
    guard case .deliver(let received) = delivered.first else {
        throw AuthError.invalidMessage
    }

    let response = try BRC104Response(
        requestID: requestID,
        status: 201,
        headers: [.init(name: "x-bsv-result", value: "ok")],
        body: Array("accepted".utf8)
    )
    let responseMessage = try sentHTTPMessage([
        try await server.makeGeneralMessage(
            payload: BRC104Codec.encode(response),
            using: received.sessionID
        )
    ])
    return HTTPAuthFixture(
        requestID: requestID,
        requestMessage: requestMessage,
        responseMessage: responseMessage
    )
}

private func sentHTTPMessage(_ actions: [AuthPeerAction]) throws -> AuthMessage {
    guard case .send(let message) = actions.first else {
        throw AuthError.invalidMessage
    }
    return message
}

private func httpPrivateKey(_ scalar: UInt8) throws -> PrivateKey {
    var bytes = [UInt8](repeating: 0, count: 32)
    bytes[31] = scalar
    return try PrivateKey(bytes)
}

private func withRequestedCertificates(
    _ message: AuthMessage, _ requested: AuthRequestedCertificateSet
) -> AuthMessage {
    AuthMessage(
        messageType: message.messageType, identityKey: message.identityKey,
        nonce: message.nonce, initialNonce: message.initialNonce, yourNonce: message.yourNonce,
        payload: message.payload, signature: message.signature,
        requestedCertificates: requested)
}

private func header(_ name: String, in headers: [BRC104Header]) -> String? {
    headers.first { $0.name == name }?.value
}

private func assertHTTPFramingSendable<T: Sendable>(_ type: T.Type) {}
