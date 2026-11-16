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
        #expect(throws: BRC104HTTPFramingError.certificateExchangeUnavailable) {
            try BRC104HTTPFrameCodec.decodeRequest(certificateRequest)
        }

        let response = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)
        let responseCertificateRequest = try responseFrame(
            basedOn: response,
            headers: response.headers + [
                .init(name: BRC104HTTPHeaderName.requestedCertificates, value: "{}")
            ]
        )
        #expect(throws: BRC104HTTPFramingError.certificateExchangeUnavailable) {
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

    /// The TypeScript `AuthFetch` sends a request frame of up to 16 MiB
    /// (`MAX_AUTH_HTTP_REQUEST_FRAME_BYTES`) and reads a response body of up to 16 MiB
    /// (`DEFAULT_SIMPLIFIED_FETCH_MAX_RESPONSE_BYTES`). A wallet storage reply carrying a 180 KB
    /// image inscription as JSON numbers was 1,330,479 bytes, and at the old 1 MiB default it was
    /// refused with `resourceLimit` before it was read.
    @Test("payloads over 1 MiB and under 16 MiB are signed, framed and read")
    func payloadsOverOneMebibyte() async throws {
        #expect(AuthLimits.standard.maximumPayloadBytes == 16 << 20)
        #expect(try AuthLimits().maximumPayloadBytes == 16 << 20)
        #expect(BRC104Limits.standard.maximumPayloadBytes == 16 << 20)
        #expect(try BRC104Limits().maximumPayloadBytes == 16 << 20)
        #expect(BRC104HTTPFramingLimits.standard.payloadLimits.maximumPayloadBytes == 16 << 20)

        let requestBody = [UInt8](repeating: 0x5b, count: (1 << 20) + 1)
        let responseBody = [UInt8](repeating: 0x31, count: 1_330_479)
        let fixture = try await makeHTTPFixture(
            requestBody: requestBody, responseBody: responseBody
        )

        let requestFrame = try BRC104HTTPFrameCodec.encodeRequest(fixture.requestMessage)
        #expect(requestFrame.body == requestBody)
        #expect(try BRC104HTTPFrameCodec.decodeRequest(requestFrame) == fixture.requestMessage)

        let responseFrame = try BRC104HTTPFrameCodec.encodeResponse(fixture.responseMessage)
        #expect(responseFrame.body == responseBody)
        let decoded = try BRC104HTTPFrameCodec.decodeResponse(
            try BRC104HTTPResponseFrame(
                status: responseFrame.status, headers: responseFrame.headers,
                body: responseFrame.body
            ),
            expectedRequestID: fixture.requestID
        )
        #expect(decoded == fixture.responseMessage)
        let inner = try BRC104Codec.decodeResponse(try #require(decoded.payload))
        #expect(inner.body == responseBody)
    }

    @Test("a response payload of exactly 16 MiB is read and one byte more is refused")
    func sixteenMebibyteBoundary() throws {
        let requestID = [UInt8](repeating: 9, count: 32)
        let empty = try BRC104Codec.encode(
            BRC104Response(requestID: requestID, status: 200, body: [])
        )
        // The empty body's one-byte length prefix is five bytes for a body this large.
        let overhead = empty.count - 1 + 5
        let largest = try BRC104Response(
            requestID: requestID, status: 200,
            body: [UInt8](repeating: 1, count: (16 << 20) - overhead)
        )
        let encoded = try BRC104Codec.encode(largest)
        #expect(encoded.count == 16 << 20)
        #expect(try BRC104Codec.decodeResponse(encoded) == largest)

        #expect(throws: BRC104Error.resourceLimit) {
            try BRC104Codec.encode(
                BRC104Response(
                    requestID: requestID, status: 200,
                    body: [UInt8](repeating: 1, count: (16 << 20) - overhead + 1)
                )
            )
        }
        #expect(throws: BRC104Error.resourceLimit) {
            try BRC104Codec.decodeResponse(encoded + [0])
        }
        #expect(throws: BRC104HTTPFramingError.resourceLimit) {
            try BRC104HTTPResponseFrame(
                status: 200, body: [UInt8](repeating: 1, count: (16 << 20) + 1)
            )
        }
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

private func makeHTTPFixture(
    requestBody: [UInt8] = Array(#"{"secret":true}"#.utf8),
    responseBody: [UInt8] = Array("accepted".utf8)
) async throws -> HTTPAuthFixture {
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
        body: requestBody
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
        body: responseBody
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

private func assertHTTPFramingSendable<T: Sendable>(_ type: T.Type) {}
