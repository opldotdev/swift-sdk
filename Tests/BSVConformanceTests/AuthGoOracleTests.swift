import BSVAuth
import BSVCore
import BSVKeys
import Testing

@Suite("BRC-103 Go oracle", .serialized)
struct AuthGoOracleTests {
    @Test("valid initial request reencodes through pinned Go")
    func messageReencode() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Auth Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            var scalar = [UInt8](repeating: 0, count: 32)
            scalar[31] = 9
            let nonce = Base64Encoding.encode([UInt8](repeating: 4, count: 32))
            let message = AuthMessage(
                messageType: .initialRequest, identityKey: try PrivateKey(scalar).publicKey,
                initialNonce: nonce)
            let input = try AuthMessageCodec.encode(message)
            let response = try client.request(
                id: "auth-message-reencode", operation: "auth.message.reencode",
                arguments: ["json": .string(Hex.encode(input))])
            guard case .object(let fields) = response.result,
                case .string(let hex)? = fields["json"]
            else {
                Issue.record("bad oracle result")
                return
            }
            let output = try Hex.decode(hex, maximumDecodedByteCount: 1 << 20)
            let decoded = try AuthMessageCodec.decode(output)
            #expect(decoded.messageType == AuthMessageType.initialRequest)
            #expect(decoded.identityKey == message.identityKey)
            #expect(decoded.initialNonce == nonce)
        }
    }

    @Test("BRC-104 request and response payloads match pinned Go")
    func payloadEncoding() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Auth Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let requestID = [UInt8](repeating: 6, count: 32)
            let request = try BRC104Request(
                requestID: requestID,
                method: "POST",
                path: "/v1/items",
                query: "?a=b",
                headers: [
                    BRC104Header(name: "content-type", value: "application/json; charset=utf-8"),
                    BRC104Header(name: "x-bsv-trace", value: "one"),
                ]
            )
            let goRequest = try client.request(
                id: "auth-payload-request",
                operation: "auth.payload.request.encode",
                arguments: [
                    "requestID": .string(Hex.encode(requestID)),
                    "method": .string("POST"),
                    "path": .string("/v1/items"),
                    "query": .string("a=b"),
                    "body": .string(""),
                    "headers": .object([
                        "content-type": .string("application/json; charset=utf-8"),
                        "x-bsv-trace": .string("one"),
                    ]),
                ]
            )
            #expect(try resultBytes(goRequest) == BRC104Codec.encode(request))

            let response = try BRC104Response(
                requestID: requestID,
                status: 201,
                headers: [
                    BRC104Header(name: "authorization", value: "Bearer token"),
                    BRC104Header(name: "x-bsv-result", value: "ok"),
                ],
                body: [1, 2]
            )
            let goResponse = try client.request(
                id: "auth-payload-response",
                operation: "auth.payload.response.encode",
                arguments: [
                    "requestID": .string(Hex.encode(requestID)),
                    "status": .string("201"),
                    "body": .string("0102"),
                    "headers": .object([
                        "authorization": .string("Bearer token"),
                        "x-bsv-result": .string("ok"),
                    ]),
                ]
            )
            #expect(try resultBytes(goResponse) == BRC104Codec.encode(response))
        }
    }

    private func resultBytes(_ response: GoOracleResponse) throws -> [UInt8] {
        guard case .object(let fields) = response.result,
            case .string(let hex)? = fields["bytes"]
        else {
            throw AuthError.invalidMessage
        }
        return try Hex.decode(hex, maximumDecodedByteCount: 1 << 20)
    }
}
