import BSVAuth
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import Foundation
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
            let output = try reencode(
                message,
                id: "auth-message-reencode",
                client: client
            )
            #expect(output == message)
        }
    }

    @Test("certificate request and response messages reencode through pinned Go")
    func certificateMessageReencode() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Auth Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let requester = try privateKey(9)
            let peer = try privateKey(10)
            let certifier = try privateKey(11)
            let nonce = Base64Encoding.encode([UInt8](repeating: 4, count: 32))
            let type = try CertificateTypeID([UInt8](repeating: 0x21, count: 32))
            let field = try CertificateFieldName("email")
            let escapedField = try CertificateFieldName("<&\u{2028}")
            let request = try AuthRequestedCertificateSet(
                certifiers: [certifier.publicKey],
                certificateTypes: [type: [field, escapedField]]
            )
            let signature = try fixtureSignature()
            let requestMessage = AuthMessage(
                messageType: .certificateRequest,
                identityKey: requester.publicKey,
                nonce: nonce,
                yourNonce: nonce,
                signature: signature.derBytes,
                requestedCertificates: request
            )
            let requestOutput = try reencode(
                requestMessage,
                id: "auth-certificate-request-reencode",
                client: client,
                expectedSigningBytes: AuthMessageCodec.certificateRequestSigningBytes(
                    request,
                    limits: .standard
                )
            )
            #expect(requestOutput == requestMessage)

            let ciphertext = try CertificateCiphertext([1, 2, 3])
            let certificate = try Certificate(
                type: type,
                serialNumber: CertificateSerialNumber([UInt8](repeating: 0x31, count: 32)),
                subject: peer.publicKey,
                certifier: certifier.publicKey,
                revocationOutpoint: Outpoint(
                    transactionID: try TransactionID(
                        wireBytes: [UInt8](repeating: 0, count: 32)
                    ),
                    outputIndex: 0
                ),
                fields: [field: ciphertext],
                signature: signature
            )
            let verifiable = try VerifiableCertificate(
                certificate: certificate,
                keyring: CertificateKeyring([field: ciphertext])
            )
            let responseMessage = AuthMessage(
                messageType: .certificateResponse,
                identityKey: peer.publicKey,
                nonce: nonce,
                yourNonce: nonce,
                signature: signature.derBytes,
                certificates: [verifiable]
            )
            let responseOutput = try reencode(
                responseMessage,
                id: "auth-certificate-response-reencode",
                client: client,
                expectedSigningBytes: AuthMessageCodec.certificateResponseSigningBytes(
                    [verifiable],
                    limits: .standard
                )
            )
            #expect(responseOutput == responseMessage)
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

    private func reencode(
        _ message: AuthMessage,
        id: String,
        client: GoOracleClient,
        expectedSigningBytes: [UInt8]? = nil
    ) throws -> AuthMessage {
        let input = try pinnedGoInput(for: message)
        let response = try client.request(
            id: id,
            operation: "auth.message.reencode",
            arguments: ["json": .string(Hex.encode(input))]
        )
        guard case .object(let fields) = response.result,
            case .string(let hex)? = fields["json"]
        else { throw AuthError.invalidMessage }
        if let expectedSigningBytes {
            guard case .string(let signingHex)? = fields["signing"] else {
                throw AuthError.invalidMessage
            }
            let signingBytes = try Hex.decode(
                signingHex,
                maximumDecodedByteCount: AuthLimits.maximumAllowedCertificateAggregateBytes
            )
            if message.messageType == .certificateRequest {
                #expect(signingBytes != expectedSigningBytes)
                try expectPinnedGoCertificateRequest(signingBytes)
            } else {
                #expect(signingBytes == expectedSigningBytes)
            }
        }
        let output = try Hex.decode(
            hex,
            maximumDecodedByteCount: AuthLimits.maximumAllowedJSONBytes
        )
        return try AuthMessageCodec.decode(
            canonicalizedPinnedGoOutput(output, messageType: message.messageType)
        )
    }

    // Pinned Go v1.3.3 has no JSON tags on RequestedCertificateSet. This adapter
    // is deliberately test-only: production Swift continues to emit and accept
    // the lowercase BRC-103 schema.
    private func pinnedGoInput(for message: AuthMessage) throws -> [UInt8] {
        let canonical = try AuthMessageCodec.encode(message)
        guard message.messageType == .certificateRequest else { return canonical }
        var object = try jsonObject(canonical)
        guard var request = object["requestedCertificates"] as? [String: Any],
            let certifiers = request.removeValue(forKey: "certifiers"),
            let types = request.removeValue(forKey: "types"),
            request.isEmpty
        else { throw AuthError.invalidMessage }
        object["requestedCertificates"] = [
            "Certifiers": certifiers,
            "CertificateTypes": types,
        ]
        return try [UInt8](JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    private func canonicalizedPinnedGoOutput(
        _ data: [UInt8],
        messageType: AuthMessageType
    ) throws -> [UInt8] {
        var object = try jsonObject(data)
        guard let request = object["requestedCertificates"] as? [String: Any],
            let types = request["CertificateTypes"] as? [String: Any],
            request.count == 2
        else { throw AuthError.invalidMessage }

        if messageType == .certificateRequest {
            guard let certifiers = request["Certifiers"] as? [Any] else {
                throw AuthError.invalidMessage
            }
            #expect(!certifiers.isEmpty)
            #expect(!types.isEmpty)
            object["requestedCertificates"] = [
                "certifiers": certifiers,
                "types": types,
            ]
        } else {
            // RequestedCertificates is a non-pointer Go struct, so omitempty is
            // ineffective and Go injects this artifact into every other message.
            let hasNoCertifiers = request["Certifiers"] is NSNull
                || (request["Certifiers"] as? [Any])?.isEmpty == true
            #expect(hasNoCertifiers)
            #expect(types.isEmpty)
            object.removeValue(forKey: "requestedCertificates")
        }
        return try [UInt8](JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    private func expectPinnedGoCertificateRequest(_ data: [UInt8]) throws {
        let request = try jsonObject(data)
        #expect(request["certifiers"] == nil)
        #expect(request["types"] == nil)
        guard let certifiers = request["Certifiers"] as? [Any],
            let types = request["CertificateTypes"] as? [String: Any]
        else { throw AuthError.invalidMessage }
        #expect(!certifiers.isEmpty)
        #expect(!types.isEmpty)
    }

    private func jsonObject(_ data: [UInt8]) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: Data(data)) as? [String: Any]
        else { throw AuthError.invalidMessage }
        return object
    }

    private func privateKey(_ scalar: UInt8) throws -> PrivateKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = scalar
        return try PrivateKey(bytes)
    }

    private func fixtureSignature() throws -> ECDSASignature {
        try ECDSASignature(derBytes: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }
}
