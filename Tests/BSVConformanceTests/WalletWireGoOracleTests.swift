import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet

final class WalletWireGoOracleTests: XCTestCase {
    func testOnePersistentPinnedGoClientChecksAllSupportedCallsBidirectionally() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let available): client = available
        case .unavailable(let reason):
            XCTAssertFalse(configuration.required)
            print("Wallet-wire Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        var sequence = 0
        let protocolID = try WalletProtocolID(securityLevel: .silent, name: "wire test")
        let keyID = try WalletKeyID("oracle-key")
        let access = try WalletKeyAccess(
            privileged: true,
            privilegedReason: "oracle reason",
            seekPermission: true
        )
        let privateKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [11])
        let signature = try privateKey.sign(digest: BSVHashing.sha256([1, 2]))
        let digest = BSVHashing.sha256([3, 4])
        let hmac = try WalletHMAC(bytes: [UInt8](repeating: 0x77, count: 32))

        let requests: [WalletWireKeyQueryRequest] = [
            .getPublicKey(WalletGetPublicKeyRequest(selection: .identity, access: access)),
            .getPublicKey(WalletGetPublicKeyRequest(selection: .derived(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self,
                forSelf: false
            ))),
            .encrypt(WalletEncryptRequest(
                protocolID: protocolID, keyID: keyID, plaintext: [1, 2], access: access
            )),
            .decrypt(WalletDecryptRequest(
                protocolID: protocolID, keyID: keyID,
                counterparty: .publicKey(privateKey.publicKey), ciphertext: [3, 4], access: access
            )),
            .createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID, keyID: keyID, data: [5], access: access
            )),
            .verifyHMAC(WalletVerifyHMACRequest(
                protocolID: protocolID, keyID: keyID, data: [6], hmac: hmac, access: access
            )),
            .createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .digest(digest), access: access
            )),
            .verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .data([7]),
                signature: signature, access: access
            )),
            .isAuthenticated(WalletIsAuthenticatedRequest()),
            .waitForAuthentication(WalletWaitForAuthenticationRequest()),
            .getHeight(WalletGetHeightRequest()),
            .getHeaderForHeight(WalletGetHeaderRequest(height: 65_536)),
            .getNetwork(WalletGetNetworkRequest()),
            .getVersion(WalletGetVersionRequest()),
        ]
        for request in requests {
            let swiftBytes = try WalletWireCodec.encodeKeyQueryRequest(
                request,
                originator: "oracle"
            )
            let reencoded = try oracleBytes(
                client,
                operation: "wallet.wire.request.reencode",
                call: request.call,
                bytes: swiftBytes,
                sequence: &sequence
            )
            XCTAssertEqual(reencoded, swiftBytes, "request call \(request.call.rawValue)")
            let decoded = try WalletWireCodec.decodeKeyQueryRequest(reencoded)
            XCTAssertEqual(decoded.request.call, request.call)
        }

        let results: [WalletWireKeyQueryResult] = [
            .getPublicKey(WalletGetPublicKeyResult(publicKey: privateKey.publicKey)),
            .encrypt(WalletEncryptResult(ciphertext: [1, 2, 3])),
            .decrypt(WalletDecryptResult(plaintext: [4, 5])),
            .createHMAC(WalletCreateHMACResult(hmac: hmac)),
            .verifyHMAC(WalletVerifyHMACResult(valid: true)),
            .createSignature(WalletCreateSignatureResult(signature: signature)),
            .verifySignature(WalletVerifySignatureResult(valid: true)),
            .isAuthenticated(WalletAuthenticatedResult(authenticated: true)),
            .waitForAuthentication(WalletAuthenticatedResult(authenticated: true)),
            .getHeight(WalletGetHeightResult(height: 65_536)),
            .getHeaderForHeight(try WalletGetHeaderResult(header: [UInt8](repeating: 9, count: 80))),
            .getNetwork(WalletGetNetworkResult(network: .mainnet)),
            .getVersion(try WalletGetVersionResult(version: "oracle-v1")),
        ]
        for result in results {
            let swiftBytes = try WalletWireCodec.encodeKeyQueryResult(result)
            let reencoded = try oracleBytes(
                client,
                operation: "wallet.wire.result.reencode",
                call: result.call,
                bytes: swiftBytes,
                sequence: &sequence
            )
            XCTAssertEqual(reencoded, swiftBytes, "result call \(result.call.rawValue)")
            XCTAssertEqual(
                try WalletWireCodec.decodeKeyQueryResult(reencoded, expectedCall: result.call).call,
                result.call
            )
        }

        let inspection = try request(
            client,
            operation: "wallet.wire.request.inspect",
            call: .getHeight,
            bytes: [25, 0],
            sequence: &sequence
        )
        XCTAssertEqual(try string(inspection, field: "call"), "25")
        XCTAssertEqual(try string(inspection, field: "parameterByteCount"), "0")
    }

    func testOracleAndSwiftRecordDeliberateStrictnessAndFailClosedBehavior() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let available): client = available
        case .unavailable:
            XCTAssertFalse(configuration.required)
            return
        }
        defer { client.close() }
        var sequence = 10_000

        // Pinned Go accepts and truncates the trailing HMAC byte. The adapter
        // rejects it before the permissive pinned decoder, as Swift does.
        let hmacWithTrailing = [UInt8](arrayLiteral: 0) + [UInt8](repeating: 1, count: 33)
        let goHMAC = try request(
            client,
            operation: "wallet.wire.result.reencode",
            call: .createHMAC,
            bytes: hmacWithTrailing,
            sequence: &sequence
        )
        XCTAssertFalse(goHMAC.ok)
        XCTAssertEqual(goHMAC.error?.category, "trailingData")
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            hmacWithTrailing,
            expectedCall: .createHMAC
        ))

        // Pinned verification decoders ignore payload. The adapter requires
        // exact empty success before it invokes them, as Swift does.
        let goVerify = try request(
            client,
            operation: "wallet.wire.result.reencode",
            call: .verifyHMAC,
            bytes: [0, 0xAA],
            sequence: &sequence
        )
        XCTAssertFalse(goVerify.ok)
        XCTAssertEqual(goVerify.error?.category, "trailingData")
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            [0, 0xAA],
            expectedCall: .verifyHMAC
        ))

        // Pinned Go parses high-S DER and serializes its normalized low-S
        // representation. The adapter rejects before pinned parsing, so no
        // normalized bytes can be mistaken for a round trip.
        let highDER = try Hex.decode(
            "3046022100c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
                "022100ff45decaeca8d1ca6bc2a5322e8deaa89faaebd04c2f75c96db8f1c41d8cabe1",
            maximumDecodedByteCount: 72
        )
        let keyParameters = [UInt8](arrayLiteral: 0, 9)
            + Array("wire test".utf8)
            + [10]
            + Array("oracle-key".utf8)
            + [0x0B, 0, 0xFF]
        let highSRequest = [UInt8](arrayLiteral: WalletCall.verifySignature.rawValue, 0)
            + keyParameters
            + [0, UInt8(highDER.count)]
            + highDER
            + [2]
            + [UInt8](repeating: 0, count: 32)
            + [0]
        let goHighSRequest = try request(
            client,
            operation: "wallet.wire.request.reencode",
            call: .verifySignature,
            bytes: highSRequest,
            sequence: &sequence
        )
        XCTAssertFalse(goHighSRequest.ok)
        XCTAssertEqual(goHighSRequest.error?.category, "invalidArgument")
        XCTAssertNil(goHighSRequest.result)
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(highSRequest)) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .nonRoundTrippableValue(kind: "high-S signature")
            )
        }

        let highSResult = [0] + highDER
        let goHighSResult = try request(
            client,
            operation: "wallet.wire.result.reencode",
            call: .createSignature,
            bytes: highSResult,
            sequence: &sequence
        )
        XCTAssertFalse(goHighSResult.ok)
        XCTAssertEqual(goHighSResult.error?.category, "invalidArgument")
        XCTAssertNil(goHighSResult.result)
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            highSResult,
            expectedCall: .createSignature
        )) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .nonRoundTrippableValue(kind: "high-S signature")
            )
        }

        // Pinned Go preserves its optional-Boolean absence sentinel. Swift
        // accepts that inbound form as false and emits the canonical 00 form.
        let absentGetPublicKey = [UInt8](arrayLiteral: WalletCall.getPublicKey.rawValue, 0, 0)
            + keyParameters
            + [0xFF, 0]
        let goAbsentGetPublicKey = try oracleBytes(
            client,
            operation: "wallet.wire.request.reencode",
            call: .getPublicKey,
            bytes: absentGetPublicKey,
            sequence: &sequence
        )
        XCTAssertEqual(goAbsentGetPublicKey, absentGetPublicKey)
        let decodedGetPublicKey = try WalletWireCodec.decodeKeyQueryRequest(absentGetPublicKey)
        guard case .getPublicKey(let getPublicKey) = decodedGetPublicKey.request,
              case .derived(_, _, _, let forSelf) = getPublicKey.selection else {
            return XCTFail("expected derived get-public-key request")
        }
        XCTAssertFalse(forSelf)
        var canonicalGetPublicKey = absentGetPublicKey
        canonicalGetPublicKey[2 + 1 + keyParameters.count] = 0
        XCTAssertEqual(
            try WalletWireCodec.encodeKeyQueryRequest(
                decodedGetPublicKey.request,
                originator: decodedGetPublicKey.originator
            ),
            canonicalGetPublicKey
        )

        let canonicalDigest = BSVHashing.sha256([3, 4])
        let canonicalSignature = try PrivateKey(
            [UInt8](repeating: 0, count: 31) + [11]
        ).sign(digest: BSVHashing.sha256([1, 2]))
        let absentVerifySignature = [UInt8](arrayLiteral: WalletCall.verifySignature.rawValue, 0)
            + keyParameters
            + [0xFF, UInt8(canonicalSignature.derBytes.count)]
            + canonicalSignature.derBytes
            + [2]
            + canonicalDigest.bytes
            + [0]
        let goAbsentVerifySignature = try oracleBytes(
            client,
            operation: "wallet.wire.request.reencode",
            call: .verifySignature,
            bytes: absentVerifySignature,
            sequence: &sequence
        )
        XCTAssertEqual(goAbsentVerifySignature, absentVerifySignature)
        let decodedVerifySignature = try WalletWireCodec.decodeKeyQueryRequest(absentVerifySignature)
        guard case .verifySignature(let verifySignature) = decodedVerifySignature.request else {
            return XCTFail("expected verify-signature request")
        }
        XCTAssertFalse(verifySignature.forSelf)
        var canonicalVerifySignature = absentVerifySignature
        canonicalVerifySignature[2 + keyParameters.count] = 0
        XCTAssertEqual(
            try WalletWireCodec.encodeKeyQueryRequest(
                decodedVerifySignature.request,
                originator: decodedVerifySignature.originator
            ),
            canonicalVerifySignature
        )

        let trailingError = try request(
            client,
            operation: "wallet.wire.result.inspect",
            call: .getVersion,
            bytes: [1, 0, 0, 0],
            sequence: &sequence
        )
        XCTAssertFalse(trailingError.ok)
        XCTAssertEqual(trailingError.error?.category, "trailingData")
        XCTAssertThrowsError(try WalletWireCodec.decodeResultFrame([1, 0, 0, 0]))
    }

    private func oracleBytes(
        _ client: GoOracleClient,
        operation: String,
        call: WalletCall,
        bytes: [UInt8],
        sequence: inout Int
    ) throws -> [UInt8] {
        let response = try request(
            client,
            operation: operation,
            call: call,
            bytes: bytes,
            sequence: &sequence
        )
        XCTAssertTrue(response.ok, response.error?.category ?? "missing oracle error")
        return try Hex.decode(
            string(response, field: "bytes"),
            maximumDecodedByteCount: 300_000
        )
    }

    private func request(
        _ client: GoOracleClient,
        operation: String,
        call: WalletCall,
        bytes: [UInt8],
        sequence: inout Int
    ) throws -> GoOracleResponse {
        defer { sequence += 1 }
        return try client.request(
            id: "wallet-wire-\(sequence)",
            operation: operation,
            arguments: [
                "call": .string(String(call.rawValue)),
                "bytes": .string(Hex.encode(bytes)),
            ]
        )
    }

    private func string(_ response: GoOracleResponse, field: String) throws -> String {
        guard case .object(let object)? = response.result,
              case .string(let value)? = object[field] else {
            throw WalletWireOracleTestError.missingField(field)
        }
        return value
    }
}

private enum WalletWireOracleTestError: Error {
    case missingField(String)
}
