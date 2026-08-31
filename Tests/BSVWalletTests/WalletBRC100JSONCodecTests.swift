import XCTest
import BSVCore
import BSVKeys
import BSVTransaction
@testable import BSVWallet

final class WalletBRC100JSONCodecTests: XCTestCase {
    func testAllCanonicalRoutesAreExactAndUnversioned() {
        let names = [
            "createAction", "signAction", "abortAction", "listActions", "internalizeAction",
            "listOutputs", "relinquishOutput", "getPublicKey", "revealCounterpartyKeyLinkage",
            "revealSpecificKeyLinkage", "encrypt", "decrypt", "createHmac", "verifyHmac",
            "createSignature", "verifySignature", "acquireCertificate", "listCertificates",
            "proveCertificate", "relinquishCertificate", "discoverByIdentityKey",
            "discoverByAttributes", "isAuthenticated", "waitForAuthentication", "getHeight",
            "getHeaderForHeight", "getNetwork", "getVersion",
        ]
        XCTAssertEqual(WalletJSONRoute.all.map(\.methodName), names)
        for (index, name) in names.enumerated() {
            let route = WalletJSONRoute(path: "/\(name)")
            XCTAssertEqual(route?.call.rawValue, UInt8(index + 1))
            XCTAssertEqual(route?.path, "/\(name)")
        }
        XCTAssertNil(WalletJSONRoute(path: "getVersion"))
        XCTAssertNil(WalletJSONRoute(path: "/v1/getVersion"))
        XCTAssertNil(WalletJSONRoute(path: "/getversion"))
        XCTAssertNil(WalletJSONRoute(path: "/getVersion/"))
        XCTAssertNil(WalletJSONRoute(path: "/unknown"))
    }

    func testEmptyObjectMethodsRejectNonemptyBodies() throws {
        let codec = try makeCodec()
        for name in ["isAuthenticated", "waitForAuthentication", "getHeight", "getNetwork", "getVersion"] {
            let route = try XCTUnwrap(WalletJSONRoute(methodName: name))
            let request = try codec.decodeRequest(route: route, from: Array("{}".utf8))
            XCTAssertEqual(request.call, route.call)
            XCTAssertEqual(try codec.encodeRequest(request), Array("{}".utf8))
            XCTAssertThrowsError(try codec.decodeRequest(route: route, from: Array("{\"extra\":1}".utf8)))
        }
    }

    func testAbsentAndExplicitFalseRemainDistinct() throws {
        let codec = try makeCodec()
        let route = try XCTUnwrap(WalletJSONRoute(methodName: "listActions"))
        let absent = try codec.decodeRequest(route: route, from: Array("{\"labels\":[]}".utf8))
        let explicit = try codec.decodeRequest(
            route: route,
            from: Array("{\"labels\":[],\"includeLabels\":false,\"seekPermission\":false}".utf8)
        )
        guard case .action(.listActions(let absentValue)) = absent,
              case .action(.listActions(let explicitValue)) = explicit else {
            return XCTFail("unexpected request case")
        }
        XCTAssertNil(absentValue.includeLabels)
        XCTAssertNil(absentValue.seekPermission)
        XCTAssertEqual(explicitValue.includeLabels, false)
        XCTAssertEqual(explicitValue.seekPermission, false)
        XCTAssertEqual(explicit.rawSeekPermission, false)
        XCTAssertEqual(explicit.effectiveSeekPermission, false)
        XCTAssertEqual(
            String(decoding: try codec.encodeRequest(explicit), as: UTF8.self),
            "{\"includeLabels\":false,\"labels\":[],\"seekPermission\":false}"
        )
    }

    func testHexBase64AndByteArrayShapes() throws {
        let codec = try makeCodec()
        let create = try codec.decodeRequest(
            route: XCTUnwrap(WalletJSONRoute(methodName: "createAction")),
            from: Array("{\"description\":\"hello\",\"outputs\":[{\"lockingScript\":\"51\",\"satoshis\":1,\"outputDescription\":\"test output\"}]}".utf8)
        )
        guard case .action(.createAction(let request)) = create else { return XCTFail() }
        XCTAssertEqual(request.outputs?.first?.lockingScript, [0x51])
        XCTAssertTrue(String(decoding: try codec.encodeRequest(create), as: UTF8.self).contains("\"lockingScript\":\"51\""))

        let abort = try codec.decodeRequest(
            route: XCTUnwrap(WalletJSONRoute(methodName: "abortAction")),
            from: Array("{\"reference\":\"AQID\"}".utf8)
        )
        guard case .action(.abortAction(let abortRequest)) = abort else { return XCTFail() }
        XCTAssertEqual(abortRequest.reference.bytes, [1, 2, 3])
        XCTAssertEqual(String(decoding: try codec.encodeRequest(abort), as: UTF8.self), "{\"reference\":\"AQID\"}")

        let headerHex = String(repeating: "00", count: 80)
        let header = try codec.decodeResult(
            route: XCTUnwrap(WalletJSONRoute(methodName: "getHeaderForHeight")),
            from: Array("{\"header\":\"\(headerHex)\"}".utf8)
        )
        guard case .keyQuery(.getHeaderForHeight(let headerResult)) = header else { return XCTFail() }
        XCTAssertEqual(headerResult.header, Array(repeating: 0, count: 80))

        let encrypted = try codec.decodeResult(
            route: XCTUnwrap(WalletJSONRoute(methodName: "encrypt")),
            from: Array("{\"ciphertext\":[\(Array(repeating: "0", count: 48).joined(separator: ","))]}".utf8)
        )
        guard case .keyQuery(.encrypt(let encryptedResult)) = encrypted else { return XCTFail() }
        XCTAssertEqual(encryptedResult.ciphertext.count, 48)
    }

    func testFailedActionStatusUsesStringNotErrorCode() throws {
        let codec = try makeCodec()
        let txid = String(repeating: "00", count: 32)
        let json = "{\"totalActions\":1,\"actions\":[{\"txid\":\"\(txid)\",\"satoshis\":0,\"status\":\"failed\",\"isOutgoing\":true,\"description\":\"failed action\",\"version\":1,\"lockTime\":0}]}"
        let result = try codec.decodeResult(
            route: XCTUnwrap(WalletJSONRoute(methodName: "listActions")),
            from: Array(json.utf8)
        )
        guard case .action(.listActions(let list)) = result else { return XCTFail() }
        XCTAssertEqual(list.actions.first?.status, .failed)
        XCTAssertTrue(String(decoding: try codec.encodeResult(result), as: UTF8.self).contains("\"status\":\"failed\""))
    }

    func testCanonicalWERRFiveSixSevenPayloads() throws {
        let codec = try makeCodec()
        let values = [
            WalletJSONErrorPayload(
                name: "WERR_REVIEW_ACTIONS",
                message: "Review actions",
                code: 5,
                details: ["txid": .string("abc"), "reviewActionResults": .array([])]
            ),
            WalletJSONErrorPayload(
                name: "WERR_INVALID_PARAMETER",
                message: "Invalid parameter",
                code: 6,
                details: ["parameter": .string("description")]
            ),
            WalletJSONErrorPayload(
                name: "WERR_INSUFFICIENT_FUNDS",
                message: "Insufficient funds",
                code: 7,
                details: ["totalSatoshisNeeded": .number(5_000), "moreSatoshisNeeded": .number(2_000)]
            ),
        ]
        for value in values {
            let bytes = try codec.encodeError(value)
            let decoded = try codec.decodeError(from: bytes)
            XCTAssertEqual(decoded, value)
            XCTAssertTrue(String(decoding: bytes, as: UTF8.self).contains("\"isError\":true"))
        }
    }

    func testIssuanceCertificateAndMalformedJSON() throws {
        let codec = try makeCodec()
        let type = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        let json = "{\"type\":\"\(type)\",\"certifier\":\"\(key)\",\"acquisitionProtocol\":\"issuance\",\"fields\":{\"name\":\"Alice\"},\"certifierUrl\":\"https://certifier.example.com\"}"
        let route = try XCTUnwrap(WalletJSONRoute(methodName: "acquireCertificate"))
        let request = try codec.decodeRequest(route: route, from: Array(json.utf8))
        guard case .certificate(.acquireCertificate(let acquisition)) = request,
              case .issuance(let issuance) = acquisition.acquisition else { return XCTFail() }
        XCTAssertEqual(issuance.certifierURL, "https://certifier.example.com")
        XCTAssertEqual(acquisition.fields.first?.value, "Alice")
        let encoded = String(decoding: try codec.encodeRequest(request), as: UTF8.self)
        XCTAssertTrue(encoded.contains("\"acquisitionProtocol\":\"issuance\""))
        XCTAssertThrowsError(try codec.decodeRequest(route: route, from: Array("{".utf8)))
    }

    func testCertificateCiphertextUsesCanonicalBase64AcrossJSONRoutes() throws {
        let raw: [UInt8] = [0x00, 0xff, 0x80, 0x01, 0x7f, 0xa5, 0x42, 0xc3]
        let expectedBase64 = "AP+AAX+lQsM="
        let codec = try makeCodec()
        let (certificate, field) = try makeCertificate(fieldBytes: raw)

        let acquireRoute = try XCTUnwrap(WalletJSONRoute(methodName: "acquireCertificate"))
        let acquireResult = WalletResult.certificate(.acquireCertificate(certificate))
        let acquireJSON = try codec.encodeResult(acquireResult)
        XCTAssertEqual(
            String(decoding: acquireJSON, as: UTF8.self),
            "{\"certifier\":\"\(Hex.encode(certificate.certifier.compressedBytes))\",\"fields\":{\"binary\":\"\(expectedBase64)\"},\"revocationOutpoint\":\"\(certificate.revocationOutpoint)\",\"serialNumber\":\"\(certificate.serialNumber.base64)\",\"subject\":\"\(Hex.encode(certificate.subject.compressedBytes))\",\"type\":\"\(certificate.type.base64)\"}"
        )
        guard case .certificate(.acquireCertificate(let acquired)) = try codec.decodeResult(
            route: acquireRoute,
            from: acquireJSON
        ) else { return XCTFail("unexpected acquireCertificate result") }
        XCTAssertEqual(acquired.fields[field]?.bytes, raw)

        let listRoute = try XCTUnwrap(WalletJSONRoute(methodName: "listCertificates"))
        let listResult = WalletResult.certificate(.listCertificates(try .init(
            totalCertificates: 1,
            certificates: [.init(certificate: certificate, keyring: nil, verifier: [])]
        )))
        let listJSON = try codec.encodeResult(listResult)
        let listObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(listJSON)) as? [String: Any]
        )
        let listedObjects = try XCTUnwrap(listObject["certificates"] as? [[String: Any]])
        let listedFields = try XCTUnwrap(listedObjects.first?["fields"] as? [String: String])
        XCTAssertEqual(listedFields[field.value], expectedBase64)
        guard case .certificate(.listCertificates(let listed)) = try codec.decodeResult(
            route: listRoute,
            from: listJSON
        ) else { return XCTFail("unexpected listCertificates result") }
        XCTAssertEqual(listed.certificates.first?.certificate.fields[field]?.bytes, raw)

        let proveRoute = try XCTUnwrap(WalletJSONRoute(methodName: "proveCertificate"))
        let proveRequest = WalletRequest.certificate(.proveCertificate(try .init(
            certificate: certificate,
            fieldsToReveal: [field],
            verifier: walletTestPrivateKey(4).publicKey
        )))
        let proveJSON = try codec.encodeRequest(proveRequest)
        let proveObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(proveJSON)) as? [String: Any]
        )
        let proveCertificate = try XCTUnwrap(proveObject["certificate"] as? [String: Any])
        let proveFields = try XCTUnwrap(proveCertificate["fields"] as? [String: String])
        XCTAssertEqual(proveFields[field.value], expectedBase64)
        guard case .certificate(.proveCertificate(let proven)) = try codec.decodeRequest(
            route: proveRoute,
            from: proveJSON
        ) else { return XCTFail("unexpected proveCertificate request") }
        XCTAssertEqual(proven.certificate.fields[field]?.bytes, raw)
    }

    func testSignedCertificateStillVerifiesAfterBRC100JSONTransport() async throws {
        let raw: [UInt8] = [0x00, 0xff, 0x80, 0x01, 0x7f, 0xa5, 0x42, 0xc3]
        let codec = try makeCodec()
        let (unsigned, _) = try makeCertificate(fieldBytes: raw)
        let signed = try await unsigned.signed(
            using: ProtoWallet(rootKey: walletTestPrivateKey(3))
        )
        let signedIsValid = try await signed.verifySignature()
        XCTAssertTrue(signedIsValid)

        let encoded = try codec.encodeResult(
            WalletResult.certificate(.acquireCertificate(signed))
        )
        guard case .certificate(.acquireCertificate(let transported)) = try codec.decodeResult(
            route: XCTUnwrap(WalletJSONRoute(methodName: "acquireCertificate")),
            from: encoded
        ) else { return XCTFail("unexpected acquireCertificate result") }

        XCTAssertEqual(
            try transported.binary(includingSignature: false),
            try signed.binary(includingSignature: false)
        )
        XCTAssertEqual(transported.signature, signed.signature)
        let transportedIsValid = try await transported.verifySignature()
        XCTAssertTrue(transportedIsValid)
    }

    func testCertificateCiphertextLimitAppliesToDecodedBytesNotBase64Expansion() throws {
        let raw: [UInt8] = [0x00, 0xff, 0x80, 0x01, 0x7f, 0xa5, 0x42, 0xc3]
        let standardCodec = try makeCodec()
        let (certificate, field) = try makeCertificate(fieldBytes: raw)
        let encoded = try standardCodec.encodeResult(
            WalletResult.certificate(.acquireCertificate(certificate))
        )
        XCTAssertTrue(String(decoding: encoded, as: UTF8.self).contains("\"binary\":\"AP+AAX+lQsM=\""))

        let exactCodec = try makeCodec(certificateLimits: try CertificateLimits(
            maximumFieldCiphertextByteCount: raw.count
        ))
        guard case .certificate(.acquireCertificate(let exact)) = try exactCodec.decodeResult(
            route: XCTUnwrap(WalletJSONRoute(methodName: "acquireCertificate")),
            from: encoded
        ) else { return XCTFail("unexpected acquireCertificate result") }
        XCTAssertEqual(exact.fields[field]?.bytes, raw)

        let exactBase64 = "AP+AAX+lQsM="
        let oversizedBase64 = "AAAAAAAAAAAA"
        XCTAssertEqual(exactBase64.utf8.count, oversizedBase64.utf8.count)
        let oversized = String(decoding: encoded, as: UTF8.self)
            .replacingOccurrences(of: exactBase64, with: oversizedBase64)
        XCTAssertThrowsError(try exactCodec.decodeResult(
            route: XCTUnwrap(WalletJSONRoute(methodName: "acquireCertificate")),
            from: Array(oversized.utf8)
        )) { error in
            XCTAssertEqual(error as? CertificateError, .invalidCanonicalBase64)
        }
    }

    func testProcessorSeparatesRouteBodyAndWalletFailures() async throws {
        let codec = try makeCodec()
        let context = try WalletRequestContext(rawOriginator: "example.com")
        let successful = WalletBRC100JSONProcessor(
            codec: codec,
            handler: NetworkHandler(shouldFail: false)
        )
        let unknown = await successful.process(
            path: "/unknown", body: Array("{}".utf8), context: context
        )
        XCTAssertEqual(unknown, .unknownRoute(path: "/unknown"))
        let invalid = await successful.process(
            path: "/getNetwork", body: Array("{".utf8), context: context
        )
        XCTAssertEqual(invalid, .invalidRequest(call: .getNetwork))
        let success = await successful.process(
            path: "/getNetwork", body: Array("{}".utf8), context: context
        )
        XCTAssertEqual(
            success,
            .success(call: .getNetwork, body: Array("{\"network\":\"mainnet\"}".utf8))
        )

        let failing = WalletBRC100JSONProcessor(
            codec: codec,
            handler: NetworkHandler(shouldFail: true),
            failureMapper: InvalidParameterMapper()
        )
        let outcome = await failing.process(
            path: "/getNetwork",
            body: Array("{}".utf8),
            context: context
        )
        guard case .walletFailure(.getNetwork, let body) = outcome else { return XCTFail() }
        let payload = try codec.decodeError(from: body)
        XCTAssertEqual(payload.code, 6)
        XCTAssertEqual(payload.details["parameter"], .string("network"))
    }

    func testOuterJSONLimitAppliesBeforeDecodeAndAfterEncode() throws {
        let base = try makeCodec()
        let codec = try WalletBRC100JSONCodec(
            beefLimits: base.beefLimits,
            maximumJSONByteCount: 1
        )
        let route = try XCTUnwrap(WalletJSONRoute(methodName: "getVersion"))
        XCTAssertThrowsError(try codec.decodeRequest(route: route, from: Array("{}".utf8))) {
            XCTAssertEqual(
                $0 as? WalletJSONCodecError,
                .jsonTooLarge(actual: 2, maximum: 1)
            )
        }
        let result = WalletResult.keyQuery(.getVersion(try .init(version: "wallet-1.0")))
        XCTAssertThrowsError(try codec.encodeResult(result)) {
            guard case .encodedJSONTooLarge = $0 as? WalletJSONCodecError else {
                return XCTFail("unexpected error: \($0)")
            }
        }
    }

    private func makeCodec(
        certificateLimits: CertificateLimits = .standard
    ) throws -> WalletBRC100JSONCodec {
        try WalletBRC100JSONCodec(beefLimits: BEEFLimits(
            maximumByteCount: 1_000_000,
            maximumMerklePathCount: 100,
            maximumTransactionCount: 1_000,
            transactionLimits: TransactionLimits(
                maximumTransactionByteCount: 100_000,
                maximumInputCount: 100,
                maximumOutputCount: 100,
                maximumScriptByteCount: 10_000
            ),
            merklePathLimits: MerklePathLimits(
                maximumByteCount: 100_000,
                maximumLeavesPerLevel: 100,
                maximumTotalLeaves: 1_000
            )
        ), certificateLimits: certificateLimits)
    }

    private func makeCertificate(
        fieldBytes: [UInt8]
    ) throws -> (certificate: Certificate, field: CertificateFieldName) {
        let fixture = try WalletWireCertificateFixture()
        let field = try CertificateFieldName("binary")
        return (
            try Certificate(
                type: fixture.type,
                serialNumber: fixture.serial,
                subject: fixture.subject,
                certifier: fixture.certifier,
                revocationOutpoint: fixture.outpoint,
                fields: [field: try CertificateCiphertext(fieldBytes)]
            ),
            field
        )
    }
}

private enum ProcessorTestError: Error { case failed }

private struct NetworkHandler: WalletRequestHandling {
    let shouldFail: Bool
    func handle(_ request: WalletRequest, context: WalletRequestContext) async throws -> WalletResult {
        guard request.call == .getNetwork else { throw ProcessorTestError.failed }
        if shouldFail { throw ProcessorTestError.failed }
        return .keyQuery(.getNetwork(.init(network: .mainnet)))
    }
}

private struct InvalidParameterMapper: WalletJSONFailureMapping {
    func payload(for error: any Error, call: WalletCall) -> WalletJSONErrorPayload {
        .init(
            name: "WERR_INVALID_PARAMETER",
            message: "Invalid network",
            code: 6,
            details: ["parameter": .string("network")]
        )
    }
}
