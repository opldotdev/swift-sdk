import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
@testable import BSVWallet

final class WalletWireAdversarialTests: XCTestCase {
    func testOptionalBooleanAndReasonDiscriminatorsAreStrict() throws {
        // identity, privileged=false, absent reason (one ff), invalid seek=02
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest([8, 0, 1, 0, 0xFF, 2])) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .invalidDiscriminator(kind: "seek permission", value: 2)
            )
        }
        for value in UInt8(2)...UInt8(0xFE) {
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(
                [8, 0, 1, 0, 0xFF, value]
            ))
        }
        // A Boolean absence consumes one ff; the eight additional bytes trail.
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(
            [8, 0, 1, 0, 0xFF] + [UInt8](repeating: 0xFF, count: 9)
        )) { error in
            XCTAssertEqual(error as? WalletWireError, .trailingBytes)
        }
        // Empty reason is not distinguishable from absence after Go round-trip.
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest([8, 0, 1, 0, 0, 0])) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .nonRoundTrippableValue(kind: "empty privileged reason")
            )
        }
    }

    func testCounterpartyAndSignatureDiscriminatorsAreStrict() throws {
        let commonPrefix = [UInt8](arrayLiteral: 0, 5) + Array("wire1".utf8) + [1, 0x6B]
        let commonSuffix = [UInt8](arrayLiteral: 0, 0xFF)
        let payload = commonPrefix + [0] + commonSuffix + [0, 0]
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest([15, 0] + payload)) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .invalidDiscriminator(kind: "counterparty", value: 0)
            )
        }

        let validCommon = commonPrefix + [0x0B] + commonSuffix
        for discriminator in [UInt8(0), 3, 255] {
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(
                [15, 0] + validCommon + [discriminator, 0]
            )) { error in
                XCTAssertEqual(
                    error as? WalletWireError,
                    .invalidDiscriminator(kind: "signature payload", value: discriminator)
                )
            }
        }
    }

    func testExactPublicKeyHMACDigestDERHeaderAndNetworkConstraints() throws {
        let publicKey = try walletTestPrivateKey(6).publicKey.compressedBytes
        XCTAssertNoThrow(try WalletWireCodec.decodeKeyQueryResult([0] + publicKey, expectedCall: .getPublicKey))
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult([0] + publicKey + [0], expectedCall: .getPublicKey))
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult([0] + Array(publicKey.dropLast()), expectedCall: .getPublicKey))
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult([0] + [4] + [UInt8](repeating: 0, count: 32), expectedCall: .getPublicKey))

        XCTAssertNoThrow(try WalletWireCodec.decodeKeyQueryResult(
            [0] + [UInt8](repeating: 1, count: 32),
            expectedCall: .createHMAC
        ))
        for count in [31, 33] {
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
                [0] + [UInt8](repeating: 1, count: count),
                expectedCall: .createHMAC
            ))
        }

        let signature = try walletTestPrivateKey(7).sign(digest: BSVHashing.sha256([1]))
        XCTAssertNoThrow(try WalletWireCodec.decodeKeyQueryResult(
            [0] + signature.derBytes,
            expectedCall: .createSignature
        ))
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            [0] + signature.derBytes + [0],
            expectedCall: .createSignature
        ))

        XCTAssertNoThrow(try WalletWireCodec.decodeKeyQueryResult(
            [0] + [UInt8](repeating: 0, count: 80),
            expectedCall: .getHeaderForHeight
        ))
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            [0] + [UInt8](repeating: 0, count: 81),
            expectedCall: .getHeaderForHeight
        ))
        for value in UInt8(2)...UInt8.max {
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
                [0, value],
                expectedCall: .getNetwork
            ))
        }
    }

    func testEmptyCallsAndEmptySuccessCallsAreExact() throws {
        for call in [WalletCall.isAuthenticated, .waitForAuthentication, .getHeight, .getNetwork, .getVersion] {
            let request = [call.rawValue, 0, 1]
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(request)) { error in
                XCTAssertEqual(error as? WalletWireError, .trailingBytes)
            }
        }
        for call in [WalletCall.verifyHMAC, .verifySignature, .waitForAuthentication] {
            XCTAssertNoThrow(try WalletWireCodec.decodeKeyQueryResult([0], expectedCall: call))
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult([0, 1], expectedCall: call)) { error in
                XCTAssertEqual(error as? WalletWireError, .trailingBytes)
            }
        }
    }

    func testNonRoundTrippableFalseAndEmptyVerifyDataAreRejected() throws {
        XCTAssertThrowsError(try WalletWireCodec.encodeKeyQueryResult(
            .verifyHMAC(WalletVerifyHMACResult(valid: false))
        ))
        XCTAssertThrowsError(try WalletWireCodec.encodeKeyQueryResult(
            .verifySignature(WalletVerifySignatureResult(valid: false))
        ))
        XCTAssertThrowsError(try WalletWireCodec.encodeKeyQueryResult(
            .waitForAuthentication(WalletAuthenticatedResult(authenticated: false))
        ))

        let request = WalletVerifySignatureRequest(
            protocolID: try walletTestProtocol("wire test"),
            keyID: try walletTestKeyID("key"),
            payload: .data([]),
            signature: try walletTestPrivateKey(8).sign(digest: BSVHashing.sha256([2]))
        )
        XCTAssertThrowsError(try WalletWireCodec.encodeKeyQueryRequest(
            .verifySignature(request),
            originator: "app"
        ))
    }

    func testHighSSignaturesAreRejectedOnCall16AndCall15EncodeDecodePaths() throws {
        let highDER = try Hex.decode(
            "3046022100c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
                "022100ff45decaeca8d1ca6bc2a5322e8deaa89faaebd04c2f75c96db8f1c41d8cabe1",
            maximumDecodedByteCount: 72
        )
        let highSignature = try ECDSASignature(derBytes: highDER)
        let protocolID = try walletTestProtocol("wire test")
        let keyID = try walletTestKeyID("key")
        let digest = BSVHashing.sha256([9])
        let request = WalletWireKeyQueryRequest.verifySignature(
            WalletVerifySignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                payload: .digest(digest),
                signature: highSignature
            )
        )

        assertHighSRejection {
            _ = try WalletWireCodec.encodeKeyQueryRequest(request, originator: "app")
        }

        var parameters = WalletWireWriter()
        try walletWireEncodeKeyParameters(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .self,
            access: .standard,
            to: &parameters,
            limits: .standard
        )
        parameters.writeOptionalBoolean(false)
        try parameters.writeVarBytes(highDER)
        parameters.writeByte(2)
        parameters.writeBytes(digest.bytes)
        parameters.writeOptionalBoolean(false)
        let rawRequest = try WalletWireCodec.encodeRequestFrame(.init(
            call: .verifySignature,
            originator: "app",
            parameters: parameters.bytes
        ))
        assertHighSRejection {
            _ = try WalletWireCodec.decodeKeyQueryRequest(rawRequest)
        }

        let result = WalletWireKeyQueryResult.createSignature(
            WalletCreateSignatureResult(signature: highSignature)
        )
        assertHighSRejection {
            _ = try WalletWireCodec.encodeKeyQueryResult(result)
        }
        assertHighSRejection {
            _ = try WalletWireCodec.decodeKeyQueryResult(
                [0] + highDER,
                expectedCall: .createSignature
            )
        }
    }

    func testCryptoVarBytesDistinguishCountLimitsFromTruncation() throws {
        let cryptoLimits = try WalletCryptoLimits(
            maximumPayloadByteCount: 2,
            maximumJSONByteCount: 1_024
        )
        let limits = try WalletWireLimits(
            maximumFrameByteCount: 10_000,
            maximumPayloadByteCount: 512,
            cryptoLimits: cryptoLimits
        )
        var key = WalletWireWriter()
        try walletWireEncodeKeyParameters(
            protocolID: walletTestProtocol("wire test"),
            keyID: walletTestKeyID("key"),
            counterparty: .self,
            access: .standard,
            to: &key,
            limits: limits
        )

        let cases: [(call: WalletCall, kind: String, maximum: Int)] = [
            (.encrypt, "plaintext", cryptoLimits.maximumPayloadByteCount),
            (.decrypt, "ciphertext", cryptoLimits.maximumCiphertextByteCount),
            (.createHMAC, "HMAC data", cryptoLimits.maximumPayloadByteCount),
        ]
        for test in cases {
            let overLimit = [test.call.rawValue, 0] + key.bytes + [UInt8(test.maximum + 1)]
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(
                overLimit,
                limits: limits
            )) { error in
                XCTAssertEqual(
                    error as? WalletWireError,
                    .countLimitExceeded(
                        kind: test.kind,
                        actual: UInt64(test.maximum + 1),
                        maximum: test.maximum
                    )
                )
            }

            let withinLimitButMissing = [test.call.rawValue, 0] + key.bytes + [UInt8(test.maximum)]
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest(
                withinLimitButMissing,
                limits: limits
            )) { error in
                XCTAssertEqual(error as? WalletWireError, .truncated)
            }
        }
    }

    func testUInt32OverflowInvalidUTF8AndUnsupportedTypedCalls() throws {
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            [0, 0xFF] + [UInt8](repeating: 0xFF, count: 8),
            expectedCall: .getHeight
        )) { error in
            XCTAssertEqual(error as? WalletWireError, .uint32Overflow)
        }
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            [0, 0xFF],
            expectedCall: .getVersion
        )) { error in
            XCTAssertEqual(error as? WalletWireError, .invalidUTF8(kind: "wallet version"))
        }
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryRequest([1, 0])) { error in
            XCTAssertEqual(error as? WalletWireError, .invalidCall(1))
        }
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult([0], expectedCall: .createAction)) { error in
            XCTAssertEqual(error as? WalletWireError, .invalidCall(1))
        }
    }

    func testResultErrorRejectsNonminimalLengthsOverflowTruncationAndInvalidUTF8() throws {
        let hostile: [[UInt8]] = [
            [1, 0xFD, 0, 0, 0],
            [1, 0xFF] + [UInt8](repeating: 0xFF, count: 8),
            [1, 2, 0x61],
            [1, 1, 0xFF, 0],
        ]
        for bytes in hostile {
            XCTAssertThrowsError(try WalletWireCodec.decodeResultFrame(bytes))
        }
    }

    private func assertHighSRejection(
        _ operation: () throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .nonRoundTrippableValue(kind: "high-S signature"),
                file: file,
                line: line
            )
        }
    }
}
