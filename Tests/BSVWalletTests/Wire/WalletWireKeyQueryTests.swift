import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
@testable import BSVWallet

final class WalletWireKeyQueryTests: XCTestCase {
    func testAllThirteenRequestsAndSemanticArmsRoundTrip() throws {
        let protocolID = try walletTestProtocol("wire test")
        let keyID = try walletTestKeyID("wire-key")
        let other = try walletTestPrivateKey(2).publicKey
        let access = try WalletKeyAccess(
            privileged: true,
            privilegedReason: "because",
            seekPermission: true
        )
        let signature = try walletTestPrivateKey(3).sign(digest: BSVHashing.sha256([9]))
        let digest = BSVHashing.sha256([1, 2, 3])
        let hmac = try WalletHMAC(bytes: [UInt8](repeating: 0x44, count: 32))

        let requests: [WalletWireKeyQueryRequest] = [
            .getPublicKey(WalletGetPublicKeyRequest(selection: .identity, access: access)),
            .getPublicKey(WalletGetPublicKeyRequest(
                selection: .derived(
                    protocolID: protocolID,
                    keyID: keyID,
                    counterparty: .publicKey(other),
                    forSelf: true
                ),
                access: access
            )),
            .encrypt(WalletEncryptRequest(
                protocolID: protocolID, keyID: keyID, counterparty: .self,
                plaintext: [0, 1, 2], access: access
            )),
            .decrypt(WalletDecryptRequest(
                protocolID: protocolID, keyID: keyID, counterparty: .anyone,
                ciphertext: [3, 4, 5], access: access
            )),
            .createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID, keyID: keyID, data: [], access: access
            )),
            .verifyHMAC(WalletVerifyHMACRequest(
                protocolID: protocolID, keyID: keyID, data: [6], hmac: hmac, access: access
            )),
            .createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .data([]), access: access
            )),
            .createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .digest(digest), access: access
            )),
            .verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .data([7]),
                signature: signature, forSelf: true, access: access
            )),
            .verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID, keyID: keyID, payload: .digest(digest),
                signature: signature, access: access
            )),
            .isAuthenticated(WalletIsAuthenticatedRequest()),
            .waitForAuthentication(WalletWaitForAuthenticationRequest()),
            .getHeight(WalletGetHeightRequest()),
            .getHeaderForHeight(WalletGetHeaderRequest(height: .max)),
            .getNetwork(WalletGetNetworkRequest()),
            .getVersion(WalletGetVersionRequest()),
        ]

        for (index, request) in requests.enumerated() {
            let originator = index.isMultiple(of: 2) ? "origin" : "世"
            let encoded = try WalletWireCodec.encodeKeyQueryRequest(request, originator: originator)
            let decoded = try WalletWireCodec.decodeKeyQueryRequest(encoded)
            XCTAssertEqual(decoded.originator, originator)
            XCTAssertEqual(decoded.request.call, request.call)
            XCTAssertEqual(
                try WalletWireCodec.encodeKeyQueryRequest(
                    decoded.request,
                    originator: decoded.originator
                ),
                encoded
            )
        }
    }

    func testAllThirteenResultsRoundTrip() throws {
        let signature = try walletTestPrivateKey(4).sign(digest: BSVHashing.sha256([8]))
        let hmac = try WalletHMAC(bytes: [UInt8](repeating: 0x55, count: 32))
        let results: [WalletWireKeyQueryResult] = [
            .getPublicKey(WalletGetPublicKeyResult(publicKey: try walletTestPrivateKey(5).publicKey)),
            .encrypt(WalletEncryptResult(ciphertext: [1, 2, 3])),
            .decrypt(WalletDecryptResult(plaintext: [4, 5])),
            .createHMAC(WalletCreateHMACResult(hmac: hmac)),
            .verifyHMAC(WalletVerifyHMACResult(valid: true)),
            .createSignature(WalletCreateSignatureResult(signature: signature)),
            .verifySignature(WalletVerifySignatureResult(valid: true)),
            .isAuthenticated(WalletAuthenticatedResult(authenticated: false)),
            .waitForAuthentication(WalletAuthenticatedResult(authenticated: true)),
            .getHeight(WalletGetHeightResult(height: 800_000)),
            .getHeaderForHeight(try WalletGetHeaderResult(header: [UInt8](repeating: 6, count: 80))),
            .getNetwork(WalletGetNetworkResult(network: .testnet)),
            .getVersion(try WalletGetVersionResult(version: "v1.2.3")),
        ]

        for result in results {
            let encoded = try WalletWireCodec.encodeKeyQueryResult(result)
            let decoded = try WalletWireCodec.decodeKeyQueryResult(
                encoded,
                expectedCall: result.call
            )
            XCTAssertEqual(decoded.call, result.call)
            XCTAssertEqual(try WalletWireCodec.encodeKeyQueryResult(decoded), encoded)
        }
    }

    func testTypedDecoderThrowsBoundedRemoteError() throws {
        let remote = try WalletWireRemoteError(
            code: 42,
            message: "private remote detail",
            stack: "private remote stack"
        )
        let bytes = try WalletWireCodec.encodeResultFrame(.failure(remote))
        XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
            bytes,
            expectedCall: .getHeight
        )) { error in
            XCTAssertEqual(error as? WalletWireRemoteError, remote)
        }
    }

    func testAbsentForSelfNormalizesToExplicitFalse() throws {
        let protocolID = try walletTestProtocol("wire normalization")
        let keyID = try walletTestKeyID("wire-key")

        let getPublicKey = WalletWireKeyQueryRequest.getPublicKey(
            WalletGetPublicKeyRequest(selection: .derived(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self,
                forSelf: false
            ))
        )
        let getPublicKeyBytes = try WalletWireCodec.encodeKeyQueryRequest(
            getPublicKey,
            originator: ""
        )
        let getPublicKeyFrame = try WalletWireCodec.decodeRequestFrame(getPublicKeyBytes)
        var getPublicKeyReader = WalletWireReader(getPublicKeyFrame.parameters)
        XCTAssertEqual(try getPublicKeyReader.readByte(), 0)
        _ = try walletWireDecodeKeyParameters(
            from: &getPublicKeyReader,
            limits: .standard
        )
        let getPublicKeyForSelfOffset = getPublicKeyReader.position
        XCTAssertEqual(getPublicKeyFrame.parameters[getPublicKeyForSelfOffset], 0)

        var absentGetPublicKeyParameters = getPublicKeyFrame.parameters
        absentGetPublicKeyParameters[getPublicKeyForSelfOffset] = 0xFF
        let absentGetPublicKey = try WalletWireCodec.encodeRequestFrame(.init(
            call: .getPublicKey,
            originator: "",
            parameters: absentGetPublicKeyParameters
        ))
        let decodedGetPublicKey = try WalletWireCodec.decodeKeyQueryRequest(absentGetPublicKey)
        XCTAssertEqual(
            try WalletWireCodec.encodeKeyQueryRequest(
                decodedGetPublicKey.request,
                originator: decodedGetPublicKey.originator
            ),
            getPublicKeyBytes
        )

        let signature = try walletTestPrivateKey(7).sign(digest: BSVHashing.sha256([7]))
        let verifySignature = WalletWireKeyQueryRequest.verifySignature(
            WalletVerifySignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                payload: .data([1]),
                signature: signature,
                forSelf: false
            )
        )
        let verifyBytes = try WalletWireCodec.encodeKeyQueryRequest(
            verifySignature,
            originator: ""
        )
        let verifyFrame = try WalletWireCodec.decodeRequestFrame(verifyBytes)
        var verifyReader = WalletWireReader(verifyFrame.parameters)
        _ = try walletWireDecodeKeyParameters(from: &verifyReader, limits: .standard)
        let verifyForSelfOffset = verifyReader.position
        XCTAssertEqual(verifyFrame.parameters[verifyForSelfOffset], 0)

        var absentVerifyParameters = verifyFrame.parameters
        absentVerifyParameters[verifyForSelfOffset] = 0xFF
        let absentVerify = try WalletWireCodec.encodeRequestFrame(.init(
            call: .verifySignature,
            originator: "",
            parameters: absentVerifyParameters
        ))
        let decodedVerify = try WalletWireCodec.decodeKeyQueryRequest(absentVerify)
        XCTAssertEqual(
            try WalletWireCodec.encodeKeyQueryRequest(
                decodedVerify.request,
                originator: decodedVerify.originator
            ),
            verifyBytes
        )
    }

    func testRepeatedAndConcurrentEncodingIsDeterministicAndSendable() async throws {
        let request = WalletWireKeyQueryRequest.getHeight(WalletGetHeightRequest())
        let expected = try WalletWireCodec.encodeKeyQueryRequest(request, originator: "concurrent")
        for _ in 0..<100 {
            XCTAssertEqual(
                try WalletWireCodec.encodeKeyQueryRequest(request, originator: "concurrent"),
                expected
            )
        }
        let outputs = try await withThrowingTaskGroup(of: [UInt8].self) { group in
            for _ in 0..<64 {
                group.addTask {
                    let decoded = try WalletWireCodec.decodeKeyQueryRequest(expected)
                    return try WalletWireCodec.encodeKeyQueryRequest(
                        decoded.request,
                        originator: decoded.originator
                    )
                }
            }
            var collected: [[UInt8]] = []
            for try await output in group { collected.append(output) }
            return collected
        }
        XCTAssertTrue(outputs.allSatisfy { $0 == expected })
    }
}
