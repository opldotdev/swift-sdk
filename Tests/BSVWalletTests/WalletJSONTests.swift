import XCTest
import Foundation
import BSVCore
import BSVCrypto
import BSVKeys
@testable import BSVWallet

final class WalletJSONTests: XCTestCase {
    func testFlattenedRequestsDefaultsAndIntegerArrays() throws {
        let protocolID = try walletTestProtocol()
        let keyID = try walletTestKeyID()
        let access = try WalletKeyAccess(privileged: true, privilegedReason: "reason", seekPermission: true)
        let request = WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            plaintext: [0, 1, 255],
            access: access
        )
        let bytes = try WalletJSON.encode(request)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any])
        XCTAssertNil(object["access"])
        XCTAssertEqual(object["privileged"] as? Bool, true)
        XCTAssertEqual(object["seekPermission"] as? Bool, true)
        XCTAssertTrue(object["plaintext"] is [Any])
        XCTAssertEqual(try WalletJSON.decode(WalletEncryptRequest.self, from: bytes).counterparty, .self)

        let base = "{\"protocolID\":[0,\"testprotocol\"],\"keyID\":\"1\",\"plaintext\":"
        for invalid in ["[-1]", "[256]", "[1.5]", "[1e999]", "[\"1\"]", "[true]", "[null]"] {
            XCTAssertThrowsError(try WalletJSON.decode(WalletEncryptRequest.self, from: Array((base + invalid + "}").utf8)))
        }
    }

    func testOperationSpecificCounterpartyDefaultsAndSignaturePresence() throws {
        let prefix = "\"protocolID\":[0,\"testprotocol\"],\"keyID\":\"1\""
        XCTAssertEqual(try WalletJSON.decode(WalletEncryptRequest.self, from: Array(("{" + prefix + ",\"plaintext\":[]}").utf8)).counterparty, .self)
        XCTAssertEqual(try WalletJSON.decode(WalletDecryptRequest.self, from: Array(("{" + prefix + ",\"ciphertext\":" + String(describing: [UInt8](repeating: 0, count: 48)) + "}").utf8)).counterparty, .self)
        XCTAssertEqual(try WalletJSON.decode(WalletCreateHMACRequest.self, from: Array(("{" + prefix + ",\"data\":[]}").utf8)).counterparty, .self)
        XCTAssertEqual(try WalletJSON.decode(WalletVerifyHMACRequest.self, from: Array(("{" + prefix + ",\"data\":[],\"hmac\":" + String(describing: [UInt8](repeating: 0, count: 32)) + "}").utf8)).counterparty, .self)
        XCTAssertEqual(try WalletJSON.decode(WalletCreateSignatureRequest.self, from: Array(("{" + prefix + ",\"data\":[]}").utf8)).counterparty, .anyone)

        let empty = try WalletJSON.decode(
            WalletCreateSignatureRequest.self,
            from: Array(("{" + prefix + ",\"data\":[]}").utf8)
        )
        if case .data(let data) = empty.payload { XCTAssertEqual(data, []) } else { XCTFail() }
        for fields in ["", ",\"data\":null", ",\"data\":[],\"hashToDirectlySign\":" + String(repeating: "0,", count: 31) + "0"] {
            XCTAssertThrowsError(try WalletJSON.decode(
                WalletCreateSignatureRequest.self,
                from: Array(("{" + prefix + fields + "}").utf8)
            ))
        }

        let derived = try WalletJSON.decode(
            WalletGetPublicKeyRequest.self,
            from: Array(("{" + prefix + "}").utf8)
        )
        if case .derived(_, _, let counterparty, let forSelf) = derived.selection {
            XCTAssertEqual(counterparty, .self)
            XCTAssertFalse(forSelf)
        } else {
            XCTFail()
        }
    }

    func testIdentityAmbiguityUnknownFieldsAndCanonicalOutput() throws {
        XCTAssertThrowsError(try WalletJSON.decode(
            WalletGetPublicKeyRequest.self,
            from: Array("{\"identityKey\":true,\"keyID\":\"x\"}".utf8)
        ))
        let decoded = try WalletJSON.decode(
            WalletGetPublicKeyRequest.self,
            from: Array("{\"identityKey\":true,\"future\":{\"nested\":[1,2,3]}}".utf8)
        )
        if case .identity = decoded.selection {} else { XCTFail() }
        XCTAssertEqual(
            String(decoding: try WalletJSON.encode(decoded), as: UTF8.self),
            "{\"identityKey\":true}"
        )
    }

    func testGoDefaultNullCounterpartyAndZeroIdentityProtocolCompatibility() throws {
        let prefix = "\"protocolID\":[0,\"testprotocol\"],\"keyID\":\"1\",\"counterparty\":null"
        let encrypt = try WalletJSON.decode(
            WalletEncryptRequest.self,
            from: Array(("{" + prefix + ",\"plaintext\":[]}").utf8)
        )
        XCTAssertEqual(encrypt.counterparty, .self)
        XCTAssertTrue(String(decoding: try WalletJSON.encode(encrypt), as: UTF8.self).contains("\"counterparty\":\"self\""))
        let signature = try WalletJSON.decode(
            WalletCreateSignatureRequest.self,
            from: Array(("{" + prefix + ",\"data\":[]}").utf8)
        )
        XCTAssertEqual(signature.counterparty, .anyone)
        XCTAssertTrue(String(decoding: try WalletJSON.encode(signature), as: UTF8.self).contains("\"counterparty\":\"anyone\""))
        let hmac = try WalletJSON.decode(
            WalletCreateHMACRequest.self,
            from: Array(("{" + prefix + ",\"data\":[]}").utf8)
        )
        XCTAssertEqual(hmac.counterparty, .self)

        let identity = try WalletJSON.decode(
            WalletGetPublicKeyRequest.self,
            from: Array("{\"identityKey\":true,\"protocolID\":[0,\"\"]}".utf8)
        )
        if case .identity = identity.selection {} else { XCTFail() }
        XCTAssertEqual(String(decoding: try WalletJSON.encode(identity), as: UTF8.self), "{\"identityKey\":true}")
        for contradictory in [
            "{\"identityKey\":true,\"protocolID\":[1,\"\"]}",
            "{\"identityKey\":true,\"protocolID\":[0,\"nonempty\"]}",
            "{\"identityKey\":true,\"protocolID\":[0,\"\"],\"counterparty\":null}",
        ] {
            XCTAssertThrowsError(try WalletJSON.decode(WalletGetPublicKeyRequest.self, from: Array(contradictory.utf8)))
        }
        for nullKnownValue in [
            "{\"identityKey\":null}",
            "{" + prefix + ",\"plaintext\":[],\"privileged\":null}",
            "{" + prefix + ",\"plaintext\":[],\"seekPermission\":null}",
            "{" + prefix + ",\"plaintext\":[],\"privilegedReason\":null}",
        ] {
            XCTAssertThrowsError(try WalletJSON.decode(WalletGetPublicKeyRequest.self, from: Array(nullKnownValue.utf8)))
        }
    }

    func testSemanticAndOuterLimits() throws {
        let limits = try WalletCryptoLimits(maximumPayloadByteCount: 2, maximumJSONByteCount: 128)
        let request = WalletEncryptRequest(
            protocolID: try walletTestProtocol(),
            keyID: try walletTestKeyID("1"),
            plaintext: [1, 2, 3]
        )
        XCTAssertThrowsError(try WalletJSON.encode(request, limits: limits))
        XCTAssertThrowsError(try WalletJSON.decode(
            WalletEncryptRequest.self,
            from: Array("{\"protocolID\":[0,\"testprotocol\"],\"keyID\":\"1\",\"plaintext\":[1,2,3]}".utf8),
            limits: limits
        ))
        XCTAssertThrowsError(try WalletJSON.decode(Bool.self, from: [UInt8](repeating: 32, count: 129), limits: limits)) { error in
            XCTAssertEqual(error as? WalletCryptoError, .jsonTooLarge(actual: 129, maximum: 128))
        }
        let tiny = try WalletCryptoLimits(maximumPayloadByteCount: 2, maximumJSONByteCount: 1)
        XCTAssertThrowsError(try WalletJSON.encode(true, limits: tiny))
    }

    func testPublicKeyHMACSignatureAndByteShapes() throws {
        let key = try walletTestPrivateKey(42).publicKey
        let publicJSON = try WalletJSON.encode(WalletGetPublicKeyResult(publicKey: key))
        XCTAssertEqual(String(decoding: publicJSON, as: UTF8.self), "{\"publicKey\":\"\(Hex.encode(key.compressedBytes))\"}")
        let hmac = try WalletHMAC(bytes: Array(0..<32))
        let hmacJSON = try WalletJSON.encode(WalletCreateHMACResult(hmac: hmac))
        XCTAssertTrue(String(decoding: hmacJSON, as: UTF8.self).contains("[0,1,2"))

        let sig = try walletTestPrivateKey(42).sign(digest: BSVHashing.sha256([1]))
        let sigJSON = try WalletJSON.encode(WalletCreateSignatureResult(signature: sig))
        XCTAssertFalse(String(decoding: sigJSON, as: UTF8.self).contains("base64"))
        XCTAssertEqual(try WalletJSON.decode(WalletCreateSignatureResult.self, from: sigJSON).signature, sig)
    }
}
