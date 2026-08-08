import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
@testable import BSVWallet

final class WalletRedactionTests: XCTestCase {
    func testSensitiveDiagnosticsAndExplicitExports() throws {
        let sentinel = "wallet-secret-sentinel"
        let bytes = Array(sentinel.utf8)
        let protocolID = try walletTestProtocol()
        let keyID = try WalletKeyID(sentinel)
        let access = try WalletKeyAccess(privileged: true, privilegedReason: sentinel)
        let hmac = try WalletHMAC(bytes: Array((bytes + [UInt8](repeating: 1, count: 32)).prefix(32)))
        let signature = try walletTestPrivateKey(42).sign(digest: BSVHashing.sha256(bytes))
        let values: [Any] = [
            keyID, access, hmac, WalletSignaturePayload.data(bytes),
            WalletPublicKeySelection.derived(protocolID: protocolID, keyID: keyID, counterparty: .self, forSelf: false),
            WalletKeyDeriver(rootKey: try walletTestPrivateKey(42)),
            ProtoWallet(rootKey: try walletTestPrivateKey(42)),
            WalletEncryptRequest(protocolID: protocolID, keyID: keyID, plaintext: bytes, access: access),
            WalletEncryptResult(ciphertext: [UInt8](repeating: 1, count: 48)),
            WalletDecryptRequest(protocolID: protocolID, keyID: keyID, ciphertext: [UInt8](repeating: 1, count: 48), access: access),
            WalletDecryptResult(plaintext: bytes),
            WalletCreateHMACRequest(protocolID: protocolID, keyID: keyID, data: bytes, access: access),
            WalletVerifyHMACRequest(protocolID: protocolID, keyID: keyID, data: bytes, hmac: hmac, access: access),
            WalletCreateHMACResult(hmac: hmac),
            WalletCreateSignatureRequest(protocolID: protocolID, keyID: keyID, payload: .data(bytes), access: access),
            WalletVerifySignatureRequest(protocolID: protocolID, keyID: keyID, payload: .data(bytes), signature: signature, access: access),
            WalletCreateSignatureResult(signature: signature),
        ]
        for value in values {
            XCTAssertFalse(String(describing: value).contains(sentinel))
            XCTAssertFalse(String(reflecting: value).contains(sentinel))
            var dumped = ""
            dump(value, to: &dumped)
            XCTAssertFalse(dumped.contains(sentinel))
            XCTAssertEqual(Mirror(reflecting: value).children.count, 0)
        }
        XCTAssertEqual(keyID.value, sentinel)
        XCTAssertEqual(hmac.bytes.count, 32)
    }
}
