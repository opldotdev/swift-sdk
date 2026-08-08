import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
@testable import BSVWallet

final class WalletWireRedactionTests: XCTestCase {
    func testFramesTypedEnumsAndRemoteErrorsRedactImplicitDiagnostics() throws {
        let secrets = [
            "origin-secret", "plaintext-secret", "ciphertext-secret", "key-id-secret",
            "reason-secret", "message-secret", "stack-secret", "hmac-secret",
            "signature-secret",
        ]
        let remote = try WalletWireRemoteError(
            code: 17,
            message: "message-secret",
            stack: "stack-secret"
        )
        let protocolID = try walletTestProtocol("wire test")
        let keyID = try walletTestKeyID("key-id-secret")
        let access = try WalletKeyAccess(
            privileged: true,
            privilegedReason: "reason-secret",
            seekPermission: true
        )
        let request = WalletWireKeyQueryRequest.encrypt(WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            plaintext: Array("plaintext-secret".utf8),
            access: access
        ))
        let decoded = WalletWireDecodedKeyQueryRequest(
            originator: "origin-secret",
            request: request
        )
        let signature = try walletTestPrivateKey(9).sign(digest: BSVHashing.sha256([3]))
        let values: [Any] = [
            remote,
            WalletWireRequestFrame(
                call: .encrypt,
                originator: "origin-secret",
                parameters: Array("ciphertext-secret".utf8)
            ),
            WalletWireResultFrame.success(Array("ciphertext-secret".utf8)),
            WalletWireResultFrame.failure(remote),
            request,
            decoded,
            WalletWireKeyQueryResult.encrypt(WalletEncryptResult(
                ciphertext: Array("ciphertext-secret".utf8)
            )),
            WalletWireKeyQueryResult.createHMAC(WalletCreateHMACResult(
                hmac: try WalletHMAC(bytes: [UInt8](repeating: 0xAB, count: 32))
            )),
            WalletWireKeyQueryResult.createSignature(WalletCreateSignatureResult(
                signature: signature
            )),
        ]

        for value in values {
            let diagnostics = diagnosticText(value)
            for secret in secrets {
                XCTAssertFalse(diagnostics.contains(secret), "leaked \(secret): \(diagnostics)")
            }
            XCTAssertFalse(diagnostics.contains("171, 171"), "leaked HMAC bytes: \(diagnostics)")
            XCTAssertFalse(diagnostics.contains(signature.derBytes.description), "leaked signature: \(diagnostics)")
        }
        XCTAssertEqual(String(describing: remote), "WalletWireRemoteError(code: 17)")
        XCTAssertTrue(diagnosticText(remote).contains("17"))
    }

    func testWireErrorsNeverCarryPayloadOrSecretText() {
        let error = WalletWireError.invalidUTF8(kind: "wallet version")
        let text = diagnosticText(error)
        XCTAssertFalse(text.contains("secret"))
        XCTAssertFalse(text.contains("payload bytes"))
    }

    private func diagnosticText(_ value: Any) -> String {
        var dumped = ""
        dump(value, to: &dumped)
        return [String(describing: value), String(reflecting: value), dumped].joined(separator: "\n")
    }
}
