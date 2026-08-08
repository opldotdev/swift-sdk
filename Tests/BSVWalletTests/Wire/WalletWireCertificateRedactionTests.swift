@testable import BSVWallet
import Testing

@Suite("Wallet-wire certificate redaction")
struct WalletWireCertificateRedactionTests {
    @Test func requestAndDecodedRequestHideCertificateFieldsAndOriginator() throws {
        let fixture = try WalletWireCertificateFixture()
        let request = WalletWireCertificateRequest.discoverByAttributes(try .init(
            attributes: [fixture.alpha: "secret-value"]
        ))
        let decoded = WalletWireDecodedCertificateRequest(
            originator: "secret-originator",
            request: request
        )
        #expect(!request.description.contains("secret"))
        #expect(!String(reflecting: request).contains("secret"))
        #expect(!decoded.description.contains("secret"))
        #expect(!String(reflecting: decoded).contains("secret"))
        #expect(Array(request.customMirror.children).count == 1)
        #expect(Array(decoded.customMirror.children).count == 1)
    }

    @Test func directABIAndResultContainersHideSecretValues() throws {
        let fixture = try WalletWireCertificateFixture()
        let item = try WalletCertificateResult(
            certificate: fixture.certificate,
            keyring: fixture.keyring,
            verifier: Array("secret-verifier".utf8)
        )
        let list = try WalletListCertificatesResult(
            totalCertificates: 1,
            certificates: [item]
        )
        let result = WalletWireCertificateResult.listCertificates(list)
        #expect(String(reflecting: item) == item.description)
        #expect(String(reflecting: list) == list.description)
        #expect(String(reflecting: result) == result.description)
        #expect(!String(reflecting: result).contains("secret"))
        #expect(Array(item.customMirror.children).isEmpty)
        #expect(Array(list.customMirror.children).isEmpty)
        #expect(Array(result.customMirror.children).count == 1)
    }
}
