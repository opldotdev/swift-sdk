import BSVWallet
import Testing

@Suite("Wallet-wire action redaction")
struct WalletWireActionRedactionTests {
    @Test func requestDiagnosticsDoNotExposeReferenceOrOriginator() throws {
        let request = WalletWireActionRequest.abortAction(WalletAbortActionRequest(
            reference: try WalletBase64Data(Array("secret-reference".utf8))
        ))
        let decoded = WalletWireDecodedActionRequest(
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

    @Test func resultDiagnosticsDoNotExposeActionText() throws {
        let result = WalletWireActionResult.abortAction(
            WalletAbortActionResult(aborted: true)
        )
        #expect(result.description == "<redacted wallet-wire action result call 3>")
        #expect(String(reflecting: result) == result.description)
        #expect(Array(result.customMirror.children).count == 1)
    }
}
