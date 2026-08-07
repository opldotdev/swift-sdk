import BSVCore
import BSVCrypto
import Testing

@Suite("BIP-39 PBKDF2 compatibility wrapper")
struct PBKDF2Tests {
    @Test("official PBKDF2-HMAC-SHA512 known answers")
    func officialKnownAnswers() throws {
        // Trezor python-mnemonic v0.21 vectors.json, English cases 0 and 4.
        let cases = [
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            ),
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa"
            ),
        ]

        for (mnemonic, expectedHex) in cases {
            let derived = try BIP39PBKDF2.deriveSeed(
                mnemonicUTF8: Array(mnemonic.utf8),
                saltUTF8: Array("mnemonicTREZOR".utf8)
            )
            #expect(derived.count == 64)
            #expect(derived == (try Hex.decode(expectedHex, maximumDecodedByteCount: 64)))
        }
    }

    @Test("fixed compatibility profile is deterministic")
    func deterministic() throws {
        let password = Array("legal winner thank year wave sausage worth useful legal winner thank yellow".utf8)
        let salt = Array("mnemonicTREZOR".utf8)
        let first = try BIP39PBKDF2.deriveSeed(mnemonicUTF8: password, saltUTF8: salt)
        let second = try BIP39PBKDF2.deriveSeed(mnemonicUTF8: password, saltUTF8: salt)
        #expect(first == second)
    }
}
