import BSVCore
import BSVCrypto
@testable import BSVKeys
import Testing

@Suite("English BIP-39 mnemonic")
struct MnemonicTests {
    @Test("all supported entropy and word sizes have exact encodings")
    func allSupportedSizes() throws {
        let cases: [(Int, String)] = [
            (16, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            (20, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address"),
            (24, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"),
            (28, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit"),
            (32, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
        ]

        for (byteCount, expectedPhrase) in cases {
            let entropy = [UInt8](repeating: 0, count: byteCount)
            let mnemonic = try Mnemonic(entropy: entropy)
            #expect(mnemonic.phrase == expectedPhrase)
            #expect(mnemonic.description == "<redacted mnemonic>")
            #expect(String(reflecting: mnemonic) == "<redacted mnemonic>")
            #expect(mnemonic.words.count == (byteCount * 8 + byteCount / 4) / 11)
            #expect(mnemonic.entropy == entropy)
            #expect(try Mnemonic(expectedPhrase) == mnemonic)
        }
    }

    @Test("entropy length validation is exact")
    func invalidEntropyLengths() {
        for count in [0, 1, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 64] {
            #expect(throws: MnemonicError.invalidEntropyByteCount(count)) {
                try Mnemonic(entropy: [UInt8](repeating: 0, count: count))
            }
        }
    }

    @Test("word count validation is exact")
    func invalidWordCounts() {
        for count in [1, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25] {
            let phrase = [String](repeating: "abandon", count: count).joined(separator: " ")
            #expect(throws: MnemonicError.invalidWordCount(count)) {
                try Mnemonic(phrase)
            }
        }
        #expect(throws: MnemonicError.invalidWordCount(0)) {
            try Mnemonic("")
        }
    }

    @Test("unknown English words and checksum changes are typed")
    func invalidWordsAndChecksum() throws {
        #expect(throws: MnemonicError.unknownWord("notaword")) {
            try Mnemonic(
                "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            )
        }

        for byteCount in [16, 20, 24, 28, 32] {
            let valid = try Mnemonic(entropy: [UInt8](repeating: 0, count: byteCount))
            var words = valid.words
            let lastIndex = try #require(BIP39EnglishWordList.indices[words[words.count - 1]])
            words[words.count - 1] = BIP39EnglishWordList.words[lastIndex ^ 1]
            #expect(throws: MnemonicError.checksumMismatch) {
                try Mnemonic(words.joined(separator: " "))
            }
        }
    }

    @Test("one Unicode whitespace character is accepted and output is canonical")
    func unicodeWhitespace() throws {
        let phrase = "abandon\tabandon\nabandon\u{2003}abandon\u{00a0}abandon abandon abandon abandon abandon abandon abandon about"
        let mnemonic = try Mnemonic(phrase)
        #expect(
            mnemonic.phrase
                == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
    }

    @Test("empty whitespace tokens are rejected")
    func malformedWhitespace() {
        let canonical = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        for phrase in [" " + canonical, canonical + " ", canonical.replacingOccurrences(of: " ", with: "  ")] {
            #expect(throws: MnemonicError.malformedPhrase) {
                try Mnemonic(phrase)
            }
        }
    }

    @Test("NFKD normalizes the phrase and passphrase before exact seed derivation")
    func unicodeNFKD() throws {
        let canonical = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let fullwidthPhrase = fullwidth(canonical)
        let mnemonic = try Mnemonic(fullwidthPhrase)
        #expect(mnemonic.phrase == canonical)

        let seed = try mnemonic.seed(passphrase: fullwidth("TREZOR"))
        #expect(
            Hex.encode(seed.bytes)
                == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        )
    }

    @Test("word list has exact count, uniqueness, order endpoints, and digest")
    func exactEnglishWordList() {
        let words = BIP39EnglishWordList.words
        #expect(words.count == 2_048)
        #expect(Set(words).count == 2_048)
        #expect(words.first == "abandon")
        #expect(words.last == "zoo")
        let upstreamBytes = Array((words.joined(separator: "\n") + "\n").utf8)
        #expect(
            Hex.encode(BSVHashing.sha256(upstreamBytes).bytes)
                == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        )
    }

    @Test("repeated parsing and seed calls are deterministic")
    func deterministic() throws {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        let first = try Mnemonic(phrase)
        let second = try Mnemonic(phrase)
        #expect(first == second)
        #expect(try first.seed(passphrase: "TREZOR") == second.seed(passphrase: "TREZOR"))
    }

    @Test("phrase parsing is scalar-exact and work-bounded")
    func scalarWhitespaceAndBounds() {
        let canonical = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        #expect(throws: MnemonicError.malformedPhrase) {
            try Mnemonic(canonical.replacingOccurrences(of: " ", with: "\r\n"))
        }
        #expect(throws: MnemonicError.malformedPhrase) {
            try Mnemonic(canonical.replacingOccurrences(of: " ", with: " \u{fe0f}"))
        }
        #expect(throws: MnemonicError.malformedPhrase) {
            try Mnemonic(String(repeating: "a", count: 4_097))
        }
        #expect(throws: MnemonicError.malformedPhrase) {
            try Mnemonic(String(repeating: "a", count: 1_000_000))
        }

        // U+FDFA expands from 3 UTF-8 bytes to 33 under NFKD. The raw input is
        // below the cap, while its normalized form exceeds it.
        #expect(throws: MnemonicError.malformedPhrase) {
            try Mnemonic(String(repeating: "\u{fdfa}", count: 128))
        }
    }

    private func fullwidth(_ value: String) -> String {
        var result = ""
        for scalar in value.unicodeScalars {
            if scalar.value == 0x20 {
                result.unicodeScalars.append(Unicode.Scalar(0x3000)!)
            } else if (0x21...0x7e).contains(scalar.value) {
                result.unicodeScalars.append(Unicode.Scalar(scalar.value + 0xfee0)!)
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
}
