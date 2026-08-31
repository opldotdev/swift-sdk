import BSVCompat
import BSVKeys
import Foundation
import Testing

@Suite("BRC-157 entropy backup")
struct BRC157EntropyTests {
    private let workedPhrase =
        "legal winner thank year wave sausage worth useful legal winner thank yellow"

    @Test("worked BRC-157 vector matches exactly")
    func workedVector() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)

        #expect(hex(subject.entropy) == "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        #expect(
            hex(subject.paddedEntropy)
                == "000000000000000000000000000000007f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
        )
        #expect(subject.mnemonic.phrase == workedPhrase)
        #expect(
            hex(try subject.rootKey().bytes)
                == "27e442c8015fc055789d6628f3b30461e8b2598aff74dc87ceef00dd8e670e55"
        )
    }

    @Test("profiles match independently derived BIP-39 and BIP-32 vectors")
    func profileVectors() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)
        let cases: [(UInt32, String)] = [
            (0, "27e442c8015fc055789d6628f3b30461e8b2598aff74dc87ceef00dd8e670e55"),
            (1, "8d5bd9de4d42da1ee10fa7d09f14ba13512b4725844e9f936bdc35b9cb9e17dc"),
            (2, "5874796bb9d0fc8fc4dfa18452d4eb5f2547970b6a31e9cd655b5b636cbb5d37"),
            (
                2_147_483_647,
                "9ece45ac5d727eeb582b9fb52045034c4f6c6b97cddb11d79f94758172af45fe"
            ),
        ]

        for (index, expected) in cases {
            #expect(hex(try subject.profileKey(index: index).bytes) == expected)
        }
        #expect(throws: BRC157Error.invalidProfileIndex(2_147_483_648)) {
            try subject.profileKey(index: 2_147_483_648)
        }
    }

    @Test("every BIP-39 word count preserves entropy and its reference root")
    func allBIP39WordCounts() throws {
        let cases: [(bytes: Int, words: Int, phrase: String, root: String)] = [
            (
                16,
                12,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon actual",
                "da1dbaa371674aad9b55a22a89f60b04c182db6ff44df2cb25f7a4547e98b667"
            ),
            (
                20,
                15,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon amateur",
                "77d42e1062e7a5944c31da26a907a0da1cacdd4942a721c1dff70080a326368d"
            ),
            (
                24,
                18,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon author",
                "0f3415c8818ddaa27dc6c90f30befa06322205b3fc799c70f6ceabdeb874f012"
            ),
            (
                28,
                21,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon breeze",
                "0b593dc1498156ecf001b1c9c86bdd1aac86f5b6047131d4a6902737576391f9"
            ),
            (
                32,
                24,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel",
                "8049e464f17f071c20cbc3eb61d0aae4b3239b69df8d59524569b24e45b97229"
            ),
        ]

        for value in cases {
            var entropy = [UInt8](repeating: 0, count: value.bytes)
            entropy[value.bytes - 1] = 1
            let fromEntropy = try BRC157Entropy(entropy: entropy)
            let fromWords = try BRC157Entropy(mnemonicPhrase: value.phrase)

            #expect(fromEntropy.mnemonic.phrase == value.phrase)
            #expect(fromWords.entropy == entropy)
            #expect(fromWords.mnemonic.words.count == value.words)
            #expect(fromWords.entropyByteCount == value.bytes)
            #expect(fromWords.paddedEntropy.count == 32)
            #expect(hex(try fromWords.rootKey().bytes) == value.root)
        }
    }

    @Test("mnemonic validation errors remain typed")
    func mnemonicValidationErrors() {
        #expect(throws: MnemonicError.unknownWord("notaword")) {
            try BRC157Entropy(
                mnemonicPhrase:
                    "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            )
        }
        #expect(throws: MnemonicError.checksumMismatch) {
            try BRC157Entropy(
                mnemonicPhrase:
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            )
        }
        #expect(throws: MnemonicError.invalidWordCount(3)) {
            try BRC157Entropy(mnemonicPhrase: "abandon abandon abandon")
        }
    }

    @Test("zero is rejected at every supported mnemonic length")
    func zeroScalar() throws {
        for byteCount in [16, 20, 24, 28, 32] {
            let zero = [UInt8](repeating: 0, count: byteCount)
            let validZeroMnemonic = try Mnemonic(entropy: zero)

            #expect(throws: BRC157Error.invalidEntropyScalar) {
                try BRC157Entropy(entropy: zero)
            }
            #expect(throws: BRC157Error.invalidEntropyScalar) {
                try BRC157Entropy(mnemonic: validZeroMnemonic)
            }
        }
    }

    @Test("scalar group-order boundary is exact")
    func scalarOrderBoundary() throws {
        let order = bytes(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        var orderMinusOne = order
        orderMinusOne[31] -= 1
        let orderMnemonic = try Mnemonic(entropy: order)

        _ = try BRC157Entropy(entropy: orderMinusOne)
        #expect(throws: BRC157Error.invalidEntropyScalar) {
            try BRC157Entropy(entropy: order)
        }
        #expect(throws: BRC157Error.invalidEntropyScalar) {
            try BRC157Entropy(mnemonic: orderMnemonic)
        }
    }

    @Test("entropy length validation is exact")
    func entropyLengthValidation() {
        for byteCount in [0, 1, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33] {
            #expect(throws: BRC157Error.invalidEntropyByteCount(byteCount)) {
                try BRC157Entropy(entropy: [UInt8](repeating: 1, count: byteCount))
            }
        }
    }

    @Test("share recovery restores the recorded original words")
    func shareRecovery() throws {
        let original = try BRC157Entropy(mnemonicPhrase: workedPhrase)
        let shares = try original.backupShares(threshold: 2, shareCount: 3)
        let recovered = try BRC157Entropy.recover(
            from: [shares[0], shares[2]],
            entropyByteCount: 16
        )
        let inferred = try BRC157Entropy.recoverUsingInferredByteCount(
            from: [shares[1], shares[2]]
        )

        #expect(recovered.entropy == original.entropy)
        #expect(recovered.mnemonic.phrase == workedPhrase)
        #expect(try recovered.rootKey() == original.rootKey())
        #expect(inferred.entropy == original.entropy)
        #expect(inferred.mnemonic.phrase == workedPhrase)

        let wrongTwentyFourWords = try Mnemonic(entropy: original.paddedEntropy)
        #expect(
            wrongTwentyFourWords.phrase
                == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                    + "abandon abstract wave sausage worth useful legal winner thank year wave sausage "
                    + "worth upgrade"
        )
        #expect(wrongTwentyFourWords.phrase != recovered.mnemonic.phrase)
    }

    @Test("recovery refuses to discard nonzero bytes for a wrong length")
    func wrongRecoveryLength() throws {
        let entropyKey = try PrivateKey([UInt8](repeating: 1, count: 32))

        #expect(throws: BRC157Error.recoveredEntropyDoesNotFitByteCount(16)) {
            try BRC157Entropy(recoveredEntropyKey: entropyKey, entropyByteCount: 16)
        }
        #expect(throws: BRC157Error.invalidEntropyByteCount(18)) {
            try BRC157Entropy(recoveredEntropyKey: entropyKey, entropyByteCount: 18)
        }
    }

    @Test("new wallet generation is always a valid 24-word scalar")
    func generation() throws {
        for _ in 0..<8 {
            let generated = try BRC157Entropy.generate()

            #expect(generated.entropyByteCount == 32)
            #expect(generated.mnemonic.words.count == 24)
            #expect(generated.paddedEntropy == generated.entropy)
            _ = try PrivateKey(generated.entropy)
        }
    }

    @Test("empty passphrase is the default and nonempty passphrases remain distinct")
    func passphraseSemantics() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)

        #expect(try subject.rootKey() == subject.rootKey(passphrase: ""))
        #expect(
            hex(try subject.rootKey(passphrase: "TREZOR").bytes)
                == "4f318fbec35366ae7fdcb82a24a37d6b9bfc8df024abb390ff58f48ddcac9f15"
        )
        #expect(try subject.rootKey() != subject.rootKey(passphrase: "TREZOR"))
    }

    @Test("diagnostics never reveal entropy or words")
    func diagnosticRedaction() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)
        var dumped = ""
        dump(subject, to: &dumped)

        for diagnostic in [String(describing: subject), String(reflecting: subject), dumped] {
            #expect(!diagnostic.contains("legal"))
            #expect(!diagnostic.contains("7f7f"))
        }
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func bytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        }
    }
}
