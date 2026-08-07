import BSVCore
import BSVCrypto
import Testing

@Suite("AESCBC")
struct AESCBCTests {
    @Test("AES-128/192/256 known answers cover empty, block, and multiblock plaintext")
    func knownAnswers() throws {
        let cases: [(key: String, iv: String, plaintext: String, ciphertext: String)] = [
            (
                "e34f15c7bd819930fe9d66e0c166e61c",
                "da9520f7d3520277035173299388bee2",
                "",
                "b10ab60153276941361000414aed0a9d"
            ),
            (
                "f4bfa5aa4f0f4d62cf736cd2969c43d580fdb92f2753bedb",
                "69a76dc4da64d89c580eb75ae975ec39",
                "0e239f239705b282ce2200fe20de1165",
                "7dbd573e4db58a318edfe29f199d8cda538a49f36486337c2711163e55fd5d0b"
            ),
            (
                "96e1e4896fb2cd05f133a6a100bc5609a7ac3ca6d81721e922dadd69ad07a892",
                "e70d83a77a2ce722ac214c00837acedf",
                "91a17e4dfcc3166a1add26ff0e7c12056e8a654f28a6de24f4ba739ceb5b5b18",
                "a615a39ff8f59f82cf72ed13e1b01e32459700561be112412961365c7a0b58aa"
                    + "7a16d68c065e77ebe504999051476bd7"
            ),
        ]

        for testCase in cases {
            let key = bytes(testCase.key)
            let iv = bytes(testCase.iv)
            let plaintext = bytes(testCase.plaintext)
            let expectedCiphertext = bytes(testCase.ciphertext)

            #expect(
                try AESCBC.encrypt(plaintext, key: key, initializationVector: iv)
                    == expectedCiphertext
            )
            #expect(
                try AESCBC.decrypt(expectedCiphertext, key: key, initializationVector: iv)
                    == plaintext
            )
        }
    }

    @Test("encryption optionally prepends exactly the supplied IV")
    func prependedInitializationVector() throws {
        let key = Array(0..<UInt8(16))
        let iv = Array(16..<UInt8(32))
        let plaintext = Array(32..<UInt8(81))
        let ciphertext = try AESCBC.encrypt(
            plaintext,
            key: key,
            initializationVector: iv
        )
        let prepended = try AESCBC.encrypt(
            plaintext,
            key: key,
            initializationVector: iv,
            prependInitializationVector: true
        )

        #expect(prepended == iv + ciphertext)
        #expect(try AESCBC.decrypt(ciphertext, key: key, initializationVector: iv) == plaintext)
    }

    @Test("all AES key sizes and PKCS#7 padding lengths round trip")
    func roundTrips() throws {
        let iv = Array(repeating: UInt8(0xa5), count: 16)
        for keyLength in [16, 24, 32] {
            let key = deterministicBytes(count: keyLength)
            for plaintextLength in 0...48 {
                let plaintext = deterministicBytes(count: plaintextLength)
                let ciphertext = try AESCBC.encrypt(
                    plaintext,
                    key: key,
                    initializationVector: iv
                )
                #expect(!ciphertext.isEmpty)
                #expect(ciphertext.count.isMultiple(of: 16))
                #expect(
                    try AESCBC.decrypt(
                        ciphertext,
                        key: key,
                        initializationVector: iv
                    ) == plaintext
                )
            }
        }
    }

    @Test("invalid keys and IVs have stable typed errors")
    func invalidKeyAndInitializationVectorLengths() {
        for keyLength in [0, 15, 17, 23, 25, 31, 33] {
            #expect(throws: AESPrimitiveError.invalidKeyByteCount(keyLength)) {
                try AESCBC.encrypt(
                    [],
                    key: Array(repeating: 0, count: keyLength),
                    initializationVector: Array(repeating: 0, count: 16)
                )
            }
            #expect(throws: AESPrimitiveError.invalidKeyByteCount(keyLength)) {
                try AESCBC.decrypt(
                    Array(repeating: 0, count: 16),
                    key: Array(repeating: 0, count: keyLength),
                    initializationVector: Array(repeating: 0, count: 16)
                )
            }
        }
        for ivLength in [0, 15, 17] {
            #expect(throws: AESPrimitiveError.invalidInitializationVectorByteCount(ivLength)) {
                try AESCBC.encrypt(
                    [],
                    key: Array(repeating: 0, count: 16),
                    initializationVector: Array(repeating: 0, count: ivLength)
                )
            }
            #expect(throws: AESPrimitiveError.invalidInitializationVectorByteCount(ivLength)) {
                try AESCBC.decrypt(
                    Array(repeating: 0, count: 16),
                    key: Array(repeating: 0, count: 16),
                    initializationVector: Array(repeating: 0, count: ivLength)
                )
            }
        }
    }

    @Test("empty and non-block ciphertext are rejected before decryption")
    func invalidCiphertextLengths() {
        let key = Array(repeating: UInt8(0), count: 16)
        let iv = Array(repeating: UInt8(0), count: 16)
        for ciphertextLength in [0, 1, 15, 17, 31, 33] {
            #expect(
                throws: AESPrimitiveError.invalidCiphertextByteCount(ciphertextLength)
            ) {
                try AESCBC.decrypt(
                    Array(repeating: 0, count: ciphertextLength),
                    key: key,
                    initializationVector: iv
                )
            }
        }
    }

    @Test("zero and corrupted PKCS#7 padding map to invalidPadding")
    func invalidPadding() throws {
        let zeroPaddingKey = bytes("db4f3e5e3795cc09a073fa6a81e5a6bc")
        let zeroPaddingIV = bytes("23468aa734f5f0f19827316ff168e94f")
        let zeroPaddingCiphertext = bytes("aa62606a287476777b92d8e4c4e53028")

        #expect(throws: AESPrimitiveError.invalidPadding) {
            try AESCBC.decrypt(
                zeroPaddingCiphertext,
                key: zeroPaddingKey,
                initializationVector: zeroPaddingIV
            )
        }

        let key = Array(repeating: UInt8(0x11), count: 16)
        let iv = Array(repeating: UInt8(0x22), count: 16)
        var ciphertext = try AESCBC.encrypt(
            Array(repeating: 0x33, count: 16),
            key: key,
            initializationVector: iv
        )
        ciphertext[15] ^= 1
        #expect(throws: AESPrimitiveError.invalidPadding) {
            try AESCBC.decrypt(ciphertext, key: key, initializationVector: iv)
        }
    }
}

private func deterministicBytes(count: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ 7) }
}

private func bytes(_ hexadecimal: String) -> [UInt8] {
    (try? Hex.decode(hexadecimal, maximumDecodedByteCount: hexadecimal.utf8.count / 2)) ?? []
}
