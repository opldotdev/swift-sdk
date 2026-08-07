import BSVCore
import BSVCrypto
import Testing

@Suite("AESGCM")
struct AESGCMTests {
    @Test("AES-128/192/256 detached known answers cover plaintext, AAD, and empty input")
    func knownAnswers() throws {
        let cases: [GCMCase] = [
            GCMCase(
                key: "5b9604fe14eadba931b0ccf34843dab9",
                nonce: "921d2507fa8007b7bd067d34",
                aad: "00112233445566778899aabbccddeeff",
                plaintext: "001d0c231287c1182784554ca3a21908",
                ciphertext: "49d8b9783e911913d87094d1f63cc765",
                tag: "1e348ba07cca2cf04c618cb4d43a5b92"
            ),
            GCMCase(
                key: "5019eb9fef82e5750b631758f0213e3e5fcca12748b40eb4",
                nonce: "ff0ddb0a0d7b36d219da12b5",
                aad: "",
                plaintext: "",
                ciphertext: "",
                tag: "7971284e6c9e6aac346fe2b7a0a064c2"
            ),
            GCMCase(
                key: "59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a",
                nonce: "2fcb1b38a99e71b84740ad9b",
                aad: "",
                plaintext: "549b365af913f3b081131ccb6b825588",
                ciphertext: "f58c16690122d75356907fd96b570fca",
                tag: "28752c20153092818faba2a334640d6e"
            ),
        ]

        for testCase in cases {
            let sealedBox = try AESGCM.seal(
                bytes(testCase.plaintext),
                key: bytes(testCase.key),
                nonce: bytes(testCase.nonce),
                authenticating: bytes(testCase.aad)
            )
            #expect(sealedBox.ciphertext == bytes(testCase.ciphertext))
            #expect(sealedBox.authenticationTag == bytes(testCase.tag))
            #expect(
                try AESGCM.open(
                    sealedBox,
                    key: bytes(testCase.key),
                    nonce: bytes(testCase.nonce),
                    authenticating: bytes(testCase.aad)
                ) == bytes(testCase.plaintext)
            )
        }
    }

    @Test("12-byte and 32-byte nonces produce deterministic detached output")
    func nonceLengths() throws {
        let twelveByteNonce = bytes("438a547a94ea88dce46c6c85")
        let emptyBox = try AESGCM.seal(
            [],
            key: bytes("bedcfb5a011ebc84600fcb296c15af0d"),
            nonce: twelveByteNonce
        )
        #expect(emptyBox.ciphertext == [])
        #expect(emptyBox.authenticationTag == bytes("960247ba5cde02e41a313c4c0136edc3"))

        let longBox = try AESGCM.seal(
            bytes("316bf99bfafc76f1bfc0b03c"),
            key: bytes("5927bae748bb69d81b5a724e0a165652"),
            nonce: bytes(
                "365e0b96932b13306f92e9bb23847165bcbf5d35e45a83d75c86ecca70131f4c"
            )
        )
        #expect(longBox.ciphertext == bytes("5348af57fafe2485b43f2bc4"))
        #expect(longBox.authenticationTag == bytes("019a96c5373c031626b6c0300d4cf78b"))
    }

    @Test("keys, short nonces, and detached tag lengths are prevalidated")
    func validation() throws {
        for keyLength in [0, 15, 17, 23, 25, 31, 33] {
            #expect(throws: AESPrimitiveError.invalidKeyByteCount(keyLength)) {
                try AESGCM.seal(
                    [],
                    key: Array(repeating: 0, count: keyLength),
                    nonce: Array(repeating: 0, count: 12)
                )
            }
            #expect(throws: AESPrimitiveError.invalidKeyByteCount(keyLength)) {
                try AESGCM.open(
                    AESGCMSealedBox(
                        ciphertext: [],
                        authenticationTag: Array(repeating: 0, count: 16)
                    ),
                    key: Array(repeating: 0, count: keyLength),
                    nonce: Array(repeating: 0, count: 12)
                )
            }
        }

        for nonceLength in [8, 11] {
            #expect(
                throws: AESPrimitiveError.invalidNonceByteCount(
                    minimum: 12,
                    actual: nonceLength
                )
            ) {
                try AESGCM.seal(
                    [],
                    key: Array(repeating: 0, count: 16),
                    nonce: Array(repeating: 0, count: nonceLength)
                )
            }
            #expect(
                throws: AESPrimitiveError.invalidNonceByteCount(
                    minimum: 12,
                    actual: nonceLength
                )
            ) {
                try AESGCM.open(
                    AESGCMSealedBox(
                        ciphertext: [],
                        authenticationTag: Array(repeating: 0, count: 16)
                    ),
                    key: Array(repeating: 0, count: 16),
                    nonce: Array(repeating: 0, count: nonceLength)
                )
            }
        }
        _ = try AESGCM.seal(
            [],
            key: Array(repeating: 0, count: 16),
            nonce: Array(repeating: 0, count: 12)
        )

        for tagLength in [15, 17] {
            #expect(
                throws: AESPrimitiveError.invalidAuthenticationTagByteCount(tagLength)
            ) {
                try AESGCM.open(
                    AESGCMSealedBox(
                        ciphertext: [],
                        authenticationTag: Array(repeating: 0, count: tagLength)
                    ),
                    key: Array(repeating: 0, count: 16),
                    nonce: Array(repeating: 0, count: 12)
                )
            }
        }
    }

    @Test("tampering each authenticated input maps uniformly to authenticationFailed")
    func authenticationFailures() throws {
        let plaintext = deterministicBytes(count: 37)
        let key = deterministicBytes(count: 32)
        let nonce = deterministicBytes(count: 12)
        let aad = deterministicBytes(count: 19)
        let sealedBox = try AESGCM.seal(
            plaintext,
            key: key,
            nonce: nonce,
            authenticating: aad
        )

        var wrongKey = key
        wrongKey[0] ^= 1
        expectAuthenticationFailure(sealedBox, key: wrongKey, nonce: nonce, aad: aad)

        var wrongNonce = nonce
        wrongNonce[0] ^= 1
        expectAuthenticationFailure(sealedBox, key: key, nonce: wrongNonce, aad: aad)

        var wrongAAD = aad
        wrongAAD[0] ^= 1
        expectAuthenticationFailure(sealedBox, key: key, nonce: nonce, aad: wrongAAD)

        var wrongCiphertext = sealedBox.ciphertext
        wrongCiphertext[0] ^= 1
        expectAuthenticationFailure(
            AESGCMSealedBox(
                ciphertext: wrongCiphertext,
                authenticationTag: sealedBox.authenticationTag
            ),
            key: key,
            nonce: nonce,
            aad: aad
        )

        var wrongTag = sealedBox.authenticationTag
        wrongTag[0] ^= 1
        expectAuthenticationFailure(
            AESGCMSealedBox(ciphertext: sealedBox.ciphertext, authenticationTag: wrongTag),
            key: key,
            nonce: nonce,
            aad: aad
        )
    }

    @Test("public values satisfy Sendable")
    func sendability() {
        requireSendable(AESPrimitiveError.authenticationFailed)
        requireSendable(AESGCMSealedBox(ciphertext: [], authenticationTag: []))
    }
}

private struct GCMCase {
    let key: String
    let nonce: String
    let aad: String
    let plaintext: String
    let ciphertext: String
    let tag: String
}

private func expectAuthenticationFailure(
    _ sealedBox: AESGCMSealedBox,
    key: [UInt8],
    nonce: [UInt8],
    aad: [UInt8]
) {
    #expect(throws: AESPrimitiveError.authenticationFailed) {
        try AESGCM.open(
            sealedBox,
            key: key,
            nonce: nonce,
            authenticating: aad
        )
    }
}

private func requireSendable<T: Sendable>(_ value: T) {}

private func deterministicBytes(count: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ 7) }
}

private func bytes(_ hexadecimal: String) -> [UInt8] {
    (try? Hex.decode(hexadecimal, maximumDecodedByteCount: hexadecimal.utf8.count / 2)) ?? []
}
