import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
@testable import BSVWallet

private enum TestRandomError: Error { case failed }
private struct FixedRandomSource: SecureRandomSource, Sendable {
    let bytes: [UInt8]
    let throwsError: Bool
    func randomBytes(count: Int) throws -> [UInt8] {
        if throwsError { throw TestRandomError.failed }
        return bytes
    }
}

final class ProtoWalletTests: XCTestCase {
    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }

    private func brcValues() throws -> (PrivateKey, PublicKey, WalletProtocolID, WalletKeyID) {
        (
            try PrivateKey(walletTestHex("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")),
            try PublicKey(walletTestHex("0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")),
            try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "BRC2 Test"),
            try WalletKeyID("42")
        )
    }

    func testPublishedBRC2EncryptionAndHMACVectors() async throws {
        let (root, counterparty, protocolID, keyID) = try brcValues()
        // Published BRC-2 compliance vector.
        let ciphertext: [UInt8] = [252,203,216,184,29,161,223,212,16,193,94,99,31,140,99,43,61,236,184,67,54,105,199,47,11,19,184,127,2,165,125,9,188,195,196,39,120,130,213,95,186,89,64,28,1,80,20,213,159,133,98,253,128,105,113,247,197,152,236,64,166,207,113,134,65,38,58,24,127,145,140,206,47,70,146,84,186,72,95,35,154,112,178,55,72,124]
        let wallet = ProtoWallet(rootKey: root)
        let plaintext = try await wallet.decrypt(WalletDecryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(counterparty),
            ciphertext: ciphertext
        )).plaintext
        XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), "BRC-2 Encryption Compliance Validated!")

        let deterministic = ProtoWallet(
            rootKey: root,
            randomSource: FixedRandomSource(bytes: Array(ciphertext.prefix(32)), throwsError: false)
        )
        let reproduced = try await deterministic.encrypt(WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(counterparty),
            plaintext: plaintext
        )).ciphertext
        XCTAssertEqual(reproduced, ciphertext)

        let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(counterparty),
            data: Array("BRC-2 HMAC Compliance Validated!".utf8)
        )).hmac.bytes
        XCTAssertEqual(hmac, [81,240,18,153,163,45,174,85,9,246,142,125,209,133,82,76,254,103,46,182,86,59,219,61,126,30,176,232,233,100,234,14])
    }

    func testWalletInternalAdminMetadataEncryptionVector() async throws {
        let root = try walletTestPrivateKey(42)
        let protocolID = WalletProtocolID.walletMetadataEncryption
        let keyID = try WalletKeyID("1")
        let nonce = (0..<32).map { UInt8($0) }
        let plaintext = Array("Yours Wallet metadata".utf8)
        // Pinned against live @bsv/sdk 2.1.6 KeyDeriver/ProtoWallet using
        // invoice `2-admin metadata encryption-1` and counterparty `self`.
        XCTAssertEqual(
            Hex.encode(try WalletKeyDeriver(rootKey: root).deriveSymmetricKey(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self
            ).bytes),
            "0070b653097c3ff272c94e9e9aa6ccdbd2bd93ead043b7f2c8e79025f2649480"
        )
        let wallet = ProtoWallet(
            rootKey: root,
            randomSource: FixedRandomSource(bytes: nonce, throwsError: false)
        )

        let ciphertext = try await wallet.encrypt(WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .self,
            plaintext: plaintext
        )).ciphertext
        XCTAssertEqual(
            Hex.encode(ciphertext),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "807fec26e74ee6626d38e9fd233e99da007e19d43997557b81ce0d4165636f0f"
                + "20fb1ca5be"
        )

        let decrypted = try await ProtoWallet(rootKey: root).decrypt(WalletDecryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .self,
            ciphertext: ciphertext
        )).plaintext
        XCTAssertEqual(decrypted, plaintext)
    }

    func testPublishedBRC3SignatureAndRoundTrips() async throws {
        let (_, counterparty, _, keyID) = try brcValues()
        let protocolID = try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "BRC3 Test")
        // Published BRC-3 compliance signature.
        let signature = try ECDSASignature(derBytes: [48,68,2,32,43,34,58,156,219,32,50,70,29,240,155,137,88,60,200,95,243,198,201,21,56,82,141,112,69,196,170,73,156,6,44,48,2,32,118,125,254,201,44,87,177,170,93,11,193,134,18,70,9,31,234,27,170,177,54,96,181,140,166,196,144,14,230,118,106,105])
        let anyone = try ProtoWallet.anyone()
        let publishedValid = try await anyone.verifySignature(WalletVerifySignatureRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(counterparty),
            payload: .data(Array("BRC-3 Compliance Validated!".utf8)),
            signature: signature
        )).valid
        XCTAssertTrue(publishedValid)

        let wallet = ProtoWallet(rootKey: try walletTestPrivateKey(42))
        for data in [[], [1], Array("ordinary".utf8)] {
            let created = try await wallet.createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                payload: .data(data)
            ))
            let dataValid = try await wallet.verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .anyone,
                payload: .data(data),
                signature: created.signature,
                forSelf: true
            )).valid
            XCTAssertTrue(dataValid)
            let digestValid = try await wallet.verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .anyone,
                payload: .digest(BSVHashing.sha256(data)),
                signature: created.signature,
                forSelf: true
            )).valid
            XCTAssertTrue(digestValid)
        }
    }

    func testCounterpartyKeyLinkageMatchesBRC69BRC72AndBRC94() async throws {
        let proverKey = try PrivateKey(scalar(7))
        let counterpartyKey = try PrivateKey(scalar(13))
        let verifierKey = try PrivateKey(scalar(17))
        let revelationTime = "2026-08-30T23:45:12.345Z"
        let prover = ProtoWallet(
            rootKey: proverKey,
            randomSource: FixedRandomSource(
                bytes: [UInt8](repeating: 0x2a, count: 32),
                throwsError: false
            )
        )
        let verifier = ProtoWallet(rootKey: verifierKey)

        let result = try await prover.revealCounterpartyKeyLinkage(
            WalletRevealCounterpartyKeyLinkageRequest(
                counterparty: counterpartyKey.publicKey,
                verifier: verifierKey.publicKey
            ),
            revelationTime: revelationTime,
            proofNonce: try PrivateKey(scalar(23))
        )

        XCTAssertEqual(result.prover, proverKey.publicKey)
        XCTAssertEqual(result.counterparty, counterpartyKey.publicKey)
        XCTAssertEqual(result.verifier, verifierKey.publicKey)
        XCTAssertEqual(result.revelationTime, revelationTime)

        let revelationProtocol = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "counterparty linkage revelation"
        )
        let keyID = try WalletKeyID(revelationTime)
        let linkage = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkage.bytes
        )).plaintext
        XCTAssertEqual(
            linkage,
            try proverKey.sharedSecret(with: counterpartyKey.publicKey).compressedBytes
        )

        let proofBytes = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkageProof.bytes
        )).plaintext
        XCTAssertEqual(proofBytes.count, 98)
        let encodedResponse = Array(proofBytes.dropFirst(66))
        let response = [UInt8](repeating: 0, count: 32 - encodedResponse.count)
            + encodedResponse
        let proof = try SharedSecretProof(
            noncePublicKey: PublicKey(Array(proofBytes[0..<33])),
            nonceSharedSecret: PublicKey(Array(proofBytes[33..<66])),
            response: response
        )
        XCTAssertTrue(proof.verify(
            proverPublicKey: proverKey.publicKey,
            counterpartyPublicKey: counterpartyKey.publicKey,
            sharedSecret: try PublicKey(linkage)
        ))
    }

    /// `@bsv/sdk` 4.1.1 writes z as `linkageProof.z.toArray('be', 32)`
    /// (packages/sdk/src/wallet/ProtoWallet.ts:196), so a response with a
    /// leading zero byte keeps it and the proof is always 98 bytes (W7).
    func testCounterpartyProofSerializesResponseAsFixed32ByteInteger() async throws {
        let proverKey = try PrivateKey(scalar(7))
        let counterpartyKey = try PrivateKey(scalar(13))
        let verifierKey = try PrivateKey(scalar(17))
        let deriver = WalletKeyDeriver(rootKey: proverKey)
        var selectedNonce: PrivateKey?
        var selectedResponse: [UInt8] = []
        for value in UInt16(1)...UInt16(1_024) {
            var bytes = [UInt8](repeating: 0, count: 32)
            bytes[30] = UInt8(value >> 8)
            bytes[31] = UInt8(truncatingIfNeeded: value)
            let nonce = try PrivateKey(bytes)
            let response = try deriver.counterpartySecretProof(
                for: counterpartyKey.publicKey,
                nonce: nonce
            ).response
            if response.first == 0 {
                selectedNonce = nonce
                selectedResponse = response
                break
            }
        }
        let nonce = try XCTUnwrap(selectedNonce)
        let wallet = ProtoWallet(
            rootKey: proverKey,
            randomSource: FixedRandomSource(
                bytes: [UInt8](repeating: 0x55, count: 32),
                throwsError: false
            )
        )
        let verifier = ProtoWallet(rootKey: verifierKey)
        let revelationTime = "2026-08-30T23:45:12.345Z"
        let result = try await wallet.revealCounterpartyKeyLinkage(
            WalletRevealCounterpartyKeyLinkageRequest(
                counterparty: counterpartyKey.publicKey,
                verifier: verifierKey.publicKey
            ),
            revelationTime: revelationTime,
            proofNonce: nonce
        )
        let proofBytes = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: WalletProtocolID(
                securityLevel: .everyAppAndCounterparty,
                name: "counterparty linkage revelation"
            ),
            keyID: WalletKeyID(revelationTime),
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkageProof.bytes
        )).plaintext
        XCTAssertEqual(selectedResponse.first, 0)
        XCTAssertEqual(Array(proofBytes.dropFirst(66)), selectedResponse)
        XCTAssertEqual(proofBytes.count, 98)
    }

    func testSpecificKeyLinkageMatchesBRC69BRC72AndProofTypeZero() async throws {
        let proverKey = try PrivateKey(scalar(7))
        let counterpartyKey = try PrivateKey(scalar(13))
        let verifierKey = try PrivateKey(scalar(17))
        let protocolID = try WalletProtocolID(securityLevel: .silent, name: "tests")
        let keyID = try WalletKeyID("test key id")
        let prover = ProtoWallet(
            rootKey: proverKey,
            randomSource: FixedRandomSource(
                bytes: [UInt8](repeating: 0x4d, count: 32),
                throwsError: false
            )
        )
        let verifier = ProtoWallet(rootKey: verifierKey)

        let result = try await prover.revealSpecificKeyLinkage(
            WalletRevealSpecificKeyLinkageRequest(
                counterparty: .publicKey(counterpartyKey.publicKey),
                verifier: verifierKey.publicKey,
                protocolID: protocolID,
                keyID: keyID
            )
        )

        XCTAssertEqual(result.prover, proverKey.publicKey)
        XCTAssertEqual(result.counterparty, counterpartyKey.publicKey)
        XCTAssertEqual(result.verifier, verifierKey.publicKey)
        XCTAssertEqual(result.protocolID, protocolID)
        XCTAssertEqual(result.keyID, keyID)
        XCTAssertEqual(result.proofType, 0)

        let revelationProtocol = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "specific linkage revelation 0 tests"
        )
        let linkage = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkage.bytes
        )).plaintext
        let sharedSecret = try proverKey.sharedSecret(with: counterpartyKey.publicKey)
        XCTAssertEqual(
            linkage,
            BSVHashing.hmacSHA256(
                Array("0-tests-test key id".utf8),
                key: sharedSecret.compressedBytes
            ).bytes
        )
        let proof = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkageProof.bytes
        )).plaintext
        XCTAssertEqual(proof, [0])
    }

    func testSpecificKeyLinkageWrapsMaximumLengthTargetProtocol() async throws {
        let proverKey = try PrivateKey(scalar(7))
        let counterpartyKey = try PrivateKey(scalar(13))
        let verifierKey = try PrivateKey(scalar(17))
        let targetProtocol = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: String(repeating: "a", count: 400)
        )
        let keyID = try WalletKeyID("boundary")
        let wallet = ProtoWallet(
            rootKey: proverKey,
            randomSource: FixedRandomSource(
                bytes: [UInt8](repeating: 0x61, count: 32),
                throwsError: false
            )
        )
        let result = try await wallet.revealSpecificKeyLinkage(
            WalletRevealSpecificKeyLinkageRequest(
                counterparty: .publicKey(counterpartyKey.publicKey),
                verifier: verifierKey.publicKey,
                protocolID: targetProtocol,
                keyID: keyID
            )
        )
        let wrappedName = "specific linkage revelation 2 " + targetProtocol.name
        XCTAssertEqual(wrappedName.utf8.count, 430)
        let verifier = ProtoWallet(rootKey: verifierKey)
        let plaintext = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: WalletProtocolID(
                securityLevel: .everyAppAndCounterparty,
                name: wrappedName
            ),
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkage.bytes
        )).plaintext
        XCTAssertEqual(plaintext.count, 32)
    }

    func testKeyLinkageRejectsSelfAndUnavailablePrivilegePolicy() async throws {
        let root = try PrivateKey(scalar(7))
        let counterparty = try PrivateKey(scalar(13)).publicKey
        let verifier = try PrivateKey(scalar(17)).publicKey
        let protocolID = try WalletProtocolID(securityLevel: .silent, name: "tests")
        let keyID = try WalletKeyID("test")
        let wallet = ProtoWallet(rootKey: root)

        await XCTAssertThrowsErrorAsync(try await wallet.revealCounterpartyKeyLinkage(
            WalletRevealCounterpartyKeyLinkageRequest(
                counterparty: root.publicKey,
                verifier: verifier
            )
        )) { error in
            XCTAssertEqual(error as? WalletCryptoError, .counterpartySelfLinkageForbidden)
        }

        for privilege in [
            try WalletPrivilege(privileged: true),
            try WalletPrivilege(privilegedReason: "audit reason"),
        ] {
            await XCTAssertThrowsErrorAsync(try await wallet.revealCounterpartyKeyLinkage(
                WalletRevealCounterpartyKeyLinkageRequest(
                    counterparty: counterparty,
                    verifier: verifier,
                    privilege: privilege
                )
            )) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.revealSpecificKeyLinkage(
                try WalletRevealSpecificKeyLinkageRequest(
                    counterparty: .publicKey(counterparty),
                    verifier: verifier,
                    protocolID: protocolID,
                    keyID: keyID,
                    privilege: privilege
                )
            )) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
        }
    }

    func testBoundsAuthenticationMutationsAndRandomFailures() async throws {
        let limits = try WalletCryptoLimits(maximumPayloadByteCount: 4, maximumJSONByteCount: 1_024)
        let root = try walletTestPrivateKey(42)
        let protocolID = try walletTestProtocol()
        let keyID = try walletTestKeyID()
        let fixed = FixedRandomSource(bytes: [UInt8](repeating: 7, count: 32), throwsError: false)
        let wallet = ProtoWallet(rootKey: root, limits: limits, randomSource: fixed)
        let payloads: [[UInt8]] = [[], [1], [1,2,3], [1,2,3,4]]
        for data in payloads {
            let encrypted = try await wallet.encrypt(WalletEncryptRequest(protocolID: protocolID, keyID: keyID, plaintext: data))
            let decrypted = try await wallet.decrypt(WalletDecryptRequest(protocolID: protocolID, keyID: keyID, ciphertext: encrypted.ciphertext)).plaintext
            XCTAssertEqual(decrypted, data)
            for index in encrypted.ciphertext.indices {
                var mutated = encrypted.ciphertext
                mutated[index] ^= 1
                await XCTAssertThrowsErrorAsync(try await wallet.decrypt(WalletDecryptRequest(protocolID: protocolID, keyID: keyID, ciphertext: mutated))) { error in
                    XCTAssertEqual(error as? WalletCryptoError, .authenticationFailed)
                }
            }
        }
        await XCTAssertThrowsErrorAsync(try await wallet.encrypt(WalletEncryptRequest(protocolID: protocolID, keyID: keyID, plaintext: [1,2,3,4,5])))
        await XCTAssertThrowsErrorAsync(try await wallet.decrypt(WalletDecryptRequest(protocolID: protocolID, keyID: keyID, ciphertext: [UInt8](repeating: 0, count: 53)))) { error in
            XCTAssertEqual(error as? WalletCryptoError, .ciphertextTooLarge(actual: 53, maximum: 52))
        }
        for count in 0..<48 {
            await XCTAssertThrowsErrorAsync(try await wallet.decrypt(WalletDecryptRequest(protocolID: protocolID, keyID: keyID, ciphertext: [UInt8](repeating: 0, count: count))))
        }
        for source in [FixedRandomSource(bytes: [], throwsError: true), FixedRandomSource(bytes: [], throwsError: false), FixedRandomSource(bytes: [UInt8](repeating: 0, count: 31), throwsError: false), FixedRandomSource(bytes: [UInt8](repeating: 0, count: 33), throwsError: false)] {
            let failing = ProtoWallet(rootKey: root, limits: limits, randomSource: source)
            await XCTAssertThrowsErrorAsync(try await failing.encrypt(WalletEncryptRequest(protocolID: protocolID, keyID: keyID, plaintext: []))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .randomGenerationFailed)
            }
        }
    }

    /// BRC-56 HMAC key vectors from `@bsv/sdk` 4.1.1
    /// (packages/sdk/src/wallet/__tests/ProtoWallet.brc56-hmac-key.test.ts:9-70).
    /// Tags use the minimal-length X coordinate as the HMAC key (W1, COMP-064).
    /// TypeScript rejects `rejectedTag` (made with the zero-padded 32-byte key);
    /// Swift still accepts it so tags Swift and Go peers made before the switch
    /// keep verifying.
    func testBRC56HMACKeyVectorsMatchTypeScript() async throws {
        let rootKey = try PrivateKey(walletTestHex(
            "f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07"
        ))
        XCTAssertEqual(
            Hex.encode(rootKey.publicKey.compressedBytes),
            "035818cd7cc614fea816c8b39eebe6e43cafc635451ec5a873f8757b418aaae91a"
        )
        let counterparty = try PublicKey(walletTestHex(
            "03458d551018414b8fe1adbcef2d0afc17e1074bfab3fdde3e1b0750bdde58a9a7"
        ))
        let protocolID = try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "hmac key vectors")
        let data = try walletTestHex("4252432d353620484d41432074657374")
        let vectors: [(WalletCounterparty, String, String, String, String?)] = [
            (.self, "k0",
             "b1273850ff41cee365a4d590e3c323822129f66c5a9b2eacb8b9e790e000e396",
             "99455edf49ea2156f6109466fb344c3027d4c14485581a50bf5ff0850328a269", nil),
            (.self, "k95",
             "0c82ac78dc853158f24883ccfda332be6ba34f821765357cc4ef2a190a28fd",
             "3a968ebaa25eaa4b1cfad138f96105bb1eb738defc066d01e37b32595900d48b",
             "054a0fc6a3b0e21b31dc627fb1d645f2eea4127dff71eac95b1f71b7cb13c787"),
            (.self, "k91538",
             "9dc11102cc72eca3c6e4e232460eac581e9b2cee1bb35c395b635d3f6393",
             "5a8b84fb2a7d9ce7b12feb8319f14dc6169e0be005a1a8e58d9b9b2d1ac29d47",
             "ff43127cb1ddfbd19776d01ce34b8c3e83916b51fa55ac045a355b731e6999f5"),
            (.publicKey(counterparty), "k0",
             "1896e0210afac8dbb4ca3bd4ea25c8377d0352ab83e62fe6ffabeca78c1a6113",
             "986af579272261acf3e890bb1650124b0dfbc0b1edacda202f8ed0c3b876c072", nil),
            (.publicKey(counterparty), "k497",
             "1829e1dd58fc2c45b6edcbb277eecdecbab1c884b42fd779e131fea5881b45",
             "3a5ea2bf5bcc9bc1461041737384bf258b0a3e5a475fb281a19c2972cdb1cff6",
             "aa39467c48a116ffb00fd7b56ff158bd9af37d1298df2f031c0125458c30f574"),
            (.publicKey(counterparty), "k29510",
             "a52a35523175d6c181e90f463a27cdbf70f4ecf055e912d6fc24ac7d0e3c",
             "ecca769bb17b1775ce8ae4326fe721ba0f7ba272300741bf4a5b068cf0cebd60",
             "2677674035f1aaac3219b3405cf8569ec07922a3ceffbd4f7c8a7948b2d3c553"),
        ]
        let wallet = ProtoWallet(rootKey: rootKey)
        let deriver = WalletKeyDeriver(rootKey: rootKey)
        for (party, keyIDText, hmacKey, tag, paddedTag) in vectors {
            let keyID = try WalletKeyID(keyIDText)
            let symmetric = try deriver.deriveSymmetricKey(
                protocolID: protocolID, keyID: keyID, counterparty: party
            )
            XCTAssertEqual(Hex.encode(walletHMACKey(symmetric.bytes)), hmacKey, keyIDText)
            let created = try await wallet.createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID, keyID: keyID, counterparty: party, data: data
            ))
            XCTAssertEqual(Hex.encode(created.hmac.bytes), tag, keyIDText)
            let valid = try await wallet.verifyHMAC(WalletVerifyHMACRequest(
                protocolID: protocolID, keyID: keyID, counterparty: party, data: data,
                hmac: WalletHMAC(bytes: walletTestHex(tag))
            )).valid
            XCTAssertTrue(valid, keyIDText)
            if let paddedTag {
                let paddedValid = try await wallet.verifyHMAC(WalletVerifyHMACRequest(
                    protocolID: protocolID, keyID: keyID, counterparty: party, data: data,
                    hmac: WalletHMAC(bytes: walletTestHex(paddedTag))
                )).valid
                XCTAssertTrue(paddedValid, "padded-key tag \(keyIDText)")
            }
        }
    }

    func testHMACMutationsPermissionsAndPublicKeys() async throws {
        let wallet = ProtoWallet(rootKey: try walletTestPrivateKey(42))
        let protocolID = try walletTestProtocol()
        let keyID = try walletTestKeyID()
        let created = try await wallet.createHMAC(WalletCreateHMACRequest(protocolID: protocolID, keyID: keyID, data: [1,2,3]))
        let initialValid = try await wallet.verifyHMAC(WalletVerifyHMACRequest(protocolID: protocolID, keyID: keyID, data: [1,2,3], hmac: created.hmac)).valid
        XCTAssertTrue(initialValid)
        for index in 0..<32 {
            var bytes = created.hmac.bytes
            bytes[index] ^= 1
            let mutatedValid = try await wallet.verifyHMAC(WalletVerifyHMACRequest(protocolID: protocolID, keyID: keyID, data: [1,2,3], hmac: WalletHMAC(bytes: bytes))).valid
            XCTAssertFalse(mutatedValid)
        }
        for data: [UInt8] in [[], [0], [0, 1, 2, 3]] {
            let bounded = try await wallet.createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID,
                keyID: keyID,
                data: data
            ))
            let valid = try await wallet.verifyHMAC(WalletVerifyHMACRequest(
                protocolID: protocolID,
                keyID: keyID,
                data: data,
                hmac: bounded.hmac
            )).valid
            XCTAssertTrue(valid)
        }
        let identity = try await wallet.getPublicKey(WalletGetPublicKeyRequest(selection: .identity)).publicKey
        XCTAssertEqual(identity, try walletTestPrivateKey(42).publicKey)

        let rejectedAccesses = [
            try WalletKeyAccess(privileged: true),
            try WalletKeyAccess(privilegedReason: "reason"),
        ]
        for access in rejectedAccesses {
            await XCTAssertThrowsErrorAsync(try await wallet.getPublicKey(WalletGetPublicKeyRequest(selection: .identity, access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.encrypt(WalletEncryptRequest(protocolID: protocolID, keyID: keyID, plaintext: [], access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.decrypt(WalletDecryptRequest(protocolID: protocolID, keyID: keyID, ciphertext: [UInt8](repeating: 0, count: 48), access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.createHMAC(WalletCreateHMACRequest(protocolID: protocolID, keyID: keyID, data: [], access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.verifyHMAC(WalletVerifyHMACRequest(protocolID: protocolID, keyID: keyID, data: [], hmac: created.hmac, access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            let standardSignature = try await wallet.createSignature(WalletCreateSignatureRequest(protocolID: protocolID, keyID: keyID, payload: .data([])))
            await XCTAssertThrowsErrorAsync(try await wallet.createSignature(WalletCreateSignatureRequest(protocolID: protocolID, keyID: keyID, payload: .data([]), access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.verifySignature(WalletVerifySignatureRequest(protocolID: protocolID, keyID: keyID, payload: .data([]), signature: standardSignature.signature, access: access))) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
        }

        for seekPermission in [nil, false, true] as [Bool?] {
            let access = try WalletKeyAccess(seekPermission: seekPermission)
            _ = try await wallet.getPublicKey(WalletGetPublicKeyRequest(
                selection: .identity,
                access: access
            ))
            let encrypted = try await wallet.encrypt(WalletEncryptRequest(
                protocolID: protocolID,
                keyID: keyID,
                plaintext: [1],
                access: access
            ))
            let decrypted = try await wallet.decrypt(WalletDecryptRequest(
                protocolID: protocolID,
                keyID: keyID,
                ciphertext: encrypted.ciphertext,
                access: access
            ))
            XCTAssertEqual(decrypted.plaintext, [1])
            let soughtHMAC = try await wallet.createHMAC(WalletCreateHMACRequest(
                protocolID: protocolID,
                keyID: keyID,
                data: [1],
                access: access
            ))
            let verifiedHMAC = try await wallet.verifyHMAC(WalletVerifyHMACRequest(
                protocolID: protocolID,
                keyID: keyID,
                data: [1],
                hmac: soughtHMAC.hmac,
                access: access
            ))
            XCTAssertTrue(verifiedHMAC.valid)
            let soughtSignature = try await wallet.createSignature(WalletCreateSignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self,
                payload: .data([1]),
                access: access
            ))
            let verifiedSignature = try await wallet.verifySignature(WalletVerifySignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                payload: .data([1]),
                signature: soughtSignature.signature,
                access: access
            ))
            XCTAssertTrue(verifiedSignature.valid)
        }
    }

    func testConcurrentImmutableOperations() async throws {
        let root = try walletTestPrivateKey(42)
        let protocolID = try walletTestProtocol()
        let keyID = try walletTestKeyID()
        let wallet = ProtoWallet(
            rootKey: root,
            randomSource: FixedRandomSource(bytes: [UInt8](repeating: 9, count: 32), throwsError: false)
        )
        try await withThrowingTaskGroup(of: Bool.self) { group in
            for index in 0..<24 {
                group.addTask {
                    let data = [UInt8(index)]
                    let encrypted = try await wallet.encrypt(WalletEncryptRequest(
                        protocolID: protocolID,
                        keyID: keyID,
                        plaintext: data
                    ))
                    let decrypted = try await wallet.decrypt(WalletDecryptRequest(
                        protocolID: protocolID,
                        keyID: keyID,
                        ciphertext: encrypted.ciphertext
                    ))
                    let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
                        protocolID: protocolID,
                        keyID: keyID,
                        data: data
                    ))
                    let hmacValid = try await wallet.verifyHMAC(WalletVerifyHMACRequest(
                        protocolID: protocolID,
                        keyID: keyID,
                        data: data,
                        hmac: hmac.hmac
                    )).valid
                    let signature = try await wallet.createSignature(WalletCreateSignatureRequest(
                        protocolID: protocolID,
                        keyID: keyID,
                        payload: .data(data)
                    ))
                    let signatureValid = try await wallet.verifySignature(WalletVerifySignatureRequest(
                        protocolID: protocolID,
                        keyID: keyID,
                        counterparty: .anyone,
                        payload: .data(data),
                        signature: signature.signature,
                        forSelf: true
                    )).valid
                    return decrypted.plaintext == data && hmacValid && signatureValid
                }
            }
            for try await valid in group { XCTAssertTrue(valid) }
        }
    }
}

func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
