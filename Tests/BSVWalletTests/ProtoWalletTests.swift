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

    func testCounterpartyProofSerializesResponseAsBRC97MinimalInteger() async throws {
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
        let expectedResponse = Array(selectedResponse.drop(while: { $0 == 0 }))
        XCTAssertEqual(Array(proofBytes.dropFirst(66)), expectedResponse)
        XCTAssertLessThan(proofBytes.count, 98)
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

        let accesses = [
            try WalletKeyAccess(privileged: true),
            try WalletKeyAccess(privilegedReason: "reason"),
            try WalletKeyAccess(seekPermission: true),
        ]
        for access in accesses {
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
