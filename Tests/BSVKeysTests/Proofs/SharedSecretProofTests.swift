@testable import BSVKeys
import Testing

@Suite("BRC-94 shared-secret proofs")
struct SharedSecretProofTests {
    @Test("deterministic proof verifies both equations")
    func deterministicProof() throws {
        let prover = try PrivateKey(scalar(7))
        let counterparty = try PrivateKey(scalar(13))
        let nonce = try PrivateKey(scalar(23))
        let sharedSecret = try prover.sharedSecret(with: counterparty.publicKey)
        let proof = try prover.sharedSecretProof(
            with: counterparty.publicKey,
            nonce: nonce
        )

        #expect(proof.response.count == 32)
        #expect(proof.verify(
            proverPublicKey: prover.publicKey,
            counterpartyPublicKey: counterparty.publicKey,
            sharedSecret: sharedSecret
        ))
    }

    @Test("fresh proofs vary and remain valid")
    func randomizedProofs() throws {
        let prover = try PrivateKey(scalar(11))
        let counterparty = try PrivateKey(scalar(17))
        let sharedSecret = try prover.sharedSecret(with: counterparty.publicKey)
        let first = try prover.sharedSecretProof(with: counterparty.publicKey)
        let second = try prover.sharedSecretProof(with: counterparty.publicKey)

        #expect(first != second)
        for proof in [first, second] {
            #expect(proof.verify(
                proverPublicKey: prover.publicKey,
                counterpartyPublicKey: counterparty.publicKey,
                sharedSecret: sharedSecret
            ))
        }
    }

    @Test("tampering any statement or proof component fails")
    func tamperingFails() throws {
        let prover = try PrivateKey(scalar(2))
        let counterparty = try PrivateKey(scalar(3))
        let nonce = try PrivateKey(scalar(5))
        let proof = try prover.sharedSecretProof(
            with: counterparty.publicKey,
            nonce: nonce
        )
        let sharedSecret = try prover.sharedSecret(with: counterparty.publicKey)
        let wrong = try PrivateKey(scalar(29))

        #expect(!proof.verify(
            proverPublicKey: wrong.publicKey,
            counterpartyPublicKey: counterparty.publicKey,
            sharedSecret: sharedSecret
        ))
        #expect(!proof.verify(
            proverPublicKey: prover.publicKey,
            counterpartyPublicKey: wrong.publicKey,
            sharedSecret: sharedSecret
        ))
        #expect(!proof.verify(
            proverPublicKey: prover.publicKey,
            counterpartyPublicKey: counterparty.publicKey,
            sharedSecret: wrong.publicKey
        ))

        var changedResponse = proof.response
        changedResponse[31] ^= 1
        let tampered = try SharedSecretProof(
            noncePublicKey: proof.noncePublicKey,
            nonceSharedSecret: proof.nonceSharedSecret,
            response: changedResponse
        )
        #expect(!tampered.verify(
            proverPublicKey: prover.publicKey,
            counterpartyPublicKey: counterparty.publicKey,
            sharedSecret: sharedSecret
        ))
    }

    @Test("response parsing is strict and nontrapping")
    func responseValidation() throws {
        let point = try PrivateKey(scalar(1)).publicKey
        for count in [0, 31, 33, 1_024] {
            #expect(throws: SharedSecretProofError.invalidResponseByteCount(count)) {
                try SharedSecretProof(
                    noncePublicKey: point,
                    nonceSharedSecret: point,
                    response: [UInt8](repeating: 1, count: count)
                )
            }
        }
        #expect(throws: SharedSecretProofError.invalidResponseScalar) {
            try SharedSecretProof(
                noncePublicKey: point,
                nonceSharedSecret: point,
                response: [UInt8](repeating: 0, count: 32)
            )
        }
        #expect(throws: SharedSecretProofError.invalidResponseScalar) {
            try SharedSecretProof(
                noncePublicKey: point,
                nonceSharedSecret: point,
                response: [UInt8](repeating: 0xff, count: 32)
            )
        }
    }

    @Test("point addition and random-key seams stay in the dependency")
    func dependencyOperations() throws {
        let two = try PrivateKey(scalar(2))
        let three = try PrivateKey(scalar(3))
        let five = try PrivateKey(scalar(5))
        #expect(try two.publicKey.adding(three.publicKey) == five.publicKey)

        let random = try PrivateKey.random()
        #expect(random.bytes.count == 32)
        #expect(try PrivateKey(random.bytes) == random)
    }

    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }
}
