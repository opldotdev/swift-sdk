import BSVCrypto

/// Stable construction and validation failures for a BRC-94 shared-secret proof.
public enum SharedSecretProofError: Error, Equatable, Sendable {
    case invalidResponseByteCount(Int)
    case invalidResponseScalar
    case generationFailed
}

/// A BRC-94 Chaum-Pedersen proof that one private scalar links both a public
/// identity key and a revealed ECDH shared point.
public struct SharedSecretProof: Hashable, Sendable {
    /// `R = rG`, the nonce public point.
    public let noncePublicKey: PublicKey
    /// `S' = rB`, the nonce shared point.
    public let nonceSharedSecret: PublicKey
    private let responseBytes: [UInt8]

    /// Creates a proof from its validated public points and 32-byte nonzero response scalar.
    public init(
        noncePublicKey: PublicKey,
        nonceSharedSecret: PublicKey,
        response: [UInt8]
    ) throws {
        guard response.count == 32 else {
            throw SharedSecretProofError.invalidResponseByteCount(response.count)
        }
        do {
            self.responseBytes = try validatedTweak(response, permitsZero: false)
        } catch {
            throw SharedSecretProofError.invalidResponseScalar
        }
        self.noncePublicKey = noncePublicKey
        self.nonceSharedSecret = nonceSharedSecret
    }

    /// The exact 32-byte big-endian response scalar `z`.
    public var response: [UInt8] { responseBytes }

    /// Verifies both BRC-94 proof equations without trapping on hostile input.
    public func verify(
        proverPublicKey: PublicKey,
        counterpartyPublicKey: PublicKey,
        sharedSecret: PublicKey
    ) -> Bool {
        do {
            let challenge = brc94Challenge(
                proverPublicKey: proverPublicKey,
                counterpartyPublicKey: counterpartyPublicKey,
                sharedSecret: sharedSecret,
                nonceSharedSecret: nonceSharedSecret,
                noncePublicKey: noncePublicKey
            )

            let zG = try PrivateKey(responseBytes).publicKey
            let firstRight: PublicKey
            if challenge.allSatisfy({ $0 == 0 }) {
                firstRight = noncePublicKey
            } else {
                firstRight = try noncePublicKey.adding(proverPublicKey.multiplying(by: challenge))
            }
            guard zG == firstRight else { return false }

            let zB = try counterpartyPublicKey.multiplying(by: responseBytes)
            let secondRight: PublicKey
            if challenge.allSatisfy({ $0 == 0 }) {
                secondRight = nonceSharedSecret
            } else {
                secondRight = try nonceSharedSecret.adding(sharedSecret.multiplying(by: challenge))
            }
            return zB == secondRight
        } catch {
            return false
        }
    }
}

extension PrivateKey {
    /// Creates a BRC-94 proof for the shared point between `self` and `counterpartyPublicKey`.
    /// A fresh cryptographically secure nonce is generated for every call.
    public func sharedSecretProof(with counterpartyPublicKey: PublicKey) throws -> SharedSecretProof {
        for _ in 0..<8 {
            let nonce: PrivateKey
            do {
                nonce = try .random()
            } catch {
                throw SharedSecretProofError.generationFailed
            }
            if let proof = try? sharedSecretProof(
                with: counterpartyPublicKey,
                nonce: nonce
            ) {
                return proof
            }
        }
        throw SharedSecretProofError.generationFailed
    }

    /// Deterministic construction seam for conformance testing. Production callers
    /// must use ``sharedSecretProof(with:)`` so nonce reuse is not possible by API.
    package func sharedSecretProof(
        with counterpartyPublicKey: PublicKey,
        nonce: PrivateKey
    ) throws -> SharedSecretProof {
        let revealedSharedSecret: PublicKey
        let nonceSharedSecret: PublicKey
        do {
            revealedSharedSecret = try self.sharedSecret(with: counterpartyPublicKey)
            nonceSharedSecret = try nonce.sharedSecret(with: counterpartyPublicKey)
        } catch {
            throw SharedSecretProofError.generationFailed
        }

        let challenge = brc94Challenge(
            proverPublicKey: publicKey,
            counterpartyPublicKey: counterpartyPublicKey,
            sharedSecret: revealedSharedSecret,
            nonceSharedSecret: nonceSharedSecret,
            noncePublicKey: nonce.publicKey
        )

        let response: [UInt8]
        do {
            if challenge.allSatisfy({ $0 == 0 }) {
                response = nonce.bytes
            } else {
                let challengeTimesPrivate = try multiplying(by: challenge)
                response = try challengeTimesPrivate.adding(tweak: nonce.bytes).bytes
            }
            return try SharedSecretProof(
                noncePublicKey: nonce.publicKey,
                nonceSharedSecret: nonceSharedSecret,
                response: response
            )
        } catch {
            throw SharedSecretProofError.generationFailed
        }
    }
}

private func brc94Challenge(
    proverPublicKey: PublicKey,
    counterpartyPublicKey: PublicKey,
    sharedSecret: PublicKey,
    nonceSharedSecret: PublicKey,
    noncePublicKey: PublicKey
) -> [UInt8] {
    var transcript: [UInt8] = []
    transcript.reserveCapacity(33 * 5)
    transcript.append(contentsOf: proverPublicKey.compressedBytes)
    transcript.append(contentsOf: counterpartyPublicKey.compressedBytes)
    transcript.append(contentsOf: sharedSecret.compressedBytes)
    transcript.append(contentsOf: nonceSharedSecret.compressedBytes)
    transcript.append(contentsOf: noncePublicKey.compressedBytes)
    return reducedScalarModuloOrder(BSVHashing.sha256(transcript).bytes)
}
