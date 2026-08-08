import BSVCrypto

/// Stable failures from BRC-42 bilateral key derivation.
public enum BRC42DerivationError: Error, Equatable, Sendable {
    /// The ECDH shared point could not be derived from validated keys.
    case sharedSecretDerivationFailed
    /// The derived scalar addition produced the point at infinity or private scalar zero.
    case invalidDerivedKey
}

extension PrivateKey {
    /// Derives the recipient's BRC-42 child private key.
    ///
    /// `self` is the recipient private key and `senderPublicKey` is the
    /// sender identity public key. The invoice number is used as its exact
    /// UTF-8 byte sequence; no Unicode normalization is applied.
    public func derivedChild(
        with senderPublicKey: PublicKey,
        invoiceNumber: String
    ) throws -> PrivateKey {
        let tweak = try brc42Tweak(
            privateKey: self,
            publicKey: senderPublicKey,
            invoiceNumber: invoiceNumber
        )
        do {
            return try adding(tweak: tweak)
        } catch {
            throw BRC42DerivationError.invalidDerivedKey
        }
    }
}

extension PublicKey {
    /// Derives the recipient's BRC-42 child public key.
    ///
    /// `self` is the recipient public key and `senderPrivateKey` is the
    /// sender identity private key. The result matches the public key of the
    /// recipient's corresponding private-key derivation.
    public func derivedChild(
        with senderPrivateKey: PrivateKey,
        invoiceNumber: String
    ) throws -> PublicKey {
        let tweak = try brc42Tweak(
            privateKey: senderPrivateKey,
            publicKey: self,
            invoiceNumber: invoiceNumber
        )
        do {
            return try adding(tweak: tweak)
        } catch {
            throw BRC42DerivationError.invalidDerivedKey
        }
    }
}

private func brc42Tweak(
    privateKey: PrivateKey,
    publicKey: PublicKey,
    invoiceNumber: String
) throws -> [UInt8] {
    let sharedPoint: PublicKey
    do {
        sharedPoint = try privateKey.sharedSecret(with: publicKey)
    } catch {
        throw BRC42DerivationError.sharedSecretDerivationFailed
    }
    let digest = BSVHashing.hmacSHA256(
        Array(invoiceNumber.utf8),
        key: sharedPoint.compressedBytes
    )
    return reducedScalarModuloOrder(digest.bytes)
}
