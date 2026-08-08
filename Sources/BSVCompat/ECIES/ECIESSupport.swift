import BSVCrypto
import BSVKeys

enum ECIESKeyDerivation {
    struct ElectrumMaterial: Equatable {
        let initializationVector: [UInt8]
        let encryptionKey: [UInt8]
        let authenticationKey: [UInt8]
    }

    struct BitcoreMaterial: Equatable {
        let encryptionKey: [UInt8]
        let authenticationKey: [UInt8]
    }

    static func electrum(sharedPoint: PublicKey) -> ElectrumMaterial {
        let digest = BSVHashing.sha512(sharedPoint.compressedBytes).bytes
        return ElectrumMaterial(
            initializationVector: Array(digest[0 ..< 16]),
            encryptionKey: Array(digest[16 ..< 32]),
            authenticationKey: Array(digest[32 ..< 64])
        )
    }

    /// Bitcore hashes the minimal unsigned big-endian shared X, rather than its
    /// fixed-width field encoding. `sharedX` is the fixed 32-byte coordinate.
    static func bitcore(sharedX: [UInt8]) -> BitcoreMaterial {
        let firstNonzero = sharedX.firstIndex(where: { $0 != 0 }) ?? sharedX.endIndex
        let minimalX = Array(sharedX[firstNonzero...])
        let digest = BSVHashing.sha512(minimalX).bytes
        return BitcoreMaterial(
            encryptionKey: Array(digest[0 ..< 32]),
            authenticationKey: Array(digest[32 ..< 64])
        )
    }

    static func bitcore(sharedPoint: PublicKey) -> BitcoreMaterial {
        bitcore(sharedX: Array(sharedPoint.compressedBytes[1 ..< 33]))
    }
}

enum ECIESPrivateKeyGenerator {
    /// A malformed or adversarial source cannot make encryption retry forever.
    static let attemptLimit = 128

    static func generate(using randomSource: any SecureRandomSource) throws -> PrivateKey {
        for _ in 0 ..< attemptLimit {
            let bytes: [UInt8]
            do {
                bytes = try randomSource.randomBytes(count: 32)
            } catch {
                throw ECIESError.randomGenerationFailed
            }
            guard bytes.count == 32 else {
                throw ECIESError.randomGenerationFailed
            }
            if let privateKey = try? PrivateKey(bytes) {
                return privateKey
            }
        }
        throw ECIESError.randomGenerationFailed
    }
}

func eciesSharedPoint(privateKey: PrivateKey, publicKey: PublicKey) throws -> PublicKey {
    do {
        return try privateKey.sharedSecret(with: publicKey)
    } catch {
        throw ECIESError.keyAgreementFailed
    }
}
