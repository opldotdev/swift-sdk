import P256K

/// A validated 32-byte secp256k1 private scalar.
///
/// Swift arrays do not guarantee zeroization, and accessing ``bytes`` creates
/// another copy. Avoid retaining unnecessary copies of long-lived private keys.
public struct PrivateKey: Hashable, Sendable {
    private let privateBytes: [UInt8]
    private let derivedPublicKey: PublicKey

    /// Creates a private key from exactly 32 big-endian scalar bytes.
    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw Secp256k1KeyError.invalidPrivateKeyByteCount(bytes.count)
        }

        let dependencyKey: P256K.Signing.PrivateKey
        do {
            dependencyKey = try P256K.Signing.PrivateKey(dataRepresentation: bytes)
        } catch {
            throw Secp256k1KeyError.invalidPrivateKey
        }

        self.privateBytes = bytes
        self.derivedPublicKey = PublicKey(validated: dependencyKey.publicKey)
    }

    /// The exact 32-byte big-endian scalar supplied at initialization.
    public var bytes: [UInt8] {
        privateBytes
    }

    /// The secp256k1 public point derived from this scalar.
    public var publicKey: PublicKey {
        derivedPublicKey
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derivedPublicKey == rhs.derivedPublicKey
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(derivedPublicKey)
    }
}
