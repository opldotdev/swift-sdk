import P256K

extension PrivateKey {
    /// Returns `(self + tweak) mod n`, where `tweak` is a 32-byte big-endian scalar.
    ///
    /// This operation delegates to P256K/libsecp256k1. The receiver is unchanged when
    /// validation or the operation fails. Swift arrays do not guarantee zeroization, so
    /// callers should avoid retaining unnecessary copies of private keys and tweaks.
    public func adding(tweak: [UInt8]) throws -> PrivateKey {
        let dependencyTweak = try validatedTweak(tweak, permitsZero: true)

        do {
            let dependencyKey = try P256K.Signing.PrivateKey(dataRepresentation: bytes)
            let result = try dependencyKey.add(dependencyTweak)
            return try PrivateKey(Array(result.dataRepresentation))
        } catch {
            throw Secp256k1OperationError.invalidTweak
        }
    }

    /// Returns `(self * tweak) mod n`, where `tweak` is a 32-byte big-endian scalar.
    ///
    /// This operation delegates to P256K/libsecp256k1. The receiver is unchanged when
    /// validation or the operation fails. Swift arrays do not guarantee zeroization, so
    /// callers should avoid retaining unnecessary copies of private keys and tweaks.
    public func multiplying(by tweak: [UInt8]) throws -> PrivateKey {
        let dependencyTweak = try validatedTweak(tweak, permitsZero: false)

        do {
            let dependencyKey = try P256K.Signing.PrivateKey(dataRepresentation: bytes)
            let result = try dependencyKey.multiply(dependencyTweak)
            return try PrivateKey(Array(result.dataRepresentation))
        } catch {
            throw Secp256k1OperationError.invalidTweak
        }
    }

    /// Computes the full raw ECDH point `self * peer`.
    ///
    /// The result is a validated curve point, not a KDF output and not libsecp256k1's
    /// default hashed x-coordinate. Call ``PublicKey/serialized(as:)`` on the returned
    /// point to obtain either standard SEC1 representation. Protocols should apply their
    /// required KDF explicitly.
    ///
    /// - Important: P256K documents that secp256k1 context randomization does not protect
    ///   ECDH's variable-point multiplication against side-channel leakage. Applications
    ///   requiring hardened ECDH need additional platform-specific protections or an
    ///   appropriately isolated execution environment.
    public func sharedSecret(with peer: PublicKey) throws -> PublicKey {
        do {
            let dependencyPrivateKey = try P256K.KeyAgreement.PrivateKey(
                dataRepresentation: bytes,
                format: .compressed
            )
            let dependencyPublicKey = try P256K.KeyAgreement.PublicKey(
                dataRepresentation: peer.compressedBytes,
                format: .compressed
            )
            let secret = dependencyPrivateKey.sharedSecretFromKeyAgreement(
                with: dependencyPublicKey,
                format: .compressed
            )
            let serializedPoint = secret.withUnsafeBytes { Array($0) }
            return try PublicKey(serializedPoint)
        } catch {
            throw Secp256k1OperationError.keyAgreementFailed
        }
    }
}

extension PublicKey {
    /// Returns `self + tweak * G`, where `tweak` is a 32-byte big-endian scalar.
    ///
    /// This operation delegates to P256K/libsecp256k1 and does not mutate the receiver.
    public func adding(tweak: [UInt8]) throws -> PublicKey {
        let dependencyTweak = try validatedTweak(tweak, permitsZero: true)

        do {
            let dependencyKey = try P256K.Signing.PublicKey(
                dataRepresentation: compressedBytes,
                format: .compressed
            )
            let result = try dependencyKey.add(dependencyTweak, format: .compressed)
            return try PublicKey(Array(result.dataRepresentation))
        } catch {
            throw Secp256k1OperationError.invalidTweak
        }
    }

    /// Returns `self * tweak`, where `tweak` is a 32-byte big-endian scalar.
    ///
    /// This operation delegates to P256K/libsecp256k1 and does not mutate the receiver.
    public func multiplying(by tweak: [UInt8]) throws -> PublicKey {
        let dependencyTweak = try validatedTweak(tweak, permitsZero: false)

        do {
            let dependencyKey = try P256K.Signing.PublicKey(
                dataRepresentation: compressedBytes,
                format: .compressed
            )
            let result = try dependencyKey.multiply(dependencyTweak, format: .compressed)
            return try PublicKey(Array(result.dataRepresentation))
        } catch {
            throw Secp256k1OperationError.invalidTweak
        }
    }
}

private let secp256k1Order: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]

private func validatedTweak(_ tweak: [UInt8], permitsZero: Bool) throws -> [UInt8] {
    guard tweak.count == 32 else {
        throw Secp256k1OperationError.invalidTweakByteCount(tweak.count)
    }

    var isLess: UInt8 = 0
    var isGreater: UInt8 = 0
    var nonzero: UInt8 = 0

    // Fixed-shape big-endian comparison: every byte is visited without deriving a
    // public key or leaving the loop when the first differing byte is encountered.
    for index in 0..<32 {
        let candidate = UInt16(tweak[index])
        let order = UInt16(secp256k1Order[index])
        let lessAtByte = UInt8((candidate &- order) >> 15)
        let greaterAtByte = UInt8((order &- candidate) >> 15)
        let undecided = 1 ^ (isLess | isGreater)
        isLess |= lessAtByte & undecided
        isGreater |= greaterAtByte & undecided
        nonzero |= tweak[index]
    }

    guard isLess == 1, permitsZero || nonzero != 0 else {
        throw Secp256k1OperationError.invalidTweak
    }

    return tweak
}
