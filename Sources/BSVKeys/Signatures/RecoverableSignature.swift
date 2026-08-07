import BSVCore
import P256K

/// Failures produced while parsing, signing, or recovering secp256k1 signatures.
public enum RecoverableSignatureError: Error, Equatable, Sendable {
    /// Compact signatures are exactly 64 bytes (`r || s`).
    case invalidCompactByteCount(Int)
    /// Recovery IDs are integers in `0...3`.
    case invalidRecoveryID(Int)
    /// A compact signature contains a zero or out-of-range scalar, or could not be parsed.
    case invalidCompactSignature
    /// The pinned secp256k1 implementation could not create a signature.
    case signingFailed
    /// No public-key candidate exists for the supplied signature, recovery ID, and digest.
    case recoveryFailed
}

/// A validated compact secp256k1 ECDSA signature and its recovery ID.
///
/// The compact bytes are the canonical fixed-width `r || s` representation. Parsing does
/// not normalize high-S signatures, so a high-S value remains high-S when viewed through
/// ``ecdsaSignature``.
public struct RecoverableSignature: Hashable, Sendable {
    private let canonicalCompactBytes: [UInt8]
    private let canonicalRecoveryID: Int
    private let canonicalECDSASignature: ECDSASignature

    /// Parses exactly 64 big-endian bytes containing `r || s` and a recovery ID in `0...3`.
    public init(compactBytes: [UInt8], recoveryID: Int) throws {
        guard compactBytes.count == 64 else {
            throw RecoverableSignatureError.invalidCompactByteCount(compactBytes.count)
        }
        guard (0...3).contains(recoveryID) else {
            throw RecoverableSignatureError.invalidRecoveryID(recoveryID)
        }

        let ecdsaSignature: ECDSASignature
        do {
            ecdsaSignature = try ECDSASignature(compactBytes: compactBytes)
            _ = try P256K.Recovery.ECDSASignature(
                compactRepresentation: compactBytes,
                recoveryId: Int32(recoveryID)
            )
        } catch {
            throw RecoverableSignatureError.invalidCompactSignature
        }

        self.canonicalCompactBytes = compactBytes
        self.canonicalRecoveryID = recoveryID
        self.canonicalECDSASignature = ecdsaSignature
    }

    /// The canonical 64-byte big-endian `r || s` encoding.
    public var compactBytes: [UInt8] {
        canonicalCompactBytes
    }

    /// The recovery ID in `0...3`.
    public var recoveryID: Int {
        canonicalRecoveryID
    }

    /// The same `r` and `s` values as a standard ECDSA signature.
    public var ecdsaSignature: ECDSASignature {
        canonicalECDSASignature
    }

    /// Recovers a candidate public key for an already-computed digest.
    ///
    /// Recovery is not authentication. A successful result is only a mathematical
    /// candidate; callers must separately establish that it is the expected public key.
    ///
    /// - Important: The nontrapping preflight mirrors the recovery failure conditions in
    ///   P256K 0.23.2's vendored libsecp256k1 0.7.1. Any dependency revision must re-audit
    ///   that equivalence before this method is shipped with the new dependency.
    public func recoverPublicKey(digest: Hash256) throws -> PublicKey {
        do {
            try preflightRecovery(digest: digest)

            let dependencySignature = try P256K.Recovery.ECDSASignature(
                compactRepresentation: canonicalCompactBytes,
                recoveryId: Int32(canonicalRecoveryID)
            )

            // P256K's initializer traps when libsecp256k1 recovery returns zero. The
            // preflight above rejects exactly that complete failure set before this call.
            let dependencyKey = P256K.Recovery.PublicKey(
                HashDigest(digest.bytes),
                signature: dependencySignature,
                format: .compressed
            )
            return try PublicKey(Array(dependencyKey.dataRepresentation))
        } catch let error as RecoverableSignatureError {
            throw error
        } catch {
            throw RecoverableSignatureError.recoveryFailed
        }
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.canonicalRecoveryID == rhs.canonicalRecoveryID
            && lhs.canonicalCompactBytes == rhs.canonicalCompactBytes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(canonicalCompactBytes)
        hasher.combine(canonicalRecoveryID)
    }

    private func preflightRecovery(digest: Hash256) throws {
        let r = Array(canonicalCompactBytes[0..<32])
        let s = Array(canonicalCompactBytes[32..<64])
        guard let x = Secp256k1RecoveryScalar.recoveryPointX(
            r: r,
            recoveryID: canonicalRecoveryID
        ) else {
            throw RecoverableSignatureError.recoveryFailed
        }

        let prefix = UInt8(0x02 | (canonicalRecoveryID & 1))
        let recoveryPoint: PublicKey
        do {
            recoveryPoint = try PublicKey([prefix] + x)
        } catch {
            throw RecoverableSignatureError.recoveryFailed
        }

        // libsecp256k1 computes Q = r^-1(sR - mG). Since r is nonzero,
        // Q is infinity exactly when the point checked here is infinity.
        do {
            let scaledRecoveryPoint = try recoveryPoint.multiplying(by: s)
            _ = try scaledRecoveryPoint.adding(
                tweak: Secp256k1RecoveryScalar.negatedMessage(digest.bytes)
            )
        } catch {
            throw RecoverableSignatureError.recoveryFailed
        }
    }
}

public extension PrivateKey {
    /// Deterministically signs an already-computed 32-byte digest for public-key recovery.
    ///
    /// P256K's digest overload delegates to libsecp256k1's RFC 6979 recoverable signer,
    /// returns a low-S signature, and does not hash the digest again.
    func signRecoverable(digest: Hash256) throws -> RecoverableSignature {
        let dependencyKey: P256K.Recovery.PrivateKey
        do {
            dependencyKey = try P256K.Recovery.PrivateKey(dataRepresentation: bytes)
        } catch {
            throw RecoverableSignatureError.signingFailed
        }

        let dependencySignature = dependencyKey.signature(for: HashDigest(digest.bytes))
        let compact = dependencySignature.compactRepresentation
        do {
            return try RecoverableSignature(
                compactBytes: Array(compact.signature),
                recoveryID: Int(compact.recoveryId)
            )
        } catch {
            throw RecoverableSignatureError.signingFailed
        }
    }
}

private enum Secp256k1RecoveryScalar {
    private static let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    // secp256k1 field prime minus group order. For recovery IDs 2 and 3,
    // libsecp256k1 requires r to be strictly below this value before using x = r + n.
    private static let fieldPrimeMinusOrder: [UInt8] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
        0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
    ]

    static func recoveryPointX(r: [UInt8], recoveryID: Int) -> [UInt8]? {
        guard recoveryID >= 2 else {
            return r
        }
        guard r.lexicographicallyPrecedes(fieldPrimeMinusOrder) else {
            return nil
        }
        return add(r, order)
    }

    static func negatedMessage(_ digest: [UInt8]) -> [UInt8] {
        let reduced = digest.lexicographicallyPrecedes(order)
            ? digest
            : subtract(digest, order)
        guard reduced.contains(where: { $0 != 0 }) else {
            return [UInt8](repeating: 0, count: 32)
        }
        return subtract(order, reduced)
    }

    private static func add(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var carry = UInt16(0)
        for index in stride(from: 31, through: 0, by: -1) {
            let sum = UInt16(lhs[index]) + UInt16(rhs[index]) + carry
            result[index] = UInt8(truncatingIfNeeded: sum)
            carry = sum >> 8
        }
        return result
    }

    private static func subtract(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = Int16(0)
        for index in stride(from: 31, through: 0, by: -1) {
            var difference = Int16(lhs[index]) - Int16(rhs[index]) - borrow
            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(difference)
        }
        return result
    }
}
