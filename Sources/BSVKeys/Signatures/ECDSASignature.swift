import BSVCore
import P256K

/// Failures produced while parsing or creating a secp256k1 ECDSA signature.
public enum ECDSASignatureError: Error, Equatable, Sendable {
    /// Compact signatures are exactly 64 bytes (`r || s`).
    case invalidCompactByteCount(Int)
    /// A compact signature contains a zero or out-of-range scalar.
    case invalidCompactSignature
    /// The input is not one complete, canonical DER ECDSA signature.
    case invalidDEREncoding
    /// The pinned secp256k1 implementation could not create a signature.
    case signingFailed
}

/// A validated secp256k1 ECDSA signature with stable compact and DER encodings.
///
/// External high-S signatures remain high-S when parsed. They can be inspected
/// and reserialized, but verification returns `false`, as required by
/// libsecp256k1's non-malleable verification policy.
public struct ECDSASignature: Hashable, Sendable {
    private let canonicalCompactBytes: [UInt8]
    private let canonicalDERBytes: [UInt8]

    /// Parses exactly 64 big-endian bytes containing `r || s`.
    public init(compactBytes: [UInt8]) throws {
        guard compactBytes.count == 64 else {
            throw ECDSASignatureError.invalidCompactByteCount(compactBytes.count)
        }
        guard Secp256k1SignatureScalar.isValid(compactBytes[0..<32]),
              Secp256k1SignatureScalar.isValid(compactBytes[32..<64]) else {
            throw ECDSASignatureError.invalidCompactSignature
        }

        let dependencySignature: P256K.Signing.ECDSASignature
        do {
            dependencySignature = try P256K.Signing.ECDSASignature(
                compactRepresentation: compactBytes
            )
        } catch {
            throw ECDSASignatureError.invalidCompactSignature
        }

        self.init(validated: dependencySignature)
    }

    /// Parses one complete strict-DER `SEQUENCE { INTEGER r, INTEGER s }`.
    public init(derBytes: [UInt8]) throws {
        guard let structurallyDecoded = StrictECDSADER.decode(derBytes) else {
            throw ECDSASignatureError.invalidDEREncoding
        }

        let dependencySignature: P256K.Signing.ECDSASignature
        do {
            dependencySignature = try P256K.Signing.ECDSASignature(
                derRepresentation: derBytes
            )
        } catch {
            throw ECDSASignatureError.invalidDEREncoding
        }

        guard Array(dependencySignature.compactRepresentation) == structurallyDecoded else {
            throw ECDSASignatureError.invalidDEREncoding
        }
        self.init(validated: dependencySignature)
    }

    fileprivate init(validated dependencySignature: P256K.Signing.ECDSASignature) {
        self.canonicalCompactBytes = Array(dependencySignature.compactRepresentation)
        self.canonicalDERBytes = Array(dependencySignature.derRepresentation)
    }

    /// Parses the signature encoding accepted by Bitcoin Script. Strict mode
    /// requires canonical DER; compatibility mode accepts the pinned Go SDK's
    /// historical unsigned, padded one-byte-length BER form.
    package init(scriptBytes: [UInt8], strict: Bool) throws {
        if strict {
            try self.init(derBytes: scriptBytes)
            return
        }
        guard let compact = PermissiveECDSABER.decode(scriptBytes) else {
            throw ECDSASignatureError.invalidDEREncoding
        }
        try self.init(compactBytes: compact)
    }

    /// The canonical 64-byte big-endian `r || s` encoding.
    public var compactBytes: [UInt8] {
        canonicalCompactBytes
    }

    /// The canonical strict-DER encoding derived by the pinned secp256k1 library.
    public var derBytes: [UInt8] {
        canonicalDERBytes
    }

    fileprivate var dependencySignature: P256K.Signing.ECDSASignature? {
        try? P256K.Signing.ECDSASignature(
            compactRepresentation: canonicalCompactBytes
        )
    }

    package var isLowS: Bool {
        Array(canonicalCompactBytes[32..<64])
            .lexicographicallyPrecedesOrEqual(to: Secp256k1SignatureScalar.halfOrder)
    }

    package func verifiesInScript(publicKey: PublicKey, digest: Hash256) -> Bool {
        let compact = isLowS
            ? canonicalCompactBytes
            : Array(canonicalCompactBytes[..<32])
                + Secp256k1SignatureScalar.negatedScalar(
                    Array(canonicalCompactBytes[32..<64])
                )
        guard let signature = try? P256K.Signing.ECDSASignature(
                  compactRepresentation: compact
              ),
              let key = try? P256K.Signing.PublicKey(
                  dataRepresentation: publicKey.compressedBytes,
                  format: .compressed
              ) else {
            return false
        }
        return key.isValidSignature(signature, for: HashDigest(digest.bytes))
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.canonicalCompactBytes == rhs.canonicalCompactBytes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(canonicalCompactBytes)
    }
}

public extension PrivateKey {
    /// Deterministically signs an already-computed 32-byte digest.
    ///
    /// P256K's digest overload delegates to libsecp256k1's RFC 6979 signer and
    /// returns a low-S signature. The digest is not hashed again.
    func sign(digest: Hash256) throws -> ECDSASignature {
        let dependencyKey: P256K.Signing.PrivateKey
        do {
            dependencyKey = try P256K.Signing.PrivateKey(dataRepresentation: bytes)
        } catch {
            throw ECDSASignatureError.signingFailed
        }

        let dependencyDigest = HashDigest(digest.bytes)
        return ECDSASignature(validated: dependencyKey.signature(for: dependencyDigest))
    }
}

public extension PublicKey {
    /// Verifies a signature against an already-computed 32-byte digest.
    ///
    /// Signature mismatches, including otherwise well-formed high-S
    /// signatures, return `false`.
    func verify(_ signature: ECDSASignature, digest: Hash256) -> Bool {
        guard let dependencySignature = signature.dependencySignature,
              let dependencyKey = try? P256K.Signing.PublicKey(
                  dataRepresentation: compressedBytes,
                  format: .compressed
              ) else {
            return false
        }

        return dependencyKey.isValidSignature(
            dependencySignature,
            for: HashDigest(digest.bytes)
        )
    }
}

private enum Secp256k1SignatureScalar {
    static let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    static let halfOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ]

    static func isValid<C: Collection>(_ bytes: C) -> Bool where C.Element == UInt8 {
        guard bytes.count == 32, bytes.contains(where: { $0 != 0 }) else {
            return false
        }
        return bytes.lexicographicallyPrecedes(order)
    }

    static func negatedScalar(_ scalar: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var difference = Int(order[index]) - Int(scalar[index]) - borrow
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

private enum PermissiveECDSABER {
    static func decode(_ input: [UInt8]) -> [UInt8]? {
        guard input.count >= 8, input[0] == 0x30 else { return nil }
        let encodedCount = Int(input[1]) + 2
        guard encodedCount >= 8, encodedCount <= input.count else { return nil }
        let bytes = Array(input[..<encodedCount])
        var cursor = 2
        guard let r = decodeInteger(bytes, cursor: &cursor),
              let s = decodeInteger(bytes, cursor: &cursor),
              cursor == bytes.count else {
            return nil
        }
        return r + s
    }

    private static func decodeInteger(
        _ bytes: [UInt8],
        cursor: inout Int
    ) -> [UInt8]? {
        guard cursor + 2 <= bytes.count, bytes[cursor] == 0x02 else {
            return nil
        }
        let count = Int(bytes[cursor + 1])
        cursor += 2
        guard count > 0, count <= bytes.count - cursor else { return nil }
        var scalar = Array(bytes[cursor..<(cursor + count)])
        cursor += count
        while scalar.first == 0, scalar.count > 1 {
            scalar.removeFirst()
        }
        guard scalar.count <= 32 else { return nil }
        scalar.insert(contentsOf: repeatElement(0, count: 32 - scalar.count), at: 0)
        guard Secp256k1SignatureScalar.isValid(scalar) else { return nil }
        return scalar
    }
}

private extension Array where Element == UInt8 {
    func lexicographicallyPrecedesOrEqual(to other: [UInt8]) -> Bool {
        self == other || lexicographicallyPrecedes(other)
    }
}

private enum StrictECDSADER {
    static func decode(_ bytes: [UInt8]) -> [UInt8]? {
        // With two positive secp256k1 scalars, canonical DER is 8...72 bytes
        // and all lengths use the one-octet short form.
        guard (8...72).contains(bytes.count),
              bytes[0] == 0x30,
              bytes[1] < 0x80,
              Int(bytes[1]) == bytes.count - 2 else {
            return nil
        }

        var cursor = 2
        guard let r = decodeInteger(bytes, cursor: &cursor),
              let s = decodeInteger(bytes, cursor: &cursor),
              cursor == bytes.count else {
            return nil
        }
        return r + s
    }

    private static func decodeInteger(
        _ bytes: [UInt8],
        cursor: inout Int
    ) -> [UInt8]? {
        guard cursor < bytes.count, bytes[cursor] == 0x02 else {
            return nil
        }
        cursor += 1

        guard cursor < bytes.count else {
            return nil
        }
        let lengthOctet = bytes[cursor]
        cursor += 1

        guard lengthOctet > 0, lengthOctet < 0x80 else {
            return nil
        }
        let length = Int(lengthOctet)
        guard length <= 33, length <= bytes.count - cursor else {
            return nil
        }

        let integer = Array(bytes[cursor..<(cursor + length)])
        cursor += length

        guard let first = integer.first, first & 0x80 == 0 else {
            return nil
        }
        if integer.count > 1,
           first == 0,
           integer[1] & 0x80 == 0 {
            return nil
        }

        let magnitude = first == 0 ? Array(integer.dropFirst()) : integer
        guard magnitude.count <= 32 else {
            return nil
        }
        let scalar = [UInt8](repeating: 0, count: 32 - magnitude.count) + magnitude
        guard Secp256k1SignatureScalar.isValid(scalar) else {
            return nil
        }
        return scalar
    }
}
