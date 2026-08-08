import BSVCore
import BSVCrypto
import BSVKeys

/// A compatibility BIP-32 extended public key.
///
/// New protocol-key applications should use BRC-42 derivation from `BSVKeys`.
/// This type keeps standard mainnet and testnet BIP-32 serialization.
public struct ExtendedPublicKey: Hashable, Sendable, CustomStringConvertible {
    public let key: PublicKey
    public let chainCode: Hash256
    public let depth: UInt8
    public let parentFingerprint: UInt32
    public let childNumber: UInt32
    public let network: BitcoinNetwork

    /// Parses an exact 111-byte xpub/tpub Base58Check serialization.
    public init(_ serialized: String) throws {
        let payload = try BIP32Payload(serialized: serialized)
        guard payload.kind == .publicKey else {
            throw ExtendedKeyError.unexpectedKeyKind(
                expected: .publicKey,
                actual: payload.kind
            )
        }
        guard payload.keyData[0] == 0x02 || payload.keyData[0] == 0x03 else {
            throw ExtendedKeyError.invalidPublicKey
        }
        do {
            key = try PublicKey(payload.keyData)
        } catch {
            throw ExtendedKeyError.invalidPublicKey
        }
        chainCode = payload.chainCode
        depth = payload.depth
        parentFingerprint = payload.parentFingerprint
        childNumber = payload.childNumber
        network = payload.network
    }

    init(
        key: PublicKey,
        chainCode: Hash256,
        depth: UInt8,
        parentFingerprint: UInt32,
        childNumber: UInt32,
        network: BitcoinNetwork
    ) {
        self.key = key
        self.chainCode = chainCode
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childNumber = childNumber
        self.network = network
    }

    /// The fingerprint of this compressed public key.
    public var fingerprint: UInt32 {
        keyFingerprint(key)
    }

    /// The canonical xpub/tpub Base58Check text.
    public var serialized: String {
        serializeBIP32(
            network: network,
            kind: .publicKey,
            depth: depth,
            parentFingerprint: parentFingerprint,
            childNumber: childNumber,
            chainCode: chainCode,
            keyData: key.compressedBytes
        )
    }

    public var description: String { serialized }

    /// Derives the exact non-hardened serialized child number without retrying.
    public func derived(at childNumber: UInt32) throws -> Self {
        guard depth < UInt8.max else {
            throw ExtendedKeyError.depthExhausted
        }
        guard childNumber < HDChildNumber.hardenedOffset else {
            throw ExtendedKeyError.hardenedPublicDerivation(childNumber: childNumber)
        }
        var data = key.compressedBytes
        data.append(contentsOf: bytes(of: childNumber))
        let digest = BSVHashing.hmacSHA512(data, key: chainCode.bytes).bytes
        let tweak = Array(digest[..<32])
        let derivedKey: PublicKey
        do {
            derivedKey = try key.adding(tweak: tweak)
        } catch {
            throw ExtendedKeyError.derivationFailed(childNumber: childNumber)
        }
        return Self(
            key: derivedKey,
            chainCode: try Hash256(Array(digest[32...])),
            depth: depth + 1,
            parentFingerprint: fingerprint,
            childNumber: childNumber,
            network: network
        )
    }

    /// Derives an explicitly normal child; hardened children are rejected.
    public func derived(_ child: HDChildNumber) throws -> Self {
        try derived(at: child.rawValue)
    }

    /// Derives an absolute public path from a depth-zero receiver.
    public func derived(path: HDKeyPath) throws -> Self {
        guard path.root == .publicKey else {
            throw ExtendedKeyError.pathRootMismatch(expected: .publicKey, actual: path.root)
        }
        guard depth == 0 else {
            throw ExtendedKeyError.pathRequiresRootKey
        }
        var result = self
        for child in path.components {
            result = try result.derived(child)
        }
        return result
    }

    /// Parses and derives an absolute `M` path.
    public func derived(path: String) throws -> Self {
        try derived(path: HDKeyPath(path))
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.key == rhs.key
            && lhs.chainCode == rhs.chainCode
            && lhs.depth == rhs.depth
            && lhs.parentFingerprint == rhs.parentFingerprint
            && lhs.childNumber == rhs.childNumber
            && sameNetwork(lhs.network, rhs.network)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(key)
        hasher.combine(chainCode)
        hasher.combine(depth)
        hasher.combine(parentFingerprint)
        hasher.combine(childNumber)
        hashNetwork(network, into: &hasher)
    }
}
