import BSVCore
import BSVCrypto

/// A BIP-32 extended private key with standard mainnet/testnet serialization.
///
/// Master seeds are restricted to BIP-32's recommended 16...64-byte range.
/// Swift arrays do not guarantee zeroization; avoid retaining unnecessary copies
/// of seeds, private keys, and derived HMAC input.
public struct ExtendedPrivateKey: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible {
    public let key: PrivateKey
    public let chainCode: Hash256
    public let depth: UInt8
    public let parentFingerprint: UInt32
    public let childNumber: UInt32
    public let network: BitcoinNetwork

    /// Generates a depth-zero master extended private key from a 16...64-byte seed.
    public init(seed: [UInt8], network: BitcoinNetwork) throws {
        guard (16...64).contains(seed.count) else {
            throw ExtendedKeyError.invalidSeedByteCount(seed.count)
        }
        let digest = BSVHashing.hmacSHA512(seed, key: Array("Bitcoin seed".utf8)).bytes
        do {
            key = try PrivateKey(Array(digest[..<32]))
        } catch {
            throw ExtendedKeyError.invalidMasterKey
        }
        chainCode = try Hash256(Array(digest[32...]))
        depth = 0
        parentFingerprint = 0
        childNumber = 0
        self.network = network
    }

    /// Parses an exact xprv/tprv Base58Check serialization.
    public init(_ serialized: String) throws {
        let payload = try BIP32Payload(serialized: serialized)
        guard payload.kind == .privateKey else {
            throw ExtendedKeyError.unexpectedKeyKind(
                expected: .privateKey,
                actual: payload.kind
            )
        }
        guard payload.keyData[0] == 0 else {
            throw ExtendedKeyError.invalidPrivateKeyMarker(payload.keyData[0])
        }
        do {
            key = try PrivateKey(Array(payload.keyData.dropFirst()))
        } catch {
            throw ExtendedKeyError.invalidPrivateKey
        }
        chainCode = payload.chainCode
        depth = payload.depth
        parentFingerprint = payload.parentFingerprint
        childNumber = payload.childNumber
        network = payload.network
    }

    init(
        key: PrivateKey,
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

    /// The corresponding extended public key, preserving all BIP-32 metadata.
    public var neutered: ExtendedPublicKey {
        ExtendedPublicKey(
            key: key.publicKey,
            chainCode: chainCode,
            depth: depth,
            parentFingerprint: parentFingerprint,
            childNumber: childNumber,
            network: network
        )
    }

    /// The fingerprint of this key's compressed public key.
    public var fingerprint: UInt32 {
        keyFingerprint(key.publicKey)
    }

    /// The canonical xprv/tprv Base58Check text.
    public var serialized: String {
        serializeBIP32(
            network: network,
            kind: .privateKey,
            depth: depth,
            parentFingerprint: parentFingerprint,
            childNumber: childNumber,
            chainCode: chainCode,
            keyData: [0] + key.bytes
        )
    }

    /// A redacted description suitable for interpolation and diagnostic logging.
    /// Use ``serialized`` only when intentionally exporting the subtree secret.
    public var description: String { "<redacted extended private key>" }

    public var debugDescription: String { description }

    /// Derives the exact serialized child number without retrying another index.
    public func derived(at childNumber: UInt32) throws -> Self {
        guard depth < UInt8.max else {
            throw ExtendedKeyError.depthExhausted
        }
        let child = HDChildNumber(rawValue: childNumber)
        var data = child.isHardened ? [UInt8(0)] + key.bytes : key.publicKey.compressedBytes
        data.append(contentsOf: bytes(of: childNumber))
        let digest = BSVHashing.hmacSHA512(data, key: chainCode.bytes).bytes
        let tweak = Array(digest[..<32])
        let derivedKey: PrivateKey
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

    /// Derives an explicitly normal or hardened child number.
    public func derived(_ child: HDChildNumber) throws -> Self {
        try derived(at: child.rawValue)
    }

    /// Derives an absolute private path from a depth-zero receiver.
    public func derived(path: HDKeyPath) throws -> Self {
        guard path.root == .privateKey else {
            throw ExtendedKeyError.pathRootMismatch(expected: .privateKey, actual: path.root)
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

    /// Parses and derives an absolute `m` path.
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
