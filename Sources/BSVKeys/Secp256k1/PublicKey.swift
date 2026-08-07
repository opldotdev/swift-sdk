import P256K

/// Standard SEC1 serialization formats exposed by the SDK.
public enum PublicKeyFormat: Sendable {
    case compressed
    case uncompressed
}

/// A validated secp256k1 public point with canonical SEC1 serializations.
public struct PublicKey: Hashable, Sendable {
    private let canonicalCompressedBytes: [UInt8]
    private let canonicalUncompressedBytes: [UInt8]

    /// Parses compressed, uncompressed, or Go-compatible hybrid SEC1 bytes.
    public init(_ sec1Bytes: [UInt8]) throws {
        let format: P256K.Format
        var normalizedBytes = sec1Bytes

        switch sec1Bytes.count {
        case 33:
            let prefix = sec1Bytes[0]
            guard prefix == 0x02 || prefix == 0x03 else {
                throw Secp256k1KeyError.invalidPublicKeyPrefix(prefix)
            }
            format = .compressed

        case 65:
            let prefix = sec1Bytes[0]
            switch prefix {
            case 0x04:
                break
            case 0x06, 0x07:
                let yLeastSignificantByte = sec1Bytes[64]
                guard (prefix & 1) == (yLeastSignificantByte & 1) else {
                    throw Secp256k1KeyError.invalidHybridParity
                }
                normalizedBytes[0] = 0x04
            default:
                throw Secp256k1KeyError.invalidPublicKeyPrefix(prefix)
            }
            format = .uncompressed

        default:
            throw Secp256k1KeyError.invalidPublicKeyByteCount(sec1Bytes.count)
        }

        let dependencyKey: P256K.Signing.PublicKey
        do {
            dependencyKey = try P256K.Signing.PublicKey(
                dataRepresentation: normalizedBytes,
                format: format
            )
        } catch {
            throw Secp256k1KeyError.invalidPublicKey
        }

        self.init(validated: dependencyKey)
    }

    init(validated dependencyKey: P256K.Signing.PublicKey) {
        let compressedKey = P256K.Signing.PublicKey(xonlyKey: dependencyKey.xonly)
        self.canonicalCompressedBytes = Array(compressedKey.dataRepresentation)
        self.canonicalUncompressedBytes = Array(dependencyKey.uncompressedRepresentation)
    }

    /// The canonical 33-byte compressed SEC1 serialization.
    public var compressedBytes: [UInt8] {
        canonicalCompressedBytes
    }

    /// The canonical 65-byte uncompressed SEC1 serialization.
    public var uncompressedBytes: [UInt8] {
        canonicalUncompressedBytes
    }

    /// Serializes this point in a standard SEC1 format.
    public func serialized(as format: PublicKeyFormat) -> [UInt8] {
        switch format {
        case .compressed:
            canonicalCompressedBytes
        case .uncompressed:
            canonicalUncompressedBytes
        }
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.canonicalCompressedBytes == rhs.canonicalCompressedBytes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(canonicalCompressedBytes)
    }
}
