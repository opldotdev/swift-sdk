import BSVCore
import BSVCrypto

/// A legacy Base58Check pay-to-public-key-hash (P2PKH) address.
public struct LegacyAddress: Hashable, Sendable, CustomStringConvertible {
    public let publicKeyHash: Hash160
    public let network: BitcoinNetwork

    /// Creates an address from an exact 20-byte public-key hash.
    public init(publicKeyHash: Hash160, network: BitcoinNetwork) {
        self.publicKeyHash = publicKeyHash
        self.network = network
    }

    /// Creates an address by hashing a canonical SEC1 public-key serialization.
    public init(
        publicKey: PublicKey,
        network: BitcoinNetwork,
        compressed: Bool = true
    ) {
        let format: PublicKeyFormat = compressed ? .compressed : .uncompressed
        self.init(
            publicKeyHash: BSVHashing.hash160(publicKey.serialized(as: format)),
            network: network
        )
    }

    /// Parses a legacy P2PKH address with a strict 21-byte payload limit.
    public init(_ text: String) throws {
        let payload: [UInt8]
        do {
            payload = try Base58Check.decode(text, maximumPayloadByteCount: 21)
        } catch let error as Base58CheckError {
            throw KeyFormatError.invalidEncoding(error)
        }

        guard payload.count == 21 else {
            throw KeyFormatError.invalidPayloadByteCount(payload.count)
        }

        switch payload[0] {
        case 0x00:
            network = .mainnet
        case 0x6f:
            network = .testnet
        default:
            throw KeyFormatError.unsupportedVersion(payload[0])
        }

        publicKeyHash = try Hash160(Array(payload.dropFirst()))
    }

    /// The canonical Base58Check legacy P2PKH encoding.
    public var description: String {
        Base58Check.encode([addressVersion] + publicKeyHash.bytes)
    }

    private var addressVersion: UInt8 {
        switch network {
        case .mainnet:
            0x00
        case .testnet:
            0x6f
        }
    }
}
