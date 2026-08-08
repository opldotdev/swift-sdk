/// A private key encoded in Bitcoin Wallet Import Format (WIF).
public struct WalletImportFormat:
    Hashable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let privateKey: PrivateKey
    public let network: BitcoinNetwork
    public let isCompressed: Bool

    /// Creates a WIF value from an already validated private key.
    public init(
        privateKey: PrivateKey,
        network: BitcoinNetwork,
        isCompressed: Bool = true
    ) {
        self.privateKey = privateKey
        self.network = network
        self.isCompressed = isCompressed
    }

    /// Parses a WIF string with a strict 34-byte payload limit.
    public init(_ text: String) throws {
        let payload: [UInt8]
        do {
            payload = try Base58Check.decode(text, maximumPayloadByteCount: 34)
        } catch let error as Base58CheckError {
            throw KeyFormatError.invalidEncoding(error)
        }

        guard payload.count == 33 || payload.count == 34 else {
            throw KeyFormatError.invalidPayloadByteCount(payload.count)
        }

        switch payload[0] {
        case 0x80:
            network = .mainnet
        case 0xef:
            network = .testnet
        default:
            throw KeyFormatError.unsupportedVersion(payload[0])
        }

        if payload.count == 34, payload[33] != 0x01 {
            throw KeyFormatError.invalidCompressionMarker(payload[33])
        }
        isCompressed = payload.count == 34

        do {
            privateKey = try PrivateKey(Array(payload[1..<33]))
        } catch let error as Secp256k1KeyError {
            throw KeyFormatError.invalidPrivateKey(error)
        }
    }

    /// The canonical Base58Check WIF encoding.
    public var encoded: String {
        var payload = [wifVersion]
        payload.append(contentsOf: privateKey.bytes)
        if isCompressed {
            payload.append(0x01)
        }
        return Base58Check.encode(payload)
    }

    /// A redacted description suitable for interpolation and diagnostic logging.
    /// Use ``encoded`` only when intentionally exporting the private key.
    public var description: String { "<redacted wallet import format>" }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(reflecting: description) }

    private var wifVersion: UInt8 {
        switch network {
        case .mainnet:
            0x80
        case .testnet:
            0xef
        }
    }
}
