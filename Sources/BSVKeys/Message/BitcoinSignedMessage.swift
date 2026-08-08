import BSVCore
import BSVCrypto

/// Failures produced while parsing, signing, or recovering Bitcoin Signed Messages.
public enum BitcoinSignedMessageError: Error, Equatable, Sendable {
    /// A wire signature was not exactly 65 bytes (`header || r || s`).
    case invalidByteCount(Int)
    /// Text was not strict, canonical, standard-padded Base64 for a BSM signature.
    case invalidBase64Encoding
    /// The compact-signature header was outside the legacy P2PKH range `27...34`.
    case invalidHeader(UInt8)
    /// Either compact ECDSA scalar was zero, out of range, or otherwise malformed.
    case invalidCompactSignature
    /// The secp256k1 implementation could not create a recoverable signature.
    case signingFailed
    /// No public-key candidate exists for the signature and framed message digest.
    case recoveryFailed
}

/// A legacy Bitcoin Signed Message compact signature.
public struct BitcoinMessageSignature: Hashable, Sendable {
    public static let byteCount = 65

    private let recoverableSignature: RecoverableSignature

    /// The compact ECDSA recovery identifier in `0...3`.
    public let recoveryID: Int

    /// Whether address verification hashes the recovered key's compressed serialization.
    public let usesCompressedPublicKey: Bool

    /// Parses an exact legacy BSM wire signature (`header || r || s`).
    public init(_ bytes: [UInt8]) throws {
        guard bytes.count == Self.byteCount else {
            throw BitcoinSignedMessageError.invalidByteCount(bytes.count)
        }

        let header = bytes[0]
        guard (27...34).contains(header) else {
            throw BitcoinSignedMessageError.invalidHeader(header)
        }

        let headerValue = Int(header) - 27
        let recoveryID = headerValue & 3
        let usesCompressedPublicKey = headerValue >= 4

        do {
            recoverableSignature = try RecoverableSignature(
                compactBytes: Array(bytes.dropFirst()),
                recoveryID: recoveryID
            )
        } catch {
            throw BitcoinSignedMessageError.invalidCompactSignature
        }

        self.recoveryID = recoveryID
        self.usesCompressedPublicKey = usesCompressedPublicKey
    }

    /// Parses strict, canonical, standard-padded Base64 containing one BSM signature.
    public init(base64Encoded text: String) throws {
        let decoded: [UInt8]
        do {
            decoded = try Base64Encoding.decode(
                text,
                alphabet: .standard,
                padding: .included,
                maximumDecodedByteCount: Self.byteCount
            )
        } catch {
            throw BitcoinSignedMessageError.invalidBase64Encoding
        }
        try self.init(decoded)
    }

    /// The canonical 65-byte BSM wire encoding.
    public var bytes: [UInt8] {
        let compressionOffset = usesCompressedPublicKey ? 4 : 0
        return [UInt8(27 + recoveryID + compressionOffset)]
            + recoverableSignature.compactBytes
    }

    /// The canonical standard-padded Base64 representation.
    public var base64Encoded: String {
        Base64Encoding.encode(bytes, alphabet: .standard, padding: .included)
    }

    /// Recovers the public-key candidate for the exact byte-oriented message.
    public func recoverPublicKey(message: [UInt8]) throws -> PublicKey {
        do {
            return try recoverableSignature.recoverPublicKey(
                digest: BitcoinSignedMessage.digest(message)
            )
        } catch {
            throw BitcoinSignedMessageError.recoveryFailed
        }
    }

    /// Verifies the message against a legacy address on that address's network.
    public func verifies(message: [UInt8], address: LegacyAddress) throws -> Bool {
        let publicKey = try recoverPublicKey(message: message)
        let recoveredAddress = LegacyAddress(
            publicKey: publicKey,
            network: address.network,
            compressed: usesCompressedPublicKey
        )
        return recoveredAddress == address
    }
}

/// Legacy Bitcoin Signed Message framing, signing, and verification.
public enum BitcoinSignedMessage {
    private static let prefix = Array("Bitcoin Signed Message:\n".utf8)

    /// Computes SHA256d over the canonical BSM CompactSize-framed preimage.
    public static func digest(_ message: [UInt8]) -> Hash256 {
        let preimage = CompactSize.encode(UInt64(prefix.count))
            + prefix
            + CompactSize.encode(UInt64(message.count))
            + message
        return BSVHashing.sha256d(preimage)
    }

    /// Signs an exact byte-oriented message using legacy BSM compact framing.
    public static func sign(
        _ message: [UInt8],
        using privateKey: PrivateKey,
        compressed: Bool = true
    ) throws -> BitcoinMessageSignature {
        let recoverable: RecoverableSignature
        do {
            recoverable = try privateKey.signRecoverable(digest: digest(message))
        } catch {
            throw BitcoinSignedMessageError.signingFailed
        }

        let compressionOffset = compressed ? 4 : 0
        let header = UInt8(27 + recoverable.recoveryID + compressionOffset)
        return try BitcoinMessageSignature([header] + recoverable.compactBytes)
    }

    /// Signs the exact UTF-8 bytes of a Swift string and returns padded Base64.
    public static func sign(
        _ message: String,
        using privateKey: PrivateKey,
        compressed: Bool = true
    ) throws -> String {
        try sign(Array(message.utf8), using: privateKey, compressed: compressed).base64Encoded
    }

    /// Verifies padded Base64 against the exact UTF-8 bytes and supplied legacy address.
    public static func verify(
        _ signature: String,
        message: String,
        address: LegacyAddress
    ) throws -> Bool {
        try BitcoinMessageSignature(base64Encoded: signature).verifies(
            message: Array(message.utf8),
            address: address
        )
    }
}
