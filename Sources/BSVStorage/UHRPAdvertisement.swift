import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import Foundation

/// Failures from decoding and authenticating a UHRP host advertisement.
///
/// Cases name the rule that failed. They never carry advertisement bytes.
public enum UHRPAdvertisementError: Error, Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    case invalidPushDrop(PushDropError)
    case unexpectedFieldCount(actual: Int)
    case payloadTooLarge(actual: Int, maximum: Int)
    case invalidHostIdentityKey
    case invalidHash
    case invalidURL
    case invalidExpiryTime
    case invalidFileSize
    case invalidSignatureEncoding
    case lockingKeyNotLinkedToHost
    case invalidSignature

    public var description: String {
        switch self {
        case .invalidPushDrop(let error):
            "UHRP advertisement is not a canonical PushDrop script (\(error))"
        case .unexpectedFieldCount(let actual):
            "UHRP advertisement must have 6 fields (found \(actual))"
        case .payloadTooLarge(let actual, let maximum):
            "UHRP advertisement payload exceeds its limit (\(actual) > \(maximum))"
        case .invalidHostIdentityKey:
            "UHRP advertisement host identity key is invalid"
        case .invalidHash:
            "UHRP advertisement hash is invalid"
        case .invalidURL:
            "UHRP advertisement must use a credential-free HTTPS URL"
        case .invalidExpiryTime:
            "UHRP advertisement expiry time is invalid"
        case .invalidFileSize:
            "UHRP advertisement file size is invalid"
        case .invalidSignatureEncoding:
            "UHRP advertisement signature is not canonical DER"
        case .lockingKeyNotLinkedToHost:
            "UHRP advertisement locking key is not linked to its host"
        case .invalidSignature:
            "UHRP advertisement signature is invalid"
        }
    }

    public var debugDescription: String { description }
}

/// One authenticated UHRP host advertisement.
///
/// This is the layout that `@bsv/sdk` 4.1.1 writes and that the TypeScript
/// `tm_uhrp` topic manager admits (`storage/UHRPAdvertisementValidation.ts`).
/// The script is a lock-before PushDrop with exactly six fields:
///
/// 0. host identity key (33-byte compressed public key)
/// 1. SHA-256 content hash (32 bytes)
/// 2. hosted file URL (UTF-8, HTTPS, at most 2048 bytes)
/// 3. expiry time in Unix seconds (canonical CompactSize, at least 1)
/// 4. file size in bytes (canonical CompactSize, at least 1)
/// 5. DER signature over fields 0 through 4 concatenated
///
/// The locking key must be the BRC-42 child of the host identity key for
/// invoice `2-uhrp advertisement-1` with the "anyone" key (scalar 1) as the
/// other party. The signature must verify under that same key.
public struct UHRPAdvertisement: Hashable, Sendable {
    /// BRC-43 security level of the advertisement protocol `[2, "uhrp advertisement"]`.
    public static let protocolSecurityLevel: UInt8 = 2
    /// BRC-43 name of the advertisement protocol.
    public static let protocolName = "uhrp advertisement"
    /// BRC-42 key ID used for every advertisement.
    public static let keyID = "1"
    /// The largest hosted-file URL, and so the largest field, in bytes.
    public static let maximumURLByteCount = 2_048
    /// The largest total field payload in bytes.
    public static let maximumPayloadByteCount = maximumURLByteCount + 256

    private static let fieldCount = 6
    private static let maximumSafeInteger: UInt64 = (1 << 53) - 1

    public let hostIdentityKey: PublicKey
    public let hash: Hash256
    public let hostedFileLocation: URL
    public let expiryTime: UInt64
    public let fileSize: UInt64
    public let lockingPublicKey: PublicKey
    public let signature: ECDSASignature

    /// Decodes one advertisement script and checks every TypeScript rule,
    /// including the BRC-42 key linkage and the host signature.
    public static func decode(_ script: Script) throws -> UHRPAdvertisement {
        let limits: PushDropLimits
        do {
            limits = try PushDropLimits(
                // One extra field lets a seven-field script fail with a
                // field-count error instead of a generic PushDrop error.
                maximumFieldCount: fieldCount + 1,
                maximumFieldByteCount: maximumURLByteCount,
                maximumScriptByteCount: 35 + maximumPayloadByteCount + (fieldCount + 1) * 3 + 4
            )
        } catch let error as PushDropError {
            throw UHRPAdvertisementError.invalidPushDrop(error)
        }

        let decoded: PushDropDecoded
        do {
            decoded = try PushDrop.decode(script, lockPosition: .beforeCompatibility, limits: limits)
        } catch let error as PushDropError {
            if case .fieldCountExceedsLimit(let actual, _) = error {
                throw UHRPAdvertisementError.unexpectedFieldCount(actual: actual)
            }
            throw UHRPAdvertisementError.invalidPushDrop(error)
        }
        let fields = decoded.fields
        guard fields.count == fieldCount else {
            throw UHRPAdvertisementError.unexpectedFieldCount(actual: fields.count)
        }
        let payload = fields.reduce(0) { $0 + $1.count }
        guard payload <= maximumPayloadByteCount else {
            throw UHRPAdvertisementError.payloadTooLarge(
                actual: payload,
                maximum: maximumPayloadByteCount
            )
        }

        let hostIdentityKey = try decodeHostIdentityKey(fields[0])
        guard fields[1].count == 32, let hash = try? Hash256(fields[1]) else {
            throw UHRPAdvertisementError.invalidHash
        }
        let hostedFileLocation = try decodeURL(fields[2])
        guard let expiryTime = positiveSafeInteger(fields[3]) else {
            throw UHRPAdvertisementError.invalidExpiryTime
        }
        guard let fileSize = positiveSafeInteger(fields[4]) else {
            throw UHRPAdvertisementError.invalidFileSize
        }
        guard (8...80).contains(fields[5].count),
            let signature = try? ECDSASignature(derBytes: fields[5]),
            signature.derBytes == fields[5]
        else {
            throw UHRPAdvertisementError.invalidSignatureEncoding
        }

        let expectedLockingKey = try linkedLockingKey(for: hostIdentityKey)
        guard expectedLockingKey == decoded.publicKey else {
            throw UHRPAdvertisementError.lockingKeyNotLinkedToHost
        }
        let signed = Array(fields[0..<5].joined())
        // TypeScript verification has no low-S rule, so a high-S signature
        // from another wallet is accepted here too.
        guard signature.verifiesInScript(
            publicKey: expectedLockingKey,
            digest: BSVHashing.sha256(signed)
        ) else {
            throw UHRPAdvertisementError.invalidSignature
        }

        return UHRPAdvertisement(
            hostIdentityKey: hostIdentityKey,
            hash: hash,
            hostedFileLocation: hostedFileLocation,
            expiryTime: expiryTime,
            fileSize: fileSize,
            lockingPublicKey: decoded.publicKey,
            signature: signature
        )
    }

    /// The key a host's advertisement must be locked to: the BRC-42 child of
    /// `hostIdentityKey` for invoice `2-uhrp advertisement-1`, derived with
    /// the "anyone" private key (scalar 1).
    public static func linkedLockingKey(for hostIdentityKey: PublicKey) throws -> PublicKey {
        let anyone = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        do {
            return try hostIdentityKey.derivedChild(
                with: anyone,
                invoiceNumber: "\(protocolSecurityLevel)-\(protocolName)-\(keyID)"
            )
        } catch {
            throw UHRPAdvertisementError.invalidHostIdentityKey
        }
    }

    private static func decodeHostIdentityKey(_ bytes: [UInt8]) throws -> PublicKey {
        guard bytes.count == 33, bytes[0] == 0x02 || bytes[0] == 0x03,
            let key = try? PublicKey(bytes),
            key.compressedBytes == bytes
        else {
            throw UHRPAdvertisementError.invalidHostIdentityKey
        }
        return key
    }

    private static func decodeURL(_ bytes: [UInt8]) throws -> URL {
        guard (1...maximumURLByteCount).contains(bytes.count),
            let text = String(bytes: bytes, encoding: .utf8),
            Array(text.utf8) == bytes,
            // TypeScript rejects any Unicode control character (\p{Cc}).
            !text.unicodeScalars.contains(where: {
                $0.value < 0x20 || (0x7f...0x9f).contains($0.value)
            }),
            let components = URLComponents(string: text),
            components.scheme?.lowercased() == "https",
            let host = components.host, !host.isEmpty,
            components.user?.isEmpty ?? true,
            components.password?.isEmpty ?? true,
            components.fragment?.isEmpty ?? true,
            let url = components.url
        else {
            throw UHRPAdvertisementError.invalidURL
        }
        return url
    }

    /// TypeScript `Reader.readVarIntNumStrict`: one canonical CompactSize,
    /// no trailing bytes, at least 1, at most `Number.MAX_SAFE_INTEGER`.
    private static func positiveSafeInteger(_ bytes: [UInt8]) -> UInt64? {
        guard let value = try? CompactSize.decode(bytes, canonicality: .required).value,
            value >= 1, value <= maximumSafeInteger
        else {
            return nil
        }
        return value
    }
}
