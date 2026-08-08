import BSVCrypto
import BSVKeys
import BSVScript

/// Limits for decoding a signed SHIP or SLAP administration token.
public struct OverlayAdminTokenLimits: Hashable, Sendable {
    public let maximumScriptByteCount: Int
    public let maximumFieldByteCount: Int
    public let overlayLimits: OverlayLimits

    public init(
        maximumScriptByteCount: Int,
        maximumFieldByteCount: Int,
        overlayLimits: OverlayLimits = .standard
    ) throws {
        guard maximumScriptByteCount > 0, maximumFieldByteCount > 0 else {
            throw OverlayAdminTokenError.invalidLimits
        }
        self.maximumScriptByteCount = maximumScriptByteCount
        self.maximumFieldByteCount = maximumFieldByteCount
        self.overlayLimits = overlayLimits
    }

    private init(standard: Void) {
        maximumScriptByteCount = 64 * 1_024
        maximumFieldByteCount = 8 * 1_024
        overlayLimits = .standard
    }

    public static let standard = Self(standard: ())
}

/// Failures while strictly decoding an overlay administration token.
public enum OverlayAdminTokenError: Error, Equatable, Sendable {
    case invalidLimits
    case invalidPushDrop
    case unexpectedFieldCount(actual: Int, expected: Int)
    case invalidProtocol
    case invalidIdentityKey
    case invalidHost
    case invalidSubject
    case invalidSignature
}

/// The typed subject advertised by an overlay administration token.
public enum OverlayAdminSubject: Hashable, Sendable {
    case ship(OverlayTopic)
    case slap(OverlayService)

    public var overlayProtocol: OverlayProtocol {
        switch self {
        case .ship: .ship
        case .slap: .slap
        }
    }
}

/// A verified SHIP or SLAP administration advertisement.
///
/// The token's signature commits to the protocol, identity key, host, and
/// subject. It is verified against the PushDrop locking public key while
/// decoding, so a decoded value is safe for a later, caller-selected discovery
/// policy to evaluate.
public struct OverlayAdminToken: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let identityPublicKey: PublicKey
    public let lockingPublicKey: PublicKey
    public let host: OverlayHost
    public let subject: OverlayAdminSubject

    public var overlayProtocol: OverlayProtocol { subject.overlayProtocol }

    public var description: String { "<redacted overlay administration token>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    fileprivate init(
        identityPublicKey: PublicKey,
        lockingPublicKey: PublicKey,
        host: OverlayHost,
        subject: OverlayAdminSubject
    ) {
        self.identityPublicKey = identityPublicKey
        self.lockingPublicKey = lockingPublicKey
        self.host = host
        self.subject = subject
    }
}

/// Strict decoder for the signed Go-compatible overlay administration token.
///
/// Wallet construction and spending are intentionally excluded. This codec
/// only verifies the immutable on-chain advertisement required by a future
/// resolver or broadcaster policy.
public enum OverlayAdminTokenCodec {
    private static let dataFieldCount = 4
    private static let signedFieldCount = 5

    public static func decode(
        _ script: Script,
        limits: OverlayAdminTokenLimits = .standard
    ) throws -> OverlayAdminToken {
        let pushDropLimits: PushDropLimits
        do {
            pushDropLimits = try PushDropLimits(
                maximumFieldCount: signedFieldCount,
                maximumFieldByteCount: limits.maximumFieldByteCount,
                maximumScriptByteCount: limits.maximumScriptByteCount
            )
        } catch {
            throw OverlayAdminTokenError.invalidLimits
        }

        let decoded: PushDropDecoded
        do {
            decoded = try PushDrop.decode(
                script,
                lockPosition: .beforeCompatibility,
                limits: pushDropLimits
            )
        } catch {
            throw OverlayAdminTokenError.invalidPushDrop
        }
        guard decoded.fields.count == signedFieldCount else {
            throw OverlayAdminTokenError.unexpectedFieldCount(
                actual: decoded.fields.count,
                expected: signedFieldCount
            )
        }

        let fields = decoded.fields
        let subject = try decodeSubject(
            protocolBytes: fields[0],
            subjectBytes: fields[3],
            limits: limits.overlayLimits
        )
        let identityPublicKey = try decodeIdentityKey(fields[1])
        let host = try decodeHost(fields[2], limits: limits.overlayLimits)
        let signature = try decodeSignature(fields[4])
        let digest = BSVHashing.sha256(try signingPayload(fields[0..<dataFieldCount]))
        guard decoded.publicKey.verify(signature, digest: digest) else {
            throw OverlayAdminTokenError.invalidSignature
        }

        return OverlayAdminToken(
            identityPublicKey: identityPublicKey,
            lockingPublicKey: decoded.publicKey,
            host: host,
            subject: subject
        )
    }

    private static func decodeSubject(
        protocolBytes: [UInt8],
        subjectBytes: [UInt8],
        limits: OverlayLimits
    ) throws -> OverlayAdminSubject {
        guard let protocolText = String(bytes: protocolBytes, encoding: .utf8) else {
            throw OverlayAdminTokenError.invalidProtocol
        }
        guard let subjectText = String(bytes: subjectBytes, encoding: .utf8) else {
            throw OverlayAdminTokenError.invalidSubject
        }
        switch protocolText {
        case OverlayProtocol.ship.rawValue:
            do {
                return .ship(try OverlayTopic(rawValue: subjectText, limits: limits))
            } catch {
                throw OverlayAdminTokenError.invalidSubject
            }
        case OverlayProtocol.slap.rawValue:
            do {
                return .slap(try OverlayService(rawValue: subjectText, limits: limits))
            } catch {
                throw OverlayAdminTokenError.invalidSubject
            }
        default:
            throw OverlayAdminTokenError.invalidProtocol
        }
    }

    private static func decodeIdentityKey(_ bytes: [UInt8]) throws -> PublicKey {
        guard bytes.count == 33 else { throw OverlayAdminTokenError.invalidIdentityKey }
        do {
            return try PublicKey(bytes)
        } catch {
            throw OverlayAdminTokenError.invalidIdentityKey
        }
    }

    private static func decodeHost(
        _ bytes: [UInt8],
        limits: OverlayLimits
    ) throws -> OverlayHost {
        guard let text = String(bytes: bytes, encoding: .utf8) else {
            throw OverlayAdminTokenError.invalidHost
        }
        do {
            return try OverlayHost(rawValue: text, limits: limits)
        } catch {
            throw OverlayAdminTokenError.invalidHost
        }
    }

    private static func decodeSignature(_ bytes: [UInt8]) throws -> ECDSASignature {
        do {
            let signature = try ECDSASignature(derBytes: bytes)
            guard signature.derBytes == bytes else {
                throw OverlayAdminTokenError.invalidSignature
            }
            return signature
        } catch let error as OverlayAdminTokenError {
            throw error
        } catch {
            throw OverlayAdminTokenError.invalidSignature
        }
    }

    private static func signingPayload(_ fields: ArraySlice<[UInt8]>) throws -> [UInt8] {
        var byteCount = 0
        for field in fields {
            let (next, overflow) = byteCount.addingReportingOverflow(field.count)
            guard !overflow else { throw OverlayAdminTokenError.invalidSignature }
            byteCount = next
        }
        var payload: [UInt8] = []
        payload.reserveCapacity(byteCount)
        for field in fields {
            payload.append(contentsOf: field)
        }
        return payload
    }
}
