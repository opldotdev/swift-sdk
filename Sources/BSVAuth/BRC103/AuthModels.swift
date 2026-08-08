import BSVKeys
import BSVWallet
import Foundation

public typealias AuthenticationWallet = WalletPublicKeyProviding & WalletSignatureOperations

/// The certificate types, certifiers, and disclosed fields that a peer requests.
///
/// An instance is always nonempty. Use `nil` on `AuthMessage` when no
/// certificates are requested.
public struct AuthRequestedCertificateSet:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    public let certifiers: [PublicKey]
    public let certificateTypes: [CertificateTypeID: [CertificateFieldName]]

    public init(
        certifiers: [PublicKey],
        certificateTypes: [CertificateTypeID: [CertificateFieldName]],
        limits: AuthLimits = .standard
    ) throws {
        guard !certifiers.isEmpty, !certificateTypes.isEmpty,
            certifiers.count <= limits.maximumCertificateCertifierCount,
            certificateTypes.count <= limits.maximumCertificateTypeCount,
            Set(certifiers).count == certifiers.count
        else { throw AuthError.invalidCertificateRequest }

        let (certifierBytes, certifierOverflow) = certifiers.count.multipliedReportingOverflow(
            by: 33)
        guard !certifierOverflow,
            certifierBytes <= limits.maximumCertificateAggregateBytes
        else { throw AuthError.resourceLimit }
        var aggregate = certifierBytes
        for fields in certificateTypes.values {
            guard !fields.isEmpty,
                fields.count <= limits.maximumCertificateFieldCount,
                Set(fields).count == fields.count
            else { throw AuthError.invalidCertificateRequest }
            let (fieldBytes, overflow) = fields.reduce(into: (0, false)) { result, field in
                let (sum, didOverflow) = result.0.addingReportingOverflow(field.value.utf8.count)
                result = (sum, result.1 || didOverflow)
            }
            let (next, aggregateOverflow) = aggregate.addingReportingOverflow(32 + fieldBytes)
            guard !overflow, !aggregateOverflow,
                next <= limits.maximumCertificateAggregateBytes
            else { throw AuthError.resourceLimit }
            aggregate = next
        }

        self.certifiers = certifiers
        self.certificateTypes = certificateTypes
    }

    public var description: String { "<redacted requested certificate set>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// A certificate that passed BRC-52 verification and request matching.
public struct AuthValidatedCertificate:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    public let certificate: Certificate
    public let disclosedFields: [CertificateFieldName: String]

    init(
        certificate: Certificate,
        disclosedFields: [CertificateFieldName: String]
    ) {
        self.certificate = certificate
        self.disclosedFields = disclosedFields
    }

    public var description: String { "<redacted validated certificate>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

public struct AuthSessionID: Hashable, Sendable {
    fileprivate let value: UUID
    public init() { value = UUID() }
}

public enum AuthSessionState: String, Equatable, Sendable {
    case challengeSent, responseSentAwaitingPeerProof, authenticated
}
public struct AuthSessionSnapshot: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let id: AuthSessionID
    public let state: AuthSessionState
    public let peer: PublicKey?
    public let sessionNonce: String
    public var description: String { "<redacted auth session>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
public struct AuthReceivedMessage: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let sessionID: AuthSessionID
    public let peer: PublicKey
    public let payload: [UInt8]
    public var description: String { "<redacted auth received message>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
public struct AuthReceivedCertificateRequest:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    public let sessionID: AuthSessionID
    public let peer: PublicKey
    public let request: AuthRequestedCertificateSet
    public var description: String { "<redacted received certificate request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
public struct AuthReceivedCertificateResponse:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    /// The peer response signature is valid. Call
    /// `AuthCertificateExchange.validate` before you trust the certificates or
    /// disclosed fields.
    public let sessionID: AuthSessionID
    public let peer: PublicKey
    public let requested: AuthRequestedCertificateSet
    public let certificates: [VerifiableCertificate]
    public var description: String { "<redacted received certificate response>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
public enum AuthPeerAction: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    case send(AuthMessage)
    case deliver(AuthReceivedMessage)
    case certificateRequest(AuthReceivedCertificateRequest)
    case certificateResponse(AuthReceivedCertificateResponse)
    public var description: String { "<redacted auth peer action>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
public enum AuthMessageType: String, Sendable {
    case initialRequest, initialResponse, certificateRequest, certificateResponse, general
}

public struct AuthMessage: Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let version: String
    public let messageType: AuthMessageType
    public let identityKey: PublicKey
    public let nonce: String?
    public let initialNonce: String?
    public let yourNonce: String?
    public let payload: [UInt8]?
    public let signature: [UInt8]?
    public let certificates: [VerifiableCertificate]?
    public let requestedCertificates: AuthRequestedCertificateSet?
    public init(
        version: String = "0.1", messageType: AuthMessageType, identityKey: PublicKey,
        nonce: String? = nil, initialNonce: String? = nil, yourNonce: String? = nil,
        payload: [UInt8]? = nil, signature: [UInt8]? = nil,
        certificates: [VerifiableCertificate]? = nil,
        requestedCertificates: AuthRequestedCertificateSet? = nil
    ) {
        self.version = version
        self.messageType = messageType
        self.identityKey = identityKey
        self.nonce = nonce
        self.initialNonce = initialNonce
        self.yourNonce = yourNonce
        self.payload = payload
        self.signature = signature
        self.certificates = certificates
        self.requestedCertificates = requestedCertificates
    }
    public var description: String { "<redacted auth message>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

public struct AuthLimits: Equatable, Sendable {
    public static let maximumAllowedJSONBytes = 64 << 20
    public static let maximumAllowedPayloadBytes = 16 << 20
    public static let maximumAllowedSessions = 65_536
    public static let maximumAllowedSessionsPerIdentity = 4_096
    public static let maximumAllowedPendingSessions = 65_536
    public static let maximumAllowedMessages = 1_000_000
    public static let maximumAllowedCertificateCount = 1_024
    public static let maximumAllowedCertificateCertifierCount = 1_024
    public static let maximumAllowedCertificateTypeCount = 1_024
    public static let maximumAllowedCertificateFieldCount = 4_096
    public static let maximumAllowedCertificateAggregateBytes = 64 << 20

    public let maximumJSONBytes: Int
    public let maximumPayloadBytes: Int
    public let maximumSessions: Int
    public let maximumSessionsPerIdentity: Int
    public let maximumPendingSessions: Int
    public let maximumMessages: Int
    public let maximumCertificateCount: Int
    public let maximumCertificateCertifierCount: Int
    public let maximumCertificateTypeCount: Int
    public let maximumCertificateFieldCount: Int
    public let maximumCertificateAggregateBytes: Int
    public let certificateLimits: CertificateLimits
    public let handshakeTimeout: Duration
    public init(
        maximumJSONBytes: Int = 8 << 20, maximumPayloadBytes: Int = 1 << 20,
        maximumSessions: Int = 1024, maximumSessionsPerIdentity: Int = 8,
        maximumPendingSessions: Int = 128, maximumMessages: Int = 4096,
        maximumCertificateCount: Int = 64, maximumCertificateCertifierCount: Int = 64,
        maximumCertificateTypeCount: Int = 64, maximumCertificateFieldCount: Int = 256,
        maximumCertificateAggregateBytes: Int = 8 << 20,
        certificateLimits: CertificateLimits = .standard,
        handshakeTimeout: Duration = .seconds(30)
    ) throws {
        guard (0...Self.maximumAllowedJSONBytes).contains(maximumJSONBytes),
            (0...Self.maximumAllowedPayloadBytes).contains(maximumPayloadBytes),
            (0...Self.maximumAllowedSessions).contains(maximumSessions),
            (0...Self.maximumAllowedSessionsPerIdentity).contains(maximumSessionsPerIdentity),
            (0...Self.maximumAllowedPendingSessions).contains(maximumPendingSessions),
            (0...Self.maximumAllowedMessages).contains(maximumMessages),
            (0...Self.maximumAllowedCertificateCount).contains(maximumCertificateCount),
            (0...Self.maximumAllowedCertificateCertifierCount).contains(
                maximumCertificateCertifierCount
            ),
            (0...Self.maximumAllowedCertificateTypeCount).contains(maximumCertificateTypeCount),
            (0...Self.maximumAllowedCertificateFieldCount).contains(
                maximumCertificateFieldCount
            ),
            (0...Self.maximumAllowedCertificateAggregateBytes).contains(
                maximumCertificateAggregateBytes
            ),
            handshakeTimeout > .zero
        else { throw AuthError.resourceLimit }
        self.maximumJSONBytes = maximumJSONBytes
        self.maximumPayloadBytes = maximumPayloadBytes
        self.maximumSessions = maximumSessions
        self.maximumSessionsPerIdentity = maximumSessionsPerIdentity
        self.maximumPendingSessions = maximumPendingSessions
        self.maximumMessages = maximumMessages
        self.maximumCertificateCount = maximumCertificateCount
        self.maximumCertificateCertifierCount = maximumCertificateCertifierCount
        self.maximumCertificateTypeCount = maximumCertificateTypeCount
        self.maximumCertificateFieldCount = maximumCertificateFieldCount
        self.maximumCertificateAggregateBytes = maximumCertificateAggregateBytes
        self.certificateLimits = certificateLimits
        self.handshakeTimeout = handshakeTimeout
    }
    private init(standard: Void) {
        maximumJSONBytes = 8 << 20
        maximumPayloadBytes = 1 << 20
        maximumSessions = 1024
        maximumSessionsPerIdentity = 8
        maximumPendingSessions = 128
        maximumMessages = 4096
        maximumCertificateCount = 64
        maximumCertificateCertifierCount = 64
        maximumCertificateTypeCount = 64
        maximumCertificateFieldCount = 256
        maximumCertificateAggregateBytes = 8 << 20
        certificateLimits = .standard
        handshakeTimeout = .seconds(30)
    }

    public static let standard = AuthLimits(standard: ())
}

public enum AuthError: Error, Equatable, Sendable {
    case invalidMessage, invalidNonce, invalidSignature, replay, sessionNotFound, unexpectedMessage,
        peerMismatch, notAuthenticated, certificateExchangeUnavailable, invalidCertificateRequest,
        certificateValidationFailed, resourceLimit, handshakeTimedOut, randomGenerationFailed
}
