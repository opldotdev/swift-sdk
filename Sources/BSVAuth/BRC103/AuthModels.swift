import BSVKeys
import BSVWallet
import Foundation

public typealias AuthenticationWallet = WalletPublicKeyProviding & WalletSignatureOperations

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
public enum AuthPeerAction: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    case send(AuthMessage)
    case deliver(AuthReceivedMessage)
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
    public let hasCertificates: Bool
    public let hasRequestedCertificates: Bool
    public init(
        version: String = "0.1", messageType: AuthMessageType, identityKey: PublicKey,
        nonce: String? = nil, initialNonce: String? = nil, yourNonce: String? = nil,
        payload: [UInt8]? = nil, signature: [UInt8]? = nil, hasCertificates: Bool = false,
        hasRequestedCertificates: Bool = false
    ) {
        self.version = version
        self.messageType = messageType
        self.identityKey = identityKey
        self.nonce = nonce
        self.initialNonce = initialNonce
        self.yourNonce = yourNonce
        self.payload = payload
        self.signature = signature
        self.hasCertificates = hasCertificates
        self.hasRequestedCertificates = hasRequestedCertificates
    }
    public var description: String { "<redacted auth message>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

public struct AuthLimits: Equatable, Sendable {
    public let maximumJSONBytes: Int
    public let maximumPayloadBytes: Int
    public let maximumSessions: Int
    public let maximumSessionsPerIdentity: Int
    public let maximumPendingSessions: Int
    public let maximumMessages: Int
    public let handshakeTimeout: Duration
    public init(
        maximumJSONBytes: Int = 8 << 20, maximumPayloadBytes: Int = 1 << 20,
        maximumSessions: Int = 1024, maximumSessionsPerIdentity: Int = 8,
        maximumPendingSessions: Int = 128, maximumMessages: Int = 4096,
        handshakeTimeout: Duration = .seconds(30)
    ) throws {
        guard maximumJSONBytes >= 0, maximumPayloadBytes >= 0, maximumSessions >= 0,
            maximumSessionsPerIdentity >= 0, maximumPendingSessions >= 0, maximumMessages >= 0,
            handshakeTimeout > .zero
        else { throw AuthError.resourceLimit }
        self.maximumJSONBytes = maximumJSONBytes
        self.maximumPayloadBytes = maximumPayloadBytes
        self.maximumSessions = maximumSessions
        self.maximumSessionsPerIdentity = maximumSessionsPerIdentity
        self.maximumPendingSessions = maximumPendingSessions
        self.maximumMessages = maximumMessages
        self.handshakeTimeout = handshakeTimeout
    }
    private init(standard: Void) {
        maximumJSONBytes = 8 << 20
        maximumPayloadBytes = 1 << 20
        maximumSessions = 1024
        maximumSessionsPerIdentity = 8
        maximumPendingSessions = 128
        maximumMessages = 4096
        handshakeTimeout = .seconds(30)
    }

    public static let standard = AuthLimits(standard: ())
}

public enum AuthError: Error, Equatable, Sendable {
    case invalidMessage, invalidNonce, invalidSignature, replay, sessionNotFound, unexpectedMessage,
        peerMismatch, notAuthenticated, certificateExchangeUnavailable, resourceLimit,
        handshakeTimedOut, randomGenerationFailed
}
