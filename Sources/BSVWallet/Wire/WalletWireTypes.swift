import BSVCore
import BSVKeys

/// Resource bounds applied before wallet-wire data is copied or decoded.
public struct WalletWireLimits: Hashable, Sendable {
    public static let hardMaximumOriginatorUTF8ByteCount = 255

    public static let standard = WalletWireLimits(
        validatedFrame: 16_777_216,
        originator: 255,
        payload: 8_388_608,
        text: 2_000,
        remoteMessage: 2_000,
        remoteStack: 8_192,
        abi: .standard,
        crypto: .standard
    )

    public let maximumFrameByteCount: Int
    public let maximumOriginatorUTF8ByteCount: Int
    public let maximumPayloadByteCount: Int
    public let maximumTextUTF8ByteCount: Int
    public let maximumRemoteMessageUTF8ByteCount: Int
    public let maximumRemoteStackUTF8ByteCount: Int
    public let abiLimits: WalletABILimits
    public let cryptoLimits: WalletCryptoLimits

    public init(
        maximumFrameByteCount: Int = 16_777_216,
        maximumOriginatorUTF8ByteCount: Int = 255,
        maximumPayloadByteCount: Int = 8_388_608,
        maximumTextUTF8ByteCount: Int = 2_000,
        maximumRemoteMessageUTF8ByteCount: Int = 2_000,
        maximumRemoteStackUTF8ByteCount: Int = 8_192,
        abiLimits: WalletABILimits = .standard,
        cryptoLimits: WalletCryptoLimits = .standard
    ) throws {
        let namedValues = [
            ("maximumFrameByteCount", maximumFrameByteCount),
            ("maximumOriginatorUTF8ByteCount", maximumOriginatorUTF8ByteCount),
            ("maximumPayloadByteCount", maximumPayloadByteCount),
            ("maximumTextUTF8ByteCount", maximumTextUTF8ByteCount),
            ("maximumRemoteMessageUTF8ByteCount", maximumRemoteMessageUTF8ByteCount),
            ("maximumRemoteStackUTF8ByteCount", maximumRemoteStackUTF8ByteCount),
        ]
        if let invalid = namedValues.first(where: { $0.1 < 0 }) {
            throw WalletWireError.invalidLimit(name: invalid.0, value: invalid.1)
        }
        guard maximumOriginatorUTF8ByteCount <= Self.hardMaximumOriginatorUTF8ByteCount else {
            throw WalletWireError.invalidLimit(
                name: "maximumOriginatorUTF8ByteCount",
                value: maximumOriginatorUTF8ByteCount
            )
        }
        guard maximumPayloadByteCount <= maximumFrameByteCount,
              maximumTextUTF8ByteCount <= maximumFrameByteCount,
              maximumRemoteMessageUTF8ByteCount <= maximumFrameByteCount,
              maximumRemoteStackUTF8ByteCount <= maximumFrameByteCount else {
            throw WalletWireError.invalidLimit(name: "wire limit relation", value: -1)
        }
        self.init(
            validatedFrame: maximumFrameByteCount,
            originator: maximumOriginatorUTF8ByteCount,
            payload: maximumPayloadByteCount,
            text: maximumTextUTF8ByteCount,
            remoteMessage: maximumRemoteMessageUTF8ByteCount,
            remoteStack: maximumRemoteStackUTF8ByteCount,
            abi: abiLimits,
            crypto: cryptoLimits
        )
    }

    private init(
        validatedFrame: Int,
        originator: Int,
        payload: Int,
        text: Int,
        remoteMessage: Int,
        remoteStack: Int,
        abi: WalletABILimits,
        crypto: WalletCryptoLimits
    ) {
        maximumFrameByteCount = validatedFrame
        maximumOriginatorUTF8ByteCount = originator
        maximumPayloadByteCount = payload
        maximumTextUTF8ByteCount = text
        maximumRemoteMessageUTF8ByteCount = remoteMessage
        maximumRemoteStackUTF8ByteCount = remoteStack
        abiLimits = abi
        cryptoLimits = crypto
    }
}

/// Strict wallet-wire validation failures. Cases carry sizes and field names,
/// never payload bytes or decoded secret text.
public enum WalletWireError: Error, Equatable, Sendable {
    case invalidLimit(name: String, value: Int)
    case invalidCall(UInt8)
    case invalidDiscriminator(kind: String, value: UInt8)
    case invalidUTF8(kind: String)
    case byteLimitExceeded(kind: String, actual: Int, maximum: Int)
    case countLimitExceeded(kind: String, actual: UInt64, maximum: Int)
    case textLimitExceeded(kind: String, actual: Int, maximum: Int)
    case noncanonicalCompactSize
    case uint32Overflow
    case truncated
    case trailingBytes
    case invalidPublicKey
    case invalidSignature
    case nonRoundTrippableValue(kind: String)
}

/// A bounded remote wallet error. Explicit accessors retain the remote text;
/// implicit diagnostics intentionally reveal only the nonzero code.
public struct WalletWireRemoteError:
    Error,
    Equatable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let code: UInt8
    public let message: String
    public let stack: String

    public init(
        code: UInt8,
        message: String,
        stack: String,
        limits: WalletWireLimits = .standard
    ) throws {
        guard code != 0 else {
            throw WalletWireError.invalidDiscriminator(kind: "remote error code", value: code)
        }
        try walletWireRequireText(
            message,
            kind: "remote message",
            maximum: limits.maximumRemoteMessageUTF8ByteCount
        )
        try walletWireRequireText(
            stack,
            kind: "remote stack",
            maximum: limits.maximumRemoteStackUTF8ByteCount
        )
        self.code = code
        self.message = message
        self.stack = stack
    }

    public var description: String { "WalletWireRemoteError(code: \(code))" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["code": code]) }
}

public struct WalletWireRequestFrame:
    Equatable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let call: WalletCall
    public let originator: String
    public let parameters: [UInt8]

    public init(call: WalletCall, originator: String, parameters: [UInt8]) {
        self.call = call
        self.originator = originator
        self.parameters = parameters
    }

    public var description: String { "<redacted wallet-wire request call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

public enum WalletWireResultFrame:
    Equatable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    case success([UInt8])
    case failure(WalletWireRemoteError)

    public var description: String { "<redacted wallet-wire result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

public enum WalletWireKeyQueryRequest:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    case getPublicKey(WalletGetPublicKeyRequest)
    case encrypt(WalletEncryptRequest)
    case decrypt(WalletDecryptRequest)
    case createHMAC(WalletCreateHMACRequest)
    case verifyHMAC(WalletVerifyHMACRequest)
    case createSignature(WalletCreateSignatureRequest)
    case verifySignature(WalletVerifySignatureRequest)
    case isAuthenticated(WalletIsAuthenticatedRequest)
    case waitForAuthentication(WalletWaitForAuthenticationRequest)
    case getHeight(WalletGetHeightRequest)
    case getHeaderForHeight(WalletGetHeaderRequest)
    case getNetwork(WalletGetNetworkRequest)
    case getVersion(WalletGetVersionRequest)

    public var call: WalletCall {
        switch self {
        case .getPublicKey: .getPublicKey
        case .encrypt: .encrypt
        case .decrypt: .decrypt
        case .createHMAC: .createHMAC
        case .verifyHMAC: .verifyHMAC
        case .createSignature: .createSignature
        case .verifySignature: .verifySignature
        case .isAuthenticated: .isAuthenticated
        case .waitForAuthentication: .waitForAuthentication
        case .getHeight: .getHeight
        case .getHeaderForHeight: .getHeaderForHeight
        case .getNetwork: .getNetwork
        case .getVersion: .getVersion
        }
    }

    public var description: String { "<redacted wallet-wire request call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

public enum WalletWireKeyQueryResult:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    case getPublicKey(WalletGetPublicKeyResult)
    case encrypt(WalletEncryptResult)
    case decrypt(WalletDecryptResult)
    case createHMAC(WalletCreateHMACResult)
    case verifyHMAC(WalletVerifyHMACResult)
    case createSignature(WalletCreateSignatureResult)
    case verifySignature(WalletVerifySignatureResult)
    case isAuthenticated(WalletAuthenticatedResult)
    case waitForAuthentication(WalletAuthenticatedResult)
    case getHeight(WalletGetHeightResult)
    case getHeaderForHeight(WalletGetHeaderResult)
    case getNetwork(WalletGetNetworkResult)
    case getVersion(WalletGetVersionResult)

    public var call: WalletCall {
        switch self {
        case .getPublicKey: .getPublicKey
        case .encrypt: .encrypt
        case .decrypt: .decrypt
        case .createHMAC: .createHMAC
        case .verifyHMAC: .verifyHMAC
        case .createSignature: .createSignature
        case .verifySignature: .verifySignature
        case .isAuthenticated: .isAuthenticated
        case .waitForAuthentication: .waitForAuthentication
        case .getHeight: .getHeight
        case .getHeaderForHeight: .getHeaderForHeight
        case .getNetwork: .getNetwork
        case .getVersion: .getVersion
        }
    }

    public var description: String { "<redacted wallet-wire result call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

public struct WalletWireDecodedKeyQueryRequest:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let originator: String
    public let request: WalletWireKeyQueryRequest

    public init(originator: String, request: WalletWireKeyQueryRequest) {
        self.originator = originator
        self.request = request
    }

    public var description: String { "<redacted decoded wallet-wire request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": request.call.rawValue]) }
}

package func walletWireRequireText(_ text: String, kind: String, maximum: Int) throws {
    let count = text.utf8.count
    guard count <= maximum else {
        throw WalletWireError.textLimitExceeded(kind: kind, actual: count, maximum: maximum)
    }
}
