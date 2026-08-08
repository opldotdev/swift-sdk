import BSVCore
import BSVKeys

public enum WalletCounterparty: Equatable, Codable, Sendable {
    case anyone
    case `self`
    case publicKey(PublicKey)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        switch text {
        case "anyone":
            self = .anyone
        case "self":
            self = .self
        default:
            guard text.utf8.count == 66,
                  let bytes = try? Hex.decode(text, maximumDecodedByteCount: 33),
                  bytes.count == 33,
                  Hex.encode(bytes) == text,
                  let key = try? PublicKey(bytes),
                  key.compressedBytes == bytes else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "counterparty must be self, anyone, or a canonical compressed public key"
                )
            }
            self = .publicKey(key)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .anyone:
            try container.encode("anyone")
        case .self:
            try container.encode("self")
        case .publicKey(let key):
            try container.encode(Hex.encode(key.compressedBytes))
        }
    }
}

/// Permission metadata carried by BRC-100 requests. This offline kernel has no
/// permission policy and rejects every non-standard value before cryptography.
public struct WalletKeyAccess:
    Equatable,
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public static let maximumPrivilegedReasonUTF8ByteCount = 1_024
    public static let standard = WalletKeyAccess(validatedPrivileged: false, reason: nil, seek: false)

    public let privileged: Bool
    public let privilegedReason: String?
    public let seekPermission: Bool

    public init(
        privileged: Bool = false,
        privilegedReason: String? = nil,
        seekPermission: Bool = false
    ) throws {
        if let privilegedReason {
            let count = privilegedReason.utf8.count
            guard count <= Self.maximumPrivilegedReasonUTF8ByteCount else {
                throw WalletValidationError.privilegedReasonTooLong(
                    actualUTF8ByteCount: count,
                    maximum: Self.maximumPrivilegedReasonUTF8ByteCount
                )
            }
        }
        self.init(validatedPrivileged: privileged, reason: privilegedReason, seek: seekPermission)
    }

    private init(validatedPrivileged: Bool, reason: String?, seek: Bool) {
        self.privileged = validatedPrivileged
        self.privilegedReason = reason
        self.seekPermission = seek
    }

    private enum CodingKeys: String, CodingKey {
        case privileged
        case privilegedReason
        case seekPermission
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let privileged = container.contains(.privileged)
            ? try container.decode(Bool.self, forKey: .privileged)
            : false
        let reason = container.contains(.privilegedReason)
            ? try container.decode(String.self, forKey: .privilegedReason)
            : nil
        let seek = container.contains(.seekPermission)
            ? try container.decode(Bool.self, forKey: .seekPermission)
            : false
        try self.init(
            privileged: privileged,
            privilegedReason: reason,
            seekPermission: seek
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if privileged { try container.encode(true, forKey: .privileged) }
        try container.encodeIfPresent(privilegedReason, forKey: .privilegedReason)
        if seekPermission { try container.encode(true, forKey: .seekPermission) }
    }

    public var description: String { "<redacted wallet key access>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}
